// Package vuln matches installed packages against OSV vulnerability data
// (docs/data-model.md §6): it syncs the OSV dumps of the ecosystems
// enrolled hosts run, and records which installed packages each
// vulnerability affects and whether patching fixes it now.
package vuln

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/vercmp"
)

// Compare orders two versions of a package: -1, 0 or 1.
type Compare func(a, b string) int

// Ecosystem is the OSV ecosystem of a distro release, e.g.
// "Ubuntu:24.04:LTS" in the "Ubuntu" bucket directory.
type Ecosystem struct {
	Name     string // "Ubuntu:24.04:LTS", "Rocky Linux:9"
	Base     string // "Ubuntu", "Rocky Linux"
	Managers []string
	Compare  Compare
}

// For returns the ecosystem of an os-release ID and VERSION_ID, and false
// for distros OSV doesn't cover. Fedora (and Fedora-based images such as
// Bazzite) has no OSV ecosystem: those hosts rely on their vendor's
// security flags on updates.
func For(osID, versionID string) (Ecosystem, bool) {
	dpkg := []string{"apt"}
	rpm := []string{"dnf", "rpm-ostree"}
	major, _, _ := strings.Cut(versionID, ".")
	if versionID == "" {
		return Ecosystem{}, false
	}
	switch osID {
	case "ubuntu":
		name := "Ubuntu:" + versionID
		// LTS releases are the even years' April ones.
		if y, m, ok := strings.Cut(versionID, "."); ok && m == "04" && len(y) == 2 && (y[1]-'0')%2 == 0 {
			name += ":LTS"
		}
		return Ecosystem{name, "Ubuntu", dpkg, vercmp.Dpkg}, true
	case "debian":
		return Ecosystem{"Debian:" + major, "Debian", dpkg, vercmp.Dpkg}, true
	case "rocky":
		return Ecosystem{"Rocky Linux:" + major, "Rocky Linux", rpm, vercmp.RPM}, true
	case "almalinux":
		return Ecosystem{"AlmaLinux:" + major, "AlmaLinux", rpm, vercmp.RPM}, true
	}
	return Ecosystem{}, false
}

// ByName finds an ecosystem by its OSV name.
func ByName(name string) (Ecosystem, bool) {
	base, rel, ok := strings.Cut(name, ":")
	if !ok {
		return Ecosystem{}, false
	}
	rel, _, _ = strings.Cut(rel, ":")
	id := map[string]string{"Ubuntu": "ubuntu", "Debian": "debian", "Rocky Linux": "rocky", "AlmaLinux": "almalinux"}[base]
	e, ok := For(id, rel)
	return e, ok && e.Name == name
}

// skipped reports records that duplicate others: Ubuntu's notices (USN)
// and Debian's advisories (DSA, DLA, DTSA) repeat the per-CVE records.
func skipped(id string) bool {
	for _, p := range []string{"USN-", "DSA-", "DLA-", "DTSA-"} {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

func (e Event) version() string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// record is the part of an OSV record Baseline keeps. Enumerated versions
// ("versions"), which make most of a record's size, are left out: the
// ranges say the same.
type record struct {
	ID        string    `json:"id"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Withdrawn string    `json:"withdrawn"`
	Aliases   []string  `json:"aliases"`
	Upstream  []string  `json:"upstream"`
	Related   []string  `json:"related"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string  `json:"type"`
			Events []Event `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			UbuntuPriority string `json:"ubuntu_priority"`
			Binaries       []struct {
				Name    string `json:"binary_name"`
				Version string `json:"binary_version"`
			} `json:"binaries"`
		} `json:"ecosystem_specific"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []store.VulnRef `json:"references"`
}

const (
	maxDetails = 8000
	maxRefs    = 20
)

// parse decodes one OSV record and keeps what affects ecosystems in eco.
// It returns ok=false for records that affect none of them, are withdrawn
// or duplicate others.
func parse(b []byte, eco map[string]bool) (store.Vuln, []store.VulnAffected, bool, error) {
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return store.Vuln{}, nil, false, err
	}
	return convert(r, eco)
}

func convert(r record, eco map[string]bool) (store.Vuln, []store.VulnAffected, bool, error) {
	if r.ID == "" || r.Withdrawn != "" || skipped(r.ID) {
		return store.Vuln{}, nil, false, nil
	}
	var affected []store.VulnAffected
	worst := ""
	for _, a := range r.Affected {
		if !eco[a.Package.Ecosystem] || a.Package.Name == "" {
			continue
		}
		var ranges [][]Event
		for _, rg := range a.Ranges {
			if rg.Type == "ECOSYSTEM" && len(rg.Events) > 0 {
				ranges = append(ranges, rg.Events)
			}
		}
		if len(ranges) == 0 {
			continue
		}
		rj, err := json.Marshal(ranges)
		if err != nil {
			return store.Vuln{}, nil, false, err
		}
		va := store.VulnAffected{VulnID: r.ID, Ecosystem: a.Package.Ecosystem, Package: a.Package.Name, Ranges: rj}
		va.Severity = Normalize(a.EcosystemSpecific.UbuntuPriority)
		if va.Severity == "" {
			va.Severity = Normalize(a.DatabaseSpecific.Severity)
		}
		if len(a.EcosystemSpecific.Binaries) > 0 && hasFix(ranges) {
			va.Binaries = map[string]string{}
			for _, bin := range a.EcosystemSpecific.Binaries {
				if bin.Name != "" && bin.Version != "" {
					va.Binaries[bin.Name] = bin.Version
				}
			}
		}
		if Rank(va.Severity) > Rank(worst) {
			worst = va.Severity
		}
		// One package can appear twice (e.g. two ranges listed apart).
		if i := slices.IndexFunc(affected, func(x store.VulnAffected) bool { return x.Package == va.Package && x.Ecosystem == va.Ecosystem }); i >= 0 {
			var prev [][]Event
			json.Unmarshal(affected[i].Ranges, &prev)
			affected[i].Ranges, _ = json.Marshal(append(prev, ranges...))
			continue
		}
		affected = append(affected, va)
	}
	if len(affected) == 0 {
		return store.Vuln{}, nil, false, nil
	}

	v := store.Vuln{ID: r.ID, Summary: r.Summary, Details: r.Details, Published: r.Published, Modified: r.Modified}
	for _, a := range append(append(r.Upstream, r.Aliases...), r.Related...) {
		if strings.HasPrefix(a, "CVE-") && !slices.Contains(v.Aliases, a) {
			v.Aliases = append(v.Aliases, a)
		}
	}
	v.Details = truncate(v.Details, maxDetails)
	if v.Summary == "" {
		// Ubuntu's per-CVE records have no summary: use the first line.
		first, _, _ := strings.Cut(strings.TrimSpace(v.Details), "\n")
		v.Summary = truncate(first, 200)
	}
	for _, ref := range r.References {
		if len(v.Refs) < maxRefs && strings.HasPrefix(ref.URL, "https://") {
			v.Refs = append(v.Refs, ref)
		}
	}
	for _, s := range r.Severity {
		if strings.HasPrefix(s.Score, "CVSS:3.") {
			if score, ok := CVSS3(s.Score); ok {
				v.CVSSScore, v.CVSSVector = &score, s.Score
				break
			}
		}
		if v.CVSSVector == "" && strings.HasPrefix(s.Score, "CVSS:") {
			v.CVSSVector = s.Score
		}
	}
	// The vendor's rating first ("Important: openssl security update"),
	// then the worst per-package one, then the CVSS score's band.
	v.Severity = Normalize(r.DatabaseSpecific.Severity)
	if v.Severity == "" {
		if word, _, ok := strings.Cut(r.Summary, ":"); ok {
			v.Severity = Normalize(word)
		}
	}
	if v.Severity == "" {
		v.Severity = worst
	}
	if v.Severity == "" && v.CVSSScore != nil {
		v.Severity = scoreBand(*v.CVSSScore)
	}
	if v.Severity == "" {
		v.Severity = "unknown"
	}
	return v, affected, true, nil
}

// truncate shortens s to at most n bytes on a character boundary, marking
// the cut with an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func hasFix(ranges [][]Event) bool {
	for _, r := range ranges {
		for _, e := range r {
			if e.Fixed != "" {
				return true
			}
		}
	}
	return false
}

// Severities from least to most severe.
var Severities = []string{"unknown", "negligible", "low", "medium", "high", "critical"}

// Rank orders severities; "" and unknown rank lowest.
func Rank(s string) int { return max(slices.Index(Severities, s), 0) }

// Normalize maps vendor ratings onto Severities; "" when it isn't one.
func Normalize(s string) string {
	switch s = strings.ToLower(strings.TrimSpace(s)); s {
	case "negligible", "unimportant":
		return "negligible"
	case "low":
		return "low"
	case "medium", "moderate":
		return "medium"
	case "high", "important":
		return "high"
	case "critical":
		return "critical"
	}
	return ""
}

func scoreBand(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "negligible"
}

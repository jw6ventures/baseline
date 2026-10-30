package vuln

import (
	"encoding/json"
	"regexp"
	"slices"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

// Check reports whether version v is inside one of an OSV entry's ranges,
// and the version that fixes it ("" when nothing does yet). Events are
// evaluated in version order, as the OSV schema specifies: introduced opens
// a vulnerable interval, fixed closes it at that version and last_affected
// just after it.
func Check(cmp Compare, ranges [][]Event, v string) (affected bool, fixed string) {
	for _, r := range ranges {
		evs := slices.Clone(r)
		slices.SortStableFunc(evs, func(a, b Event) int {
			za, zb := a.Introduced == "0", b.Introduced == "0"
			switch {
			case za && zb:
				return 0
			case za:
				return -1
			case zb:
				return 1
			}
			return cmp(a.version(), b.version())
		})
		in := false
		for i, e := range evs {
			if e.Introduced != "0" && cmp(v, e.version()) < 0 {
				// Every event from here on is past v.
				if in {
					for _, f := range evs[i:] {
						if f.Fixed != "" {
							return true, f.Fixed
						}
						if f.Introduced != "" || f.LastAffected != "" {
							break
						}
					}
				}
				break
			}
			switch {
			case e.Introduced != "":
				in = true
			case e.Fixed != "":
				in = false
			case e.LastAffected != "" && cmp(v, e.LastAffected) > 0:
				in = false
			}
		}
		if in {
			affected = true
		}
	}
	return affected, ""
}

// kernelABI finds a kernel ABI version in a package name: 6.8.0-45.
var kernelABI = regexp.MustCompile(`\d+\.\d+\.\d+-\d+`)

// CandidateKey identifies a package's pending update.
func CandidateKey(manager, name, arch string) string { return manager + "\x00" + name + "\x00" + arch }

// Match finds the installed packages that affected entries cover. Entries
// name source packages; a package is matched by its source, or its own name
// when it has none. Where an entry lists fixed versions per binary package
// (Ubuntu), those decide. Of several installed versions of one name and
// architecture (rpm kernels), only the newest is matched: older ones stay
// installed for fallback, not use; Ubuntu and Debian put the kernel ABI in
// the name instead (linux-headers-6.8.0-45-generic), so names that differ
// only in it count as one. candidates are the versions pending updates
// would install, by CandidateKey.
func Match(e Ecosystem, pkgs []model.Package, candidates map[string]string, affected []store.VulnAffected) []store.HostVuln {
	newest := map[string]model.Package{}
	var order []string
	for _, p := range pkgs {
		if !slices.Contains(e.Managers, p.Manager) {
			continue
		}
		k := kernelABI.ReplaceAllString(p.Name, "*") + "\x00" + p.Arch
		if cur, ok := newest[k]; ok {
			if e.Compare(p.FullVersion(), cur.FullVersion()) > 0 {
				newest[k] = p
			}
			continue
		}
		newest[k] = p
		order = append(order, k)
	}
	bySource := map[string][]model.Package{}
	for _, k := range order {
		p := newest[k]
		src := p.Source
		if src == "" {
			src = p.Name
		}
		bySource[src] = append(bySource[src], p)
	}

	var out []store.HostVuln
	for _, a := range affected {
		pkgs := bySource[a.Package]
		if len(pkgs) == 0 {
			continue
		}
		var ranges [][]Event
		if err := json.Unmarshal(a.Ranges, &ranges); err != nil {
			continue
		}
		sev := a.Severity
		if sev == "" {
			sev = a.VulnSeverity
		}
		if sev == "" {
			sev = "unknown"
		}
		for _, p := range pkgs {
			installed := p.FullVersion()
			var hit bool
			var fixed string
			if bin, ok := a.Binaries[p.Name]; ok {
				hit, fixed = e.Compare(installed, bin) < 0, bin
			} else {
				hit, fixed = Check(e.Compare, ranges, installed)
			}
			if !hit {
				continue
			}
			hv := store.HostVuln{VulnID: a.VulnID, Package: p.Name, Arch: p.Arch, Source: p.Source, Installed: installed,
				Fixed: fixed, Severity: sev}
			hv.Candidate = candidates[CandidateKey(p.Manager, p.Name, p.Arch)]
			hv.FixAvailable = fixed != "" && hv.Candidate != "" && e.Compare(hv.Candidate, fixed) >= 0
			out = append(out, hv)
		}
	}
	return out
}

package registry

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Rule opts a container into semver advisories (docs/agent.md §3.3).
type Rule struct {
	Track   string `json:"track"`             // patch | minor | major
	Include string `json:"include,omitempty"` // regexp a tag must match
	Exclude string `json:"exclude,omitempty"` // regexp a tag must not match
}

// Validate checks a rule as entered in the UI.
func (r Rule) Validate() error {
	switch r.Track {
	case "patch", "minor", "major":
	case "":
		return errors.New("track is required: patch, minor or major")
	default:
		return fmt.Errorf("track %q must be patch, minor or major", r.Track)
	}
	if err := checkRegexp("include", r.Include); err != nil {
		return err
	}
	return checkRegexp("exclude", r.Exclude)
}

func checkRegexp(field, expr string) error {
	if _, err := regexp.Compile(expr); err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return fmt.Errorf("%s is not a valid regular expression: %s", field, se.Code)
		}
		return fmt.Errorf("%s is not a valid regular expression", field)
	}
	return nil
}

// Advise returns the newest tag in tags that the rule allows and that is
// newer than current, and whether there is one.
//
// Candidates must have current's prerelease "shape": none if current has
// none, otherwise the same non-numeric flavor, so a container on
// 1.27.3-alpine is offered 1.28.0-alpine and never 1.28.0 or 1.28.0-rc1.
func Advise(current string, tags []string, r Rule) (string, bool) {
	switch r.Track {
	case "patch", "minor", "major":
	default:
		return "", false
	}
	cur, err := semver.NewVersion(current)
	if err != nil {
		return "", false
	}
	var include, exclude *regexp.Regexp
	if r.Include != "" {
		if include, err = regexp.Compile(r.Include); err != nil {
			return "", false
		}
	}
	if r.Exclude != "" {
		if exclude, err = regexp.Compile(r.Exclude); err != nil {
			return "", false
		}
	}
	flavor := flavorOf(cur)

	var best *semver.Version
	bestTag := ""
	for _, tag := range tags {
		if include != nil && !include.MatchString(tag) || exclude != nil && exclude.MatchString(tag) {
			continue
		}
		v, err := semver.NewVersion(tag)
		if err != nil || flavorOf(v) != flavor {
			continue
		}
		switch r.Track {
		case "patch":
			if v.Major() != cur.Major() || v.Minor() != cur.Minor() {
				continue
			}
		case "minor":
			if v.Major() != cur.Major() {
				continue
			}
		}
		if compareVersions(v, cur) <= 0 {
			continue
		}
		if best == nil {
			best, bestTag = v, tag
			continue
		}
		switch c := compareVersions(v, best); {
		case c > 0, c == 0 && preferSpelling(tag, bestTag, current):
			best, bestTag = v, tag
		}
	}
	return bestTag, best != nil
}

// flavorOf is a version's prerelease with digits and dots stripped, so
// "alpine", "alpine3.19" and "alpine3.20" are one flavor. A leading "+"
// marks that there is a prerelease at all, keeping a purely numeric one
// ("1.2.3-4") apart from none.
func flavorOf(v *semver.Version) string {
	pre := v.Prerelease()
	if pre == "" {
		return ""
	}
	return "+" + strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '.' {
			return -1
		}
		return r
	}, pre)
}

// compareVersions orders by version core and then by full semver order. For
// same-flavor prereleases this ranks 1.28.0-alpine above 1.27.3-alpine
// whatever the prerelease says; build metadata is ignored throughout.
func compareVersions(a, b *semver.Version) int {
	for _, d := range [][2]uint64{{a.Major(), b.Major()}, {a.Minor(), b.Minor()}, {a.Patch(), b.Patch()}} {
		switch {
		case d[0] > d[1]:
			return 1
		case d[0] < d[1]:
			return -1
		}
	}
	return a.Compare(b)
}

// preferSpelling breaks a tie between two spellings of one version ("1.5",
// "1.5.0", "v1.5.0"): the one written like current wins, as that's the
// series the user follows; then the longer, then the lexically greater so
// the answer doesn't depend on the registry's tag order.
func preferSpelling(a, b, current string) bool {
	if sa, sb := spellingScore(a, current), spellingScore(b, current); sa != sb {
		return sa > sb
	}
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

func spellingScore(tag, current string) int {
	score := 0
	if hasV(tag) == hasV(current) {
		score++
	}
	if components(tag) == components(current) {
		score++
	}
	return score
}

func hasV(s string) bool { return strings.HasPrefix(s, "v") }

// components counts the numbers in a tag's version core: 2 for "v1.5-alpine".
func components(s string) int {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	return strings.Count(s, ".") + 1
}

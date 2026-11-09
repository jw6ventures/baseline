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
//
// "Newer" is judged at current's precision. A floating tag such as
// 2026.8 already moves to each 2026.8.x release, which digest drift
// reports, so it is only offered a newer series (2026.9, 2027.1): never
// 2026.8.5. The tag written like current is preferred, so 2026.8 is
// offered 2026.11 over 2026.11.2 when the registry has both.
func Advise(current string, tags []string, r Rule) (string, bool) {
	return AdviseExcept(current, tags, r, nil)
}

// AdviseExcept is Advise skipping the tags same reports true for: tags
// known to serve the image current already does, which are no update.
func AdviseExcept(current string, tags []string, r Rule, same func(tag string) bool) (string, bool) {
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
	prec := min(components(current), 3)

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
		if !newerAt(v, tag, cur, prec) {
			continue
		}
		if same != nil && same(tag) {
			continue
		}
		if best == nil || better(v, tag, best, bestTag, current, prec) {
			best, bestTag = v, tag
		}
	}
	return bestTag, best != nil
}

// newerAt reports whether v (spelled tag) is newer than cur, comparing
// only the prec version numbers cur is written with. A tag that matches
// those and goes on to name a release inside cur's series (2026.8.5 for
// 2026.8) is not newer: the floating tag already gets it.
func newerAt(v *semver.Version, tag string, cur *semver.Version, prec int) bool {
	switch c := compareAt(v, cur, prec); {
	case c != 0:
		return c > 0
	case prec < 3 && components(tag) > prec:
		return false
	}
	return compareVersions(v, cur) > 0
}

// better reports whether candidate v (spelled tag) beats best (spelled
// bestTag) for a container on current, written with prec numbers.
func better(v *semver.Version, tag string, best *semver.Version, bestTag, current string, prec int) bool {
	if c := compareAt(v, best, prec); c != 0 {
		return c > 0
	}
	if sa, sb := spellingScore(tag, current), spellingScore(bestTag, current); sa != sb {
		return sa > sb
	}
	if c := compareVersions(v, best); c != 0 {
		return c > 0
	}
	return preferSpelling(tag, bestTag, current)
}

// compareAt is compareVersions limited to the first prec version numbers
// when prec is under 3.
func compareAt(a, b *semver.Version, prec int) int {
	if prec >= 3 {
		return compareVersions(a, b)
	}
	for i, d := range [][2]uint64{{a.Major(), b.Major()}, {a.Minor(), b.Minor()}} {
		if i >= prec {
			break
		}
		switch {
		case d[0] > d[1]:
			return 1
		case d[0] < d[1]:
			return -1
		}
	}
	return 0
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

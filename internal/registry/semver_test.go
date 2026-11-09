package registry

import (
	"strings"
	"testing"
)

func TestAdvise(t *testing.T) {
	series := []string{"1.4.6", "1.4.7", "1.4.8", "1.4.10", "1.5.0", "1.5.2", "2.0.0", "latest", "stable"}
	for _, c := range []struct {
		name    string
		current string
		tags    []string
		rule    Rule
		want    string
	}{
		{"patch", "1.4.7", series, Rule{Track: "patch"}, "1.4.10"},
		{"minor", "1.4.7", series, Rule{Track: "minor"}, "1.5.2"},
		{"major", "1.4.7", series, Rule{Track: "major"}, "2.0.0"},
		{"no newer", "2.0.0", series, Rule{Track: "major"}, ""},
		{"no newer in track", "1.5.2", series, Rule{Track: "minor"}, ""},
		{"unparseable current", "latest", series, Rule{Track: "major"}, ""},
		{"empty current", "", series, Rule{Track: "major"}, ""},
		{"bad track", "1.4.7", series, Rule{Track: "any"}, ""},
		{"bad include", "1.4.7", series, Rule{Track: "major", Include: "("}, ""},
		{"no tags", "1.4.7", nil, Rule{Track: "major"}, ""},

		{"prerelease skipped", "1.4.7", []string{"1.4.8-rc1", "1.5.0-beta.2", "2.0.0-alpha"}, Rule{Track: "major"}, ""},
		{"prerelease beside release", "1.4.7", []string{"1.4.8-rc1", "1.4.8", "1.4.9-rc1"}, Rule{Track: "patch"}, "1.4.8"},
		{"alpine flavor", "1.27.3-alpine",
			[]string{"1.27.4", "1.28.0", "1.27.4-alpine", "1.28.0-alpine", "1.28.0-alpine-slim", "1.29.0-perl", "1.28.0-rc1"},
			Rule{Track: "minor"}, "1.28.0-alpine"},
		{"alpine flavor patch", "1.27.3-alpine",
			[]string{"1.27.4", "1.27.4-alpine", "1.28.0-alpine"}, Rule{Track: "patch"}, "1.27.4-alpine"},
		{"alpine with base version", "3.20-alpine3.19",
			[]string{"3.21", "3.21-slim", "3.21-alpine3.20", "3.20-alpine3.20", "3.19-alpine3.20"},
			Rule{Track: "minor"}, "3.21-alpine3.20"},
		{"core before prerelease", "1.27.3-alpine3.20",
			[]string{"1.27.4-alpine3.19", "1.27.3-alpine3.21"}, Rule{Track: "patch"}, "1.27.4-alpine3.19"},
		{"same core newer prerelease", "1.27.3-alpine3.19",
			[]string{"1.27.3-alpine3.20", "1.27.3-alpine3.18"}, Rule{Track: "patch"}, "1.27.3-alpine3.20"},
		{"numeric prerelease", "1.2.3-1", []string{"1.2.3-2", "1.2.4", "1.2.3-ls1"}, Rule{Track: "patch"}, "1.2.3-2"},

		{"v prefix", "v1.4.7", []string{"v1.4.8", "1.4.9"}, Rule{Track: "patch"}, "1.4.9"},
		{"tie prefers v like current", "v1.4.7", []string{"1.5", "1.5.0", "v1.5.0"}, Rule{Track: "minor"}, "v1.5.0"},
		{"tie prefers components like current", "1.4", []string{"1.5.0", "1.5", "v1.5.0"}, Rule{Track: "minor"}, "1.5"},
		{"tie prefers longest", "1.4.7", []string{"1.5", "v1.5.0"}, Rule{Track: "minor"}, "v1.5.0"},
		{"tie order independent", "1.4.7", []string{"v1.5.0", "1.5"}, Rule{Track: "minor"}, "v1.5.0"},
		{"same version respelled is not newer", "1.4", []string{"1.4.0", "v1.4"}, Rule{Track: "major"}, ""},

		{"include", "1.4.7", []string{"1.4.8", "1.5.0", "1.5.1-ls12"}, Rule{Track: "minor", Include: `^1\.4\.`}, "1.4.8"},
		{"exclude", "1.4.7", series, Rule{Track: "major", Exclude: `^2\.`}, "1.5.2"},
		{"include raw tag", "v1.4.7", []string{"v1.4.8", "1.4.9"}, Rule{Track: "patch", Include: `^v`}, "v1.4.8"},
		{"metadata ignored", "1.0.0+build1", []string{"1.0.0+build2", "1.0.1+build1"}, Rule{Track: "patch"}, "1.0.1+build1"},
		{"metadata only", "1.0.0+build1", []string{"1.0.0+build2"}, Rule{Track: "patch"}, ""},

		{"two components", "2025.1", []string{"2025.1.1", "2025.10", "2025.2", "2025.9.3", "2024.12"}, Rule{Track: "minor"}, "2025.10"},
		{"two components patch", "2025.1", []string{"2025.1.1", "2025.10", "2025.2"}, Rule{Track: "patch"}, ""},
		{"floating minor skips its own patches", "2026.8", []string{"2026.8", "2026.8.4", "2026.8.5"}, Rule{Track: "minor"}, ""},
		{"floating minor offers next series", "2026.8", []string{"2026.8.5", "2026.11.0", "2026.11.2", "2026.11", "2027.1"}, Rule{Track: "minor"}, "2026.11"},
		{"floating minor without floating tags", "2026.8", []string{"2026.8.5", "2026.11.0", "2026.11.2"}, Rule{Track: "minor"}, "2026.11.2"},
		{"floating major skips own patches", "2026.8", []string{"2026.8.5", "2026.10.1"}, Rule{Track: "major"}, "2026.10.1"},
		{"floating major tag", "3", []string{"3.1", "3.2.4", "4", "4.0.1"}, Rule{Track: "major"}, "4"},
		{"floating major tag minor track", "3", []string{"3.1", "3.2.4"}, Rule{Track: "minor"}, ""},
		{"floating flavor", "3.20-alpine", []string{"3.20.1-alpine", "3.21.0-alpine"}, Rule{Track: "minor"}, "3.21.0-alpine"},
		{"calendar major", "2025.1.2", []string{"2026.1.0", "2025.12.4"}, Rule{Track: "major"}, "2026.1.0"},
	} {
		got, ok := Advise(c.current, c.tags, c.rule)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: Advise(%q) = %q, %v; want %q", c.name, c.current, got, ok, c.want)
		}
	}
}

func TestAdviseExcept(t *testing.T) {
	tags := []string{"1.4.8", "1.5.0", "1.5.1"}
	same := func(tag string) bool { return tag == "1.5.1" }
	if got, ok := AdviseExcept("1.4.7", tags, Rule{Track: "minor"}, same); !ok || got != "1.5.0" {
		t.Errorf("AdviseExcept = %q, %v; want 1.5.0", got, ok)
	}
	all := func(string) bool { return true }
	if got, ok := AdviseExcept("1.4.7", tags, Rule{Track: "minor"}, all); ok {
		t.Errorf("AdviseExcept = %q; want none", got)
	}
}

func TestRuleValidate(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		want string // substring of the error; "" for none
	}{
		{Rule{Track: "patch"}, ""},
		{Rule{Track: "minor", Include: `^\d+\.\d+$`, Exclude: `-rc`}, ""},
		{Rule{Track: "major"}, ""},
		{Rule{}, "track is required"},
		{Rule{Track: "Minor"}, `track "Minor" must be`},
		{Rule{Track: "minor", Include: "("}, "include is not a valid regular expression: missing closing )"},
		{Rule{Track: "minor", Exclude: "[a-"}, "exclude is not a valid regular expression"},
	} {
		err := c.rule.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v: unexpected error %v", c.rule, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%+v: error %v, want %q", c.rule, err, c.want)
		}
	}
}

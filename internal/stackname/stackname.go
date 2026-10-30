// Package stackname reads the metadata encoded in a Compose project's name.
//
// Stacks named <env><category><visibility>-<app>, such as pii-backup or
// phi-healthrecords, carry their environment, category and visibility in
// the three-letter prefix. Names without a full, known prefix (temporary
// dev stacks, Baseline itself) carry nothing.
package stackname

import "strings"

// Meta is what a stack's name says about it.
type Meta struct {
	Environment string // Dev | Staging | Test | Prod
	Category    string // Infrastructure | Entertainment | Web | Health
	Visibility  string // Internal | External
	App         string // the rest of the name
}

// The values each part takes, in the order the UI lists them.
var (
	Environments = []string{"Dev", "Test", "Staging", "Prod"}
	Categories   = []string{"Infrastructure", "Entertainment", "Web", "Health"}
	Visibilities = []string{"Internal", "External"}
)

var (
	environments = map[byte]string{'d': "Dev", 's': "Staging", 't': "Test", 'p': "Prod"}
	categories   = map[byte]string{'i': "Infrastructure", 'e': "Entertainment", 'w': "Web", 'h': "Health"}
	visibilities = map[byte]string{'i': "Internal", 'e': "External"}
)

// Parse reports the metadata in a Compose project name, and whether the
// name follows the pattern at all.
func Parse(project string) (Meta, bool) {
	prefix, app, ok := strings.Cut(strings.ToLower(project), "-")
	if !ok || len(prefix) != 3 || app == "" {
		return Meta{}, false
	}
	m := Meta{
		Environment: environments[prefix[0]],
		Category:    categories[prefix[1]],
		Visibility:  visibilities[prefix[2]],
		App:         app,
	}
	if m.Environment == "" || m.Category == "" || m.Visibility == "" {
		return Meta{}, false
	}
	return m, true
}

// Attrs is the metadata as CI attributes; nil when the name carries none.
func Attrs(project string) map[string]string {
	m, ok := Parse(project)
	if !ok {
		return nil
	}
	return map[string]string{"environment": m.Environment, "category": m.Category, "visibility": m.Visibility}
}

// Stage is an environment's place in promotion, Dev then Test or Staging
// (one level: Test is used for external stacks, Staging for internal
// ones) then Prod; -1 for an unknown environment.
func Stage(env string) int {
	switch env {
	case "Dev":
		return 0
	case "Test", "Staging":
		return 1
	case "Prod":
		return 2
	}
	return -1
}

// SameApp reports whether two stacks' names are the same app in the same
// category, whatever their environments and visibilities.
func SameApp(a, b Meta) bool { return a.App == b.App && a.Category == b.Category }

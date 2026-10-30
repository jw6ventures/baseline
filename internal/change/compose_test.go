package change

import (
	"slices"
	"testing"

	"github.com/jw6ventures/baseline/internal/store"
)

func TestEarlier(t *testing.T) {
	stack := func(project, vis string) store.Stack {
		return store.Stack{CIID: project, Project: project, Present: true, Visibility: vis}
	}
	all := []store.Stack{
		stack("dwi-app", "Internal"), stack("dwe-app", "External"), stack("twe-app", "External"),
		stack("swi-app", "Internal"), stack("pwi-app", "Internal"), stack("pwe-app", "External"),
		stack("pii-app", "Internal"), stack("dwi-other", "Internal"), stack("baseline", ""),
	}
	gone := stack("tii-app", "Internal")
	gone.Present = false
	all = append(all, gone)
	names := func(ss []store.Stack) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s.Project)
		}
		slices.Sort(out)
		return out
	}
	for project, want := range map[string][]string{
		"pwi-app":   {"swi-app"},   // Test/Staging before Dev, same visibility first
		"pwe-app":   {"twe-app"},   //
		"swi-app":   {"dwi-app"},   // Staging promotes from Dev
		"twe-app":   {"dwe-app"},   //
		"dwi-app":   nil,           // Dev is first
		"pii-app":   nil,           // another category is another app; tii-app is gone
		"baseline":  nil,           // no environment
		"pwi-other": {"dwi-other"}, // no Test or Staging: Dev
	} {
		st := stack(project, map[byte]string{'i': "Internal", 'e': "External"}[project[2]])
		if got := names(earlier(st, all)); !slices.Equal(got, want) {
			t.Errorf("earlier(%s) = %v, want %v", project, got, want)
		}
	}
	// No copy of the same visibility at that stage: any visibility.
	if got := names(earlier(stack("pwi-x", "Internal"), []store.Stack{stack("twe-x", "External"), stack("dwi-x", "Internal")})); !slices.Equal(got, []string{"twe-x"}) {
		t.Errorf("other visibility: %v", got)
	}
}

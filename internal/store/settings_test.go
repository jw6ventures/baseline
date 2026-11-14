package store_test

import (
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestRetireMissingStacks(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	c := sampleContainers()
	c.Stacks = append(c.Stacks, model.ComposeStack{Engine: "docker", Project: "old", Services: []string{"app"}})
	ingestSection(t, s, r, model.SectionContainers, c)
	stacks, _ := s.ListStacks(ctx, []string{r.HostID})
	if len(stacks) != 2 {
		t.Fatalf("stacks = %+v", stacks)
	}
	var old string
	for _, st := range stacks {
		if st.Project == "old" {
			old = st.CIID
		}
	}

	// "old" goes away and is missing an hour later.
	ingestSection(t, s, r, model.SectionContainers, sampleContainers())
	if n, _ := s.MarkMissing(ctx, time.Now().Add(2*time.Hour)); n != 1 {
		t.Fatalf("marked %d missing", n)
	}

	// Off by default: nothing is retired, however long it's gone.
	if d, err := s.RetireMissingStacksDays(ctx); err != nil || d != 0 {
		t.Fatalf("default = %d %v", d, err)
	}
	if n, err := s.RetireMissingStacks(ctx, time.Now().Add(1000*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("retired %d with the setting off: %v", n, err)
	}

	if err := s.SetRetireMissingStacksDays(ctx, store.System, -1); err == nil {
		t.Fatal("negative days accepted")
	}
	if err := s.SetRetireMissingStacksDays(ctx, store.System, 7); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.RetireMissingStacksDays(ctx); d != 7 {
		t.Fatalf("days = %d", d)
	}

	// Not yet 7 days gone: kept.
	if n, _ := s.RetireMissingStacks(ctx, time.Now().Add(6*24*time.Hour)); n != 0 {
		t.Fatalf("retired %d too early", n)
	}
	if n, err := s.RetireMissingStacks(ctx, time.Now().Add(8*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("retired %d: %v", n, err)
	}
	if ci, _ := s.GetCI(ctx, old); ci.Status != "retired" {
		t.Fatalf("old CI = %+v", ci)
	}
	// Off the host's list, still there by ID.
	if stacks, _ := s.ListStacks(ctx, []string{r.HostID}); len(stacks) != 1 || stacks[0].Project != "web" {
		t.Fatalf("listed = %+v", stacks)
	}
	if st, err := s.GetStack(ctx, old); err != nil || st.Status != "retired" {
		t.Fatalf("retired stack = %+v %v", st, err)
	}
	// Running again only retires once.
	if n, _ := s.RetireMissingStacks(ctx, time.Now().Add(9*24*time.Hour)); n != 0 {
		t.Fatalf("retired %d again", n)
	}
	entries, err := s.ListAudit(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, e := range entries {
		if e.Action == "stack.retire" && e.ObjectID == old && e.Actor == "system" {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("no stack.retire audit: %+v", entries)
	}

	// It comes back: active and listed again.
	ingestSection(t, s, r, model.SectionContainers, c)
	if ci, _ := s.GetCI(ctx, old); ci.Status != "active" {
		t.Fatalf("returned CI = %+v", ci)
	}
	if stacks, _ := s.ListStacks(ctx, []string{r.HostID}); len(stacks) != 2 {
		t.Fatalf("listed after return = %+v", stacks)
	}

	// 0 turns it off again.
	if err := s.SetRetireMissingStacksDays(ctx, store.System, 0); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.RetireMissingStacksDays(ctx); d != 0 {
		t.Fatalf("days after off = %d", d)
	}
}

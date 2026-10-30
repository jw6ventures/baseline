package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

func TestSLAClocks(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	annID := strings.TrimPrefix(ann.ID, "user:")
	types := typeIDs(t, s, "incident", "task")
	pid, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk",
		TypeIDs: types, DefaultType: types[0]})
	if err != nil {
		t.Fatal(err)
	}

	// A global policy, and one for OPS incidents that wins over it.
	if _, err := s.SaveSLAPolicy(ctx, ann, "", store.SLAPolicy{Name: "Everything", Enabled: true,
		Targets: store.SLATargets{"high": {"resolution": 600}}}); err != nil {
		t.Fatal(err)
	}
	inc, err := s.SaveSLAPolicy(ctx, ann, "", store.SLAPolicy{Name: "Ops incidents", ProjectID: pid, TypeID: types[0], Enabled: true,
		Targets: store.SLATargets{"high": {"response": 30, "resolution": 240}, "low": {"resolution": 2880}, "medium": {"response": 0}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSLAPolicy(ctx, ann, "", store.SLAPolicy{Name: "Again", ProjectID: pid, TypeID: types[0]}); !errors.Is(err, store.ErrSLAScopeTaken) {
		t.Fatalf("same scope twice: %v", err)
	}
	if _, err := s.SaveSLAPolicy(ctx, ann, "", store.SLAPolicy{Name: "ops INCIDENTS", ProjectID: pid}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same name twice: %v", err)
	}
	p, err := s.GetSLAPolicy(ctx, inc)
	if err != nil || p.ProjectKey != "OPS" || p.TypeName != "Incident" || p.Targets.Target("high", "response") != 30 ||
		p.Targets["medium"] != nil {
		t.Fatalf("policy %+v %v", p, err)
	}

	clocks := func(id string) map[string]store.SLAClock {
		t.Helper()
		cs, err := s.WorkItemSLAs(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.SLAClock{}
		for _, c := range cs {
			out[c.Metric] = c
		}
		return out
	}

	id, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: "NAS down", Priority: "high"})
	if err != nil {
		t.Fatal(err)
	}
	c := clocks(id)
	if len(c) != 2 || c["response"].PolicyName != "Ops incidents" || c["response"].TargetMinutes != 30 ||
		!c["response"].TargetAt.Equal(c["response"].StartedAt.Add(30*time.Minute)) || !c["resolution"].Running() {
		t.Fatalf("clocks on create: %+v", c)
	}
	// A task falls to the global policy; a low task has no target there.
	task, _, _ := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[1], Title: "t", Priority: "high"})
	if c := clocks(task); len(c) != 1 || c["resolution"].PolicyName != "Everything" {
		t.Fatalf("task clocks: %+v", c)
	}
	low, _, _ := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[1], Title: "t", Priority: "low"})
	if c := clocks(low); len(c) != 0 {
		t.Fatalf("low task clocks: %+v", c)
	}

	// A priority change moves the running targets.
	in := store.WorkItemInput{Title: "NAS down", Priority: "low"}
	if err := s.UpdateWorkItem(ctx, ann, id, in); err != nil {
		t.Fatal(err)
	}
	c = clocks(id)
	if c["resolution"].TargetMinutes != 2880 || c["response"].TargetMinutes != 30 {
		t.Fatalf("after priority change: %+v", c)
	}
	in.Priority = "high"
	s.UpdateWorkItem(ctx, ann, id, in)

	// Starting work meets the response; done meets the resolution, and
	// reopening runs it again.
	if err := transition(t, s, ann, id, "Start progress", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	c = clocks(id)
	if c["response"].Running() || c["response"].Breached(time.Now()) || !c["resolution"].Running() {
		t.Fatalf("after start: %+v", c)
	}
	if err := transition(t, s, ann, id, "Done", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	if c = clocks(id); c["resolution"].Running() {
		t.Fatalf("after done: %+v", c)
	}
	if err := transition(t, s, ann, id, "Reopen", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	if c = clocks(id); !c["resolution"].Running() || c["response"].Running() {
		t.Fatalf("after reopen: %+v", c)
	}
	if !c["resolution"].Breached(c["resolution"].TargetAt.Add(time.Second)) {
		t.Fatal("not breached past the target")
	}

	// Deleting the policy leaves the clocks running.
	if err := s.DeleteSLAPolicy(ctx, ann, inc); err != nil {
		t.Fatal(err)
	}
	if c = clocks(id); len(c) != 2 || c["resolution"].PolicyID != "" || c["resolution"].PolicyName != "Ops incidents" {
		t.Fatalf("after delete: %+v", c)
	}
}

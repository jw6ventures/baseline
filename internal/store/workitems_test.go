package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/store"
)

func typeIDs(t *testing.T, s *store.Store, keys ...string) []string {
	t.Helper()
	all, err := s.ListTicketTypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range keys {
		for _, tt := range all {
			if tt.Key == k {
				out = append(out, tt.ID)
			}
		}
	}
	if len(out) != len(keys) {
		t.Fatalf("ticket types %v: found %d", keys, len(out))
	}
	return out
}

// transition runs the transition called name out of the item's status, as
// the system.
func transition(t *testing.T, s *store.Store, actor store.Actor, itemID, name string, in store.TransitionInput) error {
	t.Helper()
	it, err := s.GetWorkItem(ctx, itemID)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := s.ItemTransitions(ctx, it)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range ts {
		if tr.Name == name {
			return s.TransitionWorkItem(ctx, actor, store.Runner{}, itemID, tr.ID, in)
		}
	}
	t.Fatalf("%s has no transition %q out of %s", it.Ref(), name, it.StatusName)
	return nil
}

func TestWorkItems(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	bob := user(t, s, "bob")
	annID, bobID := strings.TrimPrefix(ann.ID, "user:"), strings.TrimPrefix(bob.ID, "user:")
	types := typeIDs(t, s, "incident", "problem", "task")

	if _, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk"}); !errors.Is(err, store.ErrNoTypes) {
		t.Fatalf("project without types: %v", err)
	}
	pid, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk",
		TypeIDs: types[:2], DefaultType: types[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Again", Kind: "software", TypeIDs: types}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate key: %v", err)
	}
	p, err := s.GetProject(ctx, "ops")
	if err != nil || p.ID != pid || len(p.Types) != 2 || p.DefaultType() != types[1] || !p.Offers(types[0]) || p.Offers(types[2]) {
		t.Fatalf("project %+v %v", p, err)
	}

	// Numbering is per project and the reporter watches.
	if _, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[2], Title: "x", Priority: "low"}); !errors.Is(err, store.ErrTypeNotOffered) {
		t.Fatalf("type not offered: %v", err)
	}
	due := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	id1, ref1, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0],
		Title: "NAS offline", Description: "No ping", Priority: "high", Impact: "high", DueAt: due})
	if err != nil || ref1 != "OPS-1" {
		t.Fatalf("create: %s %v", ref1, err)
	}
	id2, ref2, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[1],
		Title: "Disks keep failing", Priority: "medium", AssigneeID: bobID})
	if err != nil || ref2 != "OPS-2" {
		t.Fatalf("create 2: %s %v", ref2, err)
	}
	w, err := s.GetWorkItemByRef(ctx, "ops-1")
	if err != nil || w.ID != id1 || w.Reporter != "ANN" || w.Status != store.StatusTodo || !w.DueAt.Equal(due) || w.TypeKey != "incident" {
		t.Fatalf("get: %+v %v", w, err)
	}
	if ws, _ := s.WorkItemWatchers(ctx, id2); len(ws) != 2 {
		t.Fatalf("watchers of OPS-2: %+v", ws)
	}

	// Edits are recorded field by field; an edit that changes nothing isn't.
	est := 3.5
	in := store.WorkItemInput{Title: "NAS offline", Description: "No ping", Priority: "critical", Impact: "high",
		AssigneeID: bobID, ParentID: id2, Estimate: &est, DueAt: due}
	if err := s.UpdateWorkItem(ctx, bob, id1, in); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateWorkItem(ctx, bob, id1, in); err != nil {
		t.Fatal(err)
	}
	hist, _ := s.WorkItemHistory(ctx, id1, 10)
	if len(hist) != 2 || !hist[1].Initial || hist[0].ActorName != "BOB" || len(hist[0].Diff.Changed) != 4 {
		t.Fatalf("history: %+v", hist)
	}
	if w, _ := s.GetWorkItem(ctx, id1); w.ParentRef != "OPS-2" || w.Assignee != "BOB" || w.Estimate == nil || *w.Estimate != 3.5 {
		t.Fatalf("after edit: %+v", w)
	}
	// A parent can't be the item itself or below it.
	if err := s.UpdateWorkItem(ctx, bob, id2, store.WorkItemInput{Title: "Disks keep failing", Priority: "medium", ParentID: id1}); !errors.Is(err, store.ErrParentCycle) {
		t.Fatalf("cycle: %v", err)
	}
	if kids, _ := s.ListWorkItems(ctx, store.WorkItemFilter{ParentID: id2}); len(kids) != 1 || kids[0].ID != id1 {
		t.Fatalf("children: %+v", kids)
	}

	// Status: done sets the resolution and resolved time, reopening clears them.
	if err := transition(t, s, bob, id1, "Done", store.TransitionInput{Resolution: "Fixed"}); err != nil {
		t.Fatal(err)
	}
	w, _ = s.GetWorkItem(ctx, id1)
	if w.Status != store.StatusDone || w.StatusName != "Done" || w.Resolution != "Fixed" || w.ResolvedAt.IsZero() {
		t.Fatalf("done: %+v", w)
	}
	if open, _ := s.ListWorkItems(ctx, store.WorkItemFilter{ProjectID: pid}); len(open) != 1 || open[0].ID != id2 {
		t.Fatalf("open items: %+v", open)
	}
	if mine, _ := s.ListWorkItems(ctx, store.WorkItemFilter{Status: "all", Assignee: bobID, Query: "ops-1"}); len(mine) != 1 {
		t.Fatalf("query: %+v", mine)
	}
	if err := transition(t, s, bob, id1, "Reopen", store.TransitionInput{Resolution: "Fixed"}); err != nil {
		t.Fatal(err)
	}
	if w, _ := s.GetWorkItem(ctx, id1); w.Status != store.StatusTodo || w.Resolution != "" || !w.ResolvedAt.IsZero() {
		t.Fatalf("reopened: %+v", w)
	}

	// Links to CIs, changes and other items show from both sides.
	nas, err := s.CreateCI(ctx, ann, store.CIInput{Type: "nas", Name: "nas1", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LinkWorkItemCI(ctx, ann, id1, nas, "affected"); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkWorkItemCI(ctx, ann, id1, nas, "affected"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate CI link: %v", err)
	}
	if cis, _ := s.WorkItemCIs(ctx, id1); len(cis) != 1 || cis[0].CI.Name != "nas1" {
		t.Fatalf("item CIs: %+v", cis)
	}
	if items, _ := s.CIWorkItems(ctx, nas); len(items) != 1 || items[0].Item.Ref() != "OPS-1" || items[0].Role != "affected" {
		t.Fatalf("CI items: %+v", items)
	}
	h := host(t, s, 1)
	c, err := s.CreateChange(ctx, ann, store.NewChange{Title: "Replace disk", Risk: action.Low, Concurrency: 1,
		Steps: []store.PlanStep{step(t, action.ServiceRestart, action.UnitParams{Unit: "smb"}, h.HostID)}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeIDByNumber(ctx, c.Number); got != c.ID {
		t.Fatalf("change by number: %s", got)
	}
	if err := s.LinkWorkItemChange(ctx, ann, id2, c.ID, "fixes"); err != nil {
		t.Fatal(err)
	}
	if chs, _ := s.WorkItemChanges(ctx, id2); len(chs) != 1 || chs[0].Change.Title != "Replace disk" || chs[0].Kind != "fixes" {
		t.Fatalf("item changes: %+v", chs)
	}
	if items, _ := s.ChangeWorkItems(ctx, c.ID); len(items) != 1 || items[0].Item.ID != id2 {
		t.Fatalf("change items: %+v", items)
	}
	if err := s.LinkWorkItems(ctx, ann, id2, id1, "caused_by"); err != nil {
		t.Fatal(err)
	}
	links, _ := s.WorkItemLinks(ctx, id1)
	if len(links) != 1 || links[0].Outgoing || links[0].Other.Ref() != "OPS-2" {
		t.Fatalf("links: %+v", links)
	}
	if err := s.UnlinkWorkItems(ctx, ann, id2, id1, "caused_by"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlinkWorkItemCI(ctx, ann, id1, nas, "affected"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlinkWorkItemChange(ctx, ann, id2, c.ID, "fixes"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlinkWorkItemCI(ctx, ann, id1, nas, "affected"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unlink twice: %v", err)
	}

	// Comments and watching.
	if err := s.AddComment(ctx, bob, bobID, id1, "Swapped the PSU", true); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s.WorkItemComments(ctx, id1); len(cs) != 1 || !cs[0].Internal || cs[0].Author != "BOB" {
		t.Fatalf("comments: %+v", cs)
	}
	if err := s.SetWatching(ctx, ann, id1, annID, false); err != nil {
		t.Fatal(err)
	}
	if ws, _ := s.WorkItemWatchers(ctx, id1); len(ws) != 1 || ws[0].ID != bobID {
		t.Fatalf("watchers: %+v", ws)
	}

	// Archived projects take no new items, and the project counts open ones.
	if err := s.UpdateProject(ctx, ann, pid, store.ProjectInput{Name: "Operations", Kind: "service_desk", Archived: true, TypeIDs: types[:2]}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: "x", Priority: "low"}); !errors.Is(err, store.ErrArchived) {
		t.Fatalf("archived: %v", err)
	}
	if ps, _ := s.ListProjects(ctx, true); len(ps) != 1 || ps[0].Open != 2 || !ps[0].Archived {
		t.Fatalf("projects: %+v", ps)
	}
	if ps, _ := s.ListProjects(ctx, false); len(ps) != 0 {
		t.Fatalf("archived project listed: %+v", ps)
	}
}

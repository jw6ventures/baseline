package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/store"
)

func TestMapStatus(t *testing.T) {
	target := []store.WfStatus{
		{Key: "todo", Category: store.StatusTodo, Initial: true},
		{Key: "doing", Category: store.StatusInProgress},
		{Key: "review", Category: store.StatusInProgress},
		{Key: "done", Category: store.StatusDone},
	}
	for _, c := range []struct {
		src    store.WfStatus
		chosen string
		key    string
		how    string
	}{
		{store.WfStatus{Key: "todo", Category: store.StatusTodo}, "", "todo", store.MapByKey},
		{store.WfStatus{Key: "in_progress", Category: store.StatusInProgress}, "", "doing", store.MapByCategory},
		{store.WfStatus{Key: "in_progress", Category: store.StatusInProgress}, "review", "review", store.MapChosen},
		{store.WfStatus{Key: "done", Category: store.StatusDone}, "done", "done", store.MapByKey},
		{store.WfStatus{Key: "done", Category: store.StatusDone}, "gone", "done", store.MapByKey},
	} {
		got, how := store.MapStatus(c.src, c.chosen, target)
		if got.Key != c.key || how != c.how {
			t.Errorf("%s (chosen %q): got %s by %s, want %s by %s", c.src.Key, c.chosen, got.Key, how, c.key, c.how)
		}
	}
	if got, how := store.MapStatus(store.WfStatus{Key: "x", Category: store.StatusDone}, "", target[:2]); got.Key != "todo" || how != store.MapInitial {
		t.Errorf("no done status: got %s by %s", got.Key, how)
	}
}

// runMigration starts a migration and runs it to the end in small batches.
func runMigration(t *testing.T, s *store.Store, actor store.Actor, id string, mapping map[string]string, items []string) int {
	t.Helper()
	n, err := s.StartMigration(ctx, actor, id, mapping, "", items)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		over, err := s.MigrateBatch(ctx, id, 1)
		if err != nil {
			t.Fatal(err)
		}
		if over {
			break
		}
		if i > n+1 {
			t.Fatalf("migration %s doesn't end", id)
		}
	}
	return n
}

func TestWorkflowMigration(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	annID := strings.TrimPrefix(ann.ID, "user:")
	types := typeIDs(t, s, "incident", "task")
	pid, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk", TypeIDs: types})
	if err != nil {
		t.Fatal(err)
	}
	item := func(title string) string {
		id, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: title, Priority: "low"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := item("a"), item("b"), item("c")
	if err := transition(t, s, ann, b, "Start progress", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	if err := transition(t, s, ann, c, "Done", store.TransitionInput{Resolution: "Fixed"}); err != nil {
		t.Fatal(err)
	}

	// v2 of the default workflow swaps In progress for Doing and Review.
	all, _ := s.ListWorkflows(ctx)
	def := all[0]
	v1 := def.LatestID
	draft, err := s.EditWorkflow(ctx, ann, def.ID)
	if err != nil {
		t.Fatal(err)
	}
	dv, _ := s.GetWorkflowVersion(ctx, draft)
	if err := s.DeleteStatus(ctx, ann, draft, statusByKey(t, dv, "in_progress").ID); err != nil {
		t.Fatal(err)
	}
	doing, _ := s.SaveStatus(ctx, ann, draft, "", store.WfStatus{Key: "doing", Name: "Doing", Category: store.StatusInProgress, Position: 1})
	review, _ := s.SaveStatus(ctx, ann, draft, "", store.WfStatus{Key: "review", Name: "Review", Category: store.StatusInProgress, Position: 2})
	todo := statusByKey(t, dv, "todo").ID
	for _, tr := range []store.WfTransition{{Name: "Start", FromID: todo, ToID: doing}, {Name: "Review", FromID: doing, ToID: review}} {
		if _, err := s.SaveTransition(ctx, ann, draft, "", tr); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PublishDraft(ctx, ann, draft); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetWorkflowVersion(ctx, v1); v.State != store.VersionPublished {
		t.Fatalf("v1 with items: %s", v.State)
	}

	if _, err := s.CreateMigration(ctx, ann, store.WfMigrationInput{Kind: store.MigrationWorkflow, FromVersionID: draft, ToWorkflowID: def.ID}); !errors.Is(err, store.ErrSameTarget) {
		t.Fatalf("migrate the newest version: %v", err)
	}
	mid, err := s.CreateMigration(ctx, ann, store.WfMigrationInput{Kind: store.MigrationWorkflow, FromVersionID: v1, ToWorkflowID: def.ID})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.GetMigration(ctx, mid)
	if !m.Draft() || m.From() != "Default v1" || m.To() != "Default" {
		t.Fatalf("draft: %+v", m)
	}

	// The plan maps by key, then by category, and counts the selection.
	plan, err := s.PlanMigration(ctx, m, nil, []string{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target.Version != 2 || len(plan.Sources) != 1 || plan.Items != 3 {
		t.Fatalf("plan: %+v", plan)
	}
	var got []string
	for _, r := range plan.Sources[0].Rows {
		got = append(got, r.Status.Key+">"+r.Target.Key+":"+r.How+":"+string(rune('0'+r.Items)))
	}
	if want := "todo>todo:key:1 in_progress>doing:category:1 done>done:key:1"; strings.Join(got, " ") != want {
		t.Fatalf("mapping:\n got %s\nwant %s", strings.Join(got, " "), want)
	}

	// Untick a; In progress goes to Review instead.
	if err := s.ExcludeItems(ctx, mid, []string{a, "not-a-uuid"}, true); err != nil {
		t.Fatal(err)
	}
	inProgress := plan.Sources[0].Rows[1].Status.ID
	if n := runMigration(t, s, ann, mid, map[string]string{inProgress: "review"}, []string{a, b, c}); n != 2 {
		t.Fatalf("moved %d, want 2", n)
	}
	if err := s.SaveMigration(ctx, mid, nil, ""); !errors.Is(err, store.ErrStarted) {
		t.Fatalf("edit a started migration: %v", err)
	}
	m, _ = s.GetMigration(ctx, mid)
	if m.State != store.MigrationDone || m.Done != 2 || m.Skipped != 0 || m.ToVersion != 2 || m.To() != "Default v2" {
		t.Fatalf("finished: %+v", m)
	}
	ib, _ := s.GetWorkItem(ctx, b)
	ic, _ := s.GetWorkItem(ctx, c)
	ia, _ := s.GetWorkItem(ctx, a)
	if ib.WorkflowVersion != 2 || ib.StatusName != "Review" || ib.Status != store.StatusInProgress {
		t.Fatalf("b: %+v", ib)
	}
	if ic.WorkflowVersion != 2 || ic.StatusName != "Done" || ic.Resolution != "Fixed" || ic.ResolvedAt.IsZero() {
		t.Fatalf("c keeps its resolution: %+v", ic)
	}
	if ia.WorkflowVersion != 1 {
		t.Fatalf("unticked a moved: %+v", ia)
	}
	hist, _ := s.WorkItemHistory(ctx, b, 1)
	if len(hist) != 1 || !strings.Contains(hist[0].Summary, "workflow") || !strings.Contains(hist[0].Summary, "status") {
		t.Fatalf("b's history: %+v", hist)
	}
	// v1 still holds a, so it stays published.
	if v, _ := s.GetWorkflowVersion(ctx, v1); v.State != store.VersionPublished {
		t.Fatalf("v1 with a on it: %s", v.State)
	}

	// Moving a too empties v1, which retires.
	mid, _ = s.CreateMigration(ctx, ann, store.WfMigrationInput{Kind: store.MigrationWorkflow, FromVersionID: v1, ToWorkflowID: def.ID})
	if _, err := s.StartMigration(ctx, ann, mid, nil, "", []string{b}); !errors.Is(err, store.ErrNothingSelected) {
		t.Fatalf("start with nothing in scope: %v", err)
	}
	runMigration(t, s, ann, mid, nil, []string{a})
	if v, _ := s.GetWorkflowVersion(ctx, v1); v.State != store.VersionRetired {
		t.Fatalf("empty v1: %s", v.State)
	}
	if ia, _ := s.GetWorkItem(ctx, a); ia.StatusName != "To do" || ia.WorkflowVersion != 2 {
		t.Fatalf("a: %+v", ia)
	}
}

func TestMoveMigration(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	annID := strings.TrimPrefix(ann.ID, "user:")
	types := typeIDs(t, s, "incident", "task")
	ops, _ := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk", TypeIDs: types})
	dev, _ := s.CreateProject(ctx, ann, store.ProjectInput{Key: "DEV", Name: "Dev", Kind: "software", TypeIDs: types[1:]})

	// Env applies to OPS incidents only, Note to both.
	env, _ := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "env", Label: "Environment", Type: store.FieldText})
	note, _ := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "note", Label: "Note", Type: store.FieldText})
	g1, _ := s.SaveFieldGroup(ctx, ann, "", store.FieldGroupInput{Name: "Ops", Fields: []store.GroupFieldInput{{FieldID: env}, {FieldID: note}}})
	g2, _ := s.SaveFieldGroup(ctx, ann, "", store.FieldGroupInput{Name: "Notes", Fields: []store.GroupFieldInput{{FieldID: note}}})
	if err := s.SetProjectTypeGroups(ctx, ann, ops, types[0], []string{g1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectTypeGroups(ctx, ann, dev, types[1], []string{g2}); err != nil {
		t.Fatal(err)
	}
	id, ref, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: ops, TypeID: types[0], Title: "x", Priority: "low",
		Custom: map[string]any{"env": "prod", "note": "keep"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := transition(t, s, ann, id, "Start progress", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}

	for _, in := range []store.WfMigrationInput{
		{Kind: store.MigrationMove, FromProjectID: ops, FromTypeID: types[0], ToProjectID: ops, ToTypeID: types[0]},
		{Kind: store.MigrationMove, FromProjectID: ops, FromTypeID: types[0], ToProjectID: dev, ToTypeID: types[0]},
	} {
		if _, err := s.CreateMigration(ctx, ann, in); err == nil {
			t.Fatalf("bad move %+v accepted", in)
		}
	}
	mid, err := s.CreateMigration(ctx, ann, store.WfMigrationInput{Kind: store.MigrationMove, FromProjectID: ops, FromTypeID: types[0],
		ToProjectID: dev, ToTypeID: types[1]})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.GetMigration(ctx, mid)
	plan, err := s.PlanMigration(ctx, m, nil, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if m.From() != "OPS Incident" || m.To() != "DEV Task" || len(plan.Dropped) != 1 || plan.Dropped[0].Key != "env" || plan.Items != 1 {
		t.Fatalf("move plan: %s to %s %+v", m.From(), m.To(), plan)
	}
	runMigration(t, s, ann, mid, nil, []string{id})

	it, err := s.GetWorkItemByRef(ctx, ref)
	if err != nil || it.ID != id || it.Ref() != "DEV-1" || it.TypeName != "Task" || it.StatusName != "In progress" {
		t.Fatalf("moved item by its old ref %s: %+v %v", ref, it, err)
	}
	if _, ok := it.Custom["env"]; ok || it.Custom["note"] != "keep" {
		t.Fatalf("custom values after the move: %v", it.Custom)
	}
	hist, _ := s.WorkItemHistory(ctx, id, 1)
	if len(hist) != 1 || !strings.Contains(hist[0].Summary, "changed ref, project, type") || !strings.Contains(hist[0].Summary, "removed Environment") {
		t.Fatalf("history: %+v", hist)
	}
	// OPS numbers carry on; the old reference never comes back.
	_, ref2, _ := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: ops, TypeID: types[0], Title: "y", Priority: "low"})
	if ref2 != "OPS-2" {
		t.Fatalf("next OPS item: %s", ref2)
	}
}

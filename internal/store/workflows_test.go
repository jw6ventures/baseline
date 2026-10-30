package store_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/store"
)

func statusByKey(t *testing.T, v store.WorkflowVersion, key string) store.WfStatus {
	t.Helper()
	for _, st := range v.Statuses {
		if st.Key == key {
			return st
		}
	}
	t.Fatalf("v%d has no status %s", v.Version, key)
	return store.WfStatus{}
}

func TestWorkflows(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	bob := user(t, s, "bob")
	annID, bobID := strings.TrimPrefix(ann.ID, "user:"), strings.TrimPrefix(bob.ID, "user:")
	types := typeIDs(t, s, "bug", "task")

	// The migration ships a published default workflow.
	all, err := s.ListWorkflows(ctx)
	if err != nil || len(all) != 1 || !all[0].Default || all[0].Latest != 1 || all[0].DraftID != "" {
		t.Fatalf("workflows: %+v %v", all, err)
	}
	def := all[0]

	// A new workflow starts as a draft copy; nothing can use it until it is
	// published.
	wid, err := s.CreateWorkflow(ctx, ann, "Software", "Bugs and tasks", def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWorkflow(ctx, ann, "software", "", ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	wf, _ := s.GetWorkflow(ctx, wid)
	if wf.Latest != 0 || wf.DraftID == "" {
		t.Fatalf("new workflow: %+v", wf)
	}
	if _, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "DEV", Name: "Dev", Kind: "software", TypeIDs: types,
		Workflows: map[string]string{types[0]: wid}}); !errors.Is(err, store.ErrNoPublished) {
		t.Fatalf("unpublished workflow on a project: %v", err)
	}
	draft, err := s.GetWorkflowVersion(ctx, wf.DraftID)
	if err != nil || !draft.Draft() || len(draft.Statuses) != 3 || len(draft.Transitions) != 4 {
		t.Fatalf("draft copy: %+v %v", draft, err)
	}

	// Edit the draft: add In review, route Start progress through it, and
	// give Done rules.
	todo, prog, done := statusByKey(t, draft, "todo"), statusByKey(t, draft, "in_progress"), statusByKey(t, draft, "done")
	review, err := s.SaveStatus(ctx, ann, draft.ID, "", store.WfStatus{Key: "in_review", Name: "In review", Category: store.StatusInProgress, Position: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveStatus(ctx, ann, draft.ID, "", store.WfStatus{Key: "in_review", Name: "Again", Category: store.StatusTodo}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate status key: %v", err)
	}
	draft, _ = s.GetWorkflowVersion(ctx, draft.ID)
	if problems := store.CheckVersion(draft); len(problems) != 1 || !strings.Contains(problems[0], "In review") {
		t.Fatalf("unreachable status: %v", problems)
	}
	if err := s.PublishDraft(ctx, ann, draft.ID); err == nil {
		t.Fatal("published a draft with an unreachable status")
	}
	var doneID string
	for _, tr := range draft.Transitions {
		if tr.Name == "Done" {
			doneID = tr.ID
		}
	}
	if _, err := s.SaveTransition(ctx, ann, draft.ID, "", store.WfTransition{Name: "Send to review", FromID: prog.ID, ToID: review, Position: 1,
		PostFunctions: []store.PostFunction{{Type: "assign", Value: "reporter"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveTransition(ctx, ann, draft.ID, "", store.WfTransition{Name: "Loop", FromID: todo.ID, ToID: todo.ID}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("transition to the same status: %v", err)
	}
	if _, err := s.SaveTransition(ctx, ann, draft.ID, doneID, store.WfTransition{Name: "Done", FromID: review, ToID: done.ID, Position: 5,
		Conditions: []store.WfCondition{{Type: "role", Role: "admin"}, {Type: "assignee"}},
		Validators: []store.Validator{{Type: "field_required", Field: "estimate"}, {Type: "comment_required"}},
		Screen:     []string{"resolution", "comment"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishDraft(ctx, ann, draft.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveStatus(ctx, ann, draft.ID, "", store.WfStatus{Key: "late", Name: "Late", Category: store.StatusTodo}); !errors.Is(err, store.ErrNotDraft) {
		t.Fatalf("edited a published version: %v", err)
	}

	// Bugs follow Software, tasks the default.
	pid, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "DEV", Name: "Dev", Kind: "software", TypeIDs: types,
		Workflows: map[string]string{types[0]: wid}})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetProject(ctx, "DEV")
	if p.Types[0].WorkflowName != "Software" || p.Types[1].WorkflowName != "Default" {
		t.Fatalf("project types: %+v", p.Types)
	}
	bug, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: "Crash", Priority: "high"})
	if err != nil {
		t.Fatal(err)
	}
	task, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[1], Title: "Tidy", Priority: "low"})
	if err != nil {
		t.Fatal(err)
	}
	it, _ := s.GetWorkItem(ctx, bug)
	if it.WorkflowName != "Software" || it.WorkflowVersion != 1 || it.StatusName != "To do" || it.Status != store.StatusTodo {
		t.Fatalf("new bug: %+v", it)
	}
	if it, _ := s.GetWorkItem(ctx, task); it.WorkflowName != "Default" {
		t.Fatalf("new task: %+v", it)
	}

	// Through the workflow: post-functions, conditions, validators, screens.
	if err := transition(t, s, bob, bug, "Start progress", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	if err := transition(t, s, bob, bug, "Send to review", store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}
	it, _ = s.GetWorkItem(ctx, bug)
	if it.StatusName != "In review" || it.Status != store.StatusInProgress || it.AssigneeID != annID {
		t.Fatalf("in review: %+v", it)
	}
	ts, _ := s.ItemTransitions(ctx, it)
	i := slices.IndexFunc(ts, func(tr store.WfTransition) bool { return tr.Name == "Done" })
	if i < 0 {
		t.Fatalf("transitions out of review: %+v", ts)
	}
	closeBug := ts[i]
	asBob := store.Runner{UserID: bobID, HasRole: func(string) bool { return false }}
	asAnn := store.Runner{UserID: annID, HasRole: func(string) bool { return false }}
	if closeBug.Allowed(it, asBob) || !closeBug.Allowed(it, asAnn) {
		t.Fatal("conditions: bob isn't the assignee or an admin, ann is the assignee")
	}
	if err := s.TransitionWorkItem(ctx, bob, asBob, bug, closeBug.ID, store.TransitionInput{}); !errors.Is(err, store.ErrTransitionDenied) {
		t.Fatalf("denied: %v", err)
	}
	var bad *store.TransitionError
	if err := s.TransitionWorkItem(ctx, ann, asAnn, bug, closeBug.ID, store.TransitionInput{Comment: "fixed"}); !errors.As(err, &bad) || !strings.Contains(bad.Msg, "Estimate") {
		t.Fatalf("estimate validator: %v", err)
	}
	est := 2.0
	in := store.WorkItemInput{Title: it.Title, Priority: it.Priority, AssigneeID: it.AssigneeID, Estimate: &est}
	if err := s.UpdateWorkItem(ctx, ann, bug, in); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionWorkItem(ctx, ann, asAnn, bug, closeBug.ID, store.TransitionInput{Resolution: "Fixed"}); !errors.As(err, &bad) || !strings.Contains(bad.Msg, "comment") {
		t.Fatalf("comment validator: %v", err)
	}
	if err := s.TransitionWorkItem(ctx, ann, asAnn, bug, closeBug.ID, store.TransitionInput{Resolution: "Fixed", Comment: "Fixed in 1.2"}); err != nil {
		t.Fatal(err)
	}
	it, _ = s.GetWorkItem(ctx, bug)
	if it.Status != store.StatusDone || it.Resolution != "Fixed" || it.ResolvedAt.IsZero() {
		t.Fatalf("closed: %+v", it)
	}
	if c, _ := s.WorkItemComments(ctx, bug); len(c) != 1 || c[0].Body != "Fixed in 1.2" || c[0].AuthorID != annID {
		t.Fatalf("screen comment: %+v", c)
	}
	if h, _ := s.WorkItemHistory(ctx, bug, 1); len(h) != 1 || !strings.Contains(h[0].Summary, "status") || h[0].Diff.Changed[0].To != "Done" {
		t.Fatalf("history: %+v", h)
	}
	// A transition that no longer applies is refused.
	if err := s.TransitionWorkItem(ctx, ann, asAnn, bug, closeBug.ID, store.TransitionInput{Resolution: "Fixed", Comment: "again"}); !errors.Is(err, store.ErrStaleTransition) {
		t.Fatalf("stale: %v", err)
	}

	// Versions: a new draft is v2; publishing it leaves the bug on v1, and
	// new bugs start on v2. v1 retires once nothing is on it.
	d2, err := s.EditWorkflow(ctx, ann, wid)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.EditWorkflow(ctx, ann, wid); again != d2 {
		t.Fatal("a second edit made another draft")
	}
	v2, _ := s.GetWorkflowVersion(ctx, d2)
	if v2.Version != 2 || len(v2.Statuses) != 4 || len(v2.Transitions) != 5 {
		t.Fatalf("v2 draft: %+v", v2)
	}
	if _, err := s.SaveStatus(ctx, ann, d2, statusByKey(t, v2, "in_review").ID, store.WfStatus{Name: "Code review",
		Category: store.StatusInProgress, Position: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishDraft(ctx, ann, d2); err != nil {
		t.Fatal(err)
	}
	if it, _ := s.GetWorkItem(ctx, bug); it.WorkflowVersion != 1 {
		t.Fatalf("the bug moved: %+v", it)
	}
	bug2, _, _ := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: "Crash 2", Priority: "high"})
	if it, _ := s.GetWorkItem(ctx, bug2); it.WorkflowVersion != 2 {
		t.Fatalf("new bug: %+v", it)
	}
	versions, _ := s.WorkflowVersions(ctx, wid)
	if len(versions) != 2 || versions[1].State != store.VersionPublished || versions[1].Items != 1 {
		t.Fatalf("versions: %+v", versions)
	}
	d3, _ := s.EditWorkflow(ctx, ann, wid)
	if err := s.DiscardDraft(ctx, ann, d3); err != nil {
		t.Fatal(err)
	}
	if wf, _ := s.GetWorkflow(ctx, wid); wf.DraftID != "" || wf.Latest != 2 {
		t.Fatalf("after discard: %+v", wf)
	}

	// The default moves; a workflow in use can't be deleted.
	if err := s.UpdateWorkflow(ctx, ann, wid, "Software", "", true); err != nil {
		t.Fatal(err)
	}
	all, _ = s.ListWorkflows(ctx)
	if !all[0].Default || all[0].ID != wid || all[1].Default {
		t.Fatalf("default: %+v", all)
	}
	if err := s.DeleteWorkflow(ctx, ann, def.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("delete a used workflow: %v", err)
	}
	spare, _ := s.CreateWorkflow(ctx, ann, "Spare", "", "")
	if err := s.DeleteWorkflow(ctx, ann, spare); err != nil {
		t.Fatal(err)
	}
	if names, _ := s.TransitionNames(ctx); !slices.ContainsFunc(names, func(n store.TransitionName) bool { return n.Name == "Done" && n.ToDone }) {
		t.Fatalf("transition names: %+v", names)
	}
}

func TestStatusPositions(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	all, _ := s.ListWorkflows(ctx)
	def := all[0]
	pub, err := s.GetWorkflowVersion(ctx, def.LatestID)
	if err != nil {
		t.Fatal(err)
	}
	todo := statusByKey(t, pub, "todo")
	if todo.X != nil || todo.Y != nil {
		t.Fatalf("unplaced status has a position: %+v", todo)
	}
	if err := s.PlaceStatuses(ctx, pub.ID, map[string]store.StatusPoint{todo.ID: {X: 1, Y: 2}}); !errors.Is(err, store.ErrNotDraft) {
		t.Fatalf("moved a status of a published version: %v", err)
	}

	// A draft's statuses move; a new one can be placed as it is added, and
	// statuses of other versions are left alone.
	draftID, err := s.EditWorkflow(ctx, ann, def.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft, _ := s.GetWorkflowVersion(ctx, draftID)
	dTodo := statusByKey(t, draft, "todo")
	if err := s.PlaceStatuses(ctx, draftID, map[string]store.StatusPoint{dTodo.ID: {X: 10.5, Y: -20}, todo.ID: {X: 99, Y: 99}}); err != nil {
		t.Fatal(err)
	}
	x, y := 300.0, 40.0
	if _, err := s.SaveStatus(ctx, ann, draftID, "", store.WfStatus{Key: "review", Name: "Review", Category: store.StatusInProgress, X: &x, Y: &y}); err != nil {
		t.Fatal(err)
	}
	// Changing a status in the form keeps its position.
	if _, err := s.SaveStatus(ctx, ann, draftID, dTodo.ID, store.WfStatus{Name: "Open", Category: store.StatusTodo, Initial: true}); err != nil {
		t.Fatal(err)
	}
	draft, _ = s.GetWorkflowVersion(ctx, draftID)
	if st := statusByKey(t, draft, "todo"); st.X == nil || *st.X != 10.5 || *st.Y != -20 {
		t.Fatalf("placed status: %+v", st)
	}
	if st := statusByKey(t, draft, "review"); st.X == nil || *st.X != 300 || *st.Y != 40 {
		t.Fatalf("new status: %+v", st)
	}
	pub, _ = s.GetWorkflowVersion(ctx, pub.ID)
	if st := statusByKey(t, pub, "todo"); st.X != nil {
		t.Fatalf("moved a status of another version: %+v", st)
	}

	// The next draft starts where this one left off.
	if _, err := s.SaveTransition(ctx, ann, draftID, "", store.WfTransition{Name: "Review", FromID: dTodo.ID, ToID: statusByKey(t, draft, "review").ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishDraft(ctx, ann, draftID); err != nil {
		t.Fatal(err)
	}
	next, err := s.EditWorkflow(ctx, ann, def.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft, _ = s.GetWorkflowVersion(ctx, next)
	if st := statusByKey(t, draft, "review"); st.X == nil || *st.X != 300 {
		t.Fatalf("copied draft: %+v", st)
	}
}

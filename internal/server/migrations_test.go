package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestMigrationScreen(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	ops, _ := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk",
		TypeIDs: []string{typeID["incident"]}})
	dev, _ := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "DEV", Name: "Dev", Kind: "software",
		TypeIDs: []string{typeID["task"]}})
	item := func(title string) string {
		_, ref, err := h.st.CreateWorkItem(ctx, store.System, "", store.WorkItemInput{ProjectID: ops, TypeID: typeID["incident"],
			Title: title, Priority: "low"})
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	a, b, c := item("alpha"), item("bravo"), item("charlie")
	if err := h.st.TransitionWorkItem(ctx, store.System, store.Runner{}, mustItem(t, h, b).ID, h.transitionID(b, "Start progress"),
		store.TransitionInput{}); err != nil {
		t.Fatal(err)
	}

	// v2 of the default workflow renames In progress to Doing, with a new
	// key.
	all, _ := h.st.ListWorkflows(ctx)
	def := all[0]
	v1 := def.LatestID
	draft, _ := h.st.EditWorkflow(ctx, store.System, def.ID)
	dv, _ := h.st.GetWorkflowVersion(ctx, draft)
	var todo, draftInProgress, inProgress string
	for _, st := range dv.Statuses {
		switch st.Key {
		case "todo":
			todo = st.ID
		case "in_progress":
			draftInProgress = st.ID
		}
	}
	first, _ := h.st.GetWorkflowVersion(ctx, v1)
	for _, st := range first.Statuses {
		if st.Key == "in_progress" {
			inProgress = st.ID
		}
	}
	h.st.DeleteStatus(ctx, store.System, draft, draftInProgress)
	doing, _ := h.st.SaveStatus(ctx, store.System, draft, "", store.WfStatus{Key: "doing", Name: "Doing", Category: store.StatusInProgress, Position: 1})
	h.st.SaveTransition(ctx, store.System, draft, "", store.WfTransition{Name: "Start", FromID: todo, ToID: doing})
	if err := h.st.PublishDraft(ctx, store.System, draft); err != nil {
		t.Fatal(err)
	}

	// Only admins migrate.
	if resp, _ := h.do(viewer, "GET", "/settings/migrations", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saw migrations: %d", resp.StatusCode)
	}
	if _, body := h.do(admin, "GET", "/settings/workflows/"+def.ID+"?v="+v1, nil); !strings.Contains(body, "/settings/migrations?from_version="+v1) {
		t.Fatalf("workflow page offers no migration:\n%s", body)
	}
	_, body := h.do(admin, "GET", "/settings/migrations?from_version="+v1, nil)
	if !strings.Contains(body, "Default v1 (3 items)") || !strings.Contains(body, "No migrations yet") {
		t.Fatalf("migrations page:\n%s", body)
	}
	resp, _ := h.do(admin, "POST", "/settings/migrations", url.Values{"kind": {"workflow"}, "from_version": {draft}, "to_workflow": {def.ID}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("migrate the newest version: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/migrations", url.Values{"kind": {"workflow"}, "from_version": {v1}, "to_workflow": {def.ID}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	page := resp.Header.Get("Location")
	mid := strings.TrimPrefix(page, "/settings/migrations/")

	// The screen maps by key and by category and ticks every item.
	_, body = h.do(admin, "GET", page, nil)
	for _, want := range []string{"Migrate Default v1 to Default", "same key", "guessed by category", "Moves <strong>3 items</strong>",
		`name="map.` + inProgress + `"`, a, b, c, `hx-post="/settings/migrations/` + mid + `/select"`, `form="migration-form"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("migration screen lacks %q:\n%s", want, body)
		}
	}
	// Untick alpha.
	alpha := mustItem(t, h, a).ID
	if resp, _ := h.do(admin, "POST", page+"/select", url.Values{"id": {alpha}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("untick: %d", resp.StatusCode)
	}
	if _, body = h.do(admin, "GET", page, nil); !strings.Contains(body, "Moves <strong>2 items</strong>") || !strings.Contains(body, "1 item unticked") {
		t.Fatalf("after unticking:\n%s", body)
	}
	// A filter narrows it too, and saving keeps the filter.
	query := url.Values{"cf": {"title"}, "co": {"contains"}, "cv": {"bravo"}, "cg": {"0"}}
	resp, _ = h.do(admin, "POST", page, url.Values{"map." + inProgress: {"doing"}, "query": {query.Encode()}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=") || !strings.Contains(loc, "bravo") {
		t.Fatalf("save: %s", loc)
	}
	if resp, _ := h.do(admin, "GET", page, nil); !strings.Contains(resp.Header.Get("Location"), "bravo") {
		t.Fatalf("the saved filter isn't restored: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Run: with no runner, it runs within the request.
	resp, _ = h.do(admin, "POST", page+"/start", url.Values{"map." + inProgress: {"doing"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "Started") {
		t.Fatalf("start: %s", loc)
	}
	if it := mustItem(t, h, b); it.WorkflowVersion != 2 || it.StatusName != "Doing" {
		t.Fatalf("bravo: v%d %s", it.WorkflowVersion, it.StatusName)
	}
	if it := mustItem(t, h, c); it.WorkflowVersion != 2 || it.StatusName != "To do" {
		t.Fatalf("charlie: v%d %s", it.WorkflowVersion, it.StatusName)
	}
	if it := mustItem(t, h, a); it.WorkflowVersion != 1 {
		t.Fatalf("unticked alpha moved")
	}
	if _, body = h.do(admin, "GET", page, nil); !strings.Contains(body, "Moved 2 items") {
		t.Fatalf("finished screen:\n%s", body)
	}
	if resp, _ := h.do(admin, "POST", page+"/select", url.Values{"id": {alpha}}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("untick after the run: %d", resp.StatusCode)
	}

	// Move alpha from its page: only an admin sees the button.
	if _, body = h.do(viewer, "GET", "/work/"+a, nil); strings.Contains(body, "/settings/migrations?") {
		t.Fatal("viewer sees Move")
	}
	if _, body = h.do(admin, "GET", "/work/"+a, nil); !strings.Contains(body, "/settings/migrations?project="+ops) {
		t.Fatalf("admin has no Move:\n%s", body)
	}
	resp, _ = h.do(admin, "POST", "/settings/migrations", url.Values{"kind": {"move"}, "from_project": {ops},
		"from_type": {typeID["incident"]}, "to_project": {dev}, "to_type": {typeID["incident"]}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("move to a type DEV doesn't offer: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/migrations", url.Values{"kind": {"move"}, "from_project": {ops},
		"from_type": {typeID["incident"]}, "to_project": {dev}, "to_type": {typeID["task"]}, "ref": {a}})
	page = resp.Header.Get("Location")
	resp, _ = h.do(admin, "GET", page, nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, a) {
		t.Fatalf("move draft doesn't start at the item: %s", loc)
	}
	_, body = h.do(admin, "GET", resp.Header.Get("Location"), nil)
	if !strings.Contains(body, "Move OPS Incident items to DEV Task") || !strings.Contains(body, "Moves <strong>1 item</strong>") ||
		!strings.Contains(body, "nothing is dropped") {
		t.Fatalf("move screen:\n%s", body)
	}
	values, _ := url.ParseQuery(strings.SplitN(resp.Header.Get("Location"), "?", 2)[1])
	h.do(admin, "POST", page+"/start", url.Values{"query": {values.Encode()}})
	if it := mustItem(t, h, a); it.Ref() != "DEV-1" || it.TypeName != "Task" || it.WorkflowVersion != 2 {
		t.Fatalf("moved alpha: %s %s v%d", it.Ref(), it.TypeName, it.WorkflowVersion)
	}
	// Its old reference still opens it, and v1 retired.
	if resp, _ := h.do(admin, "GET", "/work/"+a+"/edit", nil); resp.StatusCode != http.StatusMovedPermanently ||
		resp.Header.Get("Location") != "/work/DEV-1/edit" {
		t.Fatalf("old ref: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if v, _ := h.st.GetWorkflowVersion(ctx, v1); v.State != store.VersionRetired {
		t.Fatalf("empty v1: %s", v.State)
	}
}

func mustItem(t *testing.T, h *harness, ref string) store.WorkItem {
	t.Helper()
	it, err := h.st.GetWorkItemByRef(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

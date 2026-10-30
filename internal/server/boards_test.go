package server

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestBoards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	other := h.signIn("olga", "viewers")

	types, _ := h.st.ListTicketTypes(ctx)
	if _, err := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk",
		TypeIDs: []string{types[0].ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "DEV", Name: "Development", Kind: "software",
		TypeIDs: []string{types[0].ID}}); err != nil {
		t.Fatal(err)
	}
	ops, _ := h.st.GetProject(ctx, "OPS")
	dev, _ := h.st.GetProject(ctx, "DEV")
	newItem := func(p store.Project, title, priority string) store.WorkItem {
		t.Helper()
		id, _, err := h.st.CreateWorkItem(ctx, store.System, "", store.WorkItemInput{ProjectID: p.ID, TypeID: types[0].ID,
			Title: title, Priority: priority})
		if err != nil {
			t.Fatal(err)
		}
		it, _ := h.st.GetWorkItem(ctx, id)
		return it
	}
	disk := newItem(ops, "Replace the NAS disk", "high")
	newItem(ops, "Tidy the rack", "low")
	newItem(dev, "Ship the board", "medium")

	// Anyone with a role makes a board; it starts with a column per
	// category.
	resp, body := h.do(viewer, "POST", "/boards", url.Values{"name": {""}, "project": {"OPS"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Enter a name") {
		t.Fatalf("board without a name: %d", resp.StatusCode)
	}
	resp, _ = h.do(viewer, "POST", "/boards", url.Values{"name": {"Ops board"}, "project": {"ops"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create board: %d", resp.StatusCode)
	}
	boardURL := strings.SplitN(resp.Header.Get("Location"), "?", 2)[0]
	if resp, body := h.do(other, "POST", "/boards", url.Values{"name": {"ops BOARD"}}); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "already exists") {
		t.Fatalf("duplicate board: %d", resp.StatusCode)
	}
	_, body = h.do(other, "GET", "/boards", nil)
	if !strings.Contains(body, "Ops board") || !strings.Contains(body, "To do · In progress · Done") {
		t.Fatalf("boards page:\n%s", body)
	}

	// The board shows OPS's items only, each with its transitions: Start
	// progress leads into In progress (column 1) and Done, which asks for a
	// resolution and a comment, into Done (column 2).
	_, body = h.do(other, "GET", boardURL, nil)
	for _, want := range []string{"Replace the NAS disk", "Tidy the rack", `aria-label="In progress"`,
		"Start progress → In progress", "Done → Done…"} {
		if !strings.Contains(body, want) {
			t.Fatalf("board lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Ship the board") || strings.Contains(body, "Edit board") {
		t.Fatalf("board shows DEV's items or offers edit to someone else:\n%s", body)
	}
	plain := html.UnescapeString(body)
	if !strings.Contains(plain, `"name":"Start progress","to":"In progress","col":1,"ok":true,"screen":[]`) ||
		!strings.Contains(plain, `"name":"Done","to":"Done","col":2,"ok":true,"screen":["resolution","comment"]`) {
		t.Fatalf("card targets:\n%s", plain)
	}

	// Dropping a card runs the transition, and the board says so.
	start := h.transitionID(disk.Ref(), "Start progress")
	resp, _ = h.do(other, "POST", boardURL+"/move", url.Values{"item": {disk.ID}, "transition": {start}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, boardURL+"?") ||
		!strings.Contains(loc, "notice=") {
		t.Fatalf("move: %d %s", resp.StatusCode, loc)
	}
	if it, _ := h.st.GetWorkItem(ctx, disk.ID); it.StatusName != "In progress" {
		t.Fatalf("after the move: %s", it.StatusName)
	}
	resp, _ = h.do(other, "POST", boardURL+"/move", url.Values{"item": {disk.ID}, "transition": {start}})
	if loc, _ := url.QueryUnescape(resp.Header.Get("Location")); !strings.Contains(loc, "has moved on") {
		t.Fatalf("stale move: %s", loc)
	}
	// The screen's resolution and comment come along.
	done := h.transitionID(disk.Ref(), "Done")
	h.do(other, "POST", boardURL+"/move", url.Values{"item": {disk.ID}, "transition": {done}, "resolution": {"Fixed"},
		"comment": {"Swapped it."}})
	if it, _ := h.st.GetWorkItem(ctx, disk.ID); it.Status != store.StatusDone || it.Resolution != "Fixed" {
		t.Fatalf("after done: %s %s", it.Status, it.Resolution)
	}
	if cs, _ := h.st.WorkItemComments(ctx, disk.ID); len(cs) != 1 || cs[0].Body != "Swapped it." {
		t.Fatalf("comments: %+v", cs)
	}
	resp, _ = h.do(other, "POST", boardURL+"/move", url.Values{"item": {"no-such-item"}, "transition": {done}})
	if loc, _ := url.QueryUnescape(resp.Header.Get("Location")); !strings.Contains(loc, "no longer exists") {
		t.Fatalf("missing item: %s", loc)
	}

	// A transition whose condition fails shows greyed out and refuses.
	wfs, _ := h.st.ListWorkflows(ctx)
	draft, err := h.st.EditWorkflow(ctx, store.System, wfs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := h.st.GetWorkflowVersion(ctx, draft)
	i := slices.IndexFunc(v.Transitions, func(t store.WfTransition) bool { return t.Name == "Start progress" })
	tr := v.Transitions[i]
	tr.Conditions = []store.WfCondition{{Type: "role", Role: string(rbac.Admin)}}
	if _, err := h.st.SaveTransition(ctx, store.System, draft, tr.ID, tr); err != nil {
		t.Fatal(err)
	}
	if err := h.st.PublishDraft(ctx, store.System, draft); err != nil {
		t.Fatal(err)
	}
	gated := newItem(ops, "Gated work", "critical")
	_, body = h.do(other, "GET", boardURL, nil)
	if !strings.Contains(html.UnescapeString(body), `"name":"Start progress","to":"In progress","col":1,"ok":false`) {
		t.Fatalf("gated target:\n%s", body)
	}
	resp, _ = h.do(other, "POST", boardURL+"/move", url.Values{"item": {gated.ID}, "transition": {h.transitionID(gated.Ref(), "Start progress")}})
	if loc, _ := url.QueryUnescape(resp.Header.Get("Location")); !strings.Contains(loc, "may not run") {
		t.Fatalf("denied move: %s", loc)
	}

	// Only the board's maker and admins change it.
	if resp, _ := h.do(other, "GET", boardURL+"/edit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("someone else edited: %d", resp.StatusCode)
	}
	if resp, _ := h.do(other, "POST", boardURL+"/delete", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("someone else deleted: %d", resp.StatusCode)
	}
	_, body = h.do(viewer, "GET", boardURL+"/edit", nil)
	if !strings.Contains(body, `name="name_2" value="Done"`) || !strings.Contains(body, `value="in_progress"`) ||
		!strings.Contains(body, "Resolved") {
		t.Fatalf("edit form:\n%s", body)
	}

	// Columns by status key, reordered; a filter on priority.
	form := url.Values{"name": {"Ops board"}, "project": {"OPS"},
		"col":    {"0", "1", "2", "3"},
		"name_0": {"Closed"}, "pos_0": {"3"}, "cat_0": {"done"},
		"name_1": {"Doing"}, "pos_1": {"2"}, "status_1": {"in_progress"},
		"name_2": {"Open"}, "pos_2": {"1"}, "cat_2": {"todo", "in_progress"},
		"name_3": {""},
		"cg":     {"0", "0"}, "cf": {"priority", ""}, "co": {"ne", "eq"}, "cv": {"low", ""}}
	resp, body = h.do(viewer, "POST", boardURL, form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", resp.StatusCode, body)
	}
	b, _ := h.st.GetBoard(ctx, strings.TrimPrefix(boardURL, "/boards/"))
	var names []string
	for _, c := range b.Columns {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "Open,Doing,Closed" || len(b.Filter) != 1 || b.Filter[0][0].Value != "low" {
		t.Fatalf("saved board: %+v", b)
	}
	if b.Column("in_progress", store.StatusInProgress) != 1 || b.Column("todo", store.StatusTodo) != 0 {
		t.Fatalf("columns: %+v", b.Columns)
	}
	_, body = h.do(other, "GET", boardURL, nil)
	if strings.Contains(body, "Tidy the rack") || !strings.Contains(body, "Gated work") ||
		!strings.Contains(body, "Priority is not low") {
		t.Fatalf("filtered board:\n%s", body)
	}

	// Bad input keeps the form.
	form.Set("cv", "urgent")
	if resp, body := h.do(viewer, "POST", boardURL, form); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "isn&#39;t a value of Priority") {
		t.Fatalf("bad filter: %d\n%s", resp.StatusCode, body)
	}
	form.Set("cv", "low")
	form.Del("cat_0")
	if resp, body := h.do(viewer, "POST", boardURL, form); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "for column Closed") {
		t.Fatalf("empty column: %d\n%s", resp.StatusCode, body)
	}

	// Admins may delete anyone's board.
	resp, _ = h.do(admin, "POST", boardURL+"/delete", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if bs, _ := h.st.ListBoards(ctx); len(bs) != 0 {
		t.Fatalf("boards left: %+v", bs)
	}
	if a := h.auditActions(); !strings.Contains(a, "board.create") || !strings.Contains(a, "board.update") ||
		!strings.Contains(a, "board.delete") {
		t.Fatalf("audit: %s", a)
	}
}

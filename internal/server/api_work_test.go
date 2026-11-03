package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestAPIWorkItems(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.dispatcher()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	core, _ := h.st.CreateHostGroup(ctx, store.System, "core", "")
	h.addHost("web1", core.ID)
	h.connect(plex, []string{"systemd"}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	nas, err := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "nas", Name: "nas1", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}

	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	if _, err := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk",
		TypeIDs: []string{typeID["incident"], typeID["problem"]}, DefaultType: typeID["incident"]}); err != nil {
		t.Fatal(err)
	}
	ops, _ := h.st.GetProject(ctx, "OPS")
	// A custom field on incidents: a required pick-one.
	fieldID, err := h.st.SaveFieldDef(ctx, store.System, "", store.FieldDef{Key: "site", Label: "Site", Type: store.FieldSelect,
		Options: []string{"home", "colo"}})
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := h.st.SaveFieldGroup(ctx, store.System, "", store.FieldGroupInput{Name: "Where",
		Fields: []store.GroupFieldInput{{FieldID: fieldID, Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.SetProjectTypeGroups(ctx, store.System, ops.ID, typeID["incident"], []string{groupID}); err != nil {
		t.Fatal(err)
	}

	carl := h.signIn("carl", "media-ops")
	ct := h.mintToken(carl, "agent", "operator")
	vic := h.signIn("vic", "viewers")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer, ScopeGroupID: core.ID})
	vt := h.mintToken(vic, "read", "viewer")

	var e map[string]string
	var item workItemDetailJSON
	// fresh empties a response before decoding, so a field left out isn't
	// the last response's.
	fresh := func(it *workItemDetailJSON) *workItemDetailJSON { *it = workItemDetailJSON{}; return it }

	// Projects say what a new item may carry.
	var projects []projectJSON
	if resp := h.api(vt, "GET", "/projects", nil, &projects); resp.StatusCode != 200 || len(projects) != 1 || projects[0].Key != "OPS" {
		t.Fatalf("projects: %d %+v", resp.StatusCode, projects)
	}
	var project projectJSON
	if resp := h.api(vt, "GET", "/projects/ops", nil, &project); resp.StatusCode != 200 || len(project.Types) != 2 ||
		project.Types[0].Key != "incident" || !project.Types[0].Default || len(project.Types[0].Fields) != 1 ||
		project.Types[0].Fields[0].Key != "site" || !project.Types[0].Fields[0].Required || len(project.Types[1].Fields) != 0 {
		t.Fatalf("project: %d %+v", resp.StatusCode, project)
	}
	if resp := h.api(vt, "GET", "/projects/NOPE", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing project: %d", resp.StatusCode)
	}
	var users []userJSON
	if resp := h.api(vt, "GET", "/users", nil, &users); resp.StatusCode != 200 || len(users) < 2 {
		t.Fatalf("users: %d %+v", resp.StatusCode, users)
	}

	// Bad requests say what is wrong.
	for _, tc := range []struct {
		in   any
		want string
	}{
		{map[string]any{"title": "x"}, "project is required"},
		{map[string]any{"project": "NOPE", "title": "x"}, "no project"},
		{map[string]any{"project": "OPS", "type": "task", "title": "x"}, "doesn't offer"},
		{map[string]any{"project": "OPS", "title": " "}, "title is required"},
		{map[string]any{"project": "OPS", "title": "x", "priority": "urgent"}, "priority must be"},
		{map[string]any{"project": "OPS", "title": "x", "due": "tomorrow"}, "YYYY-MM-DD"},
		{map[string]any{"project": "OPS", "title": "x", "assignee": "nobody@example.com"}, "no user"},
		{map[string]any{"project": "OPS", "title": "x", "parent": "OPS-99"}, "no work item OPS-99"},
		{map[string]any{"project": "OPS", "title": "x"}, "Site is required"},
		{map[string]any{"project": "OPS", "title": "x", "custom": map[string]any{"site": "moon"}}, "pick one of the options"},
		{map[string]any{"project": "OPS", "title": "x", "custom": map[string]any{"rack": "2"}}, "no custom field \"rack\""},
		{map[string]any{"project": "OPS", "title": "x", "bogus": 1}, "bad JSON"},
	} {
		resp := h.api(vt, "POST", "/work", tc.in, &e)
		if (resp.StatusCode != http.StatusUnprocessableEntity && resp.StatusCode != http.StatusBadRequest) || !strings.Contains(e["error"], tc.want) {
			t.Errorf("%v: %d %q, want %q", tc.in, resp.StatusCode, e["error"], tc.want)
		}
	}

	// Any role files an item; it starts in the workflow's initial status,
	// from the API, watched by its reporter and assignee.
	resp := h.api(vt, "POST", "/work", map[string]any{"project": "ops", "title": "NAS offline", "description": "No ping",
		"priority": "high", "impact": "high", "assignee": "me", "due": "2026-11-20", "estimate": 2.5,
		"custom": map[string]any{"site": "home"}}, fresh(&item))
	if resp.StatusCode != http.StatusCreated || item.Ref != "OPS-1" || item.Type != "incident" || item.StatusCategory != store.StatusTodo ||
		item.Source != "api" || item.Reporter == nil || item.Reporter.Name != "VIC" || item.Assignee == nil ||
		item.Due != "2026-11-20" || *item.Estimate != 2.5 || item.Custom["site"] != "home" || !item.Watching ||
		!strings.HasSuffix(resp.Header.Get("Location"), "/api/v1/work/OPS-1") || len(item.Transitions) == 0 {
		t.Fatalf("create: %d %+v", resp.StatusCode, item)
	}
	h.api(ct, "POST", "/work", map[string]any{"project": "OPS", "type": "problem", "title": "Flaky PSU", "parent": "OPS-1"}, fresh(&item))
	if item.Ref != "OPS-2" || item.Parent == nil || item.Parent.Ref != "OPS-1" || item.Priority != "medium" {
		t.Fatalf("second item: %+v", item)
	}

	// Lists filter as the query asks.
	var items []workItemJSON
	for path, want := range map[string]string{
		"/work":                                "OPS-1,OPS-2",
		"/work?type=problem":                   "OPS-2",
		"/work?assignee=" + item.Reporter.ID:   "",
		"/work?assignee=none":                  "OPS-2",
		"/work?q=nas":                          "OPS-1",
		"/work?parent=OPS-1":                   "OPS-2",
		"/work?project=OPS&status=done":        "",
		"/work?project=OPS&status=all&limit=1": "OPS-1",
	} {
		if resp := h.api(vt, "GET", path, nil, &items); resp.StatusCode != 200 {
			t.Errorf("%s: %d", path, resp.StatusCode)
			continue
		}
		var got []string
		for _, it := range items {
			got = append(got, it.Ref)
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s: %v, want %s", path, got, want)
		}
	}
	if resp := h.api(vt, "GET", "/work?status=closed", nil, &e); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad status filter: %d", resp.StatusCode)
	}

	// A patch changes what it names and clears what it nulls.
	resp = h.api(vt, "PATCH", "/work/ops-1", map[string]any{"priority": "critical", "due": nil, "estimate": nil, "assignee": ""}, fresh(&item))
	if resp.StatusCode != 200 || item.Priority != "critical" || item.Due != "" || item.Estimate != nil || item.Assignee != nil ||
		item.Title != "NAS offline" || item.Custom["site"] != "home" {
		t.Fatalf("patch: %d %+v", resp.StatusCode, item)
	}
	if resp := h.api(vt, "PATCH", "/work/OPS-1", map[string]any{"custom": map[string]any{"site": nil}}, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "required") {
		t.Fatalf("clearing a required field: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(vt, "PATCH", "/work/OPS-1", map[string]any{"parent": "OPS-2"}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("parent loop: %d %v", resp.StatusCode, e)
	}
	h.api(vt, "PATCH", "/work/OPS-1", map[string]any{"custom": map[string]any{"site": "colo"}}, fresh(&item))
	if item.Custom["site"] != "colo" {
		t.Fatalf("custom patch: %+v", item.Custom)
	}

	// Comments and work notes.
	if resp := h.api(vt, "POST", "/work/OPS-1/comments", map[string]any{"body": " "}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("empty comment: %d", resp.StatusCode)
	}
	h.api(ct, "POST", "/work/OPS-1/comments", map[string]any{"body": "Looking", "internal": true}, fresh(&item))
	if len(item.Comments) != 1 || !item.Comments[0].Internal || item.Comments[0].Author.Name != "CARL" || !item.Watching {
		t.Fatalf("comment: %+v", item.Comments)
	}
	h.api(ct, "DELETE", "/work/OPS-1/watch", nil, fresh(&item))
	if item.Watching {
		t.Fatal("still watching")
	}
	h.api(ct, "POST", "/work/OPS-1/watch", nil, fresh(&item))
	if !item.Watching {
		t.Fatal("not watching")
	}

	// Links: CIs the user may see, changes they may see, other items.
	if resp := h.api(vt, "POST", "/work/OPS-1/cis", map[string]any{"ci": plex.HostID}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("vic linking plex, which they can't see: %d %v", resp.StatusCode, e)
	}
	h.api(vt, "POST", "/work/OPS-1/cis", map[string]any{"ci": nas}, fresh(&item))
	h.api(ct, "POST", "/work/OPS-1/cis", map[string]any{"ci": plex.HostID, "role": "caused_by"}, fresh(&item))
	if len(item.CIs) != 2 {
		t.Fatalf("carl sees both CIs: %+v", item.CIs)
	}
	if resp := h.api(vt, "POST", "/work/OPS-1/cis", map[string]any{"ci": nas}, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("linked twice: %d", resp.StatusCode)
	}
	h.api(vt, "GET", "/work/OPS-1", nil, fresh(&item))
	if len(item.CIs) != 1 || item.CIs[0].CI.Name != "nas1" || item.CIs[0].Role != "affected" {
		t.Fatalf("vic sees only nas1: %+v", item.CIs)
	}
	var ci struct {
		ciJSON
		Relationships []relationshipJSON `json:"relationships"`
		WorkItems     []linkedItemJSON   `json:"work_items"`
	}
	if h.api(vt, "GET", "/cis/"+nas, nil, &ci); len(ci.WorkItems) != 1 || ci.WorkItems[0].Item.Ref != "OPS-1" {
		t.Fatalf("CI's work items: %+v", ci.WorkItems)
	}
	if resp := h.api(vt, "DELETE", "/work/OPS-1/cis/"+nas+"?role=target", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unlink the wrong role: %d", resp.StatusCode)
	}
	h.api(vt, "DELETE", "/work/OPS-1/cis/"+nas+"?role=affected", nil, fresh(&item))
	if len(item.CIs) != 0 {
		t.Fatalf("unlinked: %+v", item.CIs)
	}

	var c struct {
		changeJSON
		Jobs []jobJSON `json:"jobs"`
	}
	if resp := h.api(ct, "POST", "/changes", map[string]any{"action": "service.restart", "hosts": []string{plex.HostID},
		"params": map[string]any{"unit": "nginx"}}, &c); resp.StatusCode != http.StatusCreated {
		t.Fatalf("change: %d", resp.StatusCode)
	}
	if resp := h.api(vt, "POST", "/work/OPS-1/changes", map[string]any{"change": c.Ref, "kind": "fixes"}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("vic linking a change on plex: %d %v", resp.StatusCode, e)
	}
	h.api(ct, "POST", "/work/OPS-1/changes", map[string]any{"change": c.Ref, "kind": "fixes"}, fresh(&item))
	if len(item.Changes) != 1 || item.Changes[0].Change.ID != c.ID {
		t.Fatalf("linked change: %+v", item.Changes)
	}
	var cd struct {
		changeJSON
		Jobs      []jobJSON        `json:"jobs"`
		WorkItems []linkedItemJSON `json:"work_items"`
	}
	if h.api(ct, "GET", "/changes/"+c.ID, nil, &cd); len(cd.WorkItems) != 1 || cd.WorkItems[0].Rel != "fixes" {
		t.Fatalf("change's work items: %+v", cd.WorkItems)
	}

	h.api(vt, "POST", "/work/OPS-2/links", map[string]any{"item": "OPS-1", "kind": "blocks", "direction": "in"}, fresh(&item))
	if len(item.Links) != 1 || item.Links[0].Outgoing || item.Links[0].Item.Ref != "OPS-1" {
		t.Fatalf("link: %+v", item.Links)
	}
	if resp := h.api(vt, "POST", "/work/OPS-2/links", map[string]any{"item": "OPS-2", "kind": "relates"}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("self link: %d", resp.StatusCode)
	}
	h.api(vt, "DELETE", "/work/OPS-2/links/OPS-1?kind=blocks&direction=in", nil, fresh(&item))
	if len(item.Links) != 0 {
		t.Fatalf("unlink: %+v", item.Links)
	}

	// Transitions by name or ID; a done status takes a resolution.
	if resp := h.api(vt, "POST", "/work/OPS-1/transitions", map[string]any{"transition": "Fly away"}, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "Start progress") {
		t.Fatalf("unknown transition: %d %v", resp.StatusCode, e)
	}
	h.api(vt, "POST", "/work/OPS-1/transitions", map[string]any{"transition": "start progress"}, fresh(&item))
	if item.StatusCategory != store.StatusInProgress {
		t.Fatalf("start: %+v", item)
	}
	if resp := h.api(vt, "POST", "/work/OPS-1/transitions", map[string]any{"transition": h.transitionID("OPS-1", "Done"),
		"resolution": "Gone"}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad resolution: %d %v", resp.StatusCode, e)
	}
	h.api(vt, "POST", "/work/OPS-1/transitions", map[string]any{"transition": "Done", "resolution": "Fixed"}, fresh(&item))
	if item.StatusCategory != store.StatusDone || item.Resolution != "Fixed" || item.ResolvedAt == nil {
		t.Fatalf("done: %+v", item)
	}

	var history []itemEventJSON
	if resp := h.api(vt, "GET", "/work/OPS-1/history", nil, &history); resp.StatusCode != 200 || len(history) < 5 ||
		!history[len(history)-1].Initial || history[0].Transition == "" {
		t.Fatalf("history: %d %+v", resp.StatusCode, history)
	}
	for _, ev := range history {
		if ev.CIID == plex.HostID {
			t.Fatalf("vic sees history about plex: %+v", ev)
		}
	}

	// Boards come filled as the board page fills them.
	boardID, err := h.st.CreateBoard(ctx, store.System, "", store.Board{Name: "Ops", ProjectID: ops.ID, Columns: store.DefaultColumns()})
	if err != nil {
		t.Fatal(err)
	}
	var boards []boardJSON
	if resp := h.api(vt, "GET", "/boards", nil, &boards); resp.StatusCode != 200 || len(boards) != 1 || boards[0].Project != "OPS" {
		t.Fatalf("boards: %d %+v", resp.StatusCode, boards)
	}
	var board struct {
		Board []boardColumnJSON `json:"board"`
		Total int               `json:"total"`
	}
	if resp := h.api(vt, "GET", "/boards/"+boardID, nil, &board); resp.StatusCode != 200 || len(board.Board) != 3 || board.Total != 2 ||
		len(board.Board[0].Cards) != 1 || board.Board[0].Cards[0].Ref != "OPS-2" || len(board.Board[2].Cards) != 1 ||
		len(board.Board[0].Cards[0].Transitions) == 0 {
		t.Fatalf("board: %d %+v", resp.StatusCode, board)
	}

	if got := h.auditActions(); !strings.Contains(got, "work_item.create") || !strings.Contains(got, "work_item.comment") {
		t.Fatalf("audit: %s", got)
	}
}

func TestAPICIRelationshipsAndChangeLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.dispatcher()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	h.connect(plex, []string{"systemd"}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	nas, _ := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "nas", Name: "nas1", Status: "active"})
	ups, _ := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "ups", Name: "ups1", Status: "active"})

	carl := h.signIn("carl", "media-ops")
	ct := h.mintToken(carl, "scoped", "operator")
	olga := h.signIn("olga", "ops")
	ot := h.mintToken(olga, "global", "operator")
	ov := h.mintToken(olga, "look", "viewer")
	var e map[string]string
	var rels []relationshipJSON

	// Relationships need a global operator, as in the UI.
	if resp := h.api(ct, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "depends_on", "other": ups}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped operator: %d", resp.StatusCode)
	}
	if resp := h.api(ov, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "depends_on", "other": ups}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer token: %d", resp.StatusCode)
	}
	if resp := h.api(ot, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "loves", "other": ups}, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "depends_on") {
		t.Fatalf("bad kind: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ot, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "depends_on", "other": "nope"}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad other: %d %v", resp.StatusCode, e)
	}
	resp := h.api(ot, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "depends_on", "other": ups}, &rels)
	if resp.StatusCode != http.StatusCreated || len(rels) != 1 || !rels[0].Outgoing || rels[0].Other.ID != ups || rels[0].Source != "manual" {
		t.Fatalf("relate: %d %+v", resp.StatusCode, rels)
	}
	if resp := h.api(ot, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "depends_on", "other": ups}, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("twice: %d", resp.StatusCode)
	}
	h.api(ot, "POST", "/cis/"+nas+"/relationships", map[string]any{"kind": "connected_to", "other": ups, "direction": "in"}, &rels)
	if len(rels) != 2 {
		t.Fatalf("second: %+v", rels)
	}
	if resp := h.api(ot, "DELETE", "/cis/"+nas+"/relationships/"+rels[0].ID, nil, &rels); resp.StatusCode != 200 || len(rels) != 1 {
		t.Fatalf("unrelate: %d %+v", resp.StatusCode, rels)
	}
	if resp := h.api(ot, "DELETE", "/cis/"+nas+"/relationships/00000000-0000-0000-0000-000000000000", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unrelate missing: %d", resp.StatusCode)
	}

	// Cancelling: the requester may, someone else without approver rights
	// may not; a cancelled change can't be cancelled again.
	type detail struct {
		changeJSON
		Jobs []jobJSON `json:"jobs"`
	}
	var c detail
	h.api(ct, "POST", "/changes", map[string]any{"action": "service.restart", "hosts": []string{plex.HostID},
		"params": map[string]any{"unit": "nginx"}}, &c)
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/cancel", map[string]any{"reason": "mine now"}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("olga cancelling carl's change: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ct, "POST", "/changes/"+c.ID+"/close", nil, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("closing an open change: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ct, "POST", "/changes/"+c.ID+"/cancel", map[string]any{"reason": "not needed"}, &c); resp.StatusCode != 200 || c.State != store.ChangeCancelled {
		t.Fatalf("cancel: %d %+v", resp.StatusCode, c)
	}
	if resp := h.api(ct, "POST", "/changes/"+c.ID+"/cancel", nil, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("cancel twice: %d", resp.StatusCode)
	}

	// Closing a failed change takes a review.
	h.api(ct, "POST", "/changes", map[string]any{"action": "service.restart", "hosts": []string{plex.HostID},
		"params": map[string]any{"unit": "nginx"}}, &c)
	if _, err := h.st.DB().ExecContext(ctx, `UPDATE change SET state = 'failed' WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if resp := h.api(ct, "POST", "/changes/"+c.ID+"/close", map[string]any{}, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "review") {
		t.Fatalf("close without review: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ct, "POST", "/changes/"+c.ID+"/close", map[string]any{"review": "unit was masked"}, &c); resp.StatusCode != 200 ||
		c.State != store.ChangeClosed || c.ReviewNotes != "unit was masked" {
		t.Fatalf("close: %d %+v", resp.StatusCode, c)
	}
	if got := h.auditActions(); !strings.Contains(got, "change.cancel") || !strings.Contains(got, "change.close") {
		t.Fatalf("audit: %s", got)
	}
}

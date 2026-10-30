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

func TestWorkflowEditor(t *testing.T) {
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

	// Only admins see the editor.
	if resp, _ := h.do(viewer, "GET", "/settings/workflows", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saw workflows: %d", resp.StatusCode)
	}
	_, body := h.do(admin, "GET", "/settings/workflows", nil)
	if !strings.Contains(body, "Default") || !strings.Contains(body, "A copy of Default v1") {
		t.Fatalf("workflows page:\n%s", body)
	}
	all, _ := h.st.ListWorkflows(ctx)

	// A copy of the default starts as a draft.
	resp, _ := h.do(admin, "POST", "/settings/workflows", url.Values{"name": {"Change review"}, "from": {all[0].ID}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	wfURL := strings.SplitN(resp.Header.Get("Location"), "?", 2)[0]
	wid := strings.TrimPrefix(wfURL, "/settings/workflows/")
	if resp, body := h.do(admin, "POST", "/settings/workflows", url.Values{"name": {"change review"}}); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "already exists") {
		t.Fatalf("duplicate: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", wfURL, nil)
	if !strings.Contains(body, "Version 1") || !strings.Contains(body, "draft") || !strings.Contains(body, "Publish v1") {
		t.Fatalf("draft page:\n%s", body)
	}

	// Add an Approved status and an Approve transition only approvers run.
	resp, _ = h.do(admin, "POST", wfURL+"/statuses", url.Values{"key": {"Bad key"}, "name": {"x"}, "category": {"todo"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bad status key: %s", resp.Header.Get("Location"))
	}
	h.do(admin, "POST", wfURL+"/statuses", url.Values{"key": {"approved"}, "name": {"Approved"}, "category": {"in_progress"}, "position": {"1"}})
	wf, _ := h.st.GetWorkflow(ctx, wid)
	draft, _ := h.st.GetWorkflowVersion(ctx, wf.DraftID)
	ids := map[string]string{}
	for _, st := range draft.Statuses {
		ids[st.Key] = st.ID
	}
	if ids["approved"] == "" {
		t.Fatalf("statuses: %+v", draft.Statuses)
	}
	// Publishing waits until Approved can be reached.
	resp, _ = h.do(admin, "POST", wfURL+"/publish", nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=") || !strings.Contains(loc, "Approved") {
		t.Fatalf("publish with an unreachable status: %s", loc)
	}
	_, body = h.do(admin, "GET", wfURL+"/transitions/new", nil)
	if !strings.Contains(body, "Any status") || !strings.Contains(body, "Approved (In progress)") {
		t.Fatalf("transition form:\n%s", body)
	}
	resp, body = h.do(admin, "POST", wfURL+"/transitions", url.Values{"name": {"Loop"}, "from": {ids["todo"]}, "to": {ids["todo"]}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "another status") {
		t.Fatalf("loop: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", wfURL+"/transitions", url.Values{"name": {"Approve"}, "from": {ids["todo"]}, "to": {ids["approved"]},
		"role": {"approver"}, "screen": {"comment"}, "validator": {"comment_required"}, "assign": {"actor"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add transition: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", wfURL, nil)
	if !strings.Contains(body, "role approver") || !strings.Contains(body, "assign to whoever runs it") {
		t.Fatalf("transition table:\n%s", body)
	}
	resp, _ = h.do(admin, "POST", wfURL+"/publish", nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=") {
		t.Fatalf("publish: %s", loc)
	}
	// Published versions are read only.
	resp, _ = h.do(admin, "POST", wfURL+"/statuses", url.Values{"key": {"late"}, "name": {"Late"}, "category": {"todo"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("edited a published version: %s", resp.Header.Get("Location"))
	}

	// Requests in OPS follow it.
	resp, _ = h.do(admin, "POST", "/projects", url.Values{"key": {"OPS"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["request"], typeID["incident"]}, "default_type": {typeID["request"]}, "workflow_" + typeID["request"]: {wid}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("project: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", "/projects/OPS", nil)
	if !strings.Contains(body, "Change review workflow") || !strings.Contains(body, "Default workflow") {
		t.Fatalf("project page:\n%s", body)
	}
	h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["request"]}, "title": {"New laptop"}, "priority": {"low"}})

	// The viewer sees Approve greyed out; the admin runs it, with a comment.
	_, body = h.do(viewer, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, "Change review v1") || !strings.Contains(body, `disabled title="You may not run this transition">Approve → Approved`) {
		t.Fatalf("item page for a viewer:\n%s", body)
	}
	approve := h.transitionID("OPS-1", "Approve")
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/transition", url.Values{"transition": {approve}, "comment": {"ok"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "may+not") {
		t.Fatalf("viewer approved: %s", loc)
	}
	resp, _ = h.do(admin, "POST", "/work/OPS-1/transition", url.Values{"transition": {approve}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "Add+a+comment") {
		t.Fatalf("approve without a comment: %s", loc)
	}
	h.do(admin, "POST", "/work/OPS-1/transition", url.Values{"transition": {approve}, "comment": {"Approved for Q4"}})
	it, _ := h.st.GetWorkItemByRef(ctx, "OPS-1")
	if it.StatusName != "Approved" || it.Assignee == "" {
		t.Fatalf("approved: %+v", it)
	}

	// Editing makes a v2 draft; the item stays on v1 when it is published.
	resp, _ = h.do(admin, "POST", wfURL+"/edit", nil)
	if !strings.Contains(resp.Header.Get("Location"), "v=") {
		t.Fatalf("edit: %s", resp.Header.Get("Location"))
	}
	wf, _ = h.st.GetWorkflow(ctx, wid)
	draft, _ = h.st.GetWorkflowVersion(ctx, wf.DraftID)
	if draft.Version != 2 || len(draft.Transitions) != 5 {
		t.Fatalf("v2: %+v", draft)
	}
	resp, body = h.do(admin, "GET", wfURL+"/transitions/"+draft.Transitions[0].ID, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Edit "+draft.Transitions[0].Name) {
		t.Fatalf("edit transition: %d\n%s", resp.StatusCode, body)
	}
	resp, body = h.do(admin, "GET", "/projects/OPS/edit", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="workflow_`+typeID["request"]+`"`) {
		t.Fatalf("project form: %d\n%s", resp.StatusCode, body)
	}
	h.do(admin, "POST", wfURL+"/statuses/"+draft.Statuses[0].ID, url.Values{"name": {"Submitted"}, "category": {"todo"},
		"position": {"0"}, "initial": {"1"}})
	h.do(admin, "POST", wfURL+"/publish", nil)
	if it, _ := h.st.GetWorkItemByRef(ctx, "OPS-1"); it.WorkflowVersion != 1 {
		t.Fatalf("the item moved: %+v", it)
	}
	_, body = h.do(admin, "GET", wfURL, nil)
	if !strings.Contains(body, "Version 2") || !strings.Contains(body, "Published") || !strings.Contains(body, "Edit (draft v3)") {
		t.Fatalf("published page:\n%s", body)
	}
	h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["request"]}, "title": {"Monitor"}, "priority": {"low"}})
	if it, _ := h.st.GetWorkItemByRef(ctx, "OPS-2"); it.WorkflowVersion != 2 || it.StatusName != "Submitted" {
		t.Fatalf("new item: %+v", it)
	}

	// The list engine filters by status name and workflow.
	_, body = h.list(viewer, "/work?cf=status_name&co=eq&cv=Submitted&cols=ref&cols=title&cols=workflow")
	if !strings.Contains(body, "Monitor") || strings.Contains(body, "New laptop") || !strings.Contains(body, "Change review") {
		t.Fatalf("by status name:\n%s", body)
	}

	// A workflow in use can't be deleted.
	resp, _ = h.do(admin, "POST", wfURL+"/delete", nil)
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("deleted a used workflow: %s", resp.Header.Get("Location"))
	}
	for _, want := range []string{"workflow.create", "workflow.edit", "workflow.publish", "workflow.draft", "work_item.transition"} {
		if !strings.Contains(h.auditActions(), want) {
			t.Fatalf("audit lacks %s: %s", want, h.auditActions())
		}
	}
}

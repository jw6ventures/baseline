package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestChangeEditAndEscalate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	plex := h.addHost("plex")
	h.connect(plex, []string{"systemd", "dnf", action.CapPkgPin}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	ops := h.signIn("carl", "ops")
	appr := h.signIn("dee", "approvers")
	viewer := h.signIn("vic", "viewers")

	// A window that opens twelve hours from now, so changes in it wait.
	now := time.Now().UTC()
	winID, err := h.st.SaveWindow(ctx, store.System, store.MaintenanceWindow{Name: "nightly", Kind: store.WindowKindWindow,
		Cron: fmt.Sprintf("0 %d * * *", (now.Hour()+12)%24), Duration: time.Hour, TZ: "UTC", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	get := func(id string) store.Change {
		t.Helper()
		c, err := h.st.GetChange(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	editForm := func(c store.Change) url.Values {
		f := h.srv.editForm(c)
		return f
	}

	form := url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"nginx"}, "window": {winID},
		"justification": {"stuck"}}
	resp, _ := h.do(ops, "POST", "/changes", form)
	id := changeIDFrom(t, resp)
	h.do(appr, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	c := get(id)
	if c.State != store.ChangeScheduled || c.WindowID != winID {
		t.Fatalf("waiting for its window: %s %q", c.State, c.ScheduleNote)
	}

	// Who sees Edit: the requester, not a viewer.
	if _, body := h.do(ops, "GET", "/changes/"+id, nil); !strings.Contains(body, "/changes/"+id+"/edit") ||
		!strings.Contains(body, "Escalate to Emergency") {
		t.Fatalf("requester's page lacks edit or escalate:\n%s", body)
	}
	if _, body := h.do(viewer, "GET", "/changes/"+id, nil); strings.Contains(body, "/edit\"") || strings.Contains(body, "Escalate to Emergency") {
		t.Fatal("a viewer is offered edit or escalate")
	}
	if resp, _ := h.do(viewer, "POST", "/changes/"+id+"/edit", editForm(c)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer edited: %d", resp.StatusCode)
	}
	resp, body := h.do(ops, "GET", "/changes/"+id+"/edit", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `value="Restart nginx.service on plex"`) || !strings.Contains(body, "withdraws them") {
		t.Fatalf("edit form: %d\n%s", resp.StatusCode, body)
	}

	// A text edit keeps the approval and the schedule.
	f := editForm(c)
	f.Set("title", "Restart nginx on plex")
	f.Set("test_plan", "curl it")
	resp, _ = h.do(ops, "POST", "/changes/"+id+"/edit", f)
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("text edit: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c = get(id); c.Title != "Restart nginx on plex" || c.TestPlan != "curl it" || c.State != store.ChangeScheduled || c.Approvals != 1 {
		t.Fatalf("after a text edit: %+v", c)
	}
	_, body = h.do(ops, "GET", "/changes/"+id, nil)
	if !strings.Contains(body, "Title: Restart nginx.service on plex → Restart nginx on plex") || !strings.Contains(body, "Test plan: empty → curl it") {
		t.Fatalf("history lacks the edit:\n%s", body)
	}

	// A risk edit by the requester withdraws the approval.
	f = editForm(c)
	f.Set("risk", "high")
	h.do(ops, "POST", "/changes/"+id+"/edit", f)
	if c = get(id); c.State != store.ChangeSubmitted || c.Approvals != 0 || c.Risk != "high" || c.PlannedStart.Unix() > 0 {
		t.Fatalf("after a risk edit: %s %d %s %v", c.State, c.Approvals, c.Risk, c.PlannedStart)
	}
	if _, body = h.do(ops, "GET", "/changes/"+id, nil); !strings.Contains(body, ">withdrawn<") || !strings.Contains(body, "1 approval withdrawn") {
		t.Fatalf("withdrawn approval not shown:\n%s", body)
	}
	h.do(appr, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	if c = get(id); c.State != store.ChangeScheduled || c.Approvals != 1 {
		t.Fatalf("approved again: %s %d", c.State, c.Approvals)
	}

	// An approver's edit of the rollout counts as their approval.
	f = editForm(c)
	f.Set("concurrency", "3")
	h.do(appr, "POST", "/changes/"+id+"/edit", f)
	if c = get(id); c.State != store.ChangeScheduled || c.Approvals != 1 || c.Concurrency != 3 {
		t.Fatalf("approver's edit: %s %d %d", c.State, c.Approvals, c.Concurrency)
	}

	// Bad edits are refused: a start in the past, an empty title.
	f = editForm(c)
	f.Set("not_before", now.Add(-time.Hour).In(h.srv.cfg.Location).Format("2006-01-02T15:04"))
	if resp, body = h.do(ops, "POST", "/changes/"+id+"/edit", f); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "in the past") {
		t.Fatalf("start in the past: %d", resp.StatusCode)
	}
	f = editForm(c)
	f.Set("title", " ")
	if resp, _ = h.do(ops, "POST", "/changes/"+id+"/edit", f); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("empty title: %d", resp.StatusCode)
	}

	// The requester escalates it: no more window, and it waits for one
	// approver; then it runs at once.
	if resp, _ = h.do(ops, "POST", "/changes/"+id+"/escalate", nil); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("escalated without a reason")
	}
	h.do(ops, "POST", "/changes/"+id+"/escalate", url.Values{"reason": {"nginx is down for everyone"}})
	if c = get(id); c.Kind != store.KindEmergency || c.WindowID != "" || c.State != store.ChangeSubmitted || c.Approvals != 0 || c.RequiredApprovals != 1 {
		t.Fatalf("escalated by the requester: %+v", c)
	}
	h.do(appr, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	if c = get(id); c.State != store.ChangeInProgress {
		t.Fatalf("approved emergency: %s %q", c.State, c.ScheduleNote)
	}
	_, body = h.do(ops, "GET", "/changes/"+id, nil)
	if !strings.Contains(body, "Escalated from normal to Emergency: nginx is down for everyone") || !strings.Contains(body, "maintenance window nightly removed") {
		t.Fatalf("history lacks the escalation:\n%s", body)
	}
	// Running: no more edits.
	if resp, _ = h.do(ops, "POST", "/changes/"+id+"/edit", editForm(c)); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("edited a running change")
	}

	// A Standard change waiting for its window, escalated by an approver,
	// starts now; running in its window, its jobs stop waiting for it.
	model := h.approvedModel("monthly")
	resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"pkg.upgrade"}, "model": {model}, "host": {plex.HostID},
		"window": {winID}, "submit": {"standard"}})
	sid := changeIDFrom(t, resp)
	d.Pass(ctx)
	if c = get(sid); c.State != store.ChangeScheduled {
		t.Fatalf("standard in its window: %s", c.State)
	}
	_, body = h.do(appr, "GET", "/changes/"+sid, nil)
	if !strings.Contains(body, "escalating also approves it, so it starts now") {
		t.Fatalf("approver's escalate panel:\n%s", body)
	}
	h.do(appr, "POST", "/changes/"+sid+"/escalate", url.Values{"reason": {"CVE"}})
	if c = get(sid); c.Kind != store.KindEmergency || c.State != store.ChangeApproved || c.Approvals != 1 || c.ModelID == "" {
		t.Fatalf("standard escalated by an approver: %+v", c)
	}
	d.Pass(ctx)
	if c = get(sid); c.State != store.ChangeInProgress || !c.WindowEndsAt.IsZero() {
		t.Fatalf("escalated standard: %s %v", c.State, c.WindowEndsAt)
	}

	// An operator can't escalate a running change; an approver can.
	resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"sshd"}})
	rid := changeIDFrom(t, resp)
	h.do(appr, "POST", "/changes/"+rid+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	if c = get(rid); c.State != store.ChangeInProgress {
		t.Fatalf("running: %s", c.State)
	}
	if _, body = h.do(ops, "GET", "/changes/"+rid, nil); strings.Contains(body, "Escalate to Emergency") {
		t.Fatal("an operator is offered to escalate a running change")
	}
	if resp, _ = h.do(ops, "POST", "/changes/"+rid+"/escalate", url.Values{"reason": {"x"}}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("an operator escalated a running change")
	}
	h.do(appr, "POST", "/changes/"+rid+"/escalate", url.Values{"reason": {"x"}})
	if c = get(rid); c.Kind != store.KindEmergency || c.State != store.ChangeInProgress {
		t.Fatalf("running change escalated: %s %s", c.Kind, c.State)
	}
	if strings.Count(h.auditActions(), "change.escalate") != 3 || !strings.Contains(h.auditActions(), "change.edit") {
		t.Fatalf("audit: %s", h.auditActions())
	}
}

func TestChangeEditAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	plex := h.addHost("plex")
	h.connect(plex, []string{"systemd"}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	ops := h.signIn("carl", "ops")
	appr := h.signIn("dee", "approvers")
	ot := h.mintToken(ops, "ops", "operator")

	type detail struct {
		changeJSON
		Approvals []approvalJSON `json:"approvals"`
		Jobs      []jobJSON      `json:"jobs"`
	}
	var c, out detail
	h.api(ot, "POST", "/changes", map[string]any{"action": "service.restart", "hosts": []string{plex.HostID},
		"params": map[string]any{"unit": "nginx"}, "required_approvals": 2}, &c)
	h.do(appr, "POST", "/changes/"+c.ID+"/decide", url.Values{"decision": {"approve"}})

	var e map[string]string
	for _, tc := range []struct {
		in   map[string]any
		want string
	}{
		{map[string]any{"risk": "scary"}, "risk must be"},
		{map[string]any{"required_approvals": 9}, "required_approvals"},
		{map[string]any{"title": ""}, "title"},
		{map[string]any{"not_before": "yesterday"}, "not_before"},
		{map[string]any{"window": "nope"}, "maintenance window"},
	} {
		if resp := h.api(ot, "PATCH", "/changes/"+c.ID, tc.in, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
			!strings.Contains(e["error"], tc.want) {
			t.Errorf("%v: %d %q, want %q", tc.in, resp.StatusCode, e["error"], tc.want)
		}
	}
	// Lowering the approvals needed to the one it has approves it.
	if resp := h.api(ot, "PATCH", "/changes/"+c.ID, map[string]any{"title": "Kick nginx", "required_approvals": 1}, &c); resp.StatusCode != 200 ||
		c.Title != "Kick nginx" || c.State != store.ChangeApproved || c.RequiredApprovals != 1 {
		t.Fatalf("edit: %d %+v", resp.StatusCode, c)
	}
	// Escalating through the API never approves: it waits for an approver.
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/escalate", map[string]any{}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("escalate without a reason: %d", resp.StatusCode)
	}
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/escalate", map[string]any{"reason": "outage"}, &out); resp.StatusCode != 200 ||
		out.Kind != store.KindEmergency || out.State != store.ChangeSubmitted || len(out.Approvals) != 1 || !out.Approvals[0].Withdrawn {
		t.Fatalf("escalate: %d %+v", resp.StatusCode, out)
	}
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/escalate", map[string]any{"reason": "again"}, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("escalated twice: %d", resp.StatusCode)
	}
}

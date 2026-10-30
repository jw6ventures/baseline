package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

var reModel = regexp.MustCompile(`/change-models/([0-9a-f-]{36})`)

func TestChangeLifecycleUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	plex := h.addHost("plex")
	all := &action.Policy{Jobs: true, AllowScripts: true}
	h.connect(plex, []string{"systemd", "dnf", action.CapPkgPin}, all)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	ops := h.signIn("carl", "ops")
	appr := h.signIn("dee", "approvers")
	admin := h.signIn("ann", "lab-admins")

	_, body := h.do(ops, "GET", "/changes/new?action=service.restart&host="+plex.HostID, nil)
	for _, want := range []string{`name="kind" value="emergency"`, `name="window"`, `name="planned_start"`, "Save as draft",
		`name="backout_plan"`, `name="approvals"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("form lacks %s:\n%s", want, body)
		}
	}

	// A draft, submitted later by its requester, needing two approvals.
	form := url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"nginx"}, "submit": {"draft"},
		"approvals": {"2"}, "backout_plan": {"start it again"}, "impact": {"medium"}}
	resp, _ := h.do(ops, "POST", "/changes", form)
	id := changeIDFrom(t, resp)
	c, _ := h.st.GetChange(ctx, id)
	if c.State != store.ChangeDraft || c.RequiredApprovals != 2 || c.BackoutPlan != "start it again" || c.Impact != "medium" {
		t.Fatalf("draft: %+v", c)
	}
	if _, body = h.do(appr, "GET", "/changes/"+id, nil); strings.Contains(body, ">Approve</button>") {
		t.Fatal("a draft offered for approval")
	}
	if resp, _ = h.do(appr, "POST", "/changes/"+id+"/submit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatal("someone else submitted the draft")
	}
	h.do(ops, "POST", "/changes/"+id+"/submit", nil)
	h.do(appr, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}})
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeSubmitted || c.Approvals != 1 {
		t.Fatalf("one of two approvals: %s %d", c.State, c.Approvals)
	}
	h.do(admin, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeInProgress {
		t.Fatalf("approved twice: %s", c.State)
	}
	js, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: id})
	h.st.FinishJob(ctx, store.System, plex.HostID, js[0].ID, store.JobResult{State: store.JobFailed, Error: "boom"})
	_, body = h.do(ops, "GET", "/changes/"+id, nil)
	if !strings.Contains(body, "post-implementation review") || !strings.Contains(body, "Close the change") {
		t.Fatalf("failed change page:\n%s", body)
	}
	if resp, _ = h.do(ops, "POST", "/changes/"+id+"/close", nil); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("closed without a review")
	}
	h.do(ops, "POST", "/changes/"+id+"/close", url.Values{"review": {"nginx config was broken; fixed"}})
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeClosed || c.ReviewNotes == "" {
		t.Fatalf("closed: %s", c.State)
	}
	if _, body = h.list(ops, "/changes?show=all"); !strings.Contains(body, ">normal<") || !strings.Contains(body, "closed") {
		t.Fatalf("list:\n%s", body)
	}

	// A planned start inside a freeze is refused; an Emergency change goes.
	now := time.Now().UTC()
	h.st.SaveWindow(ctx, store.System, store.MaintenanceWindow{Name: "freeze", Kind: store.WindowKindFreeze,
		Cron: fmt.Sprintf("%d %d * * *", now.Minute(), now.Hour()), Duration: 3 * time.Hour, TZ: "UTC", Active: true})
	form = url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"nginx"},
		"planned_start": {now.Add(time.Hour).Format("2006-01-02T15:04")}}
	if resp, body = h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "freeze") {
		t.Fatalf("planned in a freeze: %d\n%s", resp.StatusCode, body)
	}
	form.Set("kind", "emergency")
	form.Set("submit", "approve")
	form.Set("approvals", "3")
	resp, _ = h.do(appr, "POST", "/changes", form)
	if resp.StatusCode != http.StatusForbidden { // dee approves but isn't an operator
		t.Fatalf("approver requested a change: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/changes", form)
	id = changeIDFrom(t, resp)
	if c, _ = h.st.GetChange(ctx, id); c.Kind != store.KindEmergency || c.State != store.ChangeApproved || c.RequiredApprovals != 1 {
		t.Fatalf("emergency: %s %s %d", c.Kind, c.State, c.RequiredApprovals)
	}
	d.Pass(ctx)
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeScheduled {
		t.Fatalf("emergency with a planned start: %s", c.State)
	}
	// A Normal change approved during the freeze waits for its end.
	form = url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"nginx"}, "submit": {"approve"}}
	resp, _ = h.do(admin, "POST", "/changes", form)
	id = changeIDFrom(t, resp)
	d.Pass(ctx)
	_, body = h.do(admin, "GET", "/changes/"+id, nil)
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeScheduled || !strings.Contains(body, "Held by freeze freeze") {
		t.Fatalf("held: %s\n%s", c.State, body)
	}
}

func TestChangeModelsUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	plex := h.addHost("plex")
	h.connect(plex, []string{"systemd", "dnf", action.CapPkgPin}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	ops := h.signIn("carl", "ops")
	appr := h.signIn("dee", "approvers")
	admin := h.signIn("ann", "lab-admins")

	if resp, _ := h.do(ops, "GET", "/change-models/new", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator writes models: %d", resp.StatusCode)
	}
	_, body := h.do(admin, "GET", "/change-models/new", nil)
	if !strings.Contains(body, "action=pkg.upgrade") || strings.Contains(body, "action=container.restart") {
		t.Fatalf("model actions:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/change-models/new?action=pkg.upgrade", nil)
	if !strings.Contains(body, `name="mode"`) || !strings.Contains(body, `name="name"`) {
		t.Fatalf("model form:\n%s", body)
	}
	form := url.Values{"action": {"pkg.upgrade"}, "name": {"Security patches"}, "mode": {"security"}, "reboot": {"if_required"},
		"risk": {"medium"}}
	resp, _ := h.do(admin, "POST", "/change-models", form)
	m := reModel.FindStringSubmatch(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || m == nil {
		t.Fatalf("save model: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	mid := m[1]
	if resp, body = h.do(admin, "POST", "/change-models", form); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "already has that name") {
		t.Fatalf("duplicate name: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", "/change-models/"+mid+"/edit", nil)
	if !strings.Contains(body, `value="security" checked`) {
		t.Fatalf("edit form keeps the parameters:\n%s", body)
	}
	if resp, _ = h.do(ops, "POST", "/change-models/"+mid+"/approve", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator approved a model: %d", resp.StatusCode)
	}
	if resp, _ = h.do(ops, "GET", "/changes/new?model="+mid+"&host="+plex.HostID, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("change from a pending model: %d", resp.StatusCode)
	}
	h.do(appr, "POST", "/change-models/"+mid+"/approve", nil)
	_, body = h.do(ops, "GET", "/change-models/"+mid, nil)
	if !strings.Contains(body, "New Standard change") || !strings.Contains(body, "Install security updates, reboot if required") {
		t.Fatalf("model page:\n%s", body)
	}

	// An operator makes a Standard change from it: approved at once.
	_, body = h.do(ops, "GET", "/changes/new?model="+mid+"&host="+plex.HostID, nil)
	if !strings.Contains(body, "Create the Standard change") || strings.Contains(body, `name="mode"`) {
		t.Fatalf("standard form:\n%s", body)
	}
	resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"pkg.upgrade"}, "model": {mid}, "host": {plex.HostID},
		"mode": {"all"}, "submit": {"standard"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("standard change: %d", resp.StatusCode)
	}
	cs, _ := h.st.ListChanges(ctx, store.ChangeFilter{ModelID: mid})
	if len(cs) != 1 || cs[0].Kind != store.KindStandard || cs[0].State != store.ChangeApproved ||
		!strings.Contains(cs[0].Plan[0].Summary, "security") {
		t.Fatalf("standard change: %+v", cs)
	}
	d.Pass(ctx)
	if got := strings.Join(h.sentRunJobs(), ","); got != "pkg.upgrade" {
		t.Fatalf("sent: %s", got)
	}

	// Editing puts it back to pending; retiring stops it.
	form.Set("risk", "high")
	h.do(admin, "POST", "/change-models/"+mid, form)
	if mm, _ := h.st.GetChangeModel(ctx, mid); mm.State != store.ModelPending || mm.Risk != "high" {
		t.Fatalf("edited: %+v", mm)
	}
	h.do(admin, "POST", "/change-models/"+mid+"/retire", nil)
	if _, body = h.list(ops, "/change-models"); strings.Contains(body, "Security patches") {
		t.Fatalf("current models list a retired one:\n%s", body)
	}
	if _, body = h.list(ops, "/change-models?show=retired"); !strings.Contains(body, ">Security patches<") ||
		!strings.Contains(body, `<span class="tag">retired</span>`) || !strings.Contains(body, "Install updates") {
		t.Fatalf("retired models:\n%s", body)
	}
	if !strings.Contains(h.auditActions(), "change_model.approve") {
		t.Fatalf("audit: %s", h.auditActions())
	}
}

func TestStackUpdatesUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	h.ingest(plex, model.SectionContainers, containersFixture())
	h.st.SaveImageCheck(ctx, "docker.io/plexinc/pms-docker:1.41.0", "docker.io", "sha256:"+strings.Repeat("2", 64), "")
	h.connect(plex, []string{"docker"}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	admin := h.signIn("ann", "lab-admins")
	stacks, _ := h.st.ListStacks(ctx, []string{plex.HostID})
	st := stacks[0]

	// An agent from before M5 has no compose capability.
	_, body := h.do(ops, "GET", "/stacks/"+st.CIID, nil)
	if strings.Contains(body, "Update…") || !strings.Contains(body, "a Compose CLI and an agent from M5 on") {
		t.Fatalf("old agent:\n%s", body)
	}
	h.connect(plex, []string{"docker", action.CapCompose}, &action.Policy{Jobs: true})
	_, body = h.do(ops, "GET", "/stacks/"+st.CIID, nil)
	if !strings.Contains(body, "Update…") || !strings.Contains(body, "Pull images…") || strings.Contains(body, "update itself when") {
		t.Fatalf("stack page for an operator:\n%s", body)
	}
	_, body = h.do(ops, "GET", "/changes/new?action=compose.update&stack="+st.CIID, nil)
	if !strings.Contains(body, `name="svc.`+st.CIID+`" value="plex"`) || !strings.Contains(body, `name="health_timeout"`) ||
		!strings.Contains(body, `name="stack" value="`+st.CIID+`"`) {
		t.Fatalf("compose form:\n%s", body)
	}
	resp, _ := h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}, "stack": {st.CIID}, "service": {"plex"},
		"health_timeout": {"60"}})
	id := changeIDFrom(t, resp)
	c, _ := h.st.GetChange(ctx, id)
	if c.Plan[0].Summary != "Update stack media (plex)" || len(c.HostIDs) != 1 {
		t.Fatalf("compose change: %+v", c)
	}
	if cs, _ := h.st.ListChanges(ctx, store.ChangeFilter{CIID: st.CIID}); len(cs) != 1 {
		t.Fatal("the change doesn't list the stack as affected")
	}
	h.do(admin, "POST", "/changes/"+id+"/cancel", nil)

	// Auto-update: an approver (here the admin) sets a model; the stack
	// then updates itself because its image drifted.
	if resp, _ = h.do(ops, "POST", "/stacks/"+st.CIID+"/updates", url.Values{"auto_update": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator set auto-update: %d", resp.StatusCode)
	}
	params := []byte(`{"engine":"","project":"","health_timeout":90}`)
	mid, _ := h.st.SaveChangeModel(ctx, store.System, store.ChangeModel{Name: "compose", Action: action.ComposeUpdate, Params: params, Risk: "low"})
	if resp, _ = h.do(admin, "POST", "/stacks/"+st.CIID+"/updates", url.Values{"auto_update": {"1"}}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("auto-update without a model")
	}
	h.do(admin, "POST", "/stacks/"+st.CIID+"/updates", url.Values{"auto_update": {"1"}, "model": {mid}})
	if n, err := h.srv.changes.AutoUpdate(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("auto-update with a pending model: %d %v", n, err)
	}
	h.st.ApproveChangeModel(ctx, store.UserActor(mustUser(t, h, "ann"), ""), mid)
	_, body = h.do(admin, "GET", "/stacks/"+st.CIID, nil)
	if !strings.Contains(body, "Update now") || !strings.Contains(body, "Standard, from model") {
		t.Fatalf("stack with a model:\n%s", body)
	}
	// Another approved compose model can't be used on this stack.
	other, _ := h.st.SaveChangeModel(ctx, store.System, store.ChangeModel{Name: "other", Action: action.ComposeUpdate, Params: params, Risk: "low"})
	h.st.ApproveChangeModel(ctx, store.UserActor(mustUser(t, h, "ann"), ""), other)
	if resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}, "model": {other}, "stack": {st.CIID}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "run under that change model") {
		t.Fatalf("another model: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	if n, err := h.srv.changes.AutoUpdate(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("auto-update: %d %v", n, err)
	}
	cs, _ := h.st.ListChanges(ctx, store.ChangeFilter{CIID: st.CIID, States: []string{store.ChangeApproved}})
	if len(cs) != 1 || cs[0].Kind != store.KindStandard || cs[0].RequestedByName != "the scheduler" ||
		!strings.Contains(string(cs[0].Plan[0].Params), `"health_timeout": 90`) {
		t.Fatalf("auto change: %+v", cs)
	}
	// Not again while that one is open.
	if n, _ := h.srv.changes.AutoUpdate(ctx, time.Now()); n != 0 {
		t.Fatalf("auto-updated twice: %d", n)
	}
	d.Pass(ctx)
	if got := strings.Join(h.sentRunJobs(), ","); got != "compose.update" {
		t.Fatalf("sent: %s", got)
	}
}

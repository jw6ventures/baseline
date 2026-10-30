package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/jobs"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// connect records a Hello for a host, as its agent would send it.
func (h *harness) connect(r store.EnrollResult, caps []string, p *action.Policy) {
	h.t.Helper()
	if _, err := h.st.AgentConnected(context.Background(), r.HostID, r.AgentID, store.Hello{
		AgentVersion: "test", BootID: "b1", Capabilities: caps, Policy: p}); err != nil {
		h.t.Fatal(err)
	}
	h.hub.online[r.AgentID] = true
}

// dispatcher connects a job dispatcher that the test drives with Pass.
func (h *harness) dispatcher() *jobs.Dispatcher {
	d := jobs.New(h.st, h.hub, &jw6_utils.Utils{LogLevel: jw6_utils.Fatal})
	h.srv.SetJobs(d)
	return d
}

func (h *harness) sentRunJobs() []string {
	h.hub.mu.Lock()
	defer h.hub.mu.Unlock()
	var out []string
	for _, m := range h.hub.messages {
		if rj := m.GetRunJob(); rj != nil {
			out = append(out, rj.GetAction())
		}
		if cj := m.GetCancelJob(); cj != nil {
			out = append(out, "cancel")
		}
	}
	return out
}

var reChange = regexp.MustCompile(`/changes/([0-9a-f-]{36})`)

func changeIDFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	m := reChange.FindStringSubmatch(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || m == nil {
		t.Fatalf("expected a redirect to a change, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return m[1]
}

func TestChangesAndJobsUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	all := &action.Policy{Jobs: true, AllowScripts: true}
	h.connect(plex, []string{"systemd", "apt"}, all)
	h.connect(dns, []string{"systemd", "apt"}, nil) // an agent from before jobs
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})

	ops := h.signIn("carl", "media-ops")
	_, body := h.do(ops, "GET", "/changes/new", nil)
	if !strings.Contains(body, "Restart a service") || !strings.Contains(body, "Install updates") {
		t.Fatalf("action picker:\n%s", body)
	}
	_, body = h.do(ops, "GET", "/changes/new?action=service.restart&host="+plex.HostID+"&unit=nginx.service", nil)
	if !strings.Contains(body, `value="`+plex.HostID+`" checked`) || strings.Contains(body, "dns1") ||
		strings.Contains(body, "Submit and approve") || !strings.Contains(body, `value="nginx.service"`) {
		t.Fatalf("form:\n%s", body)
	}

	form := url.Values{"action": {"service.restart"}, "host": {plex.HostID}, "unit": {"nginx"}, "justification": {"stuck"}}
	resp, _ := h.do(ops, "POST", "/changes", form)
	id := changeIDFrom(t, resp)
	c, _ := h.st.GetChange(ctx, id)
	if c.State != store.ChangeSubmitted || c.Title != "Restart nginx.service on plex" || c.Justification != "stuck" || c.Risk != "low" {
		t.Fatalf("change: %+v", c)
	}
	_, body = h.do(ops, "GET", "/changes/"+id, nil)
	if !strings.Contains(body, c.Ref()) || !strings.Contains(body, "Waiting for approvers") || !strings.Contains(body, "Cancel this change") {
		t.Fatalf("change page:\n%s", body)
	}

	// Operators can't approve their own change, or touch hosts outside
	// their scope; nobody runs actions an agent's policy refuses.
	form.Set("submit", "approve")
	resp, body = h.do(ops, "POST", "/changes", form)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "approver role") {
		t.Fatalf("operator self-approval: %d", resp.StatusCode)
	}
	form.Del("submit")
	form.Set("host", dns.HostID)
	if resp, body = h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "operator role") {
		t.Fatalf("out of scope: %d", resp.StatusCode)
	}
	admin := h.signIn("ann", "lab-admins")
	if resp, body = h.do(admin, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "too old") {
		t.Fatalf("old agent: %d", resp.StatusCode)
	}

	viewer := h.signIn("vic", "viewers")
	if _, body = h.do(viewer, "GET", "/changes", nil); !strings.Contains(body, c.Ref()) {
		t.Fatalf("viewer list:\n%s", body)
	}
	if resp, _ = h.do(viewer, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer approved: %d", resp.StatusCode)
	}
	if resp, _ = h.do(viewer, "POST", "/changes", form); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer created: %d", resp.StatusCode)
	}

	// An approver approves; the dispatcher sends the job.
	appr := h.signIn("dee", "approvers")
	if _, body = h.do(appr, "GET", "/changes/"+id, nil); !strings.Contains(body, ">Approve</button>") {
		t.Fatalf("approver's page:\n%s", body)
	}
	if resp, _ = h.do(appr, "POST", "/changes/"+id+"/decide", url.Values{"decision": {"approve"}, "comment": {"ok"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("approve: %d", resp.StatusCode)
	}
	d.Pass(ctx)
	if got := strings.Join(h.sentRunJobs(), ","); got != "service.restart" {
		t.Fatalf("sent: %s", got)
	}
	js, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: id})
	job := js[0]
	h.st.JobStarted(ctx, plex.HostID, job.ID)
	h.st.AppendJobOutput(ctx, plex.HostID, job.ID, 1, "stdout", "restarting <nginx>\n")

	// The job page, its live stream and its raw output.
	_, body = h.do(ops, "GET", "/jobs/"+job.ID, nil)
	if !strings.Contains(body, "Restart nginx.service") || !strings.Contains(body, "restarting &lt;nginx&gt;") ||
		!strings.Contains(body, "job.js") {
		t.Fatalf("job page:\n%s", body)
	}
	if _, body = h.do(ops, "GET", "/jobs/"+job.ID+"/output.txt", nil); body != "restarting <nginx>\n" {
		t.Fatalf("raw: %q", body)
	}
	h.st.FinishJob(ctx, store.Actor{ID: "agent:" + plex.AgentID}, plex.HostID, job.ID, store.JobResult{State: store.JobSucceeded, ExitCode: new(int)})
	resp, body = h.do(ops, "GET", "/jobs/"+job.ID+"/events", nil)
	if resp.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(body, `"t":"restarting \u003cnginx\u003e\n"`) ||
		!strings.Contains(body, `"state":"succeeded"`) || !strings.HasSuffix(body, "event: done\ndata: {}\n\n") {
		t.Fatalf("events: %s\n%s", resp.Header.Get("Content-Type"), body)
	}
	// Resuming after the last chunk sends no output again.
	if _, body = h.do(ops, "GET", "/jobs/"+job.ID+"/events", nil, "Last-Event-ID", "999999"); strings.Contains(body, "event: output") {
		t.Fatalf("resumed: %s", body)
	}
	if c, _ = h.st.GetChange(ctx, id); c.State != store.ChangeImplemented {
		t.Fatalf("change: %s", c.State)
	}
	if _, body = h.do(ops, "GET", "/hosts/"+plex.HostID+"/jobs", nil); !strings.Contains(body, c.Ref()) || !strings.Contains(body, "Install updates") {
		t.Fatalf("host jobs tab:\n%s", body)
	}
	// dns1's jobs aren't plex operators' business.
	if resp, _ = h.do(ops, "GET", "/jobs/"+job.ID, nil); resp.StatusCode != 200 {
		t.Fatalf("own job: %d", resp.StatusCode)
	}

	// An admin's self-approved change goes straight to its job.
	form = url.Values{"action": {"host.reboot"}, "host": {plex.HostID}, "submit": {"approve"}}
	resp, _ = h.do(admin, "POST", "/changes", form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/jobs/") {
		t.Fatalf("self-approved: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	all2, _ := h.st.ListChanges(ctx, store.ChangeFilter{})
	reboot := all2[0]
	if !reboot.SelfApproved || reboot.Risk != "high" || reboot.State != store.ChangeApproved {
		t.Fatalf("reboot change: %+v", reboot)
	}
	d.Pass(ctx)
	// The requester cancels; the agent is told to stop the job.
	if resp, _ = h.do(viewer, "POST", "/changes/"+reboot.ID+"/cancel", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer cancelled: %d", resp.StatusCode)
	}
	h.do(admin, "POST", "/changes/"+reboot.ID+"/cancel", url.Values{"reason": {"wrong host"}})
	if got := strings.Join(h.sentRunJobs(), ","); got != "service.restart,host.reboot,cancel" {
		t.Fatalf("sent: %s", got)
	}
	if reboot, _ = h.st.GetChange(ctx, reboot.ID); reboot.State != store.ChangeCancelled {
		t.Fatalf("cancelled: %s", reboot.State)
	}
	_, body = h.do(admin, "GET", "/", nil)
	if !strings.Contains(body, "Changes") {
		t.Fatalf("nav:\n%s", body)
	}
	if got := h.auditActions(); !strings.Contains(got, "change.approve change.state change.state job.dispatch job.result change.state") ||
		!strings.Contains(got, "change.cancel") {
		t.Fatalf("audit: %s", got)
	}
}

func TestUpdatesTabOffersPatching(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	web := h.addHost("web")
	h.connect(web, []string{"apt", "systemd"}, &action.Policy{Jobs: true, AllowActions: []string{action.CategoryPatch}})
	ups := model.Updates{Managers: []string{"apt"}, Updates: []model.Update{
		{Manager: "apt", Name: "openssl", Installed: "3.0.13-1", Candidate: "3.0.13-2", Security: true},
		{Manager: "apt", Name: "linux-image-6.8.0-90-generic", Candidate: "6.8.0-90.91"},
	}}
	b, hash, _ := model.Encode(ups)
	h.st.IngestSection(ctx, web.HostID, web.AgentID, model.SectionUpdates, hash, b, "")
	admin := h.signIn("ann", "lab-admins")
	_, body := h.do(admin, "GET", "/hosts/"+web.HostID+"?tab=updates", nil)
	if !strings.Contains(body, "Install security updates…") || !strings.Contains(body, `name="pkg" value="openssl"`) ||
		!strings.Contains(body, "Pulled in by another package") {
		t.Fatalf("updates tab:\n%s", body)
	}
	// Selected packages arrive in the form.
	_, body = h.do(admin, "GET", "/changes/new?action=pkg.upgrade&mode=selected&host="+web.HostID+"&pkg=openssl", nil)
	if !strings.Contains(body, ">openssl</textarea>") || !strings.Contains(body, `value="selected" checked`) {
		t.Fatalf("form:\n%s", body)
	}
	resp, _ := h.do(admin, "POST", "/changes", url.Values{"action": {"pkg.upgrade"}, "host": {web.HostID}, "mode": {"selected"},
		"packages": {"openssl"}, "reboot": {"if_required"}, "exclude": {"kernel*, linux-*"}})
	c, _ := h.st.GetChange(ctx, changeIDFrom(t, resp))
	if c.Title != "Upgrade openssl except kernel*, linux-*, reboot if required on web" {
		t.Fatalf("title: %q", c.Title)
	}
	// Policy allows patching only.
	_, body = h.do(admin, "GET", "/hosts/"+web.HostID+"/jobs", nil)
	if !strings.Contains(body, `service&#34; actions are turned off`) || !strings.Contains(body, "scripts are turned off") {
		t.Fatalf("jobs tab:\n%s", body)
	}
	if resp, body = h.do(admin, "POST", "/changes", url.Values{"action": {"service.stop"}, "host": {web.HostID}, "unit": {"x"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "allow_actions") {
		t.Fatalf("policy: %d", resp.StatusCode)
	}
	if resp, body = h.do(admin, "POST", "/changes", url.Values{"action": {"pkg.upgrade"}, "host": {web.HostID}, "mode": {"selected"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "pick at least one package") {
		t.Fatalf("validation: %d", resp.StatusCode)
	}
}

func TestScriptLibraryUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	web := h.addHost("web")
	h.connect(web, []string{"systemd"}, &action.Policy{Jobs: true, AllowScripts: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	admin := h.signIn("ann", "lab-admins")
	ops := h.signIn("carl", "ops")

	script := url.Values{"name": {"clean-logs"}, "description": {"Trims old logs"}, "interpreter": {"/bin/sh"}, "risk": {"low"},
		"params": {"days int required /[0-9]+/ # keep this many days\ndry bool"}, "body": {"#!/bin/sh\r\nfind /var/log -mtime +$1\r\n"}}
	if resp, _ := h.do(ops, "POST", "/scripts", script); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator wrote a script: %d", resp.StatusCode)
	}
	bad := url.Values{}
	for k, v := range script {
		bad[k] = v
	}
	bad.Set("params", "days integer")
	if resp, body := h.do(admin, "POST", "/scripts", bad); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "type must be") {
		t.Fatalf("bad params: %d", resp.StatusCode)
	}
	resp, _ := h.do(admin, "POST", "/scripts", script)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/scripts/") {
		t.Fatalf("create: %d %s", resp.StatusCode, loc)
	}
	scriptID := strings.TrimPrefix(strings.Split(loc, "?")[0], "/scripts/")
	v1, _ := h.st.GetScriptVersion(ctx, scriptID, 1)
	if v1.Body != "#!/bin/sh\nfind /var/log -mtime +$1\n" || len(v1.Params) != 2 || !v1.Params[0].Required {
		t.Fatalf("v1: %+v", v1)
	}
	_, body := h.do(ops, "GET", "/scripts/"+scriptID, nil)
	if !strings.Contains(body, "find /var/log") || !strings.Contains(body, v1.SHA256) || !strings.Contains(body, "Run…") ||
		strings.Contains(body, "New version") {
		t.Fatalf("script page:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/scripts/"+scriptID+"/edit", nil)
	if !strings.Contains(body, "Save version 2") || !strings.Contains(body, "days int required /[0-9]&#43;/ # keep this many days") {
		t.Fatalf("edit:\n%s", body)
	}

	// Running it: parameters come from the version.
	_, body = h.do(ops, "GET", "/changes/new?action=script.run&host="+web.HostID+"&script="+scriptID, nil)
	if !strings.Contains(body, `name="arg_days"`) || !strings.Contains(body, "keep this many days") {
		t.Fatalf("run form:\n%s", body)
	}
	run := url.Values{"action": {"script.run"}, "host": {web.HostID}, "script": {scriptID}, "version": {"1"}, "arg_days": {"x"}, "timeout_m": {"5"}}
	if resp, body = h.do(ops, "POST", "/changes", run); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "whole number") {
		t.Fatalf("bad arg: %d", resp.StatusCode)
	}
	run.Set("arg_days", "14")
	resp, _ = h.do(ops, "POST", "/changes", run)
	id := changeIDFrom(t, resp)
	h.st.ApproveChange(ctx, store.UserActor(mustUser(t, h, "ann"), ""), id, "")
	d.Pass(ctx)
	h.hub.mu.Lock()
	rj := h.hub.messages[len(h.hub.messages)-1].GetRunJob()
	h.hub.mu.Unlock()
	if rj == nil || rj.GetScript().GetSha256() != v1.SHA256 || string(rj.GetScript().GetBody()) != v1.Body ||
		strings.Join(rj.GetScript().GetArgs(), ",") != "14," || rj.GetScript().GetEnv()["BASELINE_PARAM_DAYS"] != "14" ||
		rj.GetTimeoutSeconds() != 300 {
		t.Fatalf("run job: %+v", rj)
	}

	// Archived scripts don't run.
	h.do(admin, "POST", "/scripts/"+scriptID+"/archive", url.Values{"archived": {"1"}})
	if resp, body = h.do(ops, "POST", "/changes", run); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "archived") {
		t.Fatalf("archived: %d", resp.StatusCode)
	}
	if _, body = h.do(ops, "GET", "/scripts", nil); !strings.Contains(body, "archived") {
		t.Fatalf("list:\n%s", body)
	}
}

func mustUser(t *testing.T, h *harness, sub string) string {
	t.Helper()
	var id string
	if err := h.st.DB().QueryRow(`SELECT id FROM app_user WHERE oidc_sub = $1`, sub).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

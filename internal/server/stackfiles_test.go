package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

const webCompose = "services:\n  web:\n    image: nginx:1.27\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n"

// noSecret fails the test if the audit log or a job's parameters hold s.
func (h *harness) noSecret(s string) {
	h.t.Helper()
	ctx := context.Background()
	entries, err := h.st.ListAudit(ctx, 0, 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(fmt.Sprint(e), s) {
			h.t.Fatalf("audit entry %s holds the secret: %v", e.Action, e)
		}
	}
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{Limit: 1000})
	for _, j := range jobs {
		if strings.Contains(string(j.Params), s) {
			h.t.Fatalf("job %s's parameters hold the secret: %s", j.ID, j.Params)
		}
	}
}

// changeOrJob is the change a new-change form redirected to, or the
// change of the job it redirected to.
func (h *harness) changeOrJob(resp *http.Response) string {
	h.t.Helper()
	if id, ok := strings.CutPrefix(resp.Header.Get("Location"), "/jobs/"); ok {
		j, err := h.st.GetJob(context.Background(), id)
		if err != nil {
			h.t.Fatal(err)
		}
		return j.ChangeID
	}
	return changeIDFrom(h.t, resp)
}

func TestComposeDeployAndEdit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	d.Secrets, _ = oidc.NewCookieCodec(h.cfg.SecretKey)
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	b := h.addHost("b", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles}, &action.Policy{Jobs: true})
	h.connect(b, []string{"docker", action.CapCompose}, &action.Policy{Jobs: true}) // an older agent
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	ops := h.signIn("carl", "media-ops", "approvers")
	viewer := h.signIn("vera", "viewers")
	admin := h.signIn("ann", "lab-admins")

	// Off until an admin turns it on, and only for agents that can.
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+a.HostID, nil); !strings.Contains(body, "Compose stack management is off") {
		t.Fatalf("deploy form on an unmanaged host:\n%s", body)
	}
	if resp, _ := h.do(ops, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an operator turned management on: %d", resp.StatusCode)
	}
	for _, x := range []store.EnrollResult{a, b} {
		if resp, _ := h.do(admin, "POST", "/hosts/"+x.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("turn on: %d", resp.StatusCode)
		}
	}
	if !strings.Contains(h.auditActions(), "host.manage_compose") {
		t.Fatal("not audited")
	}
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+b.HostID, nil); !strings.Contains(body, "can&#39;t do this: it needs compose-files") {
		t.Fatalf("deploy form for an old agent:\n%s", body)
	}
	_, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+a.HostID, nil)
	if !strings.Contains(body, `name="compose"`) || !strings.Contains(body, `name="env"`) {
		t.Fatalf("deploy form:\n%s", body)
	}
	if _, body := h.do(ops, "GET", "/changes/new", nil); strings.Contains(body, "compose.deploy") {
		t.Fatal("the general form offers deploys")
	}

	// Deploy: the .env is kept encrypted, and named but never shown.
	form := url.Values{"action": {"compose.deploy"}, "host": {a.HostID}, "engine": {"docker"}, "project": {"web"},
		"compose": {strings.ReplaceAll(webCompose, "\n", "\r\n")}, "env": {"DB_PASSWORD=hunter2\r\nTZ=UTC"}, "submit": {"approve"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("env", "DB_PASSWORD=x\nhunter3\n")
	if resp, body := h.do(ops, "POST", "/changes", bad); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "line 2 isn&#39;t KEY=VALUE") {
		t.Fatalf("bad .env: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	resp, body := h.do(ops, "POST", "/changes", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	cid := h.changeOrJob(resp)
	c, _ := h.st.GetChange(ctx, cid)
	if c.Title != "Deploy stack web on a" || c.Kind != store.KindNormal {
		t.Fatalf("change %q %s", c.Title, c.Kind)
	}
	revs, err := h.st.ChangeRevisions(ctx, cid)
	if err != nil || len(revs) != 1 {
		t.Fatalf("revisions %v %v", revs, err)
	}
	rev := revs[0]
	if !rev.HasCompose || rev.Compose != webCompose || rev.ComposeSHA256 != stackenv.SHA256([]byte(webCompose)) || !rev.HasEnv ||
		strings.Join(rev.EnvKeys, ",") != "DB_PASSWORD,TZ" || !strings.HasPrefix(rev.EnvHash, "hmac-sha256:") {
		t.Fatalf("revision %+v", rev)
	}
	if enc, _ := h.st.RevisionEnv(ctx, rev.ID); enc == "" || strings.Contains(enc, "hunter2") {
		t.Fatalf("stored .env %q", enc)
	}
	h.noSecret("hunter2")

	// The job carries the files.
	d.Pass(ctx)
	h.hub.mu.Lock()
	var files string
	for _, m := range h.hub.messages {
		if j := m.GetRunJob(); j != nil && j.GetAction() == action.ComposeDeploy {
			files = string(j.GetStackFiles().GetCompose()) + "|" + string(j.GetStackFiles().GetEnv())
			if strings.Contains(string(j.GetParamsJson()), "hunter2") {
				t.Error("the job's parameters hold the secret")
			}
		}
	}
	h.hub.mu.Unlock()
	if files != webCompose+"|DB_PASSWORD=hunter2\nTZ=UTC\n" {
		t.Fatalf("sent files %q", files)
	}

	// The change page names the variables; operators may look at them.
	_, body = h.do(viewer, "GET", "/changes/"+cid, nil)
	if !strings.Contains(body, "DB_PASSWORD, TZ") || strings.Contains(body, "hunter2") || strings.Contains(body, "Show values") {
		t.Fatalf("viewer's change page:\n%s", body)
	}
	if resp, body := h.do(viewer, "POST", "/stack-revisions/"+rev.ID+"/env", url.Values{}); resp.StatusCode != http.StatusForbidden ||
		strings.Contains(body, "hunter2") {
		t.Fatalf("a viewer saw the .env: %d", resp.StatusCode)
	}
	if _, body := h.do(ops, "GET", "/changes/"+cid, nil); !strings.Contains(body, "Show values") {
		t.Fatal("no way for an operator to see the values")
	}
	if _, body := h.do(ops, "POST", "/stack-revisions/"+rev.ID+"/env", url.Values{}); !strings.Contains(body, "DB_PASSWORD=hunter2") {
		t.Fatalf("operator's .env page:\n%s", body)
	}
	if !strings.Contains(h.auditActions(), "stack.env_view") {
		t.Fatal("looking at the .env wasn't audited")
	}

	// The deploy succeeds and the stack shows up.
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: cid})
	code := 0
	if _, err := h.st.FinishJob(ctx, store.System, a.HostID, jobs[0].ID, store.JobResult{State: store.JobSucceeded, ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	stacks := appStacks(digestOld, c.CreatedAt, "web")
	stacks.Stacks[0].ConfigFiles = []model.ComposeFile{{Path: "/var/lib/baseline/stacks/web/compose.yaml",
		SHA256: stackenv.SHA256([]byte(webCompose)), Size: int64(len(webCompose)),
		Content: strings.ReplaceAll(webCompose, "${DB_PASSWORD}", "********")}}
	h.ingest(a, model.SectionContainers, stacks)
	stack := h.stackIDs(a.HostID)["web"]

	// Editing starts from Baseline's copies, not inventory's masked one.
	_, body = h.do(ops, "GET", "/changes/new?action=compose.edit&stack="+stack, nil)
	if !strings.Contains(body, "${DB_PASSWORD}") || !strings.Contains(body, "DB_PASSWORD=hunter2") || strings.Contains(body, "masked as") {
		t.Fatalf("edit form:\n%s", body)
	}
	if _, body := h.do(ops, "GET", "/stacks/"+stack, nil); !strings.Contains(body, "Edit files") || !strings.Contains(body, "Files from Baseline") {
		t.Fatalf("stack page:\n%s", body)
	}
	edit := url.Values{"action": {"compose.edit"}, "stack": {stack}, "posted": {"1"}, "compose": {webCompose},
		"change_compose": {"1"}, "change_env": {"1"}, "env": {"DB_PASSWORD=hunter2\nTZ=UTC\n"}, "submit": {"approve"}}
	if resp, body := h.do(ops, "POST", "/changes", edit); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Nothing changed") {
		t.Fatalf("empty edit: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	edit.Set("env", "DB_PASSWORD=correct-horse\nTZ=UTC\n")
	resp, body = h.do(ops, "POST", "/changes", edit)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	cid2 := h.changeOrJob(resp)
	revs, _ = h.st.ChangeRevisions(ctx, cid2)
	if len(revs) != 1 || revs[0].HasCompose || !revs[0].HasEnv || revs[0].EnvHash == rev.EnvHash {
		t.Fatalf("edit revision %+v", revs)
	}
	c2, _ := h.st.GetChange(ctx, cid2)
	if c2.Title != "Edit the .env of stack web on a" || !strings.Contains(string(c2.Plan[0].Params), `"env": true`) {
		t.Fatalf("edit change %q %s", c2.Title, c2.Plan[0].Params)
	}
	h.noSecret("correct-horse")

	// While it is open, the stack can't be edited again.
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.edit&stack="+stack, nil); !strings.Contains(body, c2.Ref()+" deploys or edits it already") {
		t.Fatalf("second edit:\n%s", body)
	}
}

func TestComposeRoots(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	b := h.addHost("b", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles, action.CapComposeRoots}, &action.Policy{Jobs: true})
	h.connect(b, []string{"docker", action.CapCompose, action.CapComposeFiles}, &action.Policy{Jobs: true}) // no roots yet
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	admin := h.signIn("ann", "lab-admins")
	roots := func(x store.EnrollResult) string {
		t.Helper()
		got, err := h.st.GetHost(ctx, x.HostID)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(got.ComposeRoots, " ")
	}

	// Roots come with Compose management, and only admins keep them.
	if resp, _ := h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/srv/stacks"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("root on an unmanaged host: %d", resp.StatusCode)
	}
	for _, x := range []store.EnrollResult{a, b} {
		h.do(admin, "POST", "/hosts/"+x.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})
	}
	if resp, _ := h.do(ops, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/srv/stacks"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an operator added a root: %d", resp.StatusCode)
	}
	for _, bad := range []string{"srv", "/", "/etc/stacks", "/usr", "/srv/../etc", "/srv//x"} {
		if resp, _ := h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {bad}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("root %q: %d", bad, resp.StatusCode)
		}
	}
	for _, r := range []string{"/srv/stacks/", "/opt/compose", "/srv/stacks"} {
		if resp, _ := h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {r}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("add %s: %d", r, resp.StatusCode)
		}
	}
	h.do(admin, "POST", "/hosts/"+b.HostID+"/compose-roots", url.Values{"root": {"/srv/stacks"}})
	if got := roots(a); got != "/srv/stacks /opt/compose" {
		t.Fatalf("roots %q", got)
	}
	if !strings.Contains(h.auditActions(), "host.compose_root_add") {
		t.Fatal("not audited")
	}
	if _, body := h.do(ops, "GET", "/hosts/"+a.HostID+"?tab=settings", nil); !strings.Contains(body, "<code>/opt/compose</code>") || strings.Contains(body, `name="root"`) {
		t.Fatalf("settings tab for an operator:\n%s", body)
	}

	// The deploy form offers them, and the change names the one picked.
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+a.HostID, nil); !strings.Contains(body, `<option>/opt/compose</option>`) {
		t.Fatalf("deploy form:\n%s", body)
	}
	form := url.Values{"action": {"compose.deploy"}, "host": {a.HostID}, "engine": {"docker"}, "project": {"web"},
		"compose": {webCompose}, "root": {"/tmp"}}
	if resp, body := h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick one of a&#39;s Compose roots") {
		t.Fatalf("deploy to another directory: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	form.Set("root", "/opt/compose")
	resp, body := h.do(ops, "POST", "/changes", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, err := h.st.GetChange(ctx, changeIDFrom(t, resp))
	steps := c.Plan
	if err != nil || len(steps) != 1 || !strings.Contains(string(steps[0].Params), `"root": "/opt/compose"`) ||
		steps[0].Summary != "Deploy stack web to /opt/compose/web" {
		t.Fatalf("steps %+v %v", steps, err)
	}
	// An agent that can't take a root yet is told to update.
	form.Set("host", b.HostID)
	form.Set("root", "/srv/stacks")
	if resp, body := h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "update it first") {
		t.Fatalf("deploy with an old agent: %d", resp.StatusCode)
	}

	// Removing one leaves the rest in order.
	if resp, _ := h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"remove": {"/srv/stacks"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("remove: %d", resp.StatusCode)
	}
	if got := roots(a); got != "/opt/compose" {
		t.Fatalf("roots after remove %q", got)
	}
}

func TestStoppedStacks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles, action.CapComposeRoots, action.CapComposeStart},
		&action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	admin := h.signIn("ann", "lab-admins")

	// The agent is told its roots while management is on, and only then.
	h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/srv/stacks"}}) // refused: off
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})
	h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/opt/stacks"}})
	if got := h.hub.configured[a.AgentID].ComposeRoots; !slices.Equal(got, []string{"/opt/stacks"}) {
		t.Fatalf("agent told roots %v", got)
	}
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"0"}})
	if got := h.hub.configured[a.AgentID].ComposeRoots; len(got) != 0 {
		t.Fatalf("agent still told roots %v with management off", got)
	}
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})

	// The agent reports a stack on disk that nothing runs from.
	h.ingest(a, model.SectionContainers, model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Socket: "/var/run/docker.sock"}},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "app", WorkingDir: "/opt/stacks/app", Services: []string{"web"},
			CLI: "docker compose", Stopped: true, ConfigFiles: []model.ComposeFile{{Path: "/opt/stacks/app/compose.yaml",
				SHA256: stackenv.SHA256([]byte(webCompose)), Content: webCompose}}}},
	})
	stack := h.stackIDs(a.HostID)["app"]
	st, err := h.st.GetStack(ctx, stack)
	if err != nil || !st.Stopped || !st.Present {
		t.Fatalf("stack %+v %v", st, err)
	}
	_, body := h.do(ops, "GET", "/stacks/"+stack, nil)
	if !strings.Contains(body, "Not running") || !strings.Contains(body, "action=compose.start") || !strings.Contains(body, "Edit files") ||
		strings.Contains(body, "action=compose.update") {
		t.Fatalf("stack page:\n%s", body)
	}
	if _, body := h.do(ops, "GET", "/stacks", nil); !strings.Contains(body, "not running") {
		t.Fatalf("stack list lacks the flag:\n%s", body)
	}

	// It can't be updated, only started.
	if resp, body := h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}, "stack": {stack}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "start it first") {
		t.Fatalf("update of a stopped stack: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	resp, body := h.do(ops, "POST", "/changes", url.Values{"action": {"compose.start"}, "stack": {stack}, "health_timeout": {"60"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("start: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, _ := h.st.GetChange(ctx, h.changeOrJob(resp))
	if c.Title != "Start stack app on a" || len(c.Plan) != 1 || !strings.Contains(string(c.Plan[0].Params), `"health_timeout": 60`) {
		t.Fatalf("change %q %+v", c.Title, c.Plan)
	}
}

func TestRootlessStacks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	caps := []string{"podman", action.CapCompose, action.CapComposeFiles, action.CapComposeRoots, action.CapComposeStart}
	a := h.addHost("a", media.ID)
	b := h.addHost("b", media.ID)
	h.connect(a, append(caps, action.CapComposeRootless), &action.Policy{Jobs: true})
	h.connect(b, caps, &action.Policy{Jobs: true}) // an older agent
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	admin := h.signIn("ann", "lab-admins")
	stacks := map[string]string{}
	for _, x := range []store.EnrollResult{a, b} {
		h.do(admin, "POST", "/hosts/"+x.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})
		h.do(admin, "POST", "/hosts/"+x.HostID+"/compose-roots", url.Values{"root": {"/home/alice/stacks"}})
		h.ingest(x, model.SectionContainers, model.Containers{
			Engines: []model.ContainerEngine{{Name: "podman", Kind: "podman", Socket: "/run/podman/podman.sock"},
				{Name: "podman:alice", Kind: "podman", Socket: "/run/user/1000/podman/podman.sock"},
				{Name: "podman:bob", Kind: "podman", Socket: "/run/user/1001/podman/podman.sock", Error: "connection refused"}},
			Stacks: []model.ComposeStack{{Engine: "podman:alice", Project: "app", WorkingDir: "/home/alice/stacks/app", Services: []string{"web"},
				CLI: "podman-compose", Stopped: true, ConfigFiles: []model.ComposeFile{{Path: "/home/alice/stacks/app/compose.yaml",
					SHA256: stackenv.SHA256([]byte(webCompose)), Content: webCompose}}}},
		})
		stacks[x.HostID] = h.stackIDs(x.HostID)["app"]
	}

	// Deploys can pick the rootless engines that can be read.
	_, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+a.HostID, nil)
	if !strings.Contains(body, "<option>podman:alice</option>") || strings.Contains(body, "podman:bob") {
		t.Fatalf("deploy form engines:\n%s", regexp.MustCompile(`<select name="engine">.*?</select>`).FindString(body))
	}
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.deploy&host="+b.HostID, nil); strings.Contains(body, "podman:alice") {
		t.Fatal("an older agent's deploy form offers a rootless engine")
	}
	form := url.Values{"action": {"compose.deploy"}, "host": {b.HostID}, "engine": {"podman:alice"}, "project": {"web"},
		"root": {"/home/alice/stacks"}, "compose": {webCompose}}
	if resp, body := h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "no podman:alice engine Baseline can deploy to") {
		t.Fatalf("rootless deploy on an older agent: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	form.Set("host", a.HostID)
	if resp, body := h.do(ops, "POST", "/changes", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rootless deploy: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}

	// Edits too, on agents that write rootless stacks' files.
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.edit&stack="+stacks[a.HostID], nil); !strings.Contains(body, `name="compose"`) ||
		strings.Contains(body, "rootless") {
		t.Fatalf("rootless edit form:\n%s", body)
	}
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.edit&stack="+stacks[b.HostID], nil); !strings.Contains(body, "can&#39;t edit rootless Podman stacks yet; update it first") {
		t.Fatalf("rootless edit form on an older agent:\n%s", body)
	}
}

func TestArchiveAndMoveStacks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles, action.CapComposeRoots, action.CapComposeStart,
		action.CapComposeArchive}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	admin := h.signIn("ann", "lab-admins")
	h.ingest(a, model.SectionContainers, model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Socket: "/var/run/docker.sock"}},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "app", WorkingDir: "/opt/stacks/app", Services: []string{"web"},
			CLI: "docker compose", Stopped: true, ConfigFiles: []model.ComposeFile{{Path: "/opt/stacks/app/compose.yaml",
				SHA256: stackenv.SHA256([]byte(webCompose)), Content: webCompose}}}},
	})
	stack := h.stackIDs(a.HostID)["app"]
	notice := func(body string) string { return regexp.MustCompile(`notice bad">[^<]*`).FindString(body) }
	post := func(form url.Values) (*http.Response, string) {
		form.Set("stack", stack)
		return h.do(ops, "POST", "/changes", form)
	}

	// Both need Compose stack management on the host.
	if _, body := h.do(ops, "GET", "/stacks/"+stack, nil); strings.Contains(body, "action=compose.archive") {
		t.Fatal("archive offered with management off")
	}
	if resp, body := post(url.Values{"action": {"compose.archive"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "management is off") {
		t.Fatalf("archive with management off: %d %s", resp.StatusCode, notice(body))
	}
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})
	_, body := h.do(ops, "GET", "/stacks/"+stack, nil)
	if !strings.Contains(body, "action=compose.archive") || strings.Contains(body, "action=compose.move") {
		t.Fatalf("stack page without roots:\n%s", body)
	}
	if resp, body := post(url.Values{"action": {"compose.move"}, "dest": {"/srv/stacks"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "no Compose roots") {
		t.Fatalf("move without roots: %d %s", resp.StatusCode, notice(body))
	}

	// A move goes under one of the host's roots.
	h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/opt/stacks"}})
	h.do(admin, "POST", "/hosts/"+a.HostID+"/compose-roots", url.Values{"root": {"/srv/stacks"}})
	if _, body := h.do(ops, "GET", "/stacks/"+stack, nil); !strings.Contains(body, "action=compose.move") {
		t.Fatal("move not offered")
	}
	if _, body := h.do(ops, "GET", "/changes/new?action=compose.move&stack="+stack, nil); !strings.Contains(body, "<option>/srv/stacks</option>") {
		t.Fatalf("move form lacks the roots:\n%s", body)
	}
	if resp, body := post(url.Values{"action": {"compose.move"}, "dest": {"/elsewhere"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "isn&#39;t one of a&#39;s Compose roots") {
		t.Fatalf("move elsewhere: %d %s", resp.StatusCode, notice(body))
	}
	resp, body := post(url.Values{"action": {"compose.move"}, "dest": {"/srv/stacks"}, "health_timeout": {"60"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("move: %d %s", resp.StatusCode, notice(body))
	}
	c, _ := h.st.GetChange(ctx, h.changeOrJob(resp))
	if c.Title != "Move stack app to /srv/stacks/app on a" || len(c.Plan) != 1 || !strings.Contains(string(c.Plan[0].Params), `"dest": "/srv/stacks"`) {
		t.Fatalf("move change %q %s", c.Title, c.Plan[0].Params)
	}

	resp, body = post(url.Values{"action": {"compose.archive"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("archive: %d %s", resp.StatusCode, notice(body))
	}
	if c, _ := h.st.GetChange(ctx, h.changeOrJob(resp)); c.Title != "Archive stack app on a" {
		t.Fatalf("archive change %q", c.Title)
	}

	// And through the API.
	ot := h.mintToken(ops, "deploy", "operator")
	var e map[string]string
	if resp := h.api(ot, "POST", "/changes", map[string]any{"action": "compose.move", "stacks": []string{stack},
		"params": map[string]any{"dest": "/elsewhere"}}, &e); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(e["error"], "Compose roots") {
		t.Fatalf("API move elsewhere: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ot, "POST", "/changes", map[string]any{"action": "compose.archive", "stacks": []string{stack}}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("API archive: %d", resp.StatusCode)
	}
}

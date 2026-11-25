package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestEditDeployFiles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	d.Secrets, _ = oidc.NewCookieCodec(h.cfg.SecretKey)
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	ops := h.signIn("carl", "media-ops")
	appr := h.signIn("dee", "approvers")
	admin := h.signIn("ann", "lab-admins")
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", url.Values{"manage_compose": {"1"}})
	notice := regexp.MustCompile(`notice bad">[^<]*`)

	form := url.Values{"action": {"compose.deploy"}, "host": {a.HostID}, "engine": {"docker"}, "project": {"web"},
		"compose": {webCompose}, "env": {"DB_PASSWORD=hunter2\nTZ=UTC\n"}}
	resp, body := h.do(ops, "POST", "/changes", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", resp.StatusCode, notice.FindString(body))
	}
	cid := changeIDFrom(t, resp)
	h.do(appr, "POST", "/changes/"+cid+"/decide", url.Values{"decision": {"approve"}})
	// Approved, and not started until the scheduler's next pass.
	c, _ := h.st.GetChange(ctx, cid)
	if c.State != store.ChangeApproved {
		t.Fatalf("state %s", c.State)
	}
	revs, _ := h.st.ChangeRevisions(ctx, cid)
	rev := revs[0]

	// The change page links to editing the files; the form starts from them.
	if _, body := h.do(ops, "GET", "/changes/"+cid, nil); !strings.Contains(body, "/edit#files") {
		t.Fatalf("no files edit link:\n%s", body)
	}
	_, body = h.do(ops, "GET", "/changes/"+cid+"/edit", nil)
	if !strings.Contains(body, `name="compose"`) || !strings.Contains(body, "${DB_PASSWORD}") || !strings.Contains(body, "DB_PASSWORD=hunter2") ||
		!strings.Contains(body, "stack files or rollout withdraws them") {
		t.Fatalf("edit form:\n%s", body)
	}
	// An approver who isn't an operator of the host sees no files to edit.
	if _, body := h.do(appr, "GET", "/changes/"+cid+"/edit", nil); strings.Contains(body, "hunter2") ||
		!strings.Contains(body, "needs the operator role") {
		t.Fatalf("approver's edit form:\n%s", body)
	}
	editForm := func() url.Values {
		f := h.srv.editForm(c)
		f.Set("files", "1")
		f.Set("compose", webCompose)
		f.Set("env", "DB_PASSWORD=hunter2\nTZ=UTC\n")
		return f
	}

	// The same files change nothing.
	if resp, _ := h.do(ops, "POST", "/changes/"+cid+"/edit", editForm()); resp.StatusCode != http.StatusSeeOther ||
		!strings.Contains(resp.Header.Get("Location"), "Nothing+changed") {
		t.Fatalf("no-op edit: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// An approver can't post files either.
	if resp, body := h.do(appr, "POST", "/changes/"+cid+"/edit", editForm()); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "needs the operator role") {
		t.Fatalf("approver's files edit: %d %s", resp.StatusCode, notice.FindString(body))
	}
	// A bad .env is refused, without quoting it.
	f := editForm()
	f.Set("env", "DB_PASSWORD=x\nhunter3\n")
	if resp, body := h.do(ops, "POST", "/changes/"+cid+"/edit", f); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "line 2 isn&#39;t KEY=VALUE") {
		t.Fatalf("bad .env: %d %s", resp.StatusCode, notice.FindString(body))
	}

	// Editing both files withdraws the approval and replaces what the job
	// will write.
	newCompose := strings.Replace(webCompose, "nginx:1.27", "nginx:1.28", 1)
	f = editForm()
	f.Set("compose", strings.ReplaceAll(newCompose, "\n", "\r\n"))
	f.Set("env", "DB_PASSWORD=correct-horse\r\nLOG=debug")
	resp, body = h.do(ops, "POST", "/changes/"+cid+"/edit", f)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("files edit: %d %s", resp.StatusCode, notice.FindString(body))
	}
	if loc, _ := url.QueryUnescape(resp.Header.Get("Location")); !strings.Contains(loc, "approval was withdrawn") {
		t.Fatalf("notice %s", loc)
	}
	c, _ = h.st.GetChange(ctx, cid)
	if c.State != store.ChangeSubmitted {
		t.Fatalf("after the edit: %s", c.State)
	}
	revs, _ = h.st.ChangeRevisions(ctx, cid)
	if len(revs) != 1 || revs[0].ID != rev.ID || revs[0].Compose != newCompose ||
		revs[0].ComposeSHA256 != stackenv.SHA256([]byte(newCompose)) || strings.Join(revs[0].EnvKeys, ",") != "DB_PASSWORD,LOG" ||
		revs[0].EnvHash == rev.EnvHash {
		t.Fatalf("revision after the edit %+v", revs)
	}
	var p action.StackFileParams
	json.Unmarshal(c.Plan[0].Params, &p)
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: cid})
	var jp action.StackFileParams
	json.Unmarshal(jobs[0].Params, &jp)
	if p.ComposeSHA256 != revs[0].ComposeSHA256 || jp.ComposeSHA256 != p.ComposeSHA256 || !jp.Env {
		t.Fatalf("plan %s job %s", c.Plan[0].Params, jobs[0].Params)
	}
	h.noSecret("correct-horse")
	h.noSecret("hunter2")

	// The history names what changed, never a value.
	_, body = h.do(ops, "GET", "/changes/"+cid, nil)
	for _, want := range []string{"Compose file: sha256 " + rev.ComposeSHA256[:12], "1 line added, 1 line removed",
		".env: added LOG; new value for DB_PASSWORD; removed TZ", "1 approval withdrawn"} {
		if !strings.Contains(body, want) {
			t.Fatalf("history lacks %q:\n%s", want, body)
		}
	}

	// Through the API: an empty env writes no .env.
	var e map[string]any
	if resp := h.api(h.mintToken(ops, "t", "operator"), "PATCH", "/changes/"+cid, map[string]any{"env": ""}, &e); resp.StatusCode != http.StatusOK {
		t.Fatalf("api edit: %d %v", resp.StatusCode, e)
	}
	revs, _ = h.st.ChangeRevisions(ctx, cid)
	jobs, _ = h.st.ListJobs(ctx, store.JobFilter{ChangeID: cid})
	if revs[0].HasEnv || len(revs[0].EnvKeys) != 0 || strings.Contains(string(jobs[0].Params), `"env"`) {
		t.Fatalf("after dropping the .env: %+v %s", revs[0], jobs[0].Params)
	}
	if resp := h.api(h.mintToken(appr, "t", "approver"), "PATCH", "/changes/"+cid, map[string]any{"compose": webCompose}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("approver's api files edit: %d %v", resp.StatusCode, e)
	}

	// Approved again, it runs with the edited files.
	h.do(appr, "POST", "/changes/"+cid+"/decide", url.Values{"decision": {"approve"}})
	d.Pass(ctx)
	h.hub.mu.Lock()
	var sent string
	for _, m := range h.hub.messages {
		if j := m.GetRunJob(); j != nil && j.GetAction() == action.ComposeDeploy {
			sent = string(j.GetStackFiles().GetCompose()) + "|" + string(j.GetStackFiles().GetEnv())
		}
	}
	h.hub.mu.Unlock()
	if sent != newCompose+"|" {
		t.Fatalf("sent files %q", sent)
	}
	// Once it has started, its files are fixed.
	f = editForm()
	if resp, _ := h.do(ops, "POST", "/changes/"+cid+"/edit", f); resp.StatusCode != http.StatusSeeOther ||
		!strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("edit after start: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

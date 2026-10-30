package server

import (
	"context"
	"encoding/json"
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

var reAPIToken = regexp.MustCompile(`baseline_api_[A-Za-z0-9_-]{43}`)

// mintToken creates an API token through the "Your access" page, as a
// user would, and returns its secret.
func (h *harness) mintToken(c *http.Client, name string, roles ...string) string {
	h.t.Helper()
	form := url.Values{"name": {name}, "lifetime": {"720h"}, "role": roles}
	resp, body := h.do(c, "POST", "/me/tokens", form)
	secret := reAPIToken.FindString(body)
	if resp.StatusCode != 200 || secret == "" || !strings.Contains(body, "shown only once") {
		h.t.Fatalf("mint %s: %d\n%s", name, resp.StatusCode, body)
	}
	return secret
}

// api calls the JSON API with a token and decodes the response into out.
func (h *harness) api(token, method, path string, in any, out any) *http.Response {
	h.t.Helper()
	var body string
	if in != nil {
		b, _ := json.Marshal(in)
		body = string(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+apiPrefix+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		h.t.Fatalf("%s %s: content type %q", method, path, ct)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			h.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp
}

func TestAPITokensAndAuth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.signIn("ann", "lab-admins")

	// Unauthenticated and bad tokens are JSON 401s, not redirects to login.
	var e map[string]string
	if resp := h.api("", "GET", "/hosts", nil, &e); resp.StatusCode != http.StatusUnauthorized || e["error"] == "" ||
		!strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no token: %d %v", resp.StatusCode, e)
	}
	if resp := h.api("baseline_api_nope", "GET", "/hosts", nil, &e); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	if resp := h.api("", "GET", "/nothing", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown endpoint: %d", resp.StatusCode)
	}

	// The page lists the roles the user may give a token; a role they don't
	// hold, or none, is refused.
	_, body := h.do(admin, "GET", "/me", nil)
	for _, r := range rbac.Roles {
		if !strings.Contains(body, `value="`+string(r)+`"`) {
			t.Fatalf("admin's role choices:\n%s", body)
		}
	}
	if resp, body := h.do(admin, "POST", "/me/tokens", url.Values{"name": {"x"}, "lifetime": {"720h"}}); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "at least one role") {
		t.Fatalf("no roles: %d", resp.StatusCode)
	}
	tok := h.mintToken(admin, "ci", "viewer", "admin")

	var me meJSON
	if resp := h.api(tok, "GET", "/me", nil, &me); resp.StatusCode != 200 || me.User.Name != "ANN" || me.Token.Name != "ci" ||
		len(me.Token.Roles) != 2 || me.Token.ExpiresAt == nil || !strings.Contains(strings.Join(me.Groups, ","), "lab-admins") {
		t.Fatalf("/me: %d %+v", resp.StatusCode, me)
	}
	if got := h.auditActions(); !strings.HasSuffix(got, "api_token.create") {
		t.Fatalf("audit: %s", got)
	}

	// A token limited to viewer is a global viewer, whatever its user is.
	ro := h.mintToken(admin, "read-only", "viewer")
	if resp := h.api(ro, "GET", "/me", nil, &me); resp.StatusCode != 200 || len(me.Global) != 1 || me.Global[0] != rbac.Viewer {
		t.Fatalf("viewer token: %d %+v", resp.StatusCode, me.Global)
	}
	if resp := h.api(ro, "POST", "/changes", map[string]any{"action": "host.reboot"}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer token creating a change: %d %v", resp.StatusCode, e)
	}
	// The audit log needs a global viewer; a viewer token of an admin has it.
	var audit []auditJSON
	if resp := h.api(ro, "GET", "/audit?limit=5", nil, &audit); resp.StatusCode != 200 || len(audit) < 3 || audit[0].Hash == "" || audit[0].Action != "api_token.create" {
		t.Fatalf("audit via token: %d %d", resp.StatusCode, len(audit))
	}

	// Revoking ends it; the UI shows it revoked and refuses a second revoke.
	tokens, err := h.st.ListAPITokens(ctx, me.User.ID)
	if err != nil || len(tokens) != 2 {
		t.Fatal(err, len(tokens))
	}
	var roID string
	for _, tk := range tokens {
		if tk.Name == "read-only" {
			roID = tk.ID
		}
	}
	if resp, _ := h.do(admin, "POST", "/me/tokens/"+roID+"/revoke", url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp := h.api(ro, "GET", "/me", nil, &e); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "POST", "/me/tokens/"+roID+"/revoke", url.Values{}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("second revoke: %s", resp.Header.Get("Location"))
	}
	if _, body := h.do(admin, "GET", "/me", nil); !strings.Contains(body, "revoked") {
		t.Fatalf("token list:\n%s", body)
	}
	// Another user can't revoke it.
	bob := h.signIn("bob", "lab-admins")
	tokens, _ = h.st.ListAPITokens(ctx, me.User.ID)
	if resp, _ := h.do(bob, "POST", "/me/tokens/"+tokens[0].ID+"/revoke", url.Values{}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bob revoked ann's token: %s", resp.Header.Get("Location"))
	}

	// An expired token stops working; one the store can't find is a 401.
	_, expired, err := h.st.NewAPIToken(ctx, store.System, me.User.ID, "old", []rbac.Role{rbac.Viewer}, []string{"lab-admins"},
		time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.api(expired, "GET", "/me", nil, &e); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", resp.StatusCode)
	}

	// Bindings apply live: a token keeps its groups, so taking the group's
	// binding away takes the token's access away too.
	viewerOnly := h.signIn("vic", "viewers")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	vt := h.mintToken(viewerOnly, "vic", "viewer")
	var any_ any
	if resp := h.api(vt, "GET", "/hosts", nil, &any_); resp.StatusCode != 200 {
		t.Fatalf("vic's token: %d", resp.StatusCode)
	}
	bindings, _ := h.st.ListRoleBindings(ctx)
	for _, b := range bindings {
		if b.IdPGroup == "viewers" {
			h.st.DeleteRoleBinding(ctx, store.System, b.ID)
		}
	}
	if resp := h.api(vt, "GET", "/hosts", nil, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("vic's token after unbinding: %d %v", resp.StatusCode, e)
	}
	if got := h.auditActions(); !strings.Contains(got, "api_token.revoke") {
		t.Fatalf("audit: %s", got)
	}
}

func TestAPIReadsFollowVisibility(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.connect(plex, []string{"systemd", "apt"}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})

	admin := h.signIn("ann", "lab-admins")
	at := h.mintToken(admin, "all", "admin")
	ops := h.signIn("carl", "media-ops")
	ot := h.mintToken(ops, "media", "operator")

	var hosts []hostJSON
	if resp := h.api(at, "GET", "/hosts", nil, &hosts); resp.StatusCode != 200 || len(hosts) != 2 {
		t.Fatalf("admin hosts: %d %d", resp.StatusCode, len(hosts))
	}
	if resp := h.api(ot, "GET", "/hosts", nil, &hosts); resp.StatusCode != 200 || len(hosts) != 1 || hosts[0].Hostname != "plex" ||
		len(hosts[0].Groups) != 1 || hosts[0].Groups[0].Name != "media" || !hosts[0].Connected || hosts[0].LastSeen == nil {
		t.Fatalf("scoped hosts: %d %+v", resp.StatusCode, hosts)
	}
	var e map[string]string
	// A host outside the scope doesn't exist, as far as the token knows.
	if resp := h.api(ot, "GET", "/hosts/"+dns.HostID, nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("out-of-scope host: %d", resp.StatusCode)
	}
	var sec sectionJSON
	if resp := h.api(ot, "GET", "/hosts/"+plex.HostID+"/sections/os", nil, &sec); resp.StatusCode != 200 || sec.CollectedAt == nil ||
		!strings.Contains(string(sec.Data), "Blue Onyx") {
		t.Fatalf("os section: %d %s", resp.StatusCode, sec.Data)
	}
	if resp := h.api(ot, "GET", "/hosts/"+plex.HostID+"/sections/certs", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unreported section: %d", resp.StatusCode)
	}
	if resp := h.api(ot, "GET", "/hosts/"+plex.HostID+"/sections/bogus", nil, &e); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown section: %d", resp.StatusCode)
	}
	var sections []sectionJSON
	if resp := h.api(ot, "GET", "/hosts/"+plex.HostID+"/sections", nil, &sections); resp.StatusCode != 200 || len(sections) != 3 {
		t.Fatalf("sections: %d %d", resp.StatusCode, len(sections))
	}
	var pkgs []map[string]any
	if resp := h.api(ot, "GET", "/hosts/"+plex.HostID+"/packages?q=openssl", nil, &pkgs); resp.StatusCode != 200 || len(pkgs) != 1 ||
		pkgs[0]["name"] != "openssl" {
		t.Fatalf("packages: %d %v", resp.StatusCode, pkgs)
	}
	var cis []ciJSON
	if resp := h.api(ot, "GET", "/cis?type=host", nil, &cis); resp.StatusCode != 200 || len(cis) != 1 || cis[0].Name != "plex" {
		t.Fatalf("cis: %d %+v", resp.StatusCode, cis)
	}
	var dash dashboardJSON
	if resp := h.api(ot, "GET", "/dashboard", nil, &dash); resp.StatusCode != 200 || dash.Fleet.Total != 1 || dash.Fleet.Online != 1 {
		t.Fatalf("dashboard: %d %+v", resp.StatusCode, dash.Fleet)
	}
	if resp := h.api(at, "GET", "/dashboard", nil, &dash); resp.StatusCode != 200 || dash.Fleet.Total != 2 || dash.Fleet.Offline != 1 {
		t.Fatalf("admin dashboard: %d %+v", resp.StatusCode, dash.Fleet)
	}
	// Scoped users can't read the audit log; everything else that is global
	// (actions, groups, windows, scripts, change models) is readable.
	if resp := h.api(ot, "GET", "/audit", nil, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped audit: %d", resp.StatusCode)
	}
	for _, path := range []string{"/actions", "/host-groups", "/windows", "/scripts", "/change-models", "/patch-groups",
		"/alert-rules", "/alerts", "/silences", "/vulnerabilities", "/vulnerability-sources", "/updates", "/containers",
		"/stacks", "/vms", "/kubernetes", "/ci-types", "/jobs", "/changes", "/calendar", "/map",
		"/hosts/" + plex.HostID + "/metrics", "/hosts/" + plex.HostID + "/metrics/cpu", "/hosts/" + plex.HostID + "/history",
		"/hosts/" + plex.HostID + "/updates", "/hosts/" + plex.HostID + "/certificates", "/hosts/" + plex.HostID + "/jobs",
		"/hosts/" + plex.HostID + "/changes", "/hosts/" + plex.HostID + "/vulnerabilities", "/hosts/" + plex.HostID + "/alerts",
		"/cis/" + plex.HostID, "/cis/" + plex.HostID + "/relationships", "/cis/" + plex.HostID + "/history"} {
		var v any
		if resp := h.api(ot, "GET", path, nil, &v); resp.StatusCode != 200 {
			t.Errorf("GET %s: %d %v", path, resp.StatusCode, v)
		} else if b, _ := json.Marshal(v); strings.Contains(string(b), "0001-01-01") {
			t.Errorf("GET %s: a zero time leaked: %s", path, b)
		}
	}
	var acts []actionJSON
	h.api(ot, "GET", "/actions", nil, &acts)
	if len(acts) != len(action.Names) || acts[0].Name != action.PkgUpgrade {
		t.Fatalf("actions: %+v", acts)
	}
}

func TestAPICreatesAndSubmitsChanges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.dispatcher()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.connect(plex, []string{"systemd", "apt"}, &action.Policy{Jobs: true, AllowScripts: true})
	h.connect(dns, []string{"systemd", "apt"}, nil) // an agent from before jobs
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})

	ops := h.signIn("carl", "media-ops")
	ot := h.mintToken(ops, "deploy", "operator")
	admin := h.signIn("ann", "lab-admins")
	at := h.mintToken(admin, "root", "admin")

	var e map[string]string
	type detail struct {
		changeJSON
		Approvals []approvalJSON `json:"approvals"`
		Jobs      []jobJSON      `json:"jobs"`
	}
	var c detail

	// Bad requests say what is wrong.
	for _, tc := range []struct {
		in   any
		want string
	}{
		{map[string]any{"action": "service.restart"}, "at least one host"},
		{map[string]any{"action": "nope", "hosts": []string{plex.HostID}}, "pick an action"},
		{map[string]any{"action": "service.restart", "hosts": []string{plex.HostID}, "params": map[string]any{"unit": "-x"}}, "unit"},
		{map[string]any{"action": "service.restart", "hosts": []string{dns.HostID}, "params": map[string]any{"unit": "nginx"}}, "operator role"},
		{map[string]any{"action": "service.restart", "hosts": []string{plex.HostID}, "params": map[string]any{"unit": "nginx"}, "kind": "huge"}, "kind must be"},
		{map[string]any{"action": "service.restart", "hosts": []string{plex.HostID}, "params": map[string]any{"unit": "nginx"}, "risk": "scary"}, "risk must be"},
		{map[string]any{"action": "service.restart", "hosts": []string{plex.HostID}, "params": map[string]any{"unit": "nginx"}, "window": "none"}, "maintenance window"},
		{map[string]any{"action": "compose.pull", "hosts": []string{plex.HostID}}, "Compose stack"},
		{map[string]any{"action": "service.restart", "hosts": []string{plex.HostID}, "bogus": 1}, "bad JSON"},
	} {
		resp := h.api(ot, "POST", "/changes", tc.in, &e)
		if (resp.StatusCode != http.StatusUnprocessableEntity && resp.StatusCode != http.StatusBadRequest) || !strings.Contains(e["error"], tc.want) {
			t.Errorf("%v: %d %q, want %q", tc.in, resp.StatusCode, e["error"], tc.want)
		}
	}
	// The admin's token can't run on dns1 either: its agent runs no jobs.
	if resp := h.api(at, "POST", "/changes", map[string]any{"action": "service.restart", "hosts": []string{dns.HostID},
		"params": map[string]any{"unit": "nginx"}}, &e); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(e["error"], "too old") {
		t.Fatalf("old agent: %d %v", resp.StatusCode, e)
	}

	// A good request creates a submitted change; there's no way to approve it.
	resp := h.api(ot, "POST", "/changes", map[string]any{
		"action": "service.restart", "hosts": []string{plex.HostID}, "params": map[string]any{"unit": "nginx"},
		"justification": "stuck", "backout_plan": "start it again", "stop_on_failure": false, "required_approvals": 2,
	}, &c)
	if resp.StatusCode != http.StatusCreated || c.State != store.ChangeSubmitted || c.Title != "Restart nginx.service on plex" ||
		c.Justification != "stuck" || c.Risk != "low" || c.StopOnFailure || c.RequiredApprovals != 2 || c.Ref == "" ||
		len(c.Hosts) != 1 || c.Hosts[0].Name != "plex" || c.SubmittedAt == nil || c.ApprovedAt != nil ||
		!strings.HasSuffix(resp.Header.Get("Location"), "/api/v1/changes/"+c.ID) || len(c.Jobs) != 1 || c.Jobs[0].State != store.JobQueued {
		t.Fatalf("create: %d %+v", resp.StatusCode, c)
	}
	if resp := h.api(ot, "GET", "/changes/"+c.ID, nil, &c); resp.StatusCode != 200 || c.Plan[0].Action != "service.restart" {
		t.Fatalf("read back: %d %+v", resp.StatusCode, c)
	}
	var list []changeJSON
	if resp := h.api(ot, "GET", "/changes?show=approval", nil, &list); resp.StatusCode != 200 || len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("list: %d %+v", resp.StatusCode, list)
	}
	if resp := h.api(ot, "GET", "/changes?show=bogus", nil, &e); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad filter: %d", resp.StatusCode)
	}
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/submit", nil, &e); resp.StatusCode != http.StatusConflict {
		t.Fatalf("submit a submitted change: %d %v", resp.StatusCode, e)
	}
	if got := h.auditActions(); !strings.Contains(got, "change.create") {
		t.Fatalf("audit: %s", got)
	}

	// A draft waits until its requester submits it; nobody else can.
	resp = h.api(ot, "POST", "/changes", map[string]any{"action": "host.reboot", "hosts": []string{plex.HostID}, "draft": true,
		"title": "reboot later", "planned_start": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)}, &c)
	if resp.StatusCode != http.StatusCreated || c.State != store.ChangeDraft || c.Title != "reboot later" || c.PlannedStart == nil ||
		c.Risk != "high" {
		t.Fatalf("draft: %d %+v", resp.StatusCode, c)
	}
	if resp := h.api(at, "POST", "/changes/"+c.ID+"/submit", nil, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin submitting carl's draft: %d %v", resp.StatusCode, e)
	}
	if resp := h.api(ot, "POST", "/changes/"+c.ID+"/submit", nil, &c); resp.StatusCode != 200 || c.State != store.ChangeSubmitted {
		t.Fatalf("submit: %d %+v", resp.StatusCode, c)
	}

	// A script: its version and risk come from the library, its args are checked.
	scriptID, err := h.st.CreateScript(ctx, store.System, "disk report", "", store.NewScriptVersion{Interpreter: "/bin/sh",
		Params: []action.ScriptParam{{Name: "path", Required: true}}, Risk: action.Medium, Body: "#!/bin/sh\ndf $path\n"})
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.api(ot, "POST", "/changes", map[string]any{"action": "script.run", "hosts": []string{plex.HostID},
		"params": map[string]any{"script_id": scriptID}}, &e); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(e["error"], "path") {
		t.Fatalf("missing arg: %d %v", resp.StatusCode, e)
	}
	resp = h.api(ot, "POST", "/changes", map[string]any{"action": "script.run", "hosts": []string{plex.HostID},
		"params": map[string]any{"script_id": scriptID, "args": map[string]string{"path": "/"}}}, &c)
	if resp.StatusCode != http.StatusCreated || c.Plan[0].ScriptVersion != 1 || c.Risk != "medium" || !strings.Contains(c.Title, "disk report") {
		t.Fatalf("script change: %d %+v", resp.StatusCode, c)
	}
	var sv scriptVersionJSON
	if resp := h.api(ot, "GET", "/scripts/"+scriptID+"/versions/1", nil, &sv); resp.StatusCode != 200 || !strings.Contains(sv.Body, "df") {
		t.Fatalf("script version: %d %+v", resp.StatusCode, sv)
	}

	// A viewer token of the same operator can read the change but not create one.
	vt := h.mintToken(ops, "look", "viewer")
	if resp := h.api(vt, "GET", "/changes/"+c.ID, nil, &c); resp.StatusCode != 200 {
		t.Fatalf("viewer token reading: %d", resp.StatusCode)
	}
	if resp := h.api(vt, "POST", "/changes", map[string]any{"action": "host.reboot", "hosts": []string{plex.HostID}}, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer token creating: %d", resp.StatusCode)
	}
}

func TestAPIChangesOnStacksAndContainers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	b := h.addHost("b", media.ID)
	h.ingest(a, model.SectionContainers, appStacks(digestOld, time.Now(), "dwi-app", "metrics"))
	h.ingest(b, model.SectionContainers, appStacks(digestOld, time.Now(), "pwi-app"))
	h.connect(a, []string{"docker", action.CapCompose}, &action.Policy{Jobs: true})
	h.connect(b, []string{"docker"}, &action.Policy{Jobs: true}) // no Compose CLI
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ops := h.signIn("carl", "media-ops")
	ot := h.mintToken(ops, "deploy", "operator")
	ids := h.stackIDs(a.HostID, b.HostID)

	var e map[string]string
	type detail struct {
		changeJSON
		Approvals []approvalJSON `json:"approvals"`
		Jobs      []jobJSON      `json:"jobs"`
	}
	var c detail
	// Two stacks in one change, one step each; the stacks are affected CIs.
	resp := h.api(ot, "POST", "/changes", map[string]any{"action": "compose.update", "stacks": []string{ids["dwi-app"], ids["metrics"]},
		"params": map[string]any{"services": []string{"app"}, "health_timeout": 60}}, &c)
	if resp.StatusCode != http.StatusCreated || len(c.Plan) != 2 || c.Title != "Update 2 Compose stacks (dwi-app, metrics) on a" ||
		!strings.Contains(string(c.Plan[0].Params), `"services"`) || len(c.Jobs) != 2 {
		t.Fatalf("stacks: %d %v %+v", resp.StatusCode, e, c)
	}
	var list []changeJSON
	if resp := h.api(ot, "GET", "/changes?ci="+ids["metrics"], nil, &list); resp.StatusCode != 200 || len(list) != 1 {
		t.Fatalf("by stack: %d %d", resp.StatusCode, len(list))
	}
	for _, tc := range []struct {
		in   any
		want string
	}{
		{map[string]any{"action": "compose.update"}, "Compose stacks"},
		{map[string]any{"action": "compose.update", "stack": ids["pwi-app"]}, "compose"},
		{map[string]any{"action": "compose.update", "stack": ids["metrics"], "params": map[string]any{"project": "x"}}, "leave them out"},
		{map[string]any{"action": "service.restart", "hosts": []string{a.HostID}, "stacks": []string{ids["metrics"]}}, "only apply"},
		{map[string]any{"action": "container.restart", "containers": []string{"nope"}}, "no such container"},
	} {
		if resp := h.api(ot, "POST", "/changes", tc.in, &e); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(e["error"], tc.want) {
			t.Errorf("%v: %d %q, want %q", tc.in, resp.StatusCode, e["error"], tc.want)
		}
	}

	// Containers, likewise: one on each host.
	var containers []containerJSON
	if resp := h.api(ot, "GET", "/containers", nil, &containers); resp.StatusCode != 200 || len(containers) != 3 {
		t.Fatalf("containers: %d %d", resp.StatusCode, len(containers))
	}
	var pick []string
	for _, cr := range containers {
		if cr.Name == "metrics-app-1" || cr.Name == "pwi-app-app-1" {
			pick = append(pick, cr.CIID)
		}
	}
	resp = h.api(ot, "POST", "/changes", map[string]any{"action": "container.restart", "containers": pick}, &c)
	if resp.StatusCode != http.StatusCreated || len(c.Plan) != 2 || len(c.Hosts) != 2 || c.Risk != "low" ||
		!strings.Contains(c.Title, "2 containers") {
		t.Fatalf("containers: %d %v %+v", resp.StatusCode, e, c)
	}
	// Or by engine and name on one host, for a script that knows them.
	resp = h.api(ot, "POST", "/changes", map[string]any{"action": "container.restart", "hosts": []string{b.HostID},
		"params": map[string]any{"engine": "docker", "name": "pwi-app-app-1"}}, &c)
	if resp.StatusCode != http.StatusCreated || len(c.Plan) != 1 {
		t.Fatalf("by name: %d %v", resp.StatusCode, e)
	}
	var st struct {
		stackJSON
		Containers []containerJSON `json:"containers"`
	}
	if resp := h.api(ot, "GET", "/stacks/"+ids["metrics"], nil, &st); resp.StatusCode != 200 || st.Project != "metrics" || len(st.Containers) != 1 {
		t.Fatalf("stack: %d %+v", resp.StatusCode, st)
	}
}

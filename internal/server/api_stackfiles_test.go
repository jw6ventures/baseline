package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestAPIComposeDeployAndEdit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	d.Secrets, _ = oidc.NewCookieCodec(h.cfg.SecretKey)
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	h.connect(a, []string{"docker", action.CapCompose, action.CapComposeFiles}, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	ops := h.mintToken(h.signIn("carl", "media-ops"), "ci", "operator")
	viewer := h.mintToken(h.signIn("vera", "viewers"), "ro", "viewer")
	admin := h.signIn("ann", "lab-admins")

	deploy := map[string]any{"action": "compose.deploy", "hosts": []string{a.HostID},
		"params": map[string]any{"engine": "docker", "project": "web", "compose": webCompose, "env": "DB_PASSWORD=hunter2\nTZ=UTC"}}
	var e map[string]string
	if resp := h.api(ops, "POST", "/changes", deploy, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "Compose stack management is off") {
		t.Fatalf("deploy to an unmanaged host: %d %v", resp.StatusCode, e)
	}
	h.do(admin, "POST", "/hosts/"+a.HostID+"/manage-compose", map[string][]string{"manage_compose": {"1"}})

	for name, tc := range map[string]struct {
		req  map[string]any
		want string
	}{
		"no compose": {map[string]any{"action": "compose.deploy", "hosts": []string{a.HostID},
			"params": map[string]any{"engine": "docker", "project": "web"}}, "params.compose"},
		"two hosts": {map[string]any{"action": "compose.deploy", "hosts": []string{a.HostID, a.HostID + "x"},
			"params": map[string]any{"engine": "docker", "project": "web", "compose": webCompose}}, "one host"},
		"unknown field": {map[string]any{"action": "compose.deploy", "hosts": []string{a.HostID},
			"params": map[string]any{"engine": "docker", "project": "web", "compose": webCompose, "files": 1}}, "unknown field"},
		"bad env": {map[string]any{"action": "compose.deploy", "hosts": []string{a.HostID},
			"params": map[string]any{"engine": "docker", "project": "web", "compose": webCompose, "env": "A=1\nnope\n"}}, "line 2"},
	} {
		if resp := h.api(ops, "POST", "/changes", tc.req, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
			!strings.Contains(e["error"], tc.want) {
			t.Errorf("%s: %d %v", name, resp.StatusCode, e)
		}
	}
	if resp := h.api(viewer, "POST", "/changes", deploy, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer token deployed: %d", resp.StatusCode)
	}

	// Deploy: submitted (never approved by the API), with its files kept.
	var out struct {
		ID        string              `json:"id"`
		State     string              `json:"state"`
		Title     string              `json:"title"`
		Revisions []stackRevisionJSON `json:"stack_revisions"`
	}
	if resp := h.api(ops, "POST", "/changes", deploy, &out); resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy: %d", resp.StatusCode)
	}
	if out.State != store.ChangeSubmitted || out.Title != "Deploy stack web on a" || len(out.Revisions) != 1 ||
		out.Revisions[0].Compose == nil || *out.Revisions[0].Compose != webCompose || !out.Revisions[0].Env ||
		strings.Join(out.Revisions[0].EnvKeys, ",") != "DB_PASSWORD,TZ" {
		t.Fatalf("deploy change %+v", out)
	}
	h.noSecret("hunter2")
	var raw map[string]any
	h.api(viewer, "GET", "/changes/"+out.ID, nil, &raw)
	if b, _ := json.Marshal(raw); strings.Contains(string(b), "hunter2") {
		t.Fatal("the change detail holds the secret")
	}
	if resp := h.api(ops, "POST", "/changes", deploy, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "already deploys web") {
		t.Fatalf("second deploy: %d %v", resp.StatusCode, e)
	}

	// The stack comes up; finish the change so it can be edited.
	if err := h.st.ApproveChange(ctx, store.UserActor(mustUser(t, h, "ann"), ""), out.ID, ""); err != nil {
		t.Fatal(err)
	}
	d.Pass(ctx)
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: out.ID})
	code := 0
	if len(jobs) != 1 {
		t.Fatalf("jobs %v", jobs)
	}
	if _, err := h.st.FinishJob(ctx, store.System, a.HostID, jobs[0].ID, store.JobResult{State: store.JobSucceeded, ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	c, _ := h.st.GetChange(ctx, out.ID)
	rev := out.Revisions[0]
	stacks := appStacks(digestOld, c.CreatedAt, "web")
	stacks.Stacks[0].ConfigFiles = []model.ComposeFile{{Path: "/var/lib/baseline/stacks/web/compose.yaml",
		SHA256: stackenv.SHA256([]byte(webCompose)), Size: int64(len(webCompose)),
		Content: strings.ReplaceAll(webCompose, "${DB_PASSWORD}", "********")}}
	h.ingest(a, model.SectionContainers, stacks)
	stack := h.stackIDs(a.HostID)["web"]

	// Files: Baseline's copy of the Compose file; the .env only for operators, on asking.
	var files stackFilesJSON
	if resp := h.api(viewer, "GET", "/stacks/"+stack+"/files", nil, &files); resp.StatusCode != http.StatusOK ||
		files.Compose == nil || files.Compose.Content != webCompose || files.Compose.Masked || !files.Env.Known ||
		files.Env.Text != nil || files.Env.Revision != rev.ID {
		t.Fatalf("files: %d %+v", resp.StatusCode, files)
	}
	if resp := h.api(viewer, "GET", "/stacks/"+stack+"/files?env=1", nil, &e); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer read the .env: %d", resp.StatusCode)
	}
	files = stackFilesJSON{}
	if h.api(ops, "GET", "/stacks/"+stack+"/files?env=1", nil, &files); files.Env.Text == nil ||
		*files.Env.Text != "DB_PASSWORD=hunter2\nTZ=UTC\n" {
		t.Fatalf("operator's files %+v", files)
	}
	if !strings.Contains(h.auditActions(), "stack.env_view") {
		t.Fatal("reading the .env wasn't audited")
	}

	// Edit: only the .env; the Compose file stays.
	edit := map[string]any{"action": "compose.edit", "stack": stack,
		"params": map[string]any{"env": "DB_PASSWORD=correct-horse\nTZ=UTC\n", "base_sha256": "nope"}}
	if resp := h.api(ops, "POST", "/changes", edit, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "changed since") {
		t.Fatalf("stale edit: %d %v", resp.StatusCode, e)
	}
	edit["params"].(map[string]any)["base_sha256"] = files.Compose.SHA256
	if resp := h.api(ops, "POST", "/changes", map[string]any{"action": "compose.edit", "stack": stack,
		"params": map[string]any{"project": "x", "env": "A=1"}}, &e); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("edit naming the project: %d", resp.StatusCode)
	}
	if resp := h.api(ops, "POST", "/changes", map[string]any{"action": "compose.edit", "stack": stack,
		"params": map[string]any{"compose": webCompose}}, &e); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(e["error"], "nothing changed") {
		t.Fatalf("empty edit: %d %v", resp.StatusCode, e)
	}
	out.Revisions = nil
	if resp := h.api(ops, "POST", "/changes", edit, &out); resp.StatusCode != http.StatusCreated {
		t.Fatalf("edit: %d", resp.StatusCode)
	}
	if out.Title != "Edit the .env of stack web on a" || len(out.Revisions) != 1 || out.Revisions[0].Compose != nil ||
		!out.Revisions[0].Env {
		t.Fatalf("edit change %+v", out)
	}
	c2, _ := h.st.GetChange(ctx, out.ID)
	if !strings.Contains(string(c2.Plan[0].Params), `"env": true`) {
		t.Fatalf("edit plan %+v", c2)
	}
	h.noSecret("correct-horse")
}

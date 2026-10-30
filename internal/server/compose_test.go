package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

var (
	digestOld = "sha256:" + strings.Repeat("1", 64)
	digestNew = "sha256:" + strings.Repeat("2", 64)
)

// appStacks is a containers section with one single-service stack per
// project, each running ghcr.io/me/app:1 pulled by digest, started at
// started.
func appStacks(digest string, started time.Time, projects ...string) model.Containers {
	c := model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Version: "28.0"}},
		Images:  []model.ContainerImage{{Engine: "docker", ID: "img", Digests: []string{"ghcr.io/me/app@" + digest}}},
	}
	for _, p := range projects {
		c.Containers = append(c.Containers, model.Container{Engine: "docker", Name: p + "-app-1", ID: p, Image: "ghcr.io/me/app:1",
			ImageID: "img", State: "running", StartedAt: started.UTC().Format(time.RFC3339), ComposeProject: p, ComposeService: "app"})
		c.Stacks = append(c.Stacks, model.ComposeStack{Engine: "docker", Project: p, WorkingDir: "/srv/" + p, Services: []string{"app"},
			CLI: "docker compose", ConfigFiles: []model.ComposeFile{{Path: "/srv/" + p + "/compose.yaml", SHA256: "ab", Size: 1}}})
	}
	return c
}

// stackIDs maps project names to stack CI IDs.
func (h *harness) stackIDs(hostIDs ...string) map[string]string {
	h.t.Helper()
	stacks, err := h.st.ListStacks(context.Background(), hostIDs)
	if err != nil {
		h.t.Fatal(err)
	}
	m := map[string]string{}
	for _, st := range stacks {
		m[st.Project] = st.CIID
	}
	return m
}

// composeModel creates an approved compose.update change model.
func (h *harness) composeModel(name string) string {
	h.t.Helper()
	ctx := context.Background()
	params, err := change.ModelParams(action.ComposeUpdate, []byte(`{"health_timeout":60}`))
	if err != nil {
		h.t.Fatal(err)
	}
	u, err := h.st.UpsertUser(ctx, "model-approver", "approver@example.com", "Approver")
	if err != nil {
		h.t.Fatal(err)
	}
	actor := store.UserActor(u.ID, "10.0.0.1")
	id, err := h.st.SaveChangeModel(ctx, actor, store.ChangeModel{Name: name, Action: action.ComposeUpdate, Params: params, Risk: "low"})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.st.ApproveChangeModel(ctx, actor, id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestChangeFormPicksStacksAndContainers(t *testing.T) {
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
	ids := h.stackIDs(a.HostID, b.HostID)

	// From the change page, with no stack chosen: every stack, filters,
	// and why pwi-app can't be picked.
	_, body := h.do(ops, "GET", "/changes/new?action=compose.update", nil)
	for _, want := range []string{`name="stack" value="` + ids["dwi-app"] + `"`, `name="stack" value="` + ids["metrics"] + `"`,
		`data-env="Dev"`, `data-filter="env"`, `data-filter="visibility"`, "can&#39;t do this: it needs compose"} {
		if !strings.Contains(body, want) {
			t.Fatalf("stack picker lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "start from a stack") {
		t.Fatal("still sends people to the stack page")
	}
	if regexp.MustCompile(`name="stack" value="`+ids["pwi-app"]+`"[^>]*disabled`).FindString(body) == "" {
		t.Fatal("pwi-app is offered on a host without a Compose CLI")
	}

	// Two stacks in one change, one step each; services per stack.
	resp, body := h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}, "stack": {ids["dwi-app"], ids["metrics"]},
		"svc." + ids["metrics"]: {"app"}, "health_timeout": {"60"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, _ := h.st.GetChange(ctx, changeIDFrom(t, resp))
	if len(c.Plan) != 2 || c.Title != "Update 2 Compose stacks (dwi-app, metrics) on a" ||
		!strings.Contains(string(c.Plan[1].Params), `"services": [`) || strings.Contains(string(c.Plan[0].Params), "services") ||
		!strings.Contains(c.Plan[0].Summary, "dwi-app") {
		t.Fatalf("change: %q %+v", c.Title, c.Plan)
	}
	for _, p := range []string{"dwi-app", "metrics"} {
		if cs, _ := h.st.ListChanges(ctx, store.ChangeFilter{CIID: ids[p]}); len(cs) != 1 {
			t.Fatalf("%s isn't affected", p)
		}
	}
	// Nothing picked, or a stack its host can't update.
	if resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}}); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "Pick at least one Compose stack") {
		t.Fatalf("no stack: %d", resp.StatusCode)
	}
	if resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"compose.update"}, "stack": {ids["pwi-app"]}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("stack on a host without Compose: %d", resp.StatusCode)
	}

	// Containers, likewise.
	_, body = h.do(ops, "GET", "/changes/new?action=container.restart", nil)
	if !strings.Contains(body, `name="container"`) || !strings.Contains(body, "pwi-app-app-1") {
		t.Fatalf("container picker:\n%s", body)
	}
	rows, _ := h.st.ListContainers(ctx, []string{a.HostID, b.HostID})
	var picked []string
	for _, r := range rows {
		if r.Name != "metrics-app-1" {
			picked = append(picked, r.CIID)
		}
	}
	resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"container.restart"}, "container": picked})
	c, _ = h.st.GetChange(ctx, changeIDFrom(t, resp))
	if len(c.Plan) != 2 || len(c.HostIDs) != 2 || !strings.HasPrefix(c.Title, "Restart 2 containers") {
		t.Fatalf("restart change: %q %+v", c.Title, c.Plan)
	}
}

func TestContainersClassificationColumns(t *testing.T) {
	h := newHarness(t)
	a := h.addHost("a")
	h.ingest(a, model.SectionContainers, appStacks(digestOld, time.Now(), "dwi-app", "pee-media", "metrics"))
	h.st.CreateRoleBinding(context.Background(), store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	viewer := h.signIn("vic", "viewers")

	// The old stacks view's address opens the stacks list.
	_, body := h.list(viewer, "/containers?view=stacks")
	for _, want := range []string{">Environment</a></th>", ">Category</a></th>", ">Visibility</a></th>",
		`data-f="environment" data-op="eq" data-nop="ne" data-v="Prod"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("stacks view lacks %s:\n%s", want, body)
		}
	}
	// So do its filters, as conditions.
	shows := func(q string, want ...string) {
		t.Helper()
		_, body := h.list(viewer, "/containers?view=stacks&"+q)
		for _, p := range []string{"dwi-app", "pee-media", "metrics"} {
			if got := strings.Contains(body, ">"+p+"</a></td>"); got != slices.Contains(want, p) {
				t.Errorf("%s: %s shown %v", q, p, got)
			}
		}
	}
	shows("env=Prod", "pee-media")
	shows("category=Web", "dwi-app")
	shows("visibility=External", "pee-media")
	shows("env=none", "metrics")
	shows("env=Dev&visibility=External")
	shows("q=app", "dwi-app")
}

func TestComposePatchGroupPromotes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	devHost, prodHost := h.addHost("dev1"), h.addHost("prod1")
	now := time.Now()
	h.ingest(devHost, model.SectionContainers, appStacks(digestNew, now.Add(-3*time.Hour), "dwi-app"))
	h.ingest(prodHost, model.SectionContainers, appStacks(digestOld, now.Add(-30*24*time.Hour), "pwi-app", "pwi-solo"))
	h.st.SaveImageCheck(ctx, "ghcr.io/me/app:1", "ghcr.io", digestNew, "")
	for _, r := range []store.EnrollResult{devHost, prodHost} {
		h.connect(r, []string{"docker", action.CapCompose}, &action.Policy{Jobs: true})
	}
	admin := h.signIn("ann", "lab-admins")
	ids := h.stackIDs(devHost.HostID, prodHost.HostID)
	mid := h.composeModel("stacks")

	// The form offers stacks for a compose.update model, and needs some.
	_, body := h.do(admin, "GET", "/patch-groups/new", nil)
	if !strings.Contains(body, `data-kind="compose"`) || !strings.Contains(body, `name="stack" value="`+ids["pwi-app"]+`"`) {
		t.Fatalf("form:\n%s", body)
	}
	form := url.Values{"name": {"prod stacks"}, "model": {mid}, "cron": {"0 4 * * *"}, "tz": {"UTC"}, "soak": {"2h"},
		"threshold": {"100"}, "concurrency": {"1"}, "promote": {"1"}, "stop_on_failure": {"1"}, "enabled": {"1"}}
	if resp, body := h.do(admin, "POST", "/patch-groups", form); resp.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "Pick the Compose stacks") {
		t.Fatalf("no stacks: %d", resp.StatusCode)
	}
	form["stack"] = []string{ids["pwi-app"], ids["pwi-solo"]}
	resp, _ := h.do(admin, "POST", "/patch-groups", form)
	m := rePatchGroup.FindStringSubmatch(resp.Header.Get("Location"))
	if m == nil {
		t.Fatalf("save: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	pg, _ := h.st.GetPatchGroup(ctx, m[1])
	if !pg.Compose() || pg.HostGroupID != "" || len(pg.Stacks) != 2 || pg.StackNames[0] != "pwi-app on prod1" {
		t.Fatalf("group: %+v", pg)
	}

	// Dev runs the new image and has for 3h, past the 2h soak: pwi-app
	// takes it. pwi-solo has no earlier copy and takes everything newer.
	if _, err := h.srv.changes.RunCycle(ctx, pg, now, now); err != nil {
		t.Fatal(err)
	}
	cs, _ := h.st.ListPatchCycles(ctx, pg.ID, 1)
	if len(cs) != 1 || cs[0].ChangeID == "" || cs[0].Hosts != 2 {
		t.Fatalf("cycle: %+v", cs)
	}
	plan := map[string]store.PlannedHost{}
	for _, p := range cs[0].Planned {
		plan[p.Project] = p
	}
	if p := plan["pwi-app"]; !p.Job || !slices.Equal(p.Services, []string{"app"}) || p.Validator != "dwi-app on dev1" {
		t.Fatalf("pwi-app: %+v", p)
	}
	if p := plan["pwi-solo"]; !p.Job || p.Services != nil || !strings.Contains(p.Note, "no earlier copy") {
		t.Fatalf("pwi-solo: %+v", p)
	}
	c, _ := h.st.GetChange(ctx, cs[0].ChangeID)
	if c.Kind != store.KindStandard || len(c.Plan) != 2 || !strings.Contains(string(c.Plan[0].Params), `"app"`) {
		t.Fatalf("change: %+v", c)
	}
	_, body = h.do(admin, "GET", "/patch-groups/"+pg.ID, nil)
	if !strings.Contains(body, "pwi-app on prod1") || !strings.Contains(body, "validated on dwi-app on dev1") {
		t.Fatalf("group page:\n%s", body)
	}
	h.do(admin, "POST", "/changes/"+c.ID+"/cancel", nil)

	// Dev only just took the image: prod waits for the soak.
	h.ingest(devHost, model.SectionContainers, appStacks(digestNew, now.Add(-30*time.Minute), "dwi-app"))
	h.srv.changes.RunCycle(ctx, pg, now.Add(time.Minute), now.Add(time.Minute))
	cs, _ = h.st.ListPatchCycles(ctx, pg.ID, 1)
	for _, p := range cs[0].Planned {
		if p.Project == "pwi-app" && (p.Job || p.Deferred != 1 || !strings.Contains(p.Note, "haven't soaked")) {
			t.Fatalf("young image: %+v", p)
		}
	}

	// Dev doesn't run it at all.
	h.ingest(devHost, model.SectionContainers, appStacks(digestOld, now.Add(-3*time.Hour), "dwi-app"))
	h.srv.changes.RunCycle(ctx, pg, now.Add(2*time.Minute), now.Add(2*time.Minute))
	cs, _ = h.st.ListPatchCycles(ctx, pg.ID, 1)
	for _, p := range cs[0].Planned {
		if p.Project == "pwi-app" && (p.Job || !strings.Contains(p.Note, "none of its newer images runs on dwi-app on dev1")) {
			t.Fatalf("unvalidated image: %+v", p)
		}
	}
}

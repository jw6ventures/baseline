package change_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

var oldDigest = "sha256:" + strings.Repeat("1", 64)

// stackSection is a containers section with one stack; each service runs
// image, with labels.
func stackSection(project string, images, groups map[string]string) model.Containers {
	c := model.Containers{Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Version: "28.0"}}}
	st := model.ComposeStack{Engine: "docker", Project: project, WorkingDir: "/srv/" + project, CLI: "docker compose",
		ConfigFiles: []model.ComposeFile{{Path: "/srv/" + project + "/compose.yaml"}}}
	for svc, img := range images {
		var labels map[string]string
		if g, ok := groups[svc]; ok {
			name, order, _ := strings.Cut(g, "/")
			labels = map[string]string{updategroup.LabelGroup: name, updategroup.LabelOrder: order}
		}
		repo := img[:strings.LastIndex(img, ":")]
		c.Images = append(c.Images, model.ContainerImage{Engine: "docker", ID: "img-" + svc, Digests: []string{repo + "@" + oldDigest}})
		c.Containers = append(c.Containers, model.Container{Engine: "docker", Name: project + "-" + svc + "-1", ID: project + svc,
			Image: img, ImageID: "img-" + svc, State: "running", ComposeProject: project, ComposeService: svc, Labels: labels})
		st.Services = append(st.Services, svc)
	}
	c.Stacks = []model.ComposeStack{st}
	return c
}

func (e *env) composeModel() string {
	e.t.Helper()
	params, _ := change.ModelParams(action.ComposeUpdate, []byte(`{"health_timeout":60}`))
	id, err := e.st.SaveChangeModel(ctx, e.ann, store.ChangeModel{Name: "compose", Action: action.ComposeUpdate, Params: params, Risk: "low"})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.ApproveChangeModel(ctx, e.ann, id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func summaries(c store.Change) string {
	var out []string
	for _, s := range c.Plan {
		x := s.Summary
		if s.UpdateGroup != "" {
			x += "@" + s.UpdateGroup
		}
		out = append(out, x)
	}
	return strings.Join(out, "|")
}

func (e *env) open() []store.Change {
	e.t.Helper()
	cs, err := e.st.ListChanges(ctx, store.ChangeFilter{States: []string{store.ChangeApproved, store.ChangeSubmitted}, Limit: 100})
	if err != nil {
		e.t.Fatal(err)
	}
	return cs
}

func TestUpdateGroups(t *testing.T) {
	e := newEnv(t)
	a, b := e.host("a", "debian", "13"), e.host("b", "debian", "13")
	e.ingest(a, model.SectionContainers, stackSection("authentik",
		map[string]string{"server": "ghcr.io/goauthentik/server:2026.8", "redis": "docker.io/library/redis:7"},
		map[string]string{"server": "authentik/1"}))
	e.ingest(b, model.SectionContainers, stackSection("duplicati",
		map[string]string{"duplicati": "lscr.io/linuxserver/duplicati:latest", "proxy": "ghcr.io/goauthentik/proxy:2026.8"},
		map[string]string{"proxy": "authentik/2"}))
	for _, h := range []store.EnrollResult{a, b} {
		if _, err := e.st.AgentConnected(ctx, h.HostID, h.AgentID, store.Hello{AgentVersion: "test", BootID: "b1",
			Capabilities: []string{"docker", action.CapCompose, action.CapComposeRetag}, Policy: &action.Policy{Jobs: true}}); err != nil {
			t.Fatal(err)
		}
	}
	newer := "sha256:" + strings.Repeat("2", 64)
	for _, ref := range []string{"ghcr.io/goauthentik/server:2026.8", "ghcr.io/goauthentik/proxy:2026.8", "lscr.io/linuxserver/duplicati:latest"} {
		e.st.SaveImageCheck(ctx, ref, "ghcr.io", newer, "")
	}
	mid := e.composeModel()
	stacks, _ := e.st.ListStacks(ctx, []string{a.HostID, b.HostID})
	ids := map[string]string{}
	for _, st := range stacks {
		ids[st.Project] = st.CIID
	}
	e.st.SetStackUpdates(ctx, e.ann, ids["duplicati"], mid, "", true)
	e.st.SetStackUpdates(ctx, e.ann, ids["authentik"], mid, "", false)

	// Duplicati updates itself, but its outpost waits for the server,
	// whose stack doesn't update itself.
	if n, err := e.m.AutoUpdate(ctx, e.now); err != nil || n != 1 {
		t.Fatalf("auto-update: %d %v", n, err)
	}
	cs := e.open()
	if len(cs) != 1 || summaries(cs[0]) != "Update stack duplicati (duplicati)" {
		t.Fatalf("changes: %d %q", len(cs), summaries(cs[0]))
	}
	e.st.CancelChange(ctx, store.System, cs[0].ID, "test")
	e.now = e.now.Add(time.Hour)

	// A Compose patch group holding only Duplicati does the same, and says
	// why the outpost waits.
	pg, err := e.st.SavePatchGroup(ctx, e.ann, store.PatchGroup{Name: "stacks", Stacks: []string{ids["duplicati"]}, Cron: "0 2 * * *",
		TZ: "UTC", ModelID: mid, SuccessThreshold: 100, Concurrency: 1, StopOnFailure: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := e.st.GetPatchGroup(ctx, pg)
	if _, err := e.m.RunCycle(ctx, g, e.now, e.now); err != nil {
		t.Fatal(err)
	}
	cs = e.open()
	if len(cs) != 1 || summaries(cs[0]) != "Update stack duplicati (duplicati)" {
		t.Fatalf("patch group changes: %d %q", len(cs), summaries(cs[0]))
	}
	cycle, _ := e.st.LastRanCycle(ctx, pg)
	if cycle == nil || len(cycle.Planned) != 1 || !strings.Contains(cycle.Planned[0].Note, "proxy waits: it waits for server in authentik on a") {
		t.Fatalf("cycle: %+v", cycle)
	}
	e.st.CancelChange(ctx, store.System, cs[0].ID, "test")
	e.st.DeletePatchGroup(ctx, e.ann, pg)

	// Once the server's stack updates itself, its update brings the
	// outpost along, after it; Duplicati is then busy with that change.
	e.st.SetStackUpdates(ctx, e.ann, ids["authentik"], mid, "", true)
	if n, err := e.m.AutoUpdate(ctx, e.now); err != nil || n != 1 {
		t.Fatalf("auto-update: %d %v", n, err)
	}
	cs = e.open()
	want := "Update stack authentik (redis)|Update stack authentik (server)@authentik|Update stack duplicati (proxy)@authentik"
	if len(cs) != 1 || summaries(cs[0]) != want || cs[0].Kind != store.KindStandard {
		t.Fatalf("changes: %d %q", len(cs), summaries(cs[0]))
	}
	e.st.CancelChange(ctx, store.System, cs[0].ID, "test")

	// A newer tag the server's semver rule allows is proposed once, as a
	// Normal change for an approver.
	ctrs, _ := e.st.ListContainers(ctx, []string{a.HostID})
	for _, c := range ctrs {
		if c.ComposeService == "server" {
			if err := e.st.SetSemverRule(ctx, e.ann, c.CIID, &registry.Rule{Track: "minor"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.st.SaveTags(ctx, "ghcr.io/goauthentik/server", []string{"2026.7", "2026.8", "2026.9"}, "")
	e.st.SaveImageCheck(ctx, "ghcr.io/goauthentik/server:2026.9", "ghcr.io", "sha256:"+strings.Repeat("3", 64), "")
	if n, err := e.m.ProposeRetags(ctx, e.now); err != nil || n != 1 {
		t.Fatalf("propose: %d %v", n, err)
	}
	cs = e.open()
	if len(cs) != 1 || cs[0].Kind != store.KindNormal || cs[0].State != store.ChangeSubmitted ||
		cs[0].Title != "Move update group authentik to tag 2026.9" ||
		summaries(cs[0]) != "Update stack authentik (server) to tag 2026.9@authentik|Update stack duplicati (proxy) to tag 2026.9@authentik" {
		t.Fatalf("proposal: %+v %q", cs, summaries(cs[0]))
	}
	if n, err := e.m.ProposeRetags(ctx, e.now); err != nil || n != 0 {
		t.Fatalf("proposed again: %d %v", n, err)
	}
	// Rejected, it isn't proposed again.
	e.st.CancelChange(ctx, store.System, cs[0].ID, "test")
	if n, err := e.m.ProposeRetags(ctx, e.now); err != nil || n != 0 {
		t.Fatalf("proposed after cancel: %d %v", n, err)
	}
}

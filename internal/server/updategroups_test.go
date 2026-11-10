package server

import (
	"context"
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
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// groupStack is a containers section with one stack whose services run
// these images, with these labels.
func groupStack(project string, services map[string]string, labels map[string]map[string]string) model.Containers {
	c := model.Containers{Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Version: "28.0"}}}
	st := model.ComposeStack{Engine: "docker", Project: project, WorkingDir: "/srv/" + project, CLI: "docker compose",
		ConfigFiles: []model.ComposeFile{{Path: "/srv/" + project + "/compose.yaml", SHA256: "ab", Size: 1}}}
	for svc, img := range services {
		repo, _, _ := strings.Cut(img, ":")
		if strings.Count(img, ":") > 0 && strings.LastIndex(img, ":") > strings.LastIndex(img, "/") {
			repo = img[:strings.LastIndex(img, ":")]
		}
		c.Images = append(c.Images, model.ContainerImage{Engine: "docker", ID: "img-" + svc, Digests: []string{repo + "@" + digestOld}})
		st.Services = append(st.Services, svc)
		c.Containers = append(c.Containers, model.Container{Engine: "docker", Name: project + "-" + svc + "-1", ID: project + svc,
			Image: img, ImageID: "img-" + svc, State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339),
			ComposeProject: project, ComposeService: svc, Labels: labels[svc]})
	}
	c.Stacks = []model.ComposeStack{st}
	return c
}

func groupLabels(group, order string) map[string]string {
	return map[string]string{updategroup.LabelGroup: group, updategroup.LabelOrder: order}
}

func TestUpdateGroups(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	a := h.addHost("a", media.ID)
	b := h.addHost("b", media.ID)
	h.ingest(a, model.SectionContainers, groupStack("authentik",
		map[string]string{"server": "ghcr.io/goauthentik/server:2026.8", "redis": "redis:7"},
		map[string]map[string]string{"server": groupLabels("authentik", "1")}))
	h.ingest(b, model.SectionContainers, groupStack("duplicati",
		map[string]string{"duplicati": "lscr.io/linuxserver/duplicati:latest", "proxy": "ghcr.io/goauthentik/proxy:2026.8"},
		map[string]map[string]string{"proxy": groupLabels("authentik", "2")}))
	caps := []string{"docker", action.CapCompose, action.CapComposeRetag}
	h.connect(a, caps, &action.Policy{Jobs: true})
	h.connect(b, caps, &action.Policy{Jobs: true})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-approvers", Role: rbac.Approver, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	ann := h.signIn("ann", "media-approvers", "media-ops")
	ids := h.stackIDs(a.HostID, b.HostID)
	// The server has a newer image behind its tag.
	h.st.SaveImageCheck(ctx, "ghcr.io/goauthentik/server:2026.8", "ghcr.io", digestNew, "")

	// Updating Duplicati by hand brings the Authentik server along, ahead
	// of its outpost; Duplicati itself is a step of its own.
	resp, body := h.do(ann, "POST", "/changes", url.Values{"action": {"compose.update"}, "stack": {ids["duplicati"]},
		"health_timeout": {"60"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, _ := h.st.GetChange(ctx, changeIDFrom(t, resp))
	var got []string
	for _, s := range c.Plan {
		got = append(got, s.Summary+"@"+s.UpdateGroup)
	}
	if want := "Update stack duplicati (duplicati)@ Update stack authentik (server)@authentik Update stack duplicati (proxy)@authentik"; strings.Join(got, " ") != want {
		t.Fatalf("plan: %q", got)
	}
	if c.Plan[2].UpdateOrder != 2 || len(c.HostIDs) != 2 {
		t.Fatalf("plan: %+v hosts %v", c.Plan, c.HostIDs)
	}
	h.st.CancelChange(ctx, store.System, c.ID, "test")

	// The pages.
	_, body = h.do(ann, "GET", "/update-groups", nil)
	if !strings.Contains(body, `href="/update-groups/authentik"`) || !strings.Contains(body, "server in authentik on a") {
		t.Fatalf("groups page:\n%s", body)
	}
	_, body = h.do(ann, "GET", "/update-groups/authentik", nil)
	for _, want := range []string{"ghcr.io/goauthentik/proxy:2026.8", "Approve and run", `action="/update-groups/authentik/retag"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("group page lacks %q:\n%s", want, body)
		}
	}
	_, body = h.do(ann, "GET", "/stacks/"+ids["authentik"], nil)
	if !strings.Contains(body, `id="update-groups"`) || !strings.Contains(body, "set by labels") {
		t.Fatalf("stack page:\n%s", body)
	}

	// Redis joins on the stack's page.
	resp, _ = h.do(ann, "POST", "/stacks/"+ids["authentik"]+"/update-group", url.Values{"service": {"redis"}, "group": {"Authentik"}, "order": {"1"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("set: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	st, _ := h.st.GetStack(ctx, ids["authentik"])
	if st.UpdateGroups["redis"] != (store.UpdateGroup{Group: "authentik", Order: 1}) {
		t.Fatalf("setting: %+v", st.UpdateGroups)
	}
	resp, _ = h.do(ann, "POST", "/stacks/"+ids["authentik"]+"/update-group", url.Values{"service": {"redis"}, "group": {"bad name!"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bad name accepted: %s", resp.Header.Get("Location"))
	}

	// Moving the group to a tag: one change, the leaders first.
	resp, body = h.do(ann, "POST", "/update-groups/authentik/retag", url.Values{"tag": {"2026.9"}, "submit": {"approve"}})
	id := changeIDFrom(t, resp)
	c, _ = h.st.GetChange(ctx, id)
	got = nil
	for _, s := range c.Plan {
		got = append(got, s.Summary)
	}
	if want := "Update stack authentik (redis, server) to tag 2026.9|Update stack duplicati (proxy) to tag 2026.9"; strings.Join(got, "|") != want ||
		c.Title != "Move update group authentik to tag 2026.9" || c.Kind != store.KindNormal || c.State != store.ChangeApproved {
		t.Fatalf("retag change %q %s %s: %q", c.Title, c.Kind, c.State, got)
	}

	// The outpost's job waits for the server's, and is skipped when it fails.
	if err := h.st.StartChange(ctx, id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	queued, err := h.st.QueuedJobs(ctx)
	if err != nil || len(queued) != 1 || queued[0].HostID != a.HostID {
		t.Fatalf("queued: %v %+v", err, queued)
	}
	if _, err := h.st.FinishJob(ctx, store.System, a.HostID, queued[0].ID, store.JobResult{State: store.JobRolledBack, Error: "unhealthy"}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: id})
	for _, j := range jobs {
		if j.HostID == b.HostID && (j.State != store.JobCancelled || !strings.Contains(j.Error, "update group authentik")) {
			t.Fatalf("outpost job: %s %q", j.State, j.Error)
		}
	}

	// An agent that can't change tags blocks the move.
	h.connect(b, []string{"docker", action.CapCompose}, &action.Policy{Jobs: true})
	resp, _ = h.do(ann, "POST", "/update-groups/authentik/retag", url.Values{"tag": {"2026.10"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=") || !strings.Contains(loc, "tags") {
		t.Fatalf("old agent: %s", loc)
	}
}

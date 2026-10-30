package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

type fakeChecker struct{ n int }

func (f *fakeChecker) Trigger() { f.n++ }

func containersFixture() model.Containers {
	digest := "sha256:" + strings.Repeat("1", 64)
	return model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Version: "28.0"}},
		Containers: []model.Container{
			{Engine: "docker", Name: "media-plex-1", ID: "abc", Image: "plexinc/pms-docker:1.41.0", ImageID: "i1", State: "running",
				Health: "healthy", ComposeProject: "media", ComposeService: "plex", Labels: map[string]string{"a": "b"}},
		},
		Images: []model.ContainerImage{{Engine: "docker", ID: "i1", Digests: []string{"plexinc/pms-docker@" + digest}}},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "media", WorkingDir: "/srv/media", Services: []string{"plex"},
			CLI: "docker compose", ConfigFiles: []model.ComposeFile{{Path: "/srv/media/compose.yaml", SHA256: "abcdef", Size: 20,
				Content: "services:\n  plex:\n    environment:\n      TOKEN: ********\n"}}}},
	}
}

// firstLink returns the first href matching a pattern in body.
func firstLink(t *testing.T, body, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(`href="(` + pattern + `)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link matching %s in:\n%s", pattern, body)
	}
	return m[1]
}

func TestContainersPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ck := &fakeChecker{}
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.ingest(plex, model.SectionContainers, containersFixture())
	other := containersFixture()
	other.Containers[0].Name, other.Stacks = "pihole", nil
	other.Containers[0].ComposeProject, other.Containers[0].ComposeService = "", ""
	h.ingest(dns, model.SectionContainers, other)
	h.st.SaveImageCheck(ctx, "docker.io/plexinc/pms-docker:1.41.0", "docker.io", "sha256:"+strings.Repeat("2", 64), "")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	h.srv.SetChecker(ck)

	admin := h.signIn("ann", "lab-admins")
	_, body := h.list(admin, "/containers")
	if !strings.Contains(body, "media-plex-1") || !strings.Contains(body, "pihole") || !strings.Contains(body, "newer image") {
		t.Fatalf("containers:\n%s", body)
	}
	_, body = h.list(admin, "/containers?view=stacks&updates=1")
	if !strings.Contains(body, ">media<") || !strings.Contains(body, `data-f="drift" data-op="eq" data-nop="ne" data-v="1"`) {
		t.Fatalf("stacks:\n%s", body)
	}

	// A scoped operator sees and edits only their group's containers.
	ops := h.signIn("carl", "media-ops")
	_, body = h.list(ops, "/containers")
	if !strings.Contains(body, "media-plex-1") || strings.Contains(body, "pihole") {
		t.Fatalf("scoped containers:\n%s", body)
	}
	cpath := firstLink(t, body, `/containers/[0-9a-f-]{36}`)
	resp, body := h.do(ops, "GET", cpath, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Check now") || !strings.Contains(body, "Track") {
		t.Fatalf("container page %d:\n%s", resp.StatusCode, body)
	}
	resp, _ = h.do(ops, "POST", cpath+"/rule", url.Values{"track": {"minor"}, "include": {`^\d+\.\d+\.\d+$`}})
	if resp.StatusCode != http.StatusSeeOther || ck.n != 1 {
		t.Fatalf("rule: %d, triggered %d", resp.StatusCode, ck.n)
	}
	resp, _ = h.do(ops, "POST", cpath+"/rule", url.Values{"track": {"minor"}, "include": {"("}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bad regexp accepted: %s", resp.Header.Get("Location"))
	}
	h.st.SaveTags(ctx, "docker.io/plexinc/pms-docker", []string{"1.41.0", "1.41.3", "1.42.1", "latest"}, "")
	_, body = h.do(ops, "GET", cpath, nil)
	if !strings.Contains(body, "1.42.1 available") {
		t.Fatalf("advice missing:\n%s", body)
	}
	// The list knows it too, and filters on it.
	_, list := h.list(ops, "/containers?cf=advice&co=eq&cv=1.42.1&cols=name,update,advice&sort=name")
	if !strings.Contains(list, "media-plex-1") || !strings.Contains(list, `data-v="1.42.1"`) {
		t.Fatalf("advice in the list:\n%s", list)
	}
	resp, _ = h.do(ops, "POST", cpath+"/check", nil)
	if resp.StatusCode != http.StatusSeeOther || ck.n != 2 {
		t.Fatalf("check now: %d, triggered %d", resp.StatusCode, ck.n)
	}

	// Stack page: files (masked by the agent), pinning.
	spath := firstLink(t, body, `/stacks/[0-9a-f-]{36}`)
	_, body = h.do(ops, "GET", spath, nil)
	if !strings.Contains(body, "/srv/media/compose.yaml") || !strings.Contains(body, "TOKEN: ********") || !strings.Contains(body, "minor") {
		t.Fatalf("stack page:\n%s", body)
	}
	if _, body = h.list(ops, "/containers?show=updates"); !strings.Contains(body, "media-plex-1") {
		t.Fatalf("no update to prompt for:\n%s", body)
	}
	h.do(ops, "POST", spath+"/pin", url.Values{"pinned": {"1"}})
	_, body = h.list(ops, "/containers?updates=1")
	if strings.Contains(body, "media-plex-1") {
		t.Fatalf("pinned stack still prompts:\n%s", body)
	}

	// A global viewer can see but not change anything.
	viewer := h.signIn("vic", "viewers")
	if resp, _ := h.do(viewer, "POST", cpath+"/rule", url.Values{"track": {"off"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer set a rule: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "POST", spath+"/pin", url.Values{"pinned": {"0"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer pinned: %d", resp.StatusCode)
	}
	// Someone without access to the host gets a 404.
	_, body = h.list(admin, "/containers?q=pihole")
	other1 := firstLink(t, body, `/containers/[0-9a-f-]{36}`)
	if resp, _ := h.do(ops, "GET", other1, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("scoped user saw another group's container: %d", resp.StatusCode)
	}

	// The host's tabs.
	h.ingest(plex, model.SectionServices, model.Services{Units: []model.Service{{Name: "backup.service", Active: "failed", Load: "loaded"}}})
	h.ingest(plex, model.SectionPorts, model.Ports{Listeners: []model.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 32400, Process: "Plex Media Serv"}}})
	h.ingest(plex, model.SectionReboot, model.Reboot{Required: true, Reasons: []string{"running kernel 6.8.0-85 is older than the installed 6.8.0-87"}})
	h.ingest(plex, model.SectionCerts, model.Certs{Certs: []model.Cert{{Location: "tcp:32400", Subject: "CN=plex",
		NotAfter: time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)}}})
	for tab, want := range map[string]string{
		"overview": "Reboot required", "containers": "media-plex-1", "services": "backup.service",
		"ports": "32400", "certificates": "CN=plex", "metrics": "No metrics",
	} {
		path := "/hosts/" + plex.HostID + "?tab=" + tab
		if _, ok := hostLists[tab]; ok {
			path = "/hosts/" + plex.HostID + "/" + tab
		}
		resp, body := h.do(ops, "GET", path, nil)
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Fatalf("tab %s: %d, no %q:\n%s", tab, resp.StatusCode, want, body)
		}
	}
	_, body = h.do(admin, "GET", "/", nil)
	if !strings.Contains(body, "Certificates expiring soon") || !strings.Contains(body, "reboot required") || !strings.Contains(body, "failed service") {
		t.Fatalf("dashboard:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/hosts", nil)
	if !strings.Contains(body, "reboot required") {
		t.Fatalf("hosts list:\n%s", body)
	}
}

func TestCIPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-viewers", Role: rbac.Viewer, ScopeGroupID: media.ID})
	web := h.addHost("web1")

	ops := h.signIn("olga", "ops")
	resp, body := h.do(ops, "GET", "/cis/new?type=nas", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "TLS endpoint to check") {
		t.Fatalf("new form %d:\n%s", resp.StatusCode, body)
	}
	resp, body = h.do(ops, "POST", "/cis", url.Values{"type": {"nas"}, "name": {"nas1"}, "status": {"active"},
		"attr_tls_endpoint": {"not a host:port!"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "host:port") || !strings.Contains(body, `value="nas1"`) {
		t.Fatalf("bad endpoint: %d\n%s", resp.StatusCode, body)
	}
	resp, _ = h.do(ops, "POST", "/cis", url.Values{"type": {"nas"}, "name": {"nas1"}, "status": {"active"},
		"tags": {"storage, lab"}, "attr_vendor": {"Synology"}, "attr_url": {"https://nas1.lan:5001"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	nas := strings.TrimPrefix(strings.Split(resp.Header.Get("Location"), "?")[0], "/cis/")

	// Relate it to the host; the graph and both sides show it.
	resp, _ = h.do(ops, "POST", "/cis/"+nas+"/relationships", url.Values{"kind": {"connected_to"}, "other": {web.HostID}, "direction": {"in"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("relate: %s", resp.Header.Get("Location"))
	}
	_, body = h.do(ops, "GET", "/cis/"+nas, nil)
	if !strings.Contains(body, "<svg class=\"rel-graph\"") || !strings.Contains(body, "Synology") || !strings.Contains(body, "connected_to") ||
		!strings.Contains(body, `href="https://nas1.lan:5001"`) {
		t.Fatalf("CI page:\n%s", body)
	}
	_, body = h.do(ops, "GET", "/cis/"+web.HostID, nil)
	if !strings.Contains(body, "nas1") || !strings.Contains(body, "Open host page") {
		t.Fatalf("host CI page:\n%s", body)
	}

	// Edit, with history.
	h.do(ops, "POST", "/cis/"+nas, url.Values{"name": {"nas1"}, "status": {"active"}, "attr_vendor": {"QNAP"}})
	_, body = h.do(ops, "GET", "/cis/"+nas, nil)
	if !strings.Contains(body, "attrs.vendor") || !strings.Contains(body, "QNAP") {
		t.Fatalf("after edit:\n%s", body)
	}

	// A viewer sees the CI list and agentless CIs but can't edit.
	viewer := h.signIn("vic", "viewers")
	_, body = h.do(viewer, "GET", "/cis", nil)
	if !strings.Contains(body, "nas1") || !strings.Contains(body, "web1") || strings.Contains(body, "New CI") {
		t.Fatalf("viewer list:\n%s", body)
	}
	if resp, _ := h.do(viewer, "POST", "/cis/"+nas, url.Values{"name": {"x"}, "status": {"active"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer edited: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "POST", "/cis/"+nas+"/delete", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer deleted: %d", resp.StatusCode)
	}
	// A user scoped to another group doesn't see the host's CI.
	scoped := h.signIn("sam", "media-viewers")
	_, body = h.do(scoped, "GET", "/cis", nil)
	if !strings.Contains(body, "nas1") || strings.Contains(body, "web1") {
		t.Fatalf("scoped list:\n%s", body)
	}
	if resp, _ := h.do(scoped, "GET", "/cis/"+web.HostID, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("scoped user saw the host CI: %d", resp.StatusCode)
	}
	// Discovered CIs can't be edited.
	if resp, body := h.do(ops, "POST", "/cis/"+web.HostID, url.Values{"type": {"nas"}, "name": {"x"}, "status": {"active"}}); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "maintained by discovery") {
		t.Fatalf("edited a host CI: %d", resp.StatusCode)
	}

	resp, _ = h.do(ops, "POST", "/cis/"+nas+"/delete", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if !strings.Contains(h.auditActions(), "ci.create") || !strings.Contains(h.auditActions(), "ci.delete") {
		t.Fatalf("audit = %s", h.auditActions())
	}
}

func TestRegistrySettings(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	resp, _ := h.do(admin, "POST", "/settings/registries", url.Values{"registry": {"https://index.docker.io/"}, "username": {"me"}, "secret": {"hunter2"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	_, body := h.do(admin, "GET", "/settings/registries", nil)
	if !strings.Contains(body, ">docker.io<") || strings.Contains(body, "hunter2") {
		t.Fatalf("registries:\n%s", body)
	}
	creds, err := RegistryCredentials(context.Background(), h.st, h.srv.secrets)
	if err != nil || creds["docker.io"] != [2]string{"me", "hunter2"} {
		t.Fatalf("credentials = %v %v", creds, err)
	}
	ops := h.signIn("olga", "ops-nobody")
	if resp, _ := h.do(ops, "GET", "/settings/registries", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: %d", resp.StatusCode)
	}
}

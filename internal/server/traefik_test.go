package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestTraefikHostnamesPages(t *testing.T) {
	h := newHarness(t)
	plex := h.addHost("plex")
	c := containersFixture()
	c.Containers[0].Labels = map[string]string{
		"traefik.http.routers.plex.rule":        "Host(`plex.example.com`)",
		"traefik.http.routers.plex.entrypoints": "websecure",
	}
	h.ingest(plex, model.SectionContainers, c)
	admin := h.signIn("ann", "lab-admins")

	_, body := h.do(admin, "GET", "/containers", nil)
	resp, body := h.do(admin, "GET", firstLink(t, body, `/containers/[0-9a-f-]{36}`), nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "<h2>Hostnames</h2>") ||
		!strings.Contains(body, `href="https://plex.example.com"`) || !strings.Contains(body, "router plex · websecure") {
		t.Fatalf("container page %d:\n%s", resp.StatusCode, body)
	}
	m := regexp.MustCompile(`href="(/cis/[0-9a-f-]{36})">CI</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link to the hostname's CI:\n%s", body)
	}
	resp, stack := h.do(admin, "GET", firstLink(t, body, `/stacks/[0-9a-f-]{36}`), nil)
	if resp.StatusCode != 200 || !strings.Contains(stack, `href="https://plex.example.com"`) {
		t.Fatalf("stack page %d:\n%s", resp.StatusCode, stack)
	}

	// The CI's page shows the discovered fields and can't be edited.
	_, body = h.list(admin, "/cis?type=service_endpoint")
	if !strings.Contains(body, "plex.example.com") {
		t.Fatalf("CI list:\n%s", body)
	}
	resp, body = h.do(admin, "GET", m[1], nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "<h1>plex.example.com</h1>") || !strings.Contains(body, "Traefik routers") ||
		!strings.Contains(body, "<strong>hosted_by</strong>") || !strings.Contains(body, "<strong>member_of</strong>") ||
		strings.Contains(body, `/edit"`) {
		t.Fatalf("CI page %d:\n%s", resp.StatusCode, body)
	}
	// Service endpoints added by hand don't get the discovered fields.
	_, body = h.do(admin, "GET", "/cis/new?type=service_endpoint", nil)
	if !strings.Contains(body, `name="attr_url"`) || strings.Contains(body, `name="attr_routers"`) {
		t.Fatalf("new CI form:\n%s", body)
	}

	// The host's Containers tab: what routes its hostnames.
	_, body = h.do(admin, "GET", "/hosts/"+plex.HostID+"/containers", nil)
	if !strings.Contains(body, "<h2>Traefik</h2>") || !strings.Contains(body, "no Traefik Baseline knows of") {
		t.Fatalf("containers tab:\n%s", body)
	}
	edge := h.addHost("edge")
	h.ingest(edge, model.SectionContainers, model.Containers{
		Engines:    []model.ContainerEngine{{Name: "docker", Kind: "docker"}},
		Containers: []model.Container{{Engine: "docker", Name: "traefik", ID: "t1", Image: "traefik:v3.1", State: "running"}},
	})
	_, body = h.do(admin, "GET", "/hosts/"+plex.HostID+"/containers", nil)
	m = regexp.MustCompile(`<option value="([0-9a-f-]{36})">traefik \(container\)</option>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Traefik container offered:\n%s", body)
	}
	resp, _ = h.do(admin, "POST", "/hosts/"+plex.HostID+"/traefik", url.Values{"traefik": {m[1]}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set traefik: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", "/hosts/"+plex.HostID+"/containers", nil)
	if !strings.Contains(body, ">traefik</a> <span class=\"muted small\">(container on another node)</span>") {
		t.Fatalf("routing not shown:\n%s", body)
	}
	// Only offered CIs can be picked.
	if resp, _ = h.do(admin, "POST", "/hosts/"+plex.HostID+"/traefik", url.Values{"traefik": {plex.HostID}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("routed by itself: %d", resp.StatusCode)
	}

	// An older agent masked a router named like a secret.
	c.Containers[0].Labels["traefik.http.routers.auth.rule"] = "********"
	h.ingest(plex, model.SectionContainers, c)
	_, body = h.list(admin, "/containers?q=plex")
	_, body = h.do(admin, "GET", firstLink(t, body, `/containers/[0-9a-f-]{36}`), nil)
	if !strings.Contains(body, "masked the rule of Traefik router auth as if") {
		t.Fatalf("no masked-rule notice:\n%s", body)
	}
}

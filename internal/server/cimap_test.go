package server

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestCIMap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.ingest(plex, model.SectionContainers, containersFixture())
	other := containersFixture()
	other.Containers[0].Name, other.Containers[0].State, other.Stacks = "pihole", "exited", nil
	other.Containers[0].Image = "pihole/pihole:2025.01"
	other.Containers[0].ComposeProject, other.Containers[0].ComposeService = "", ""
	h.ingest(dns, model.SectionContainers, other)
	h.st.SaveImageCheck(ctx, "docker.io/plexinc/pms-docker:1.41.0", "docker.io", "sha256:"+strings.Repeat("2", 64), "")
	sw, err := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "network_device", Name: "switch1", Status: "active", Tags: []string{"core"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.AddRelationship(ctx, store.System, sw, plex.HostID, "connected_to"); err != nil {
		t.Fatal(err)
	}
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Viewer, ScopeGroupID: media.ID})

	load := func(c string) (mapData, map[string]mapNode) {
		t.Helper()
		resp, body := h.do(h.signIn(c, map[string]string{"ann": "lab-admins", "carl": "media-ops"}[c]), "GET", "/map.json", nil)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("map.json: %d %s", resp.StatusCode, body)
		}
		var d mapData
		if err := json.Unmarshal([]byte(body), &d); err != nil {
			t.Fatal(err)
		}
		byName := map[string]mapNode{}
		for _, n := range d.Nodes {
			byName[n.Name] = n
		}
		return d, byName
	}
	names := func(d mapData, id string) string { // "kind:name" of the other end
		var out []string
		for _, e := range d.Edges {
			for _, n := range d.Nodes {
				if e.From == id && n.ID == e.To {
					out = append(out, e.Kind+">"+n.Name)
				}
				if e.To == id && n.ID == e.From {
					out = append(out, e.Kind+"<"+n.Name)
				}
			}
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}

	admin := h.signIn("ann", "lab-admins")
	resp, body := h.do(admin, "GET", "/map", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "/static/cimap.js") || !strings.Contains(body, `data-src="/map.json"`) ||
		!strings.Contains(body, `href="/map" aria-current="page"`) {
		t.Fatalf("map page: %d\n%s", resp.StatusCode, body)
	}

	// An admin sees everything: hosts, containers, the stack and the switch,
	// with every relationship between them.
	d, by := load("ann")
	for _, n := range []string{"plex", "dns1", "media-plex-1", "media", "pihole", "switch1"} {
		if _, ok := by[n]; !ok {
			t.Fatalf("map lacks %s: %+v", n, d.Nodes)
		}
	}
	if got := names(d, by["plex"].ID); got != "connected_to<switch1 runs_on<media runs_on<media-plex-1" {
		t.Fatalf("plex edges: %s", got)
	}
	if got := names(d, by["media-plex-1"].ID); got != "member_of>media runs_on>plex" {
		t.Fatalf("container edges: %s", got)
	}
	for _, e := range d.Edges {
		if e.Manual != (e.Kind == "connected_to") {
			t.Fatalf("manual flag: %+v", e)
		}
	}
	if p := by["plex"]; !slices.Equal(p.Groups, []string{media.ID}) || p.Link != "/hosts/"+p.ID || p.Type != "host" {
		t.Fatalf("plex node: %+v", p)
	}
	if c := by["media-plex-1"]; c.Host != "plex" || c.Link != "/containers/"+c.ID {
		t.Fatalf("container node: %+v", c)
	}
	if len(d.Groups) != 1 || d.Groups[0].Label != "media" || len(d.Kinds) != len(store.RelationKinds) ||
		!slices.ContainsFunc(d.Types, func(o mapOption) bool { return o.Key == "network_device" }) {
		t.Fatalf("options: %+v %+v %+v", d.Groups, d.Kinds, d.Types)
	}

	// Health: the hosts' agents aren't connected, plex's image moved on,
	// pihole is stopped, and the switch has nothing to judge.
	if p := by["plex"]; p.Health != "bad" || !slices.Contains(p.Notes, "agent offline") {
		t.Fatalf("plex health: %+v", p)
	}
	if c := by["media-plex-1"]; c.Health != "warn" || !slices.Contains(c.Notes, "newer image") {
		t.Fatalf("container health: %+v", c)
	}
	if c := by["pihole"]; c.Health != "off" || !slices.Contains(c.Notes, "exited") {
		t.Fatalf("stopped container health: %+v", c)
	}
	if s := by["switch1"]; s.Health != "ok" || len(s.Notes) != 0 || !slices.Equal(s.Tags, []string{"core"}) || s.Source != "manual" {
		t.Fatalf("switch: %+v", s)
	}

	// A scoped viewer sees their group's hosts and the agentless switch,
	// and no relationship reaching outside.
	d, by = load("carl")
	if _, ok := by["dns1"]; ok {
		t.Fatalf("scoped map shows dns1: %+v", d.Nodes)
	}
	if _, ok := by["pihole"]; ok {
		t.Fatalf("scoped map shows pihole: %+v", d.Nodes)
	}
	if got := names(d, by["plex"].ID); got != "connected_to<switch1 runs_on<media runs_on<media-plex-1" {
		t.Fatalf("scoped plex edges: %s", got)
	}
	if len(d.Nodes) != 4 || len(d.Edges) != 4 {
		t.Fatalf("scoped map: %d nodes %d edges", len(d.Nodes), len(d.Edges))
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/store"
)

// The CI map draws every CI the user can see and every relationship between
// them. The page is a shell; web/static/cimap.js fetches /map.json, lays the
// graph out and does the filtering, focus and export in the browser.

// mapNode is one CI on the map. Health is ok, warn, bad or off (stopped on
// purpose, planned or retired), with the reasons in Notes.
type mapNode struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Status string   `json:"status"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
	Groups []string `json:"groups"`
	Host   string   `json:"host,omitempty"` // the host a discovered CI lives on
	Link   string   `json:"link"`
	Health string   `json:"health"`
	Notes  []string `json:"notes"`
}

type mapEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Manual bool   `json:"manual,omitempty"`
}

type mapOption struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type mapData struct {
	Types  []mapOption `json:"types"`
	Kinds  []string    `json:"kinds"`
	Groups []mapOption `json:"groups"`
	Nodes  []mapNode   `json:"nodes"`
	Edges  []mapEdge   `json:"edges"`
}

// mapLimit caps the CIs on the map. A homelab has hundreds; past this the
// browser's layout would crawl anyway.
const mapLimit = 20000

func (s *Server) ciMap(w http.ResponseWriter, r *http.Request) {
	s.pages.render(w, http.StatusOK, "cimap", s.data(r, "CI map", nil))
}

func (s *Server) ciMapJSON(w http.ResponseWriter, r *http.Request) {
	d, err := s.mapData(r)
	if err != nil {
		s.log.Log("Server", "map", jw6_utils.Error, err.Error())
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(d)
}

// mapData is every CI the user can see, whatever its status, and the
// relationships whose both ends they can see. The browser filters.
func (s *Server) mapData(r *http.Request) (mapData, error) {
	ctx := r.Context()
	d := mapData{Kinds: store.RelationKinds, Nodes: []mapNode{}, Edges: []mapEdge{}, Groups: []mapOption{}}
	hosts, err := s.visibleHosts(r)
	if err != nil {
		return d, err
	}
	ids := make([]string, len(hosts))
	hostGroups := map[string][]string{}
	hostNames := map[string]string{}
	for i, h := range hosts {
		ids[i] = h.ID
		hostGroups[h.ID] = h.GroupIDs
		hostNames[h.ID] = h.Hostname
	}
	cis, err := s.store.ListCIs(ctx, store.CIFilter{Status: "all", HostIDs: ids, Limit: mapLimit})
	if err != nil {
		return d, err
	}
	types, err := s.store.CITypes(ctx)
	if err != nil {
		return d, err
	}
	for _, t := range types {
		d.Types = append(d.Types, mapOption{t.Key, t.Label})
	}

	d.Nodes = make([]mapNode, len(cis))
	byID := map[string]*mapNode{}
	for i, c := range cis {
		n := mapNode{ID: c.ID, Name: c.Name, Type: c.Type, Status: c.Status, Source: c.Source, Tags: c.Tags,
			Groups: hostGroups[c.HostID], Host: hostNames[c.HostID], Link: s.url(ciLink(c)), Health: "ok", Notes: []string{}}
		if n.Tags == nil {
			n.Tags = []string{}
		}
		if n.Groups == nil {
			n.Groups = []string{}
		}
		switch c.Status {
		case "missing":
			n.Health = "bad"
			n.Notes = append(n.Notes, "missing from discovery")
		case "retired", "planned":
			n.Health = "off"
		}
		d.Nodes[i] = n
		byID[c.ID] = &d.Nodes[i]
	}
	if err := s.mapHealth(r, hosts, ids, byID); err != nil {
		return d, err
	}

	rels, err := s.store.AllRelationships(ctx)
	if err != nil {
		return d, err
	}
	for _, e := range rels {
		if byID[e.From] != nil && byID[e.To] != nil {
			d.Edges = append(d.Edges, mapEdge{From: e.From, To: e.To, Kind: e.Kind, Manual: e.Source == "manual"})
		}
	}

	groups, err := s.store.ListHostGroups(ctx)
	if err != nil {
		return d, err
	}
	used := map[string]bool{}
	for _, n := range d.Nodes {
		for _, g := range n.Groups {
			used[g] = true
		}
	}
	for _, g := range groups {
		if used[g.ID] {
			d.Groups = append(d.Groups, mapOption{g.ID, g.Name})
		}
	}
	return d, nil
}

// mapHealth marks the nodes that need attention: hosts that are offline or
// owe updates or a reboot, containers that stopped or have a newer image,
// guests that aren't running, Kubernetes objects short of ready replicas,
// and anything with a firing alert.
func (s *Server) mapHealth(r *http.Request, hosts []store.Host, ids []string, nodes map[string]*mapNode) error {
	ctx := r.Context()
	rank := map[string]int{"ok": 0, "off": 0, "warn": 1, "bad": 2}
	// worse raises a node's health to level, never lowers it, and notes
	// why. "ok" only adds the note.
	worse := func(id, level, note string) {
		n := nodes[id]
		if n == nil || n.Status == "retired" {
			return
		}
		if rank[level] > rank[n.Health] {
			n.Health = level
		}
		n.Notes = append(n.Notes, note)
	}
	// stopped marks something switched off on purpose: grey, unless
	// something is wrong with it too.
	stopped := func(id, state string) {
		if n := nodes[id]; n != nil && n.Health == "ok" {
			n.Health = "off"
		}
		worse(id, "ok", state)
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}

	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		if !h.Connected {
			worse(h.ID, "bad", "agent offline")
		}
		if h.DisksFailing > 0 {
			worse(h.ID, "bad", plural(h.DisksFailing, "drive failing", "drives failing"))
		}
		if h.FailedServices > 0 {
			worse(h.ID, "warn", plural(h.FailedServices, "failed service", "failed services"))
		}
		if h.DisksDegrading > 0 {
			worse(h.ID, "warn", plural(h.DisksDegrading, "drive degrading", "drives degrading"))
		}
		if h.SecurityUpdates > 0 {
			worse(h.ID, "warn", plural(h.SecurityUpdates, "security update", "security updates"))
		} else if h.Updates > 0 {
			worse(h.ID, "ok", plural(h.Updates, "update", "updates"))
		}
		if h.RebootRequired {
			worse(h.ID, "warn", "reboot required")
		}
		if h.CertsExpiring > 0 {
			worse(h.ID, "warn", plural(h.CertsExpiring, "certificate expiring", "certificates expiring"))
		}
	}

	ctrs, err := s.store.ListContainers(ctx, ids)
	if err != nil {
		return err
	}
	for _, c := range ctrs {
		switch c.State {
		case "running":
		case "restarting", "dead":
			worse(c.CIID, "bad", c.State)
		default:
			stopped(c.CIID, c.State)
		}
		if c.Health == "unhealthy" {
			worse(c.CIID, "bad", "unhealthy")
		}
		if c.Drift && !c.Pinned {
			worse(c.CIID, "warn", "newer image")
		}
	}

	guests, err := s.store.ListGuests(ctx, ids)
	if err != nil {
		return err
	}
	for _, g := range guests {
		switch g.State {
		case "running", "":
		case "crashed":
			worse(g.CIID, "bad", g.State)
		default:
			stopped(g.CIID, g.State)
		}
	}

	clusters, err := s.store.ListClusters(ctx, ids)
	if err != nil {
		return err
	}
	for _, cl := range clusters {
		if !cl.Connected {
			worse(cl.CIID, "bad", "cluster agent offline")
		}
		objs, err := s.store.ClusterObjects(ctx, cl.CIID)
		if err != nil {
			return err
		}
		for _, o := range objs {
			switch {
			case !o.Present:
			case o.Kind == "Node":
				if !o.Node.Ready {
					worse(o.CIID, "bad", "not ready")
				}
				if o.Node.Unschedulable {
					worse(o.CIID, "warn", "cordoned")
				}
			case o.Workload.Kind != "CronJob" && o.Workload.Ready < o.Workload.Replicas:
				worse(o.CIID, "warn", fmt.Sprintf("%d/%d ready", o.Workload.Ready, o.Workload.Replicas))
			}
		}
	}

	alerts, err := s.store.ListAlerts(ctx, store.AlertFilter{Open: true})
	if err != nil {
		return err
	}
	for _, a := range alerts {
		if a.State != store.AlertFiring {
			continue
		}
		level := "warn"
		if a.Severity == "critical" {
			level = "bad"
		}
		worse(a.CIID, level, "alert: "+a.RuleName)
	}
	for _, n := range nodes {
		if len(n.Notes) > 6 {
			n.Notes = append(n.Notes[:5], fmt.Sprintf("and %d more", len(n.Notes)-5))
		}
	}
	return nil
}

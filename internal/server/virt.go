package server

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Virtual machines -------------------------------------------------------------

type vmsView struct {
	List *listView

	Total, Running, WithAgent, Hypervisors int
}

// vms lists the guests of every hypervisor the user can see.
func (s *Server) vms(w http.ResponseWriter, r *http.Request) {
	l, ok := s.buildList(w, r, "vm")
	if !ok {
		return
	}
	v := vmsView{List: l}
	if !isHTMX(r) {
		ids, err := s.visibleHostIDs(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		all, err := s.store.ListGuests(r.Context(), ids)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		hypervisors := map[string]bool{}
		for _, g := range all {
			if !g.Present {
				continue
			}
			v.Total++
			hypervisors[g.HostID] = true
			if g.State == "running" {
				v.Running++
			}
			if g.AgentHostID != "" {
				v.WithAgent++
			}
		}
		v.Hypervisors = len(hypervisors)
	}
	s.renderList(w, r, "vms", "Virtual machines", v, l)
}

type vmView struct {
	Guest store.Guest
	Seen  time.Time // the CI's last_seen, for a guest that's gone
}

func (s *Server) vmPage(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetGuest(r.Context(), r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	ids, ierr := s.visibleHostIDs(r)
	if ierr != nil {
		s.serverError(w, r, ierr)
		return
	}
	// Don't confirm that a guest exists to someone who can't see its
	// hypervisor.
	if err != nil || !slices.Contains(ids, g.HostID) {
		s.errorPage(w, r, http.StatusNotFound, "No such virtual machine.")
		return
	}
	v := vmView{Guest: g}
	if !g.Present {
		c, err := s.store.GetCI(r.Context(), g.CIID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		v.Seen = c.LastSeen
	}
	s.pages.render(w, http.StatusOK, "vm", s.data(r, g.Name, v))
}

// Kubernetes -------------------------------------------------------------------

type clustersView struct {
	Clusters []store.Cluster
	// Waiting are cluster agents that haven't reported a cluster yet. The
	// Hosts list leaves cluster agents out, so this is where they show.
	Waiting []store.Host
}

// clusters lists the Kubernetes clusters whose agents the user can see.
func (s *Server) clusters(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ids := make([]string, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	cs, err := s.store.ListClusters(r.Context(), ids)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := clustersView{Clusters: cs}
	for _, h := range hosts {
		if h.ClusterAgent() && !h.Revoked && !slices.ContainsFunc(cs, func(c store.Cluster) bool { return c.HostID == h.ID }) {
			v.Waiting = append(v.Waiting, h)
		}
	}
	s.pages.render(w, http.StatusOK, "clusters", s.data(r, "Kubernetes", v))
}

var clusterTabs = []string{"nodes", "workloads", "services", "ingresses", "manifests"}

type clusterView struct {
	Cluster   store.Cluster
	Tab       string
	Query     string
	Section   *model.K8s
	SectionAt time.Time
	Nodes     []store.K8sObject
	Workloads []store.K8sObject
	Services  []model.K8sService
	Ingresses []model.K8sIngress
	// Endpoints map ingress hostnames to their service_endpoint CIs.
	Endpoints  map[string]string
	Namespaces []string
	Namespace  string
	// Gone are nodes and workloads the cluster no longer has.
	Gone int
	// Bundles are the manifests Baseline applied (k8s.deploy, k8s.edit).
	Bundles []store.Bundle
	// CanDeploy: the user may apply manifests to the cluster; DeployBlock
	// says why the agent can't, if it can't.
	CanDeploy   bool
	DeployBlock string
}

func (s *Server) clusterPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.store.GetCluster(ctx, r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	ids, ierr := s.visibleHostIDs(r)
	if ierr != nil {
		s.serverError(w, r, ierr)
		return
	}
	if err != nil || !slices.Contains(ids, c.HostID) {
		s.errorPage(w, r, http.StatusNotFound, "No such cluster.")
		return
	}
	q := r.URL.Query()
	v := clusterView{Cluster: c, Tab: q.Get("tab"), Query: strings.TrimSpace(q.Get("q")), Namespace: q.Get("ns")}
	if !slices.Contains(clusterTabs, v.Tab) {
		v.Tab = "nodes"
	}
	var k model.K8s
	if v.SectionAt, err = s.section(r, c.HostID, model.SectionK8s, &k); err == nil {
		v.Section = &k
		v.Namespaces = k.Namespaces
	} else if !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	objs, err := s.store.ClusterObjects(ctx, c.CIID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	match := func(ns string, fields ...string) bool {
		if v.Namespace != "" && ns != v.Namespace {
			return false
		}
		lq := strings.ToLower(v.Query)
		return lq == "" || strings.Contains(strings.ToLower(ns+"/"+strings.Join(fields, " ")), lq)
	}
	for _, o := range objs {
		if !o.Present {
			v.Gone++
		}
		switch {
		case o.Kind == "Node":
			v.Nodes = append(v.Nodes, o)
		case match(o.Namespace, append([]string{o.Name, o.Kind}, o.Workload.Images...)...):
			v.Workloads = append(v.Workloads, o)
		}
	}
	if v.Section != nil {
		for _, sv := range k.Services {
			if match(sv.Namespace, sv.Name, sv.Type, sv.ClusterIP, strings.Join(sv.ExternalIPs, " ")) {
				v.Services = append(v.Services, sv)
			}
		}
		for _, in := range k.Ingresses {
			if match(in.Namespace, append([]string{in.Name, in.Class}, in.Hosts...)...) {
				v.Ingresses = append(v.Ingresses, in)
			}
		}
	}
	if v.Tab == "ingresses" {
		if v.Endpoints, err = s.store.ClusterEndpoints(ctx, c.CIID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if v.Tab == "manifests" {
		if v.Bundles, err = s.store.ClusterBundles(ctx, c.CIID); err != nil {
			s.serverError(w, r, err)
			return
		}
		if h, err := s.store.GetHost(ctx, c.HostID); err == nil && principal(r).Grants.HasOn(rbac.Operator, h.GroupIDs) {
			v.CanDeploy = true
			v.DeployBlock = manifestClusterBlock(action.MustGet(action.K8sDeploy), h)
		}
	}
	s.pages.render(w, http.StatusOK, "cluster", s.data(r, c.Name, v))
}

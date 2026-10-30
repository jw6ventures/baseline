package server

import (
	"encoding/json"
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

// Me, actions, dashboard ---------------------------------------------------------

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	t := p.Token
	out := meJSON{
		User:   userJSON{ID: p.User.ID, Email: p.User.Email, Name: p.User.Name, Subject: p.User.OIDCSub},
		Token:  tokenJSON{ID: t.ID, Name: t.Name, Roles: t.Roles, CreatedAt: t.CreatedAt, ExpiresAt: ts(t.ExpiresAt)},
		Global: p.Grants.Global(), Scoped: []scopedJSON{}, Groups: strs(p.Groups),
	}
	if out.Global == nil {
		out.Global = []rbac.Role{}
	}
	if scoped := p.Grants.Scoped(); len(scoped) > 0 {
		groups, err := s.store.ListHostGroups(r.Context())
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		for _, hg := range groups {
			if roles, ok := scoped[hg.ID]; ok {
				out.Scoped = append(out.Scoped, scopedJSON{GroupID: hg.ID, GroupName: hg.Name, Roles: roles})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiActions(w http.ResponseWriter, r *http.Request) {
	out := make([]actionJSON, 0, len(action.Names))
	for _, n := range action.Names {
		sp := action.MustGet(n)
		out = append(out, actionJSON{Name: sp.Name, Label: sp.Label, Category: sp.Category, Risk: string(sp.Risk),
			TimeoutS: int(sp.Timeout / time.Second), Needs: strs(sp.Needs), Sections: strs(sp.Sections)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiDashboard(w http.ResponseWriter, r *http.Request) {
	v, err := s.dashboardData(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dashboardToJSON(v))
}

// Hosts -------------------------------------------------------------------------

func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	q := r.URL.Query()
	if lq := strings.ToLower(strings.TrimSpace(q.Get("q"))); lq != "" {
		hosts = slices.DeleteFunc(hosts, func(h store.Host) bool {
			hay := strings.ToLower(strings.Join(append([]string{h.Hostname, h.FQDN, h.OSPretty, h.Kernel}, h.GroupNames...), " "))
			return !strings.Contains(hay, lq)
		})
	}
	if g := q.Get("group"); g != "" {
		hosts = slices.DeleteFunc(hosts, func(h store.Host) bool { return !slices.Contains(h.GroupIDs, g) })
	}
	if queryBool(r, "connected") {
		hosts = slices.DeleteFunc(hosts, func(h store.Host) bool { return !h.Connected })
	}
	if !queryBool(r, "revoked") {
		hosts = slices.DeleteFunc(hosts, func(h store.Host) bool { return h.Revoked })
	}
	writeJSON(w, http.StatusOK, hostsToJSON(hosts))
}

func (s *Server) apiHost(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, hostToJSON(h))
}

func (s *Server) apiHostSections(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	names, err := s.store.HostSectionNames(r.Context(), h.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out := make([]sectionJSON, 0, len(names))
	for _, n := range names {
		_, at, err := s.store.HostSection(r.Context(), h.ID, n)
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		out = append(out, sectionJSON{Section: n, CollectedAt: ts(at)})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiHostSection returns a stored inventory section as the agent reported
// it (types in internal/model).
func (s *Server) apiHostSection(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	name := r.PathValue("section")
	if !slices.Contains(model.Sections, name) {
		apiError(w, http.StatusNotFound, "no such section; one of "+strings.Join(model.Sections, ", "))
		return
	}
	data, at, err := s.store.HostSection(r.Context(), h.ID, name)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "the host hasn't reported this section")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sectionJSON{Section: name, CollectedAt: ts(at), Data: json.RawMessage(data)})
}

func (s *Server) apiHostPackages(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	pkgs, err := s.store.HostPackages(r.Context(), h.ID, strings.TrimSpace(r.URL.Query().Get("q")))
	if pkgs == nil {
		pkgs = []model.Package{}
	}
	s.respond(w, r, pkgs, err)
}

func (s *Server) apiHostUpdates(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	ups, err := s.store.HostUpdates(r.Context(), h.ID)
	out := make([]hostUpdateJSON, 0, len(ups))
	for _, u := range ups {
		out = append(out, hostUpdateJSON{Update: u.Update, FirstSeen: ts(u.FirstSeen)})
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiHostCerts(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	certs, err := s.store.CICerts(r.Context(), h.ID)
	s.respond(w, r, certsToJSON(certs), err)
}

func (s *Server) apiHostHistory(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	entries, err := s.store.HostHistory(r.Context(), h.ID, queryInt(r, "limit", 100, 1000))
	s.respond(w, r, historyToJSON(entries), err)
}

func (s *Server) apiHostMetricPanels(w http.ResponseWriter, r *http.Request) {
	if _, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	type panel struct {
		ID    string   `json:"id"`
		Title string   `json:"title"`
		Kind  string   `json:"kind"`
		Names []string `json:"names"`
		Unit  string   `json:"unit"`
	}
	type rng struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		StepS int    `json:"step_s"`
	}
	var out struct {
		Panels []panel `json:"panels"`
		Ranges []rng   `json:"ranges"`
	}
	for _, p := range metricPanels {
		out.Panels = append(out.Panels, panel{p.ID, p.Title, p.Kind, p.Names, p.Unit})
	}
	for _, g := range metricRanges {
		out.Ranges = append(out.Ranges, rng{g.Key, g.Label, int(g.Step / time.Second)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiHostMetrics(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	p, ok := findPanel(r.PathValue("panel"))
	if !ok {
		apiError(w, http.StatusNotFound, "no such panel; GET /hosts/{id}/metrics lists them")
		return
	}
	c, err := s.panelData(r, h.ID, p, findRange(r.URL.Query().Get("range")))
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, chartJSON(c, s.cfg.Location.String()))
}

func (s *Server) apiHostJobs(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), store.JobFilter{HostID: h.ID, States: jobFilters[r.URL.Query().Get("show")],
		Limit: queryInt(r, "limit", 100, 1000)})
	s.respond(w, r, jobsToJSON(jobs), err)
}

func (s *Server) apiHostChanges(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	changes, err := s.listChangesJSON(r, store.ChangeFilter{HostID: h.ID})
	s.respond(w, r, changes, err)
}

func (s *Server) apiHostVulns(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	f := vulnFilterFrom(r, []string{h.ID})
	matches, err := s.store.HostVulns(r.Context(), f)
	s.respond(w, r, hostVulnsToJSON(matches), err)
}

func (s *Server) apiHostAlerts(w http.ResponseWriter, r *http.Request) {
	h, err := s.apiLoadHost(r, r.PathValue("id"), rbac.Viewer)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	f := store.AlertFilter{Open: true, CIID: h.ID}
	if queryBool(r, "history") {
		f = store.AlertFilter{Resolved: time.Now().Add(-time.Duration(queryInt(r, "days", 7, 90)) * 24 * time.Hour), CIID: h.ID}
	}
	alerts, err := s.store.ListAlerts(r.Context(), f)
	out := make([]alertJSON, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, alertToJSON(a))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiHostGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListHostGroups(r.Context())
	out := make([]hostGroupJSON, 0, len(groups))
	for _, g := range groups {
		out = append(out, hostGroupJSON{ID: g.ID, Name: g.Name, Description: g.Description, CreatedAt: ts(g.CreatedAt)})
	}
	s.respond(w, r, out, err)
}

// apiUpdates lists pending updates by package across the hosts the user
// can see, as the Updates page's package view does.
func (s *Server) apiUpdates(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var ids []string
	for _, h := range hosts {
		if !h.Revoked {
			ids = append(ids, h.ID)
		}
	}
	pkgs, err := s.store.UpdatesByPackage(r.Context(), ids, strings.TrimSpace(r.URL.Query().Get("q")), queryBool(r, "security"))
	out := make([]packageUpdateJSON, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, packageUpdateJSON{Manager: p.Manager, Name: p.Name, Candidates: strs(p.Candidates),
			Security: p.Security, Image: p.Image, Hosts: refs(p.HostIDs, p.Hosts), FirstSeen: ts(p.FirstSeen)})
	}
	s.respond(w, r, out, err)
}

// Containers, stacks, VMs, Kubernetes ----------------------------------------------

func (s *Server) apiContainers(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	q := r.URL.Query()
	if h := q.Get("host"); h != "" {
		if !slices.Contains(ids, h) {
			writeJSON(w, http.StatusOK, []containerJSON{})
			return
		}
		ids = []string{h}
	}
	rows, err := s.store.ListContainers(r.Context(), ids)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	stacks, err := s.store.ListStacks(r.Context(), ids)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	views, err := s.containerViews(r, rows, stacks)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	lq := strings.ToLower(strings.TrimSpace(q.Get("q")))
	updates := queryBool(r, "updates")
	views = slices.DeleteFunc(views, func(c containerView) bool {
		if updates && !c.HasUpdate() {
			return true
		}
		if st := q.Get("stack"); st != "" && c.StackCI != st {
			return true
		}
		return lq != "" && !strings.Contains(strings.ToLower(strings.Join([]string{c.Name, c.Image, c.Hostname, c.ComposeProject}, " ")), lq)
	})
	writeJSON(w, http.StatusOK, containersToJSON(views))
}

func (s *Server) apiLoadContainer(r *http.Request, id string) (containerView, error) {
	c, err := s.store.GetContainer(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return containerView{}, errAPINotFound
	}
	if err != nil {
		return containerView{}, err
	}
	if _, err := s.apiLoadHost(r, c.HostID, rbac.Viewer); err != nil {
		return containerView{}, err
	}
	var stacks []store.Stack
	if c.StackCI != "" {
		if st, err := s.store.GetStack(r.Context(), c.StackCI); err == nil {
			stacks = []store.Stack{st}
		}
	}
	views, err := s.containerViews(r, []store.ContainerRow{c}, stacks)
	if err != nil {
		return containerView{}, err
	}
	return views[0], nil
}

func (s *Server) apiContainer(w http.ResponseWriter, r *http.Request) {
	c, err := s.apiLoadContainer(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, containerToJSON(c))
}

func (s *Server) apiStacks(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if h := r.URL.Query().Get("host"); h != "" {
		if !slices.Contains(ids, h) {
			writeJSON(w, http.StatusOK, []stackJSON{})
			return
		}
		ids = []string{h}
	}
	stacks, err := s.store.ListStacks(r.Context(), ids)
	if lq := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); lq != "" {
		stacks = slices.DeleteFunc(stacks, func(st store.Stack) bool {
			return !strings.Contains(strings.ToLower(strings.Join([]string{st.Project, st.Hostname, st.WorkingDir, st.Environment,
				st.Category, st.Visibility}, " ")), lq)
		})
	}
	s.respond(w, r, stacksToJSON(stacks), err)
}

func (s *Server) apiStack(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err == nil {
		_, err = s.apiLoadHost(r, st.HostID, rbac.Viewer)
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	rows, err := s.store.ListContainers(r.Context(), []string{st.HostID})
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	rows = slices.DeleteFunc(rows, func(c store.ContainerRow) bool { return c.StackCI != st.CIID })
	views, err := s.containerViews(r, rows, []store.Stack{st})
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var out struct {
		stackJSON
		Containers []containerJSON `json:"containers"`
	}
	out.stackJSON, out.Containers = stackToJSON(st), containersToJSON(views)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVMs(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	all, err := s.store.ListGuests(r.Context(), ids)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	q := r.URL.Query()
	lq := strings.ToLower(strings.TrimSpace(q.Get("q")))
	out := make([]guestJSON, 0, len(all))
	for _, g := range all {
		if p := q.Get("platform"); p != "" && g.Platform != p {
			continue
		}
		if h := q.Get("host"); h != "" && g.HostID != h {
			continue
		}
		if !queryBool(r, "gone") && !g.Present {
			continue
		}
		if lq != "" && !strings.Contains(strings.ToLower(strings.Join(append([]string{g.Name, g.Hostname, g.AgentHostname,
			g.OSType, g.ID}, g.Tags...), " ")), lq) {
			continue
		}
		out = append(out, guestToJSON(g))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVM(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetGuest(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err == nil {
		// Don't confirm that a guest exists to someone who can't see its hypervisor.
		if _, herr := s.apiLoadHost(r, g.HostID, rbac.Viewer); herr != nil {
			err = errAPINotFound
		}
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, guestToJSON(g))
}

func (s *Server) apiClusters(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	cs, err := s.store.ListClusters(r.Context(), ids)
	out := make([]clusterJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, clusterToJSON(c))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiCluster(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.store.GetCluster(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err == nil {
		if _, herr := s.apiLoadHost(r, c.HostID, rbac.Viewer); herr != nil {
			err = errAPINotFound
		}
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var out struct {
		clusterJSON
		CollectedAt *time.Time         `json:"collected_at,omitempty"`
		Namespaces  []string           `json:"namespaces"`
		Nodes       []k8sObjectJSON    `json:"nodes"`
		Workloads   []k8sObjectJSON    `json:"workloads"`
		Services    []model.K8sService `json:"services"`
		Ingresses   []model.K8sIngress `json:"ingresses"`
		Cluster     *model.K8sCluster  `json:"cluster,omitempty"`
	}
	out.clusterJSON = clusterToJSON(c)
	out.Namespaces, out.Nodes, out.Workloads = []string{}, []k8sObjectJSON{}, []k8sObjectJSON{}
	out.Services, out.Ingresses = []model.K8sService{}, []model.K8sIngress{}
	var k model.K8s
	at, err := s.section(r, c.HostID, model.SectionK8s, &k)
	switch {
	case err == nil:
		out.CollectedAt = ts(at)
		out.Namespaces = strs(k.Namespaces)
		out.Cluster = &k.Cluster
		if k.Services != nil {
			out.Services = k.Services
		}
		if k.Ingresses != nil {
			out.Ingresses = k.Ingresses
		}
	case !errors.Is(err, store.ErrNotFound):
		s.apiServerError(w, r, err)
		return
	}
	objs, err := s.store.ClusterObjects(ctx, c.CIID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	ns := r.URL.Query().Get("namespace")
	for _, o := range objs {
		if o.Kind == "Node" {
			out.Nodes = append(out.Nodes, k8sObjectToJSON(o))
		} else if ns == "" || o.Namespace == ns {
			out.Workloads = append(out.Workloads, k8sObjectToJSON(o))
		}
	}
	if ns != "" {
		out.Services = slices.DeleteFunc(out.Services, func(sv model.K8sService) bool { return sv.Namespace != ns })
		out.Ingresses = slices.DeleteFunc(out.Ingresses, func(in model.K8sIngress) bool { return in.Namespace != ns })
	}
	writeJSON(w, http.StatusOK, out)
}

// CIs --------------------------------------------------------------------------

func (s *Server) apiCITypes(w http.ResponseWriter, r *http.Request) {
	types, err := s.store.CITypes(r.Context())
	out := make([]ciTypeJSON, 0, len(types))
	for _, t := range types {
		fields := t.Fields
		if fields == nil {
			fields = []store.CIField{}
		}
		out = append(out, ciTypeJSON{Key: t.Key, Label: t.Label, Fields: fields})
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiCIs(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	q := r.URL.Query()
	cis, err := s.store.ListCIs(r.Context(), store.CIFilter{Type: q.Get("type"), Status: q.Get("status"),
		Query: strings.TrimSpace(q.Get("q")), HostIDs: ids, Limit: queryInt(r, "limit", 500, 5000)})
	s.respond(w, r, cisToJSON(cis), err)
}

// apiLoadCI fetches a CI the user may see: agentless ones are visible to
// every viewer, discovered ones to whoever may see their host.
func (s *Server) apiLoadCI(r *http.Request, id string) (store.CI, []string, error) {
	c, err := s.store.GetCI(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return c, nil, err
	}
	_, ids, ierr := s.apiVisibleIDs(r)
	if ierr != nil {
		return c, nil, ierr
	}
	if err != nil || !canSeeCI(c, ids) {
		return c, nil, errAPINotFound
	}
	return c, ids, nil
}

func (s *Server) apiCI(w http.ResponseWriter, r *http.Request) {
	c, ids, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	rels, err := s.visibleRelationships(r, c.ID, ids)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var out struct {
		ciJSON
		Relationships []relationshipJSON `json:"relationships"`
	}
	out.ciJSON, out.Relationships = ciToJSON(c), relationshipsToJSON(rels)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) visibleRelationships(r *http.Request, ciID string, ids []string) ([]store.Relationship, error) {
	rels, err := s.store.CIRelationships(r.Context(), ciID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(rels, func(rel store.Relationship) bool { return !canSeeCI(rel.Other, ids) }), nil
}

func (s *Server) apiCIRelationships(w http.ResponseWriter, r *http.Request) {
	c, ids, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	rels, err := s.visibleRelationships(r, c.ID, ids)
	s.respond(w, r, relationshipsToJSON(rels), err)
}

func (s *Server) apiCIHistory(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	limit := queryInt(r, "limit", 100, 1000)
	var entries []store.HistoryEntry
	if c.Type == "host" {
		entries, err = s.store.HostHistory(r.Context(), c.ID, limit)
	} else {
		entries, err = s.store.CIHistory(r.Context(), c.ID, limit)
	}
	s.respond(w, r, historyToJSON(entries), err)
}

func (s *Server) apiCICerts(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	certs, err := s.store.CICerts(r.Context(), c.ID)
	s.respond(w, r, certsToJSON(certs), err)
}

func (s *Server) apiMap(w http.ResponseWriter, r *http.Request) {
	d, err := s.mapData(r)
	s.respond(w, r, d, err)
}

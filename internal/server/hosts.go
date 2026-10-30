package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/inventory"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// visibleHosts filters hosts to those the user can view: a global role, or
// a role scoped to one of the host's groups.
func (s *Server) visibleHosts(r *http.Request) ([]store.Host, error) {
	all, err := s.store.ListHosts(r.Context())
	if err != nil {
		return nil, err
	}
	g := principal(r).Grants
	var out []store.Host
	for _, h := range all {
		if g.HasOn(rbac.Viewer, h.GroupIDs) {
			out = append(out, h)
		}
	}
	return out, nil
}

type hostListView struct {
	IsAdmin bool
	List    *listView
}

func (s *Server) hostList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "host")
	if !ok {
		return
	}
	s.renderList(w, r, "hosts", "Hosts", hostListView{IsAdmin: principal(r).Grants.Has(rbac.Admin), List: v}, v)
}

// loadHost fetches the host in the path and checks the user may see it.
// It writes the error response itself and returns ok=false.
func (s *Server) loadHost(w http.ResponseWriter, r *http.Request, need rbac.Role) (store.Host, bool) {
	h, err := s.store.GetHost(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such host.")
		return h, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return h, false
	}
	g := principal(r).Grants
	if !g.HasOn(rbac.Viewer, h.GroupIDs) {
		// Don't confirm that a host exists to someone who can't see it.
		s.errorPage(w, r, http.StatusNotFound, "No such host.")
		return h, false
	}
	if !g.HasOn(need, h.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this on this host.")
		return h, false
	}
	return h, true
}

type hostView struct {
	Host       store.Host
	Tab        string
	Online     bool
	CanRefresh bool
	IsAdmin    bool
	Notice     string

	OS           *model.OS
	OSAt         time.Time
	Hardware     *model.Hardware
	HardwareAt   time.Time
	Smart        *model.Smart
	SmartAt      time.Time
	PackagesAt   time.Time
	Packages     []model.Package
	PackageQuery string
	Updates      []store.HostUpdate
	UpdateInfo   *model.Updates // warnings and holds
	UpdatesAt    time.Time
	Metrics      metricsView
	History      []historyView
	// List is the tab's related list (hostLists).
	List         *listView
	Traefik      store.TraefikRouting
	TraefikNodes []store.CI // what the host can be routed by
	Engines      []model.ContainerEngine
	ContainersAt time.Time
	Services     []model.Service
	ServicesAt   time.Time
	ServiceQuery string
	Ports        []model.Listener
	PortsAt      time.Time
	Certs        []store.CertRow
	CertsAt      time.Time
	Reboot       *model.Reboot
	AllGroups    []store.HostGroup
	// Latest is the newest published agent version, offered to admins.
	Latest string

	// Open alerts on the host (overview), and its vulnerabilities.
	Alerts       []store.Alert
	Vulns        []store.HostVuln
	FixableOnly  bool
	FixablePkgs  []string // packages whose upgrade fixes something
	VulnSeverity string

	// CanRun: the user may request changes on this host (operator).
	CanRun  bool
	Actions []hostAction

	Tabs []hostTab
	// Guest is the VM or container this host runs in; Node the Kubernetes
	// node it is; Cluster the cluster a cluster agent reports.
	Guest   *store.GuestOf
	Node    *store.NodeOf
	Cluster *store.Cluster
	// The hypervisor's guests (VMs tab) and the node's runtime (Kubernetes).
	VMs       *model.VMs
	VMsAt     time.Time
	K8sNode   *model.K8sNode
	K8sNodeAt time.Time
	Pods      []podView
}

// podView is a pod on a node with its containers, from crictl.
type podView struct {
	model.CRIPod
	Containers []model.CRIContainer
}

// hostAction is an action offered on a host's Jobs tab.
type hostAction struct {
	action.Spec
	Why string // why the host can't run it; "" if it can
}

// actionAllowed reports whether the host can run an action now, and why not.
func actionAllowed(h store.Host, name string) (bool, string) {
	spec, _ := action.Get(name)
	if ok, why := h.Policy.Allows(name); !ok {
		return false, why
	}
	return spec.Supported(h.Capabilities)
}

type historyView struct {
	At        time.Time
	Actor     string
	ChangeID  string // the change behind it; "" for an unplanned change
	ChangeRef string
	Section   string
	Initial   bool
	Summary   string
	Diff      inventory.Diff
}

var hostTabs = []string{"overview", "hardware", "packages", "updates", "vulnerabilities", "containers", "stacks", "vms",
	"kubernetes", "services", "ports", "certificates", "metrics", "jobs", "history", "settings"}

var tabLabels = map[string]string{"vms": "VMs"}

// hostTab is a tab of a host's page. Its related lists have their own
// paths (hostLists); the other tabs are ?tab=.
type hostTab struct{ Key, Label, URL string }

// tabsFor lists the tabs a host's page has: a cluster agent is no machine,
// the VMs and Kubernetes tabs only appear on hypervisors and nodes, and
// Stacks only on hosts that run Compose stacks.
func tabsFor(h store.Host, sections []string, node, stacks bool) []hostTab {
	var out []hostTab
	for _, t := range hostTabs {
		switch {
		case h.ClusterAgent() && t != "overview" && t != "history" && t != "settings":
			continue
		case t == "vms" && !slices.Contains(sections, model.SectionVMs):
			continue
		case t == "kubernetes" && !node && !slices.Contains(sections, model.SectionK8sNode):
			continue
		case t == "stacks" && !stacks:
			continue
		}
		label := tabLabels[t]
		if label == "" {
			label = strings.ToUpper(t[:1]) + t[1:]
		}
		u := "/hosts/" + h.ID + "?tab=" + t
		if _, ok := hostLists[t]; ok {
			u = "/hosts/" + h.ID + "/" + t
		}
		out = append(out, hostTab{t, label, u})
	}
	return out
}

func (s *Server) hostDetail(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tab := q.Get("tab")
	// Related lists moved to their own paths: keep old links working.
	if _, ok := hostLists[tab]; ok {
		q.Del("tab")
		u := "/hosts/" + r.PathValue("id") + "/" + tab
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		http.Redirect(w, r, s.url(u), http.StatusSeeOther)
		return
	}
	s.hostPage(w, r, tab)
}

// hostPage is a host's page open at a tab.
func (s *Server) hostPage(w http.ResponseWriter, r *http.Request, tab string) {
	h, ok := s.loadHost(w, r, rbac.Viewer)
	if !ok {
		return
	}
	ctx := r.Context()
	p := principal(r)
	v := hostView{
		Host: h, Tab: tab, Online: s.hub != nil && s.hub.Online(h.AgentID),
		CanRefresh: p.Grants.HasOn(rbac.Operator, h.GroupIDs), IsAdmin: p.Grants.Has(rbac.Admin),
		Notice: r.URL.Query().Get("notice"),
	}
	v.CanRun = v.CanRefresh && !h.Revoked && !h.ClusterAgent()
	sections, err := s.store.HostSectionNames(ctx, h.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n, err := s.store.HostNode(ctx, h.ID); err == nil {
		v.Node = &n
	} else if !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	stacks, err := s.store.ListStacks(ctx, []string{h.ID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Tabs = tabsFor(h, sections, v.Node != nil, len(stacks) > 0)
	if !slices.ContainsFunc(v.Tabs, func(t hostTab) bool { return t.Key == v.Tab }) {
		if _, ok := hostLists[v.Tab]; ok {
			http.Redirect(w, r, s.url("/hosts/"+h.ID), http.StatusSeeOther)
			return
		}
		v.Tab = "overview"
	}
	if _, ok := hostLists[v.Tab]; ok {
		if v.List, ok = s.hostListView(w, r, h.ID, v.Tab); !ok {
			return
		}
		// The list shows its own notices.
		v.Notice = ""
		if isHTMX(r) {
			s.renderList(w, r, "host", h.DisplayName(), v, v.List)
			return
		}
	}

	switch v.Tab {
	case "overview":
		var o model.OS
		if v.OSAt, err = s.section(r, h.ID, model.SectionOS, &o); err == nil {
			v.OS = &o
		}
		var hw model.Hardware
		if v.HardwareAt, err = s.section(r, h.ID, model.SectionHardware, &hw); err == nil {
			v.Hardware = &hw
		}
		var sm model.Smart
		if v.SmartAt, err = s.section(r, h.ID, model.SectionSmart, &sm); err == nil {
			sm.Devices = model.DedupeSmart(sm.Devices) // as stored from older agents
			v.Smart = &sm
		}
		var rb model.Reboot
		if _, err = s.section(r, h.ID, model.SectionReboot, &rb); err == nil {
			v.Reboot = &rb
		}
		if err == nil || errors.Is(err, store.ErrNotFound) {
			v.Alerts, err = s.store.ListAlerts(ctx, store.AlertFilter{Open: true, CIID: h.ID})
		}
		if err == nil {
			var g store.GuestOf
			if g, err = s.store.HostGuest(ctx, h.ID); err == nil {
				v.Guest = &g
			}
		}
		if (err == nil || errors.Is(err, store.ErrNotFound)) && h.ClusterAgent() {
			var c store.Cluster
			if c, err = s.store.ClusterOfAgent(ctx, h.ID); err == nil {
				v.Cluster = &c
			}
		}
		if v.IsAdmin && err == nil {
			var rels []store.ReleaseVersion
			if rels, err = s.store.ListReleases(ctx); err == nil && len(rels) > 0 {
				v.Latest = rels[0].Version
			}
		}
	case "hardware":
		var hw model.Hardware
		if v.HardwareAt, err = s.section(r, h.ID, model.SectionHardware, &hw); err == nil {
			v.Hardware = &hw
		}
		var sm model.Smart
		if v.SmartAt, err = s.section(r, h.ID, model.SectionSmart, &sm); err == nil {
			sm.Devices = model.DedupeSmart(sm.Devices) // as stored from older agents
			v.Smart = &sm
		}
	case "packages":
		v.PackageQuery = r.URL.Query().Get("q")
		v.Packages, err = s.store.HostPackages(ctx, h.ID, v.PackageQuery)
		if err == nil {
			_, v.PackagesAt, err = s.store.HostSection(ctx, h.ID, model.SectionPackages)
		}
	case "updates":
		var u model.Updates
		if v.UpdatesAt, err = s.section(r, h.ID, model.SectionUpdates, &u); err == nil {
			v.UpdateInfo = &u
			v.Updates, err = s.store.HostUpdates(ctx, h.ID)
		}
	case "vulnerabilities":
		q := r.URL.Query()
		v.FixableOnly, v.VulnSeverity = q.Get("fixable") != "0", q.Get("severity")
		if v.Vulns, err = s.store.HostVulns(ctx, store.VulnFilter{HostIDs: []string{h.ID}, FixableOnly: v.FixableOnly,
			MinSeverity: v.VulnSeverity, Limit: 5000}); err == nil {
			for _, m := range v.Vulns {
				if m.FixAvailable && !slices.Contains(v.FixablePkgs, m.Package) {
					v.FixablePkgs = append(v.FixablePkgs, m.Package)
				}
			}
			slices.Sort(v.FixablePkgs)
		}
	case "containers":
		var sec model.Containers
		if v.ContainersAt, err = s.section(r, h.ID, model.SectionContainers, &sec); err == nil {
			v.Engines = sec.Engines
		}
		if err == nil || errors.Is(err, store.ErrNotFound) {
			v.Traefik, err = s.store.HostTraefik(ctx, h.ID)
		}
		if err == nil && v.CanRefresh {
			var ids []string
			if ids, err = s.visibleHostIDs(r); err == nil {
				v.TraefikNodes, err = s.store.TraefikNodes(ctx, h.ID, ids)
			}
		}
	case "vms":
		var vm model.VMs
		if v.VMsAt, err = s.section(r, h.ID, model.SectionVMs, &vm); err == nil {
			v.VMs = &vm
		}
	case "kubernetes":
		var kn model.K8sNode
		if v.K8sNodeAt, err = s.section(r, h.ID, model.SectionK8sNode, &kn); err == nil {
			v.K8sNode = &kn
			v.Pods = podViews(kn)
		}
	case "services":
		v.ServiceQuery = strings.TrimSpace(r.URL.Query().Get("q"))
		if _, v.ServicesAt, err = s.store.HostSection(ctx, h.ID, model.SectionServices); err == nil || errors.Is(err, store.ErrNotFound) {
			v.Services, err = s.store.HostServices(ctx, h.ID)
		}
		if q := strings.ToLower(v.ServiceQuery); q != "" {
			v.Services = slices.DeleteFunc(v.Services, func(u model.Service) bool {
				return !strings.Contains(strings.ToLower(u.Name+" "+u.Description+" "+u.Active+" "+u.Enabled), q)
			})
		}
	case "ports":
		if _, v.PortsAt, err = s.store.HostSection(ctx, h.ID, model.SectionPorts); err == nil || errors.Is(err, store.ErrNotFound) {
			v.Ports, err = s.store.HostPorts(ctx, h.ID)
		}
	case "certificates":
		if _, v.CertsAt, err = s.store.HostSection(ctx, h.ID, model.SectionCerts); err == nil || errors.Is(err, store.ErrNotFound) {
			v.Certs, err = s.store.CICerts(ctx, h.ID)
		}
	case "metrics":
		v.Metrics, err = s.metricsView(r, h.ID)
	case "jobs":
		for _, n := range action.Names {
			_, why := actionAllowed(h, n)
			v.Actions = append(v.Actions, hostAction{Spec: action.MustGet(n), Why: why})
		}
	case "settings":
		if v.IsAdmin {
			v.AllGroups, err = s.store.ListHostGroups(ctx)
		}
	case "history":
		var entries []store.HistoryEntry
		entries, err = s.store.HostHistory(ctx, h.ID, 200)
		v.History = historyViews(entries)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "host", s.data(r, h.DisplayName(), v))
}

// podViews groups a node's containers under their pods; containers whose
// pod sandbox is gone are kept under a pod of that name too.
func podViews(kn model.K8sNode) []podView {
	var out []podView
	at := map[string]int{}
	for _, p := range kn.Pods {
		at[p.Namespace+"/"+p.Name] = len(out)
		out = append(out, podView{CRIPod: p})
	}
	for _, c := range kn.Containers {
		k := c.Namespace + "/" + c.Pod
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, podView{CRIPod: model.CRIPod{Namespace: c.Namespace, Name: c.Pod, State: "notready"}})
		}
		out[i].Containers = append(out[i].Containers, c)
	}
	return out
}

// section loads and decodes one stored inventory section.
func (s *Server) section(r *http.Request, hostID, name string, into any) (time.Time, error) {
	data, at, err := s.store.HostSection(r.Context(), hostID, name)
	if err != nil {
		return at, err
	}
	return at, json.Unmarshal(data, into)
}

func (s *Server) backToHost(w http.ResponseWriter, r *http.Request, id, notice string) {
	s.backToHostTab(w, r, id, "", notice)
}

func (s *Server) backToHostTab(w http.ResponseWriter, r *http.Request, id, tab, notice string) {
	u := "/hosts/" + id + "?notice=" + urlQueryEscape(notice)
	if tab != "" {
		u += "&tab=" + urlQueryEscape(tab)
	}
	http.Redirect(w, r, s.url(u), http.StatusSeeOther)
}

// hostRefresh asks the agent to resend its inventory now, or only to check
// for updates. Operators may do this: it reads the host, it doesn't change
// it (refreshing repository metadata leaves installed packages alone).
func (s *Server) hostRefresh(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Operator)
	if !ok {
		return
	}
	var sections []string
	tab, notice := "", "Refresh requested. New inventory appears within a few seconds; the update check can take a minute or two."
	if r.FormValue("section") == model.SectionUpdates {
		sections, tab = []string{model.SectionUpdates}, "updates"
		notice = "Update check requested. Refreshing repository metadata can take a minute or two; reload this page to see the result."
	}
	if s.hub == nil || !s.hub.RequestInventory(h.AgentID, sections) {
		s.backToHostTab(w, r, h.ID, tab, "The agent isn't connected, so it can't refresh now.")
		return
	}
	s.store.Audit(r.Context(), s.actor(r), store.AuditEvent{
		Action: "host.refresh", ObjectType: "host", ObjectID: h.ID,
		Details: map[string]any{"hostname": h.Hostname, "sections": sections},
	})
	s.backToHostTab(w, r, h.ID, tab, notice)
}

// hostAgentUpdate asks one host's agent to move to a published version
// (the newest by default). Admin only: it replaces code that runs as root.
func (s *Server) hostAgentUpdate(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	version := r.FormValue("version")
	if version == "" {
		rels, err := s.store.ListReleases(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(rels) == 0 {
			s.backToHost(w, r, h.ID, "No agent release is published.")
			return
		}
		version = rels[0].Version
	}
	changed, err := s.store.RequestAgentUpdate(r.Context(), s.actor(r), []string{h.ID}, version)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	switch {
	case len(changed) == 0 && h.Policy.SelfUpdateOff:
		s.backToHost(w, r, h.ID, "This host's agent.conf has self_update = off: run install.sh on the host to update its agent.")
	case len(changed) == 0:
		s.backToHost(w, r, h.ID, "Nothing to do: the agent already runs "+version+", or there's no "+version+" build for its architecture.")
	case s.hub != nil && s.hub.UpdateAgent(h.AgentID):
		s.backToHost(w, r, h.ID, "Update to "+version+" sent. The agent restarts into it in a few seconds.")
	default:
		s.backToHost(w, r, h.ID, "The agent updates to "+version+" when it next connects.")
	}
}

func (s *Server) hostGroups(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	if err := s.store.SetHostGroups(r.Context(), s.actor(r), h.ID, r.Form["group"]); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.backToHostTab(w, r, h.ID, "settings", "Host groups saved.")
}

// hostHighSecurity turns the host's high security flag on or off, and tells
// its agent what that changes about collecting hardware.
func (s *Server) hostHighSecurity(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	on := r.FormValue("high_security") == "1"
	changed, err := s.store.SetHostHighSecurity(r.Context(), s.actor(r), h.ID, on)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	notice := "High security turned off."
	if on {
		notice = "High security turned on: hardware changes from now on alert until acknowledged."
	}
	if changed && !s.configureAgent(r, h.ID) && !h.Revoked {
		notice += " The agent picks this up when it next connects."
	}
	s.backToHostTab(w, r, h.ID, "settings", notice)
}

// configureAgent sends the host's agent its settings again after they
// changed. It reports whether the agent got them now; otherwise it gets
// them when it next connects.
func (s *Server) configureAgent(r *http.Request, hostID string) bool {
	h, err := s.store.GetHost(r.Context(), hostID)
	return err == nil && s.hub != nil && s.hub.Configure(h.AgentID, h.AgentSettings())
}

// hostTraefik sets the Traefik on another node that routes the host's
// hostnames.
func (s *Server) hostTraefik(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Operator)
	if !ok {
		return
	}
	target := r.FormValue("traefik")
	if target != "" {
		ids, err := s.visibleHostIDs(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		nodes, err := s.store.TraefikNodes(r.Context(), h.ID, ids)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !slices.ContainsFunc(nodes, func(c store.CI) bool { return c.ID == target }) {
			s.errorPage(w, r, http.StatusBadRequest, "Pick a Traefik container or host.")
			return
		}
	}
	if err := s.store.SetHostTraefik(r.Context(), s.actor(r), h.ID, target); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/hosts/"+h.ID+"/containers?notice="+urlQueryEscape("Traefik routing saved.")), http.StatusSeeOther)
}

func (s *Server) hostRevoke(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	err := s.store.RevokeHost(r.Context(), s.actor(r), h.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	if s.hub != nil {
		s.hub.Disconnect(h.AgentID)
	}
	s.backToHostTab(w, r, h.ID, "settings", "Host revoked. Its agent can no longer connect. Re-enrolling the machine creates a new host record.")
}

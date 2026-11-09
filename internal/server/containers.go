package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
)

// Checker runs the server's registry checks (internal/checks).
type Checker interface {
	// Trigger asks for a check pass now instead of at the next interval.
	Trigger()
}

// SetChecker connects the registry checker, so "Check now" runs at once.
func (s *Server) SetChecker(c Checker) { s.checker = c }

// containerView is a container with what the UI says about its image.
type containerView struct {
	store.ContainerRow
	Rule    *registry.Rule // the rule that applies: the container's, or its Compose service's
	Advice  string         // newest tag the rule allows, if newer
	CanEdit bool           // operator on the container's host
}

// HasUpdate reports an update to prompt for: digest drift or a semver
// advisory, unless the stack is pinned.
func (c containerView) HasUpdate() bool { return !c.Pinned && (c.Drift || c.Advice != "") }

// ShortDigest abbreviates a digest for tables: sha256:0123456789ab.
func shortDigest(d string) string {
	if algo, hex, ok := strings.Cut(d, ":"); ok && len(hex) > 12 {
		return algo + ":" + hex[:12]
	}
	return d
}

// containerViews adds advisories to containers: each container's rule (its
// own, or its stack's for its Compose service) is applied to the tags last
// listed for its repository.
func (s *Server) containerViews(r *http.Request, rows []store.ContainerRow, stacks []store.Stack) ([]containerView, error) {
	g := principal(r).Grants
	groups := map[string][]string{}
	if hosts, err := s.visibleHosts(r); err == nil {
		for _, h := range hosts {
			groups[h.ID] = h.GroupIDs
		}
	}
	out := make([]containerView, len(rows))
	for i, c := range rows {
		out[i] = containerView{ContainerRow: c, CanEdit: g.HasOn(rbac.Operator, groups[c.HostID])}
	}
	return out, s.advise(r.Context(), out, stacks)
}

// advise sets each container's rule and the newest tag it allows.
func (s *Server) advise(ctx context.Context, out []containerView, stacks []store.Stack) error {
	rows := make([]store.ContainerRow, len(out))
	for i := range out {
		rows[i] = out[i].ContainerRow
	}
	var repos []string
	for i, rule := range store.SemverRules(rows, stacks) {
		out[i].Rule = rule
		if rule != nil && out[i].CheckRef != "" {
			if ref, err := registry.ParseRef(out[i].CheckRef); err == nil {
				repos = append(repos, ref.Repo())
			}
		}
	}
	if len(repos) == 0 {
		return nil
	}
	tags, err := s.store.RepositoryTags(ctx, repos)
	if err != nil {
		return err
	}
	checks, err := s.store.RepositoryImageChecks(ctx, repos)
	if err != nil {
		return err
	}
	for i := range out {
		if out[i].Rule == nil || out[i].CheckRef == "" {
			continue
		}
		ref, err := registry.ParseRef(out[i].CheckRef)
		if err != nil {
			continue
		}
		if tag, ok := out[i].ContainerRow.Advise(*out[i].Rule, tags[ref.Repo()], checks); ok {
			out[i].Advice = tag
		}
	}
	return nil
}

// containerAdvice is the newest tag each container's semver rule allows,
// by container CI id, for the containers list (containerTable). It covers
// every host: the list's scope limits what shows.
func (s *Server) containerAdvice(ctx context.Context) (map[string]string, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	rows, err := s.store.ListContainers(ctx, ids)
	if err != nil {
		return nil, err
	}
	stacks, err := s.store.ListStacks(ctx, ids)
	if err != nil {
		return nil, err
	}
	views := make([]containerView, len(rows))
	for i, c := range rows {
		views[i] = containerView{ContainerRow: c}
	}
	if err := s.advise(ctx, views, stacks); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, v := range views {
		if v.Advice != "" {
			out[v.CIID] = v.Advice
		}
	}
	return out, nil
}

// visibleHostIDs lists the hosts the user may view, revoked ones included.
func (s *Server) visibleHostIDs(r *http.Request) ([]string, error) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	return ids, nil
}

type containersView struct {
	Tab  string // containers | stacks
	List *listView

	Total, Running, Updates, StackCount int
}

// noClass is the filter value old links used for stacks whose name
// carries no metadata.
const noClass = "none"

// containers lists every container on the hosts the user can see.
func (s *Server) containers(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query(); q.Get("view") == "stacks" {
		q.Del("view")
		http.Redirect(w, r, s.url("/stacks?"+q.Encode()), http.StatusSeeOther)
		return
	}
	s.containerList(w, r, "container")
}

// stacks lists every Compose stack on the hosts the user can see.
func (s *Server) stacks(w http.ResponseWriter, r *http.Request) { s.containerList(w, r, "stack") }

// containerList is the Containers page with one of its tabs' lists.
func (s *Server) containerList(w http.ResponseWriter, r *http.Request, table string) {
	l, ok := s.buildList(w, r, table)
	if !ok {
		return
	}
	v := containersView{Tab: "containers", List: l}
	if table == "stack" {
		v.Tab = "stacks"
	}
	if !isHTMX(r) {
		if err := s.containerStats(r, &v); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.renderList(w, r, "containers", "Containers", v, l)
}

// containerStats counts what the page's figures show.
func (s *Server) containerStats(r *http.Request, v *containersView) error {
	ids, err := s.visibleHostIDs(r)
	if err != nil {
		return err
	}
	rows, err := s.store.ListContainers(r.Context(), ids)
	if err != nil {
		return err
	}
	stacks, err := s.store.ListStacks(r.Context(), ids)
	if err != nil {
		return err
	}
	all, err := s.containerViews(r, rows, stacks)
	if err != nil {
		return err
	}
	for _, c := range all {
		v.Total++
		if c.State == "running" {
			v.Running++
		}
		if c.HasUpdate() {
			v.Updates++
		}
	}
	for _, st := range stacks {
		if st.Present {
			v.StackCount++
		}
	}
	return nil
}

// loadContainer fetches the container in the path, checking the user may
// see its host (and holds need there).
func (s *Server) loadContainer(w http.ResponseWriter, r *http.Request, need rbac.Role) (store.ContainerRow, store.Host, bool) {
	c, err := s.store.GetContainer(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such container. It may have been removed; its CI is kept under CIs.")
		return c, store.Host{}, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return c, store.Host{}, false
	}
	h, ok := s.hostAccess(w, r, c.HostID, need, "No such container.")
	return c, h, ok
}

// hostAccess checks the user's role on a host that owns another object.
func (s *Server) hostAccess(w http.ResponseWriter, r *http.Request, hostID string, need rbac.Role, notFound string) (store.Host, bool) {
	h, err := s.store.GetHost(r.Context(), hostID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return h, false
	}
	g := principal(r).Grants
	if err != nil || !g.HasOn(rbac.Viewer, h.GroupIDs) {
		s.errorPage(w, r, http.StatusNotFound, notFound)
		return h, false
	}
	if !g.HasOn(need, h.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this on this host.")
		return h, false
	}
	return h, true
}

type containerPageView struct {
	C      containerView
	Host   store.Host
	Stack  *store.Stack
	Notice string
	Error  string
	Tracks []string
	// Hostnames Traefik routes to it.
	Hostnames []store.CI
	// MaskedRouters are routers whose rule an older agent masked as a
	// secret, so their hostnames are unknown.
	MaskedRouters []string
}

func (s *Server) containerPage(w http.ResponseWriter, r *http.Request) {
	c, h, ok := s.loadContainer(w, r, rbac.Viewer)
	if !ok {
		return
	}
	v := containerPageView{Host: h, Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error"),
		Tracks: []string{"patch", "minor", "major"}}
	var stacks []store.Stack
	if c.StackCI != "" {
		st, err := s.store.GetStack(r.Context(), c.StackCI)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		if err == nil {
			v.Stack, stacks = &st, []store.Stack{st}
		}
	}
	views, err := s.containerViews(r, []store.ContainerRow{c}, stacks)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v.C = views[0]
	if v.Hostnames, err = s.store.ServedHostnames(r.Context(), c.CIID); err != nil {
		s.serverError(w, r, err)
		return
	}
	for k, val := range c.Labels {
		if f := strings.Split(k, "."); len(f) == 5 && strings.EqualFold(f[0], "traefik") &&
			strings.EqualFold(f[2], "routers") && strings.EqualFold(f[4], "rule") && val == "********" {
			v.MaskedRouters = append(v.MaskedRouters, f[3])
		}
	}
	slices.Sort(v.MaskedRouters)
	s.pages.render(w, http.StatusOK, "container", s.data(r, c.Name, v))
}

func (s *Server) backToContainer(w http.ResponseWriter, r *http.Request, id, kind, msg string) {
	http.Redirect(w, r, s.url("/containers/"+id+"?"+kind+"="+urlQueryEscape(msg)), http.StatusSeeOther)
}

// containerCheck re-checks a container's image on its registry now.
// Operators may: it reads a registry, it doesn't touch the host.
func (s *Server) containerCheck(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadContainer(w, r, rbac.Operator)
	if !ok {
		return
	}
	if c.CheckRef == "" {
		s.backToContainer(w, r, c.CIID, "error", "This image can't be checked: it was built locally or is pinned by digest.")
		return
	}
	if err := s.store.ForgetImageCheck(r.Context(), c.CheckRef); err != nil {
		s.serverError(w, r, err)
		return
	}
	if s.checker != nil {
		s.checker.Trigger()
	}
	s.backToContainer(w, r, c.CIID, "notice", "Check requested. The result appears here within a minute.")
}

// containerRule sets or clears a container's semver advisory rule.
func (s *Server) containerRule(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadContainer(w, r, rbac.Operator)
	if !ok {
		return
	}
	var rule *registry.Rule
	if track := r.FormValue("track"); track != "" && track != "off" {
		rule = &registry.Rule{Track: track, Include: strings.TrimSpace(r.FormValue("include")),
			Exclude: strings.TrimSpace(r.FormValue("exclude"))}
		if err := rule.Validate(); err != nil {
			s.backToContainer(w, r, c.CIID, "error", err.Error())
			return
		}
	}
	if err := s.store.SetSemverRule(r.Context(), s.actor(r), c.CIID, rule); err != nil {
		s.serverError(w, r, err)
		return
	}
	if rule == nil {
		s.backToContainer(w, r, c.CIID, "notice", "Semver advisories turned off.")
		return
	}
	if s.checker != nil {
		s.checker.Trigger()
	}
	s.backToContainer(w, r, c.CIID, "notice", "Rule saved. Tags are listed from the registry within a minute.")
}

type stackPageView struct {
	Stack      store.Stack
	Host       store.Host
	Containers []containerView
	Files      []composeFileView
	Hostnames  []store.CI // Traefik routes to its containers
	CanEdit    bool
	Notice     string
	Error      string

	// Updates (M5).
	CanUpdate    bool   // request compose.pull/update changes
	CanStart     bool   // request a compose.start change
	CanArchive   bool   // request a compose.archive change
	CanMove      bool   // request a compose.move change (the host has Compose roots)
	UpdateBlock  string // why the stack can't be updated
	CanSettings  bool   // set the model, window and auto-update
	Models       []store.ChangeModel
	Windows      []store.MaintenanceWindow
	HostWindow   string // the window auto-updates use when the stack has none
	Changes      []store.Change
	StandardOnly bool // the stack's model is approved: updates are Standard changes

	// Files: what Baseline deployed or edited, and whether the user may edit
	// them (EditBlock says why not, when the host manages its stacks).
	Revisions []store.ComposeRevision
	CanFiles  bool
	EditBlock string
	CanSeeEnv bool // operators see .env values
	// Drift: the Compose file on the host isn't the one Baseline last wrote.
	FileDrift bool
}

type composeFileView struct {
	Path, SHA256, Content, Error string
	Size                         int64
	Truncated                    bool
}

func (s *Server) stackPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, err := s.store.GetStack(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such stack.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	h, ok := s.hostAccess(w, r, st.HostID, rbac.Viewer, "No such stack.")
	if !ok {
		return
	}
	rows, err := s.store.ListContainers(ctx, []string{st.HostID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rows = slices.DeleteFunc(rows, func(c store.ContainerRow) bool { return c.StackCI != st.CIID })
	v := stackPageView{Stack: st, Host: h, CanEdit: principal(r).Grants.HasOn(rbac.Operator, h.GroupIDs),
		Notice: r.URL.Query().Get("notice")}
	if v.Containers, err = s.containerViews(r, rows, []store.Stack{st}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Hostnames, err = s.store.ServedHostnames(ctx, st.CIID); err != nil {
		s.serverError(w, r, err)
		return
	}
	// The files' content is in the host's latest containers section.
	v.Files = s.stackComposeFiles(r, st)
	if v.Revisions, err = s.store.StackRevisions(ctx, st.HostID, st.Engine, st.Project, 20); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.CanSeeEnv = v.CanEdit
	if h.ManageCompose && v.CanEdit {
		v.EditBlock = s.editBlock(ctx, action.MustGet(action.ComposeEdit), st, h)
		v.CanFiles = v.EditBlock == ""
	}
	for _, rev := range v.Revisions {
		if rev.HasCompose && rev.JobState == store.JobSucceeded {
			v.FileDrift = len(v.Files) == 1 && v.Files[0].SHA256 != "" && v.Files[0].SHA256 != rev.ComposeSHA256
			break
		}
	}
	if err := s.stackUpdatesView(r, &v); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "stack", s.data(r, st.Project, v))
}

// stackUpdatesView fills in the stack page's update settings and history.
func (s *Server) stackUpdatesView(r *http.Request, v *stackPageView) error {
	ctx := r.Context()
	st, h, g := v.Stack, v.Host, principal(r).Grants
	v.Error = r.URL.Query().Get("error")
	ok, why := st.Updatable()
	if ok {
		if allowed, reason := h.Policy.Allows(action.ComposeUpdate); !allowed {
			ok, why = false, reason
		} else if supported, reason := action.MustGet(action.ComposeUpdate).Supported(h.Capabilities); !supported {
			ok, why = false, "the host's agent "+reason+" (a Compose CLI and an agent from M5 on)"
		}
	}
	v.UpdateBlock = why
	v.CanUpdate = ok && g.HasOn(rbac.Operator, h.GroupIDs)
	if ok, _ := st.Startable(); ok && g.HasOn(rbac.Operator, h.GroupIDs) {
		allowed, _ := h.Policy.Allows(action.ComposeStart)
		supported, _ := action.MustGet(action.ComposeStart).Supported(h.Capabilities)
		v.CanStart = allowed && supported
	}
	if ok, _ := st.Drivable(); ok && h.ManageCompose && g.HasOn(rbac.Operator, h.GroupIDs) {
		allowed, _ := h.Policy.Allows(action.ComposeArchive)
		supported, _ := action.MustGet(action.ComposeArchive).Supported(h.Capabilities)
		v.CanArchive = allowed && supported
		v.CanMove = v.CanArchive && len(h.ComposeRoots) > 0
	}
	v.CanSettings = g.HasOn(rbac.Approver, h.GroupIDs)
	v.StandardOnly = st.ModelState == store.ModelApproved
	var err error
	if v.Models, err = s.store.ListChangeModels(ctx, action.ComposeUpdate); err != nil {
		return err
	}
	v.Models = slices.DeleteFunc(v.Models, func(m store.ChangeModel) bool { return m.State == store.ModelRetired && m.ID != st.ModelID })
	ws, err := s.store.ListWindows(ctx)
	if err != nil {
		return err
	}
	for _, w := range ws {
		if w.Kind == store.WindowKindWindow && (w.Active || w.ID == st.WindowID) {
			v.Windows = append(v.Windows, w)
		}
	}
	if st.WindowID == "" {
		if cal, err := s.changes.LoadCalendar(ctx); err == nil {
			if w, ok := cal.WindowFor(h.ID, time.Now()); ok {
				v.HostWindow = w.Name
			}
		}
	}
	v.Changes, err = s.store.ListChanges(ctx, store.ChangeFilter{CIID: st.CIID, Limit: 10})
	return err
}

// stackUpdates sets how a stack is updated: under which Standard change
// model, in which window, and whether it updates itself. Pre-approving its
// updates is an approver's call on the host.
func (s *Server) stackUpdates(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such stack.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, ok := s.hostAccess(w, r, st.HostID, rbac.Approver, "No such stack."); !ok {
		return
	}
	back := func(kind, msg string) {
		http.Redirect(w, r, s.url("/stacks/"+st.CIID+"?"+kind+"="+urlQueryEscape(msg)), http.StatusSeeOther)
	}
	modelID, windowID, auto := r.FormValue("model"), r.FormValue("window"), r.FormValue("auto_update") == "1"
	if modelID != "" {
		m, err := s.store.GetChangeModel(r.Context(), modelID)
		if err != nil || m.Action != action.ComposeUpdate || (m.State == store.ModelRetired && m.ID != st.ModelID) {
			back("error", "Pick a compose.update change model.")
			return
		}
	}
	if windowID != "" {
		if win, err := s.store.GetWindow(r.Context(), windowID); err != nil || win.Kind != store.WindowKindWindow {
			back("error", "Pick a maintenance window.")
			return
		}
	}
	if auto && modelID == "" {
		back("error", "Auto-update runs as Standard changes, so it needs a change model.")
		return
	}
	if err := s.store.SetStackUpdates(r.Context(), s.actor(r), st.CIID, modelID, windowID, auto); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "Saved."
	if auto {
		msg = "Saved. The stack updates itself when its images drift, inside its window."
	}
	back("notice", msg)
}

type composeFileJSON struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Content   string `json:"content"`
	Error     string `json:"error"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
}

// stackPin turns update prompts for a stack off (databases) or back on.
func (s *Server) stackPin(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such stack.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, ok := s.hostAccess(w, r, st.HostID, rbac.Operator, "No such stack."); !ok {
		return
	}
	pinned := r.FormValue("pinned") == "1"
	if err := s.store.SetStackPinned(r.Context(), s.actor(r), st.CIID, pinned); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "Stack unpinned: image updates are shown again."
	if pinned {
		msg = "Stack pinned: image updates aren't prompted for."
	}
	http.Redirect(w, r, s.url("/stacks/"+st.CIID+"?notice="+urlQueryEscape(msg)), http.StatusSeeOther)
}

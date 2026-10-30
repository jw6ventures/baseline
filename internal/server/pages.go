package server

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

type dashboardView struct {
	Fleet store.FleetCounts

	HostsWithUpdates int
	Updates          int
	SecurityUpdates  int
	DisksFailing     int
	DisksDegrading   int
	// Attention lists hosts with failing drives or security updates.
	Attention []store.Host
	// AgentsOutdated counts agents not on the newest release (admins only).
	AgentsOutdated int
	IsAdmin        bool

	Containers       int
	ContainerUpdates int
	// Guests and clusters on visible hypervisors and cluster agents.
	Guests, GuestsRunning int
	Clusters              int
	NodesNotReady         int
	RebootRequired        int
	FailedServices        int
	// Expiring are certificates that expire within 30 days, on visible
	// hosts and on agentless endpoints.
	Expiring []store.CertRow
	// Changes counts changes that affect only visible hosts.
	Changes store.ChangeCounts
	// Upcoming are window and freeze openings in the next week.
	Upcoming []upcomingWindow

	Alerts alertCounts
	// Vulns counts distinct vulnerabilities on visible hosts; Fixable those
	// pending updates fix, by severity.
	Vulns          int
	Fixable        int
	FixableSevere  int // high or critical
	HostsFixable   int
	VulnsUncovered int // hosts whose distro OSV doesn't cover
}

type upcomingWindow struct {
	Name, Kind string
	Scope      []string
	Start, End time.Time
	Open       bool
}

// upcomingWindows lists window and freeze openings within d, soonest
// first.
func (s *Server) upcomingWindows(r *http.Request, d time.Duration) ([]upcomingWindow, error) {
	cal, err := s.changes.LoadCalendar(r.Context())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []upcomingWindow
	for _, w := range cal.Windows {
		if !w.Active {
			continue
		}
		for _, o := range w.Sched.Openings(now, now.Add(d), 3) {
			out = append(out, upcomingWindow{Name: w.Name, Kind: w.Kind, Scope: w.ScopeNames, Start: o.Start, End: o.End,
				Open: o.Contains(now)})
		}
	}
	slices.SortFunc(out, func(a, b upcomingWindow) int { return a.Start.Compare(b.Start) })
	if len(out) > 8 {
		out = out[:8]
	}
	return out, nil
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	v, err := s.dashboardData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "dashboard", s.data(r, "Dashboard", v))
}

// dashboardData gathers the dashboard's counts over the hosts the user
// can see; the API serves the same numbers.
func (s *Server) dashboardData(r *http.Request) (dashboardView, error) {
	var v dashboardView
	hosts, err := s.visibleHosts(r)
	if err != nil {
		return v, err
	}
	v.IsAdmin = principal(r).Grants.Has(rbac.Admin)
	latest := ""
	if v.IsAdmin {
		rels, err := s.store.ListReleases(r.Context())
		if err != nil {
			return v, err
		}
		if len(rels) > 0 {
			latest = rels[0].Version
		}
	}
	c := &v.Fleet
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		c.Total++
		if h.Connected {
			c.Online++
		} else {
			c.Offline++
		}
		if h.DuplicateIdentity {
			c.Duplicate++
		}
		v.Updates += h.Updates
		v.SecurityUpdates += h.SecurityUpdates
		if h.Updates > 0 {
			v.HostsWithUpdates++
		}
		v.DisksFailing += h.DisksFailing
		v.DisksDegrading += h.DisksDegrading
		v.Containers += h.Containers
		v.ContainerUpdates += h.ContainerUpdates
		v.FailedServices += h.FailedServices
		if h.RebootRequired {
			v.RebootRequired++
		}
		if h.DisksFailing > 0 || h.DisksDegrading > 0 || h.SecurityUpdates > 0 || h.FailedServices > 0 || h.RebootRequired {
			v.Attention = append(v.Attention, h)
		}
		if latest != "" && h.AgentVersion != latest && !h.ClusterAgent() {
			v.AgentsOutdated++
		}
	}
	var ids []string
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	guests, err := s.store.ListGuests(r.Context(), ids)
	if err != nil {
		return v, err
	}
	for _, g := range guests {
		if g.Present {
			v.Guests++
			if g.State == "running" {
				v.GuestsRunning++
			}
		}
	}
	clusters, err := s.store.ListClusters(r.Context(), ids)
	if err != nil {
		return v, err
	}
	for _, c := range clusters {
		if c.Status == "active" {
			v.Clusters++
			v.NodesNotReady += c.Nodes - c.NodesReady
		}
	}
	if v.Expiring, err = s.store.ExpiringCerts(r.Context(), ids, time.Now().Add(store.CertWarning)); err != nil {
		return v, err
	}
	if v.Upcoming, err = s.upcomingWindows(r, 7*24*time.Hour); err != nil {
		return v, err
	}
	if v.Changes, err = s.store.ChangeCounts(r.Context(), ids); err != nil {
		return v, err
	}
	if v.Alerts, err = s.openAlertCounts(r.Context(), r); err != nil {
		return v, err
	}
	var live []string
	for _, h := range hosts {
		if !h.Revoked {
			live = append(live, h.ID)
			if !h.VulnsAt.IsZero() && h.VulnEcosystem == "" {
				v.VulnsUncovered++
			}
		}
	}
	if v.Vulns, v.Fixable, v.FixableSevere, err = s.store.VulnTotals(r.Context(), live); err != nil {
		return v, err
	}
	counts, err := s.store.HostVulnCounts(r.Context(), live)
	if err != nil {
		return v, err
	}
	for _, c := range counts {
		if c.Fixable > 0 {
			v.HostsFixable++
		}
	}
	return v, nil
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	s.renderMe(w, r, http.StatusOK, meView{Error: r.URL.Query().Get("error"), Notice: r.URL.Query().Get("notice")})
}

// meView is the "Your access" page: the user's grants and API tokens.
type meView struct {
	grantsView
	Tokens []store.APIToken
	// Roles a new token may be limited to: the ones the user holds.
	Roles     []rbac.Role
	Lifetimes []lifetime
	Error     string
	Notice    string
	// NewToken is set once, right after creating one: it is never shown again.
	NewToken string
	NewName  string
	APIURL   string
}

var apiTokenLifetimes = []lifetime{{"720h", "30 days"}, {"2160h", "90 days"}, {"8760h", "1 year"}, {"never", "Never"}}

func (s *Server) renderMe(w http.ResponseWriter, r *http.Request, status int, v meView) {
	p := principal(r)
	v.grantsView = s.grantsView(r)
	v.Roles, v.Lifetimes = p.Grants.Roles(), apiTokenLifetimes
	v.APIURL = s.cfg.PublicURL.String() + apiPrefix
	var err error
	if v.Tokens, err = s.store.ListAPITokens(r.Context(), p.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, status, "me", s.data(r, "Your access", v))
}

// createAPIToken mints a token for the signed-in user, limited to roles
// they hold. The token carries the session's IdP groups, so it has at most
// the access this session has.
func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	p := principal(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 100 {
		s.renderMe(w, r, http.StatusBadRequest, meView{Error: "Give the token a name."})
		return
	}
	var roles []rbac.Role
	for _, v := range r.Form["role"] {
		role, err := rbac.ParseRole(v)
		if err != nil || !p.Grants.HasAnywhere(role) {
			s.renderMe(w, r, http.StatusBadRequest, meView{Error: "A token can only have roles you hold."})
			return
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		s.renderMe(w, r, http.StatusBadRequest, meView{Error: "Pick at least one role for the token."})
		return
	}
	var expires time.Time
	if l := r.FormValue("lifetime"); l != "never" {
		d, err := time.ParseDuration(l)
		if err != nil || !slices.ContainsFunc(apiTokenLifetimes, func(x lifetime) bool { return x.Value == l }) {
			s.renderMe(w, r, http.StatusBadRequest, meView{Error: "Pick how long the token lasts."})
			return
		}
		expires = time.Now().Add(d)
	}
	_, secret, err := s.store.NewAPIToken(r.Context(), s.actor(r), p.User.ID, name, roles, p.Groups, expires)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderMe(w, r, http.StatusOK, meView{NewToken: secret, NewName: name})
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	err := s.store.RevokeAPIToken(r.Context(), s.actor(r), principal(r).User.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, s.url("/me?error="+urlQueryEscape("That token was already revoked.")), http.StatusSeeOther)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/me?notice="+urlQueryEscape("Token revoked.")), http.StatusSeeOther)
	}
}

type grantsView struct {
	Global []rbac.Role
	Scoped []scopedGrant
}

type scopedGrant struct {
	Group string
	Roles []rbac.Role
}

func (s *Server) grantsView(r *http.Request) grantsView {
	g := principal(r).Grants
	v := grantsView{Global: g.Global()}
	scoped := g.Scoped()
	if len(scoped) == 0 {
		return v
	}
	groups, _ := s.store.ListHostGroups(r.Context())
	for _, hg := range groups {
		if roles, ok := scoped[hg.ID]; ok {
			v.Scoped = append(v.Scoped, scopedGrant{hg.Name, roles})
		}
	}
	return v
}

// Audit log -------------------------------------------------------------------

const auditPageSize = 100

type auditView struct {
	IsAdmin  bool
	Verified *store.AuditVerification
	List     *listView
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	s.renderAudit(w, r, nil)
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderAudit(w, r, &v)
}

func (s *Server) renderAudit(w http.ResponseWriter, r *http.Request, verified *store.AuditVerification) {
	l, ok := s.buildList(w, r, "audit")
	if !ok {
		return
	}
	s.renderList(w, r, "audit", "Audit log", auditView{IsAdmin: principal(r).Grants.Has(rbac.Admin), Verified: verified, List: l}, l)
}

// Settings: role bindings and host groups --------------------------------------

type accessView struct {
	Bindings   []store.RoleBinding
	HostGroups []store.HostGroup
	Roles      []rbac.Role
	Bootstrap  string
	Error      string
	Notice     string
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bindings, err := s.store.ListRoleBindings(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.store.ListHostGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	s.pages.render(w, http.StatusOK, "access", s.data(r, "Access", accessView{
		Bindings: bindings, HostGroups: groups, Roles: rbac.Roles,
		Bootstrap: s.cfg.BootstrapAdminGroup, Error: q.Get("error"), Notice: q.Get("notice"),
	}))
}

// backToAccess redirects after a POST, carrying a one-line message.
func (s *Server) backToAccess(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/access?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) actor(r *http.Request) store.Actor {
	return store.UserActor(principal(r).User.ID, clientIP(r))
}

func (s *Server) createBinding(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimSpace(r.FormValue("idp_group"))
	role, err := rbac.ParseRole(r.FormValue("role"))
	if group == "" || err != nil {
		s.backToAccess(w, r, "error", "Enter an Authentik group and pick a role.")
		return
	}
	scope := r.FormValue("scope")
	if scope == "global" {
		scope = ""
	}
	_, err = s.store.CreateRoleBinding(r.Context(), s.actor(r), store.RoleBinding{IdPGroup: group, Role: role, ScopeGroupID: scope})
	switch {
	case errors.Is(err, store.ErrConflict):
		s.backToAccess(w, r, "error", "That binding already exists.")
	case errors.Is(err, store.ErrNotFound):
		s.backToAccess(w, r, "error", "That host group no longer exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAccess(w, r, "notice", "Added: "+group+" → "+string(role)+".")
	}
}

func (s *Server) deleteBinding(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteRoleBinding(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToAccess(w, r, "error", "That binding was already removed.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAccess(w, r, "notice", "Binding removed.")
	}
}

func (s *Server) createHostGroup(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.backToAccess(w, r, "error", "Enter a host group name.")
		return
	}
	_, err := s.store.CreateHostGroup(r.Context(), s.actor(r), name, strings.TrimSpace(r.FormValue("description")))
	switch {
	case errors.Is(err, store.ErrConflict):
		s.backToAccess(w, r, "error", "A host group named "+name+" already exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAccess(w, r, "notice", "Host group "+name+" created.")
	}
}

func (s *Server) deleteHostGroup(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteHostGroup(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToAccess(w, r, "error", "That host group was already removed.")
	case errors.Is(err, store.ErrInUse):
		s.backToAccess(w, r, "error", "That host group can't be removed: "+strings.TrimPrefix(err.Error(), "in use: ")+".")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAccess(w, r, "notice", "Host group removed, with any bindings scoped to it.")
	}
}

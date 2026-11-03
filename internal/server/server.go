// Package server is Baseline's HTTP side: the web UI and the JSON API at /api/v1.
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/config"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	sessionCookie = "baseline_session"
	loginCookie   = "baseline_login"

	// Session lifetime (docs/architecture.md §5.1): 12h sliding, capped.
	idleTimeout = 12 * time.Hour
	maxLifetime = 7 * 24 * time.Hour
	loginTTL    = 10 * time.Minute
)

// Authenticator is the part of *oidc.Authenticator the server uses, so tests
// can stand in for the IdP.
type Authenticator interface {
	AuthRequest() (oidc.AuthRequest, error)
	Exchange(ctx context.Context, code, nonce, pkceVerifier string) (*oidc.Session, error)
}

// Hub reaches connected agents (internal/gateway).
type Hub interface {
	Online(agentID string) bool
	RequestInventory(agentID string, sections []string) bool
	UpdateAgent(agentID string) bool
	// Configure re-sends an agent its config after the host's high
	// security flag changed.
	Configure(agentID string, set store.AgentSettings) bool
	Disconnect(agentID string)
}

type Server struct {
	cfg     config.Config
	store   *store.Store
	auth    Authenticator
	hub     Hub
	caFP    []byte // CA fingerprint, embedded in enrollment tokens
	agents  *agentFiles
	cookies *oidc.CookieCodec // session cookie, BASELINE_COOKIE_KEY
	secrets *oidc.CookieCodec // secrets at rest, BASELINE_SECRET_KEY
	opts    oidc.CookieOptions
	log     *jw6_utils.Utils
	pages   *renderer
	version string
	checker Checker     // nil: no registry checks (tests)
	unifi   UniFiPoller // nil: UniFi consoles aren't polled (tests)
	jobs    Jobs        // nil: jobs aren't dispatched (tests)
	polls   AgentPoller // nil: cluster agents aren't asked for pods and logs (tests)
	// changes checks schedules and runs patch groups on demand; the
	// scheduler itself runs beside the dispatcher.
	changes  *change.Manager
	vulns    VulnSyncer // nil: OSV sync is off
	notifier Notifier   // nil: test messages wait for the next delivery pass
	// migrate nudges the migration runner; nil when it isn't running
	// (tests), and a started migration runs within the request.
	migrate chan struct{}
}

func New(cfg config.Config, st *store.Store, auth Authenticator, hub Hub, caFingerprint []byte, log *jw6_utils.Utils, version string) (*Server, error) {
	cookies, err := oidc.NewCookieCodec(cfg.CookieKey)
	if err != nil {
		return nil, err
	}
	secrets, err := oidc.NewCookieCodec(cfg.SecretKey)
	if err != nil {
		return nil, err
	}
	pages, err := newRenderer(cfg.Location)
	if err != nil {
		return nil, err
	}
	opts := oidc.DefaultCookieOptions()
	opts.Secure = cfg.SecureCookies()
	if p := cfg.PublicURL.Path; p != "" {
		opts.Path = p
	}
	return &Server{
		cfg: cfg, store: st, auth: auth, hub: hub, caFP: caFingerprint, agents: &agentFiles{dir: cfg.AgentDir},
		cookies: cookies, secrets: secrets,
		opts: opts, log: log, pages: pages, version: version, changes: change.New(st, log),
	}, nil
}

// Handler returns the full HTTP handler: routes behind cross-origin (CSRF)
// protection and security headers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /static/", staticHandler())

	// Public: hosts being installed have no session.
	mux.HandleFunc("GET /install.sh", s.installScript)
	mux.HandleFunc("GET /download/{file}", s.download)

	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)

	mux.Handle("GET /{$}", s.page(anyRole, s.dashboard))
	mux.Handle("GET /me", s.authed(s.me))
	mux.Handle("POST /me/tokens", s.authed(s.createAPIToken))
	mux.Handle("POST /me/tokens/{id}/revoke", s.authed(s.revokeAPIToken))
	// The JSON API, authenticated with API tokens (docs/api.md).
	s.apiRoutes(mux)

	mux.Handle("GET /hosts", s.page(anyRole, s.hostList))
	mux.Handle("GET /hosts/{id}", s.page(anyRole, s.hostDetail))
	mux.Handle("GET /hosts/{id}/metrics/{panel}", s.page(anyRole, s.hostMetricsJSON))
	for tab := range hostLists {
		mux.Handle("GET /hosts/{id}/"+tab, s.page(anyRole, s.hostTabPage(tab)))
	}
	mux.Handle("POST /hosts/{id}/refresh", s.page(anyRole, s.hostRefresh))
	mux.Handle("POST /hosts/{id}/groups", s.page(adminOnly, s.hostGroups))
	mux.Handle("POST /hosts/{id}/traefik", s.page(anyRole, s.hostTraefik))
	mux.Handle("POST /hosts/{id}/high-security", s.page(adminOnly, s.hostHighSecurity))
	mux.Handle("POST /hosts/{id}/manage-compose", s.page(adminOnly, s.hostManageCompose))
	mux.Handle("POST /hosts/{id}/compose-roots", s.page(adminOnly, s.hostComposeRoots))
	mux.Handle("POST /hosts/{id}/revoke", s.page(adminOnly, s.hostRevoke))
	mux.Handle("POST /hosts/{id}/agent-update", s.page(adminOnly, s.hostAgentUpdate))
	mux.Handle("GET /updates", s.page(anyRole, s.updates))
	mux.Handle("GET /updates/packages", s.page(anyRole, s.packageUpdates))
	mux.Handle("GET /containers", s.page(anyRole, s.containers))
	mux.Handle("GET /containers/{id}", s.page(anyRole, s.containerPage))
	mux.Handle("POST /containers/{id}/check", s.page(anyRole, s.containerCheck))
	mux.Handle("POST /containers/{id}/rule", s.page(anyRole, s.containerRule))
	mux.Handle("GET /stacks", s.page(anyRole, s.stacks))
	mux.Handle("GET /stacks/{id}", s.page(anyRole, s.stackPage))
	mux.Handle("POST /stacks/{id}/pin", s.page(anyRole, s.stackPin))
	mux.Handle("POST /stack-revisions/{id}/env", s.page(anyRole, s.revisionEnvPage))
	mux.Handle("POST /stacks/{id}/updates", s.page(anyRole, s.stackUpdates))
	mux.Handle("GET /vms", s.page(anyRole, s.vms))
	mux.Handle("GET /vms/{id}", s.page(anyRole, s.vmPage))
	mux.Handle("GET /kubernetes", s.page(anyRole, s.clusters))
	mux.Handle("GET /kubernetes/{id}", s.page(anyRole, s.clusterPage))
	mux.Handle("GET /kubernetes/{id}/workloads/{wid}", s.page(anyRole, s.workloadPage))
	mux.Handle("GET /kubernetes/{id}/workloads/{wid}/logs", s.page(anyRole, s.workloadLogs))
	mux.Handle("GET /work", s.page(anyRole, s.workList))
	mux.Handle("GET /work/new", s.page(anyRole, s.workNew))
	mux.Handle("POST /work", s.page(anyRole, s.workCreate))
	mux.Handle("GET /work/{ref}", s.page(anyRole, s.workPage))
	mux.Handle("GET /work/{ref}/edit", s.page(anyRole, s.workEdit))
	mux.Handle("POST /work/{ref}", s.page(anyRole, s.workUpdate))
	mux.Handle("POST /work/{ref}/transition", s.page(anyRole, s.workTransition))
	mux.Handle("POST /work/{ref}/comments", s.page(anyRole, s.workComment))
	mux.Handle("POST /work/{ref}/watch", s.page(anyRole, s.workWatch))
	mux.Handle("POST /work/{ref}/cis", s.page(anyRole, s.workCI(true)))
	mux.Handle("POST /work/{ref}/cis/delete", s.page(anyRole, s.workCI(false)))
	mux.Handle("POST /work/{ref}/changes", s.page(anyRole, s.workChange(true)))
	mux.Handle("POST /work/{ref}/changes/delete", s.page(anyRole, s.workChange(false)))
	mux.Handle("POST /work/{ref}/links", s.page(anyRole, s.workLink(true)))
	mux.Handle("POST /work/{ref}/links/delete", s.page(anyRole, s.workLink(false)))
	s.boardRoutes(mux)
	s.projectLabelRoutes(mux)
	mux.Handle("GET /projects", s.page(anyRole, s.projectList))
	mux.Handle("GET /projects/new", s.page(adminOnly, s.projectNew))
	mux.Handle("POST /projects", s.page(adminOnly, s.projectCreate))
	mux.Handle("GET /projects/{key}", s.page(anyRole, s.projectPage))
	mux.Handle("GET /projects/{key}/edit", s.page(adminOnly, s.projectEdit))
	mux.Handle("POST /projects/{key}", s.page(adminOnly, s.projectUpdate))
	mux.Handle("GET /projects/{key}/types/{type}", s.page(adminOnly, s.projectTypePage))
	mux.Handle("POST /projects/{key}/types/{type}/groups", s.page(adminOnly, s.projectTypeGroups))
	mux.Handle("GET /projects/{key}/types/{type}/layouts/{screen}", s.page(adminOnly, s.projectLayout))
	mux.Handle("POST /projects/{key}/types/{type}/layouts/{screen}", s.page(adminOnly, s.projectLayoutSave))
	mux.Handle("POST /projects/{key}/types/{type}/layouts/{screen}/delete", s.page(adminOnly, s.projectLayoutDelete))

	mux.Handle("GET /cis", s.page(anyRole, s.ciList))
	mux.Handle("GET /map", s.page(anyRole, s.ciMap))
	mux.Handle("GET /map.json", s.page(anyRole, s.ciMapJSON))
	mux.Handle("GET /cis/new", s.page(globalOperator, s.ciNew))
	mux.Handle("POST /cis", s.page(globalOperator, s.ciCreate))
	mux.Handle("GET /cis/{id}", s.page(anyRole, s.ciPage))
	mux.Handle("GET /cis/{id}/edit", s.page(globalOperator, s.ciEdit))
	mux.Handle("POST /cis/{id}", s.page(globalOperator, s.ciUpdate))
	mux.Handle("POST /cis/{id}/delete", s.page(anyRole, s.ciDelete))
	mux.Handle("POST /cis/{id}/relationships", s.page(globalOperator, s.ciRelate))
	mux.Handle("POST /cis/{id}/relationships/{rel}/delete", s.page(globalOperator, s.ciUnrelate))

	mux.Handle("GET /changes", s.page(anyRole, s.changeList))
	mux.Handle("GET /changes/new", s.page(anyOperator, s.changeNew))
	mux.Handle("POST /changes", s.page(anyOperator, s.changeCreate))
	mux.Handle("GET /changes/{id}", s.page(anyRole, s.changePage))
	mux.Handle("POST /changes/{id}/decide", s.page(anyRole, s.changeDecide))
	mux.Handle("POST /changes/{id}/cancel", s.page(anyRole, s.changeCancel))
	mux.Handle("POST /changes/{id}/submit", s.page(anyOperator, s.changeSubmit))
	mux.Handle("POST /changes/{id}/close", s.page(anyRole, s.changeClose))
	mux.Handle("GET /change-models", s.page(anyRole, s.modelList))
	mux.Handle("GET /change-models/new", s.page(adminOnly, s.modelNew))
	mux.Handle("POST /change-models", s.page(adminOnly, s.modelSave))
	mux.Handle("GET /change-models/{id}", s.page(anyRole, s.modelPage))
	mux.Handle("GET /change-models/{id}/edit", s.page(adminOnly, s.modelEdit))
	mux.Handle("POST /change-models/{id}", s.page(adminOnly, s.modelSave))
	mux.Handle("POST /change-models/{id}/approve", s.page(globalApprover, s.modelApprove))
	mux.Handle("POST /change-models/{id}/retire", s.page(adminOnly, s.modelRetire))
	// Maintenance windows, the calendar and patch groups (M5).
	s.scheduleRoutes(mux)
	mux.Handle("GET /jobs", s.page(anyRole, s.jobList))
	mux.Handle("GET /jobs/{id}", s.page(anyRole, s.jobPage))
	mux.Handle("GET /jobs/{id}/events", s.page(anyRole, s.jobEvents))
	mux.Handle("GET /jobs/{id}/output.txt", s.page(anyRole, s.jobRaw))
	mux.Handle("GET /scripts", s.page(anyRole, s.scriptList))
	mux.Handle("GET /scripts/new", s.page(adminOnly, s.scriptNew))
	mux.Handle("POST /scripts", s.page(adminOnly, s.scriptSave))
	mux.Handle("GET /scripts/{id}", s.page(anyRole, s.scriptPage))
	mux.Handle("GET /scripts/{id}/edit", s.page(adminOnly, s.scriptEdit))
	mux.Handle("POST /scripts/{id}", s.page(adminOnly, s.scriptSave))
	mux.Handle("POST /scripts/{id}/archive", s.page(adminOnly, s.scriptArchive))
	// Vulnerabilities, alerts and notification channels (M6).
	s.vulnRoutes(mux)
	s.alertRoutes(mux)
	// Saved lists, inline edits and bulk actions of the list engine.
	s.listRoutes(mux)
	s.migrationRoutes(mux)

	// Entries name hosts across every group, so scoped-only users can't read it.
	mux.Handle("GET /audit", s.page(globalViewer, s.auditLog))
	mux.Handle("POST /audit/verify", s.page(adminOnly, s.auditVerify))

	mux.Handle("GET /settings/{$}", s.page(adminOnly, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.url("/settings/access"), http.StatusFound)
	}))
	mux.Handle("GET /settings/access", s.page(adminOnly, s.access))
	mux.Handle("POST /settings/access/bindings", s.page(adminOnly, s.createBinding))
	mux.Handle("POST /settings/access/bindings/{id}/delete", s.page(adminOnly, s.deleteBinding))
	mux.Handle("POST /settings/access/groups", s.page(adminOnly, s.createHostGroup))
	mux.Handle("POST /settings/access/groups/{id}/delete", s.page(adminOnly, s.deleteHostGroup))
	mux.Handle("GET /settings/enrollment", s.page(adminOnly, s.enrollment))
	mux.Handle("POST /settings/enrollment/tokens", s.page(adminOnly, s.createToken))
	mux.Handle("POST /settings/enrollment/tokens/{id}/revoke", s.page(adminOnly, s.revokeToken))
	mux.Handle("GET /settings/agents", s.page(adminOnly, s.agentSettings))
	mux.Handle("POST /settings/agents/update", s.page(adminOnly, s.agentsUpdate))
	mux.Handle("GET /settings/ticket-types", s.page(adminOnly, s.ticketTypes))
	mux.Handle("POST /settings/ticket-types", s.page(adminOnly, s.ticketTypeSave))
	mux.Handle("POST /settings/ticket-types/{id}", s.page(adminOnly, s.ticketTypeSave))
	mux.Handle("GET /settings/slas", s.page(adminOnly, s.slaPolicies))
	mux.Handle("POST /settings/slas", s.page(adminOnly, s.slaPolicySave))
	mux.Handle("POST /settings/slas/{id}", s.page(adminOnly, s.slaPolicySave))
	mux.Handle("POST /settings/slas/{id}/delete", s.page(adminOnly, s.slaPolicyDelete))
	mux.Handle("GET /settings/workflows", s.page(adminOnly, s.workflows))
	mux.Handle("POST /settings/workflows", s.page(adminOnly, s.workflowCreate))
	mux.Handle("GET /settings/workflows/{id}", s.page(adminOnly, s.workflowPage))
	mux.Handle("POST /settings/workflows/{id}", s.page(adminOnly, s.workflowUpdate))
	mux.Handle("POST /settings/workflows/{id}/delete", s.page(adminOnly, s.workflowDelete))
	mux.Handle("POST /settings/workflows/{id}/edit", s.page(adminOnly, s.workflowEdit))
	mux.Handle("POST /settings/workflows/{id}/publish", s.page(adminOnly, s.draftOp(s.workflowPublish)))
	mux.Handle("POST /settings/workflows/{id}/discard", s.page(adminOnly, s.draftOp(s.workflowDiscard)))
	mux.Handle("POST /settings/workflows/{id}/statuses", s.page(adminOnly, s.draftOp(s.statusSave)))
	mux.Handle("POST /settings/workflows/{id}/statuses/{sid}", s.page(adminOnly, s.draftOp(s.statusSave)))
	mux.Handle("POST /settings/workflows/{id}/statuses/{sid}/delete", s.page(adminOnly, s.draftOp(s.statusDelete)))
	mux.Handle("POST /settings/workflows/{id}/layout", s.page(adminOnly, s.statusLayout))
	mux.Handle("GET /settings/workflows/{id}/transitions/new", s.page(adminOnly, s.transitionPage))
	mux.Handle("GET /settings/workflows/{id}/transitions/{tid}", s.page(adminOnly, s.transitionPage))
	mux.Handle("POST /settings/workflows/{id}/transitions", s.page(adminOnly, s.transitionSave))
	mux.Handle("POST /settings/workflows/{id}/transitions/{tid}", s.page(adminOnly, s.transitionSave))
	mux.Handle("POST /settings/workflows/{id}/transitions/{tid}/delete", s.page(adminOnly, s.draftOp(s.transitionDelete)))
	mux.Handle("GET /settings/ticket-types/{id}/layouts/{screen}", s.page(adminOnly, s.typeLayout))
	mux.Handle("POST /settings/ticket-types/{id}/layouts/{screen}", s.page(adminOnly, s.typeLayoutSave))
	mux.Handle("POST /settings/ticket-types/{id}/layouts/{screen}/delete", s.page(adminOnly, s.typeLayoutDelete))
	mux.Handle("GET /settings/fields", s.page(adminOnly, s.fields))
	mux.Handle("POST /settings/fields", s.page(adminOnly, s.fieldSave))
	mux.Handle("POST /settings/fields/{id}", s.page(adminOnly, s.fieldSave))
	mux.Handle("POST /settings/fields/{id}/delete", s.page(adminOnly, s.fieldDelete))
	mux.Handle("GET /settings/field-groups", s.page(adminOnly, s.fieldGroups))
	mux.Handle("GET /settings/field-groups/new", s.page(adminOnly, s.fieldGroupNew))
	mux.Handle("POST /settings/field-groups", s.page(adminOnly, s.fieldGroupSave))
	mux.Handle("GET /settings/field-groups/{id}", s.page(adminOnly, s.fieldGroupEdit))
	mux.Handle("POST /settings/field-groups/{id}", s.page(adminOnly, s.fieldGroupSave))
	mux.Handle("POST /settings/field-groups/{id}/delete", s.page(adminOnly, s.fieldGroupDelete))
	mux.Handle("GET /settings/registries", s.page(adminOnly, s.registries))
	mux.Handle("POST /settings/registries", s.page(adminOnly, s.saveRegistry))
	mux.Handle("POST /settings/registries/{id}/delete", s.page(adminOnly, s.deleteRegistry))
	mux.Handle("GET /settings/unifi", s.page(adminOnly, s.unifiSettings))
	mux.Handle("POST /settings/unifi", s.page(adminOnly, s.unifiSave))
	mux.Handle("GET /settings/unifi/{id}", s.page(adminOnly, s.unifiSettings))
	mux.Handle("POST /settings/unifi/{id}", s.page(adminOnly, s.unifiSave))
	mux.Handle("POST /settings/unifi/{id}/delete", s.page(adminOnly, s.unifiDelete))
	mux.Handle("POST /settings/unifi/{id}/poll", s.page(adminOnly, s.unifiPoll))

	var h http.Handler = mux
	if p := s.cfg.PublicURL.Path; p != "" {
		h = http.StripPrefix(p, h)
	}
	return securityHeaders(http.NewCrossOriginProtection().Handler(h))
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// PurgeSessions deletes expired sessions every interval until ctx ends.
func (s *Server) PurgeSessions(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.store.PurgeSessions(ctx)
			if err != nil {
				s.log.Log("Server", "PurgeSessions", jw6_utils.Error, err.Error())
			} else if n > 0 {
				s.log.Log("Server", "PurgeSessions", jw6_utils.Debug, fmt.Sprintf("removed %d expired sessions", n))
			}
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// clientIP is the address that reached Traefik. The server publishes no
// ports, so every request arrives through the proxy, which appends the peer
// it saw as the last X-Forwarded-For entry.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// url builds an absolute path under the public URL's path prefix.
func (s *Server) url(path string) string { return s.cfg.PublicURL.Path + path }

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

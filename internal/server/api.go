package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// The JSON API at /api/v1 (docs/api.md). It reads everything the web UI
// shows, under the same role checks, and creates and submits changes. It
// is authenticated with an API token in the Authorization header: a token
// acts as its user with at most the roles it names (docs/architecture.md
// §5.1). Responses are JSON; errors are {"error": "..."} with the status.
const apiPrefix = "/api/v1"

func (s *Server) apiRoutes(mux *http.ServeMux) {
	get := func(pattern string, allow access, h http.HandlerFunc) {
		mux.Handle("GET "+apiPrefix+pattern, s.api(allow, h))
	}
	post := func(pattern string, allow access, h http.HandlerFunc) {
		mux.Handle("POST "+apiPrefix+pattern, s.api(allow, h))
	}
	get("/me", anyRole, s.apiMe)
	get("/dashboard", anyRole, s.apiDashboard)
	get("/actions", anyRole, s.apiActions)

	get("/hosts", anyRole, s.apiHosts)
	get("/hosts/{id}", anyRole, s.apiHost)
	get("/hosts/{id}/sections", anyRole, s.apiHostSections)
	get("/hosts/{id}/sections/{section}", anyRole, s.apiHostSection)
	get("/hosts/{id}/packages", anyRole, s.apiHostPackages)
	get("/hosts/{id}/updates", anyRole, s.apiHostUpdates)
	get("/hosts/{id}/certificates", anyRole, s.apiHostCerts)
	get("/hosts/{id}/history", anyRole, s.apiHostHistory)
	get("/hosts/{id}/metrics", anyRole, s.apiHostMetricPanels)
	get("/hosts/{id}/metrics/{panel}", anyRole, s.apiHostMetrics)
	get("/hosts/{id}/jobs", anyRole, s.apiHostJobs)
	get("/hosts/{id}/changes", anyRole, s.apiHostChanges)
	get("/hosts/{id}/vulnerabilities", anyRole, s.apiHostVulns)
	get("/hosts/{id}/alerts", anyRole, s.apiHostAlerts)
	get("/host-groups", anyRole, s.apiHostGroups)
	get("/updates", anyRole, s.apiUpdates)

	get("/containers", anyRole, s.apiContainers)
	get("/containers/{id}", anyRole, s.apiContainer)
	get("/stacks", anyRole, s.apiStacks)
	get("/stacks/{id}", anyRole, s.apiStack)
	get("/stacks/{id}/files", anyRole, s.apiStackFiles)
	get("/vms", anyRole, s.apiVMs)
	get("/vms/{id}", anyRole, s.apiVM)
	get("/kubernetes", anyRole, s.apiClusters)
	get("/kubernetes/{id}", anyRole, s.apiCluster)
	get("/kubernetes/{id}/manifests", anyRole, s.apiClusterManifests)
	get("/kubernetes/{id}/workloads/{wid}/pods", anyRole, s.apiWorkloadPods)
	get("/kubernetes/{id}/workloads/{wid}/logs", anyRole, s.apiWorkloadLogs)

	get("/ci-types", anyRole, s.apiCITypes)
	get("/cis", anyRole, s.apiCIs)
	get("/cis/{id}", anyRole, s.apiCI)
	get("/cis/{id}/relationships", anyRole, s.apiCIRelationships)
	get("/cis/{id}/history", anyRole, s.apiCIHistory)
	get("/cis/{id}/certificates", anyRole, s.apiCICerts)
	get("/map", anyRole, s.apiMap)

	get("/changes", anyRole, s.apiChanges)
	post("/changes", anyOperator, s.apiChangeCreate)
	get("/changes/{id}", anyRole, s.apiChange)
	post("/changes/{id}/submit", anyOperator, s.apiChangeSubmit)
	get("/change-models", anyRole, s.apiChangeModels)
	get("/change-models/{id}", anyRole, s.apiChangeModel)
	get("/jobs", anyRole, s.apiJobs)
	get("/jobs/{id}", anyRole, s.apiJob)
	get("/jobs/{id}/output", anyRole, s.apiJobOutput)
	get("/scripts", anyRole, s.apiScripts)
	get("/scripts/{id}", anyRole, s.apiScript)
	get("/scripts/{id}/versions/{version}", anyRole, s.apiScriptVersion)
	get("/windows", anyRole, s.apiWindows)
	get("/calendar", anyRole, s.apiCalendar)
	get("/patch-groups", anyRole, s.apiPatchGroups)
	get("/patch-groups/{id}", anyRole, s.apiPatchGroup)

	get("/vulnerabilities", anyRole, s.apiVulns)
	get("/vulnerabilities/{id}", anyRole, s.apiVuln)
	get("/vulnerability-sources", anyRole, s.apiVulnSources)
	get("/alerts", anyRole, s.apiAlerts)
	get("/alerts/{id}", anyRole, s.apiAlert)
	get("/alert-rules", anyRole, s.apiAlertRules)
	get("/silences", anyRole, s.apiSilences)
	// Entries name hosts across every group, so scoped-only users can't read it.
	get("/audit", globalViewer, s.apiAudit)

	// Anything else under the prefix is a JSON 404, not the HTML page.
	mux.HandleFunc(apiPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "no such endpoint")
	})
}

// api authenticates a request with its bearer token, puts the principal in
// the context (so the UI's visibility helpers apply as they are) and
// checks the endpoint's access rule.
func (s *Server) api(allow access, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		secret, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Baseline"`)
			apiError(w, http.StatusUnauthorized, "an API token is required: Authorization: Bearer <token>")
			return
		}
		t, err := s.store.LookupAPIToken(r.Context(), secret)
		if errors.Is(err, store.ErrNotFound) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Baseline", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "the API token is unknown, revoked or expired")
			return
		}
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		bindings, err := s.store.RBACBindings(r.Context())
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		p := &Principal{
			User:   t.User,
			Groups: t.IdPGroups,
			Grants: rbac.Resolve(t.IdPGroups, bindings, s.cfg.BootstrapAdminGroup).Restrict(t.Roles),
			Token:  &t,
		}
		switch {
		case p.Grants.Empty():
			apiError(w, http.StatusForbidden, "this token has no role: its user's role bindings or the token's roles changed")
			return
		case !allow(p.Grants):
			apiError(w, http.StatusForbidden, "this token's roles don't allow this")
			return
		}
		next(w, r.WithContext(contextWithPrincipal(r.Context(), p)))
	})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// Responses --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) apiServerError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Log("API", r.Method+" "+r.URL.Path, jw6_utils.Error, err.Error())
	apiError(w, http.StatusInternalServerError, "server error; the details are in the server log")
}

// apiFail is an error with the status to answer. Loaders return it so
// handlers stay short.
type apiFail struct {
	status int
	msg    string
}

func (e *apiFail) Error() string { return e.msg }

func failf(status int, format string, args ...any) error {
	return &apiFail{status: status, msg: fmt.Sprintf(format, args...)}
}

var (
	errAPINotFound  = &apiFail{http.StatusNotFound, "not found"}
	errAPIForbidden = &apiFail{http.StatusForbidden, "this token's roles don't allow this"}
)

// respond writes v, or the error: an apiFail with its status, anything
// else as a 500.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, v any, err error) {
	var f *apiFail
	switch {
	case errors.As(err, &f):
		apiError(w, f.status, f.msg)
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

// Requests ---------------------------------------------------------------------

const maxAPIBody = 4 << 20 // Compose files and .envs ride in change requests

// readJSON decodes a request body into v, rejecting unknown fields so a
// misspelt one doesn't silently do nothing.
func readJSON(r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return failf(http.StatusUnsupportedMediaType, "send JSON (Content-Type: application/json)")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAPIBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return failf(http.StatusBadRequest, "bad JSON: %v", err)
	}
	if dec.More() {
		return failf(http.StatusBadRequest, "bad JSON: more than one value")
	}
	return nil
}

// queryInt reads an integer query parameter, bounded to [1, max]; def
// when it is missing or not a number.
func queryInt(r *http.Request, key string, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || n < 1 {
		return def
	}
	return min(n, max)
}

func queryBool(r *http.Request, key string) bool {
	switch strings.ToLower(r.URL.Query().Get(key)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// Loaders ---------------------------------------------------------------------
// Each one applies the same visibility rule as the UI page: a host, or an
// object that lives on one, is "not found" to a user who can't see it,
// and a role short of need is forbidden.

func (s *Server) apiLoadHost(r *http.Request, id string, need rbac.Role) (store.Host, error) {
	h, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return h, errAPINotFound
	}
	if err != nil {
		return h, err
	}
	g := principal(r).Grants
	if !g.HasOn(rbac.Viewer, h.GroupIDs) {
		return h, errAPINotFound
	}
	if !g.HasOn(need, h.GroupIDs) {
		return h, errAPIForbidden
	}
	return h, nil
}

// apiVisibleIDs is the set of hosts the user may see, for filtering lists.
func (s *Server) apiVisibleIDs(r *http.Request) (map[string]bool, []string, error) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		return nil, nil, err
	}
	set := make(map[string]bool, len(hosts))
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		set[h.ID] = true
		ids = append(ids, h.ID)
	}
	return set, ids, nil
}

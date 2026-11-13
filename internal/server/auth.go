package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// pendingLogin is sealed into the short-lived login cookie between /auth/login
// and /auth/callback.
type pendingLogin struct {
	Req  oidc.AuthRequest
	Next string
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	req, err := s.auth.AuthRequest()
	if err != nil {
		s.log.Log("Auth", "login", jw6_utils.Error, err.Error())
		s.errorPage(w, r, http.StatusServiceUnavailable, "The identity provider is unavailable. Try again shortly.")
		return
	}
	pl := pendingLogin{Req: req, Next: safeNext(r.URL.Query().Get("next"))}
	if err := s.cookies.SetCookie(w, loginCookie, pl, loginTTL, s.opts); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, req.URL, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(reason string, err error) {
		msg := reason
		if err != nil {
			msg += ": " + err.Error()
		}
		s.log.Log("Auth", "callback", jw6_utils.Warn, msg)
		s.store.Audit(r.Context(), store.Actor{ID: "anonymous", IP: clientIP(r)}, store.AuditEvent{
			Action: "auth.login_failed", Details: map[string]any{"reason": reason},
		})
		s.errorPage(w, r, http.StatusBadRequest, "Sign-in failed ("+reason+"). Start again from the sign-in page.")
	}

	var pl pendingLogin
	if err := s.cookies.ReadCookie(r, loginCookie, &pl); err != nil {
		fail("login expired or cookie missing", err)
		return
	}
	oidc.ClearCookie(w, loginCookie, s.opts)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("identity provider returned "+e, nil)
		return
	}
	if q.Get("state") == "" || q.Get("state") != pl.Req.State {
		fail("state mismatch", nil)
		return
	}
	sess, err := s.auth.Exchange(r.Context(), q.Get("code"), pl.Req.Nonce, pl.Req.PKCEVerifier)
	if err != nil {
		fail("token exchange", err)
		return
	}

	user, err := s.store.UpsertUser(r.Context(), sess.Subject, sess.Email, sess.Name)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups := stringsClaim(sess.Claims, s.cfg.GroupsClaim)
	blob, err := s.secrets.Seal(sess, 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	token, err := s.store.CreateSession(r.Context(), store.NewSession{
		UserID: user.ID, IdPGroups: groups, OIDCBlob: []byte(blob),
		IP: clientIP(r), UserAgent: r.UserAgent(),
		IdleTimeout: idleTimeout, MaxLifetime: maxLifetime,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.cookies.SetCookie(w, sessionCookie, token, maxLifetime, s.opts); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.store.Audit(r.Context(), store.UserActor(user.ID, clientIP(r)), store.AuditEvent{
		Action: "auth.login", ObjectType: "user", ObjectID: user.ID,
		Details: map[string]any{"subject": user.OIDCSub, "email": user.Email, "groups": groups},
	})
	s.log.Log("Auth", "callback", jw6_utils.Info, fmt.Sprintf("%s signed in (groups: %s)",
		user.DisplayName(), strings.Join(groups, ", ")))
	http.Redirect(w, r, s.url(pl.Next), http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	var token string
	if err := s.cookies.ReadCookie(r, sessionCookie, &token); err == nil {
		if ss, err := s.store.LookupSession(r.Context(), token, idleTimeout); err == nil {
			s.store.Audit(r.Context(), store.UserActor(ss.User.ID, clientIP(r)), store.AuditEvent{
				Action: "auth.logout", ObjectType: "user", ObjectID: ss.User.ID,
			})
		}
		if err := s.store.DeleteSession(r.Context(), token); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	oidc.ClearCookie(w, sessionCookie, s.opts)
	s.pages.render(w, http.StatusOK, "signed_out", pageData{Title: "Signed out"})
}

// Principal is the signed-in user and what they may do, for one request.
type Principal struct {
	User   store.User
	Groups []string
	Grants rbac.Grants
	// Token is set for an API request; its grants are the user's limited
	// to the token's roles.
	Token *store.APIToken
}

type ctxKey struct{}

func principal(r *http.Request) *Principal {
	p, _ := r.Context().Value(ctxKey{}).(*Principal)
	return p
}

func contextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// authed loads the session or sends the browser to sign in. Grants are
// resolved per request, so binding edits apply without signing out.
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		if err := s.cookies.ReadCookie(r, sessionCookie, &token); err != nil {
			s.toLogin(w, r)
			return
		}
		// Live status polling (static/live.js) isn't the user's activity, so
		// it doesn't keep an unattended session alive past its idle timeout.
		idle := idleTimeout
		if isLivePoll(r) {
			idle = 0
		}
		ss, err := s.store.LookupSession(r.Context(), token, idle)
		if errors.Is(err, store.ErrNotFound) {
			oidc.ClearCookie(w, sessionCookie, s.opts)
			s.toLogin(w, r)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		bindings, err := s.store.RBACBindings(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		p := &Principal{
			User:   ss.User,
			Groups: ss.IdPGroups,
			Grants: rbac.Resolve(ss.IdPGroups, bindings, s.cfg.BootstrapAdminGroup),
		}
		next(w, r.WithContext(contextWithPrincipal(r.Context(), p)))
	})
}

// livePollHeader marks a request static/live.js makes to refresh a page's
// status in place.
const livePollHeader = "X-Baseline-Live"

func isLivePoll(r *http.Request) bool { return r.Header.Get(livePollHeader) == "1" }

// access decides whether a principal may see a page.
type access func(rbac.Grants) bool

var (
	anyRole      access = func(g rbac.Grants) bool { return g.HasAnywhere(rbac.Viewer) }
	adminOnly    access = func(g rbac.Grants) bool { return g.Has(rbac.Admin) }
	globalViewer access = func(g rbac.Grants) bool { return g.Has(rbac.Viewer) }
	// globalOperator edits agentless CIs, which belong to no host group.
	globalOperator access = func(g rbac.Grants) bool { return g.Has(rbac.Operator) }
	// anyOperator may request changes on some hosts; handlers check which.
	anyOperator access = func(g rbac.Grants) bool { return g.HasAnywhere(rbac.Operator) }
	// globalApprover approves change models, which apply to any host.
	globalApprover access = func(g rbac.Grants) bool { return g.Has(rbac.Approver) }
)

// page is authed plus an access check. A user with no role at all gets an
// explanation instead of a bare 403.
func (s *Server) page(allow access, next http.HandlerFunc) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		switch {
		case p.Grants.Empty():
			s.pages.render(w, http.StatusForbidden, "no_access", s.data(r, "No access", nil))
		case !allow(p.Grants):
			s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this.")
		default:
			next(w, r)
		}
	})
}

func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	if isLivePoll(r) {
		// The page stops refreshing and asks the user to sign in again.
		http.Error(w, "signed out", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		s.errorPage(w, r, http.StatusUnauthorized, "Your session has expired. Sign in again.")
		return
	}
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, s.url("/auth/login?next="+url.QueryEscape(next)), http.StatusFound)
}

// safeNext only allows a local path, so the login can't become an open
// redirect.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return "/"
	}
	return next
}

// stringsClaim reads a claim that should be a list of strings. Authentik
// sends groups as a JSON array.
func stringsClaim(claims map[string]any, key string) []string {
	var out []string
	switch v := claims[key].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case string:
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// LazyAuthenticator runs OIDC discovery on first use and retries it on later
// requests until it succeeds, so the server starts even while the IdP is
// down or restarting.
type LazyAuthenticator struct {
	Config oidc.Config

	mu   sync.Mutex
	auth *oidc.Authenticator
	last time.Time
	err  error
}

func (l *LazyAuthenticator) get(ctx context.Context) (*oidc.Authenticator, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.auth != nil {
		return l.auth, nil
	}
	if time.Since(l.last) < 5*time.Second {
		return nil, l.err // don't hammer a down IdP
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.auth, l.err = oidc.NewAuthenticator(ctx, l.Config)
	l.last = time.Now()
	return l.auth, l.err
}

// Warm tries discovery once, e.g. at startup, so a misconfiguration shows in
// the log straight away.
func (l *LazyAuthenticator) Warm(ctx context.Context) error {
	_, err := l.get(ctx)
	return err
}

func (l *LazyAuthenticator) AuthRequest() (oidc.AuthRequest, error) {
	a, err := l.get(context.Background())
	if err != nil {
		return oidc.AuthRequest{}, err
	}
	return a.AuthRequest()
}

func (l *LazyAuthenticator) Exchange(ctx context.Context, code, nonce, verifier string) (*oidc.Session, error) {
	a, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return a.Exchange(ctx, code, nonce, verifier)
}

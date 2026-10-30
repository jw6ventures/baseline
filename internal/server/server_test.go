package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/config"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

// fakeIdP stands in for Authentik. The next login gets sub and groups.
type fakeIdP struct {
	sub    string
	groups []string
}

func (f *fakeIdP) AuthRequest() (oidc.AuthRequest, error) {
	return oidc.AuthRequest{URL: "https://idp.example/authorize", State: "state-1", Nonce: "nonce-1", PKCEVerifier: "pkce-1"}, nil
}

func (f *fakeIdP) Exchange(_ context.Context, code, nonce, verifier string) (*oidc.Session, error) {
	if code != "good" || nonce != "nonce-1" || verifier != "pkce-1" {
		return nil, errors.New("bad exchange")
	}
	groups := make([]any, len(f.groups))
	for i, g := range f.groups {
		groups[i] = g
	}
	return &oidc.Session{
		Subject: f.sub, Email: f.sub + "@example.com", Name: strings.ToUpper(f.sub),
		Claims: map[string]any{"sub": f.sub, "groups": groups},
	}, nil
}

// fakeHub records what the server asked of connected agents.
type fakeHub struct {
	online       map[string]bool
	requested    []string
	sections     [][]string
	updated      []string
	disconnected []string
	configured   map[string]store.AgentSettings // by agent
	mu           sync.Mutex
	messages     []*agentv1.ServerMessage // sent by the job dispatcher
}

func (f *fakeHub) Online(id string) bool { return f.online[id] }
func (f *fakeHub) RequestInventory(id string, sections []string) bool {
	f.requested = append(f.requested, id)
	f.sections = append(f.sections, sections)
	return f.online[id]
}
func (f *fakeHub) UpdateAgent(id string) bool {
	f.updated = append(f.updated, id)
	return f.online[id]
}
func (f *fakeHub) Configure(id string, set store.AgentSettings) bool {
	if f.configured == nil {
		f.configured = map[string]store.AgentSettings{}
	}
	f.configured[id] = set
	return f.online[id]
}
func (f *fakeHub) Disconnect(id string) { f.disconnected = append(f.disconnected, id) }
func (f *fakeHub) Send(id string, m *agentv1.ServerMessage) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, m)
	return f.online[id]
}

type harness struct {
	t     *testing.T
	st    *store.Store
	idp   *fakeIdP
	hub   *fakeHub
	srv   *Server
	ts    *httptest.Server
	cfg   config.Config
	nonce int
}

func newHarness(t *testing.T) *harness {
	st, _ := storetest.New(t)
	h := &harness{t: t, st: st, idp: &fakeIdP{}, hub: &fakeHub{online: map[string]bool{}}}
	h.ts = httptest.NewUnstartedServer(nil)
	u, _ := url.Parse("http://" + h.ts.Listener.Addr().String())
	key := make([]byte, 32)
	h.cfg = config.Config{
		PublicURL: u, GroupsClaim: "groups", BootstrapAdminGroup: "lab-admins",
		CookieKey: key, SecretKey: key, Location: time.UTC,
		GRPCPublicAddr: "agent.baseline.example:443", AgentDir: t.TempDir(),
	}
	srv, err := New(h.cfg, st, h.idp, h.hub, make([]byte, 32), &jw6_utils.Utils{LogLevel: jw6_utils.Fatal}, "test")
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	h.ts.Config.Handler = srv.Handler()
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	return h
}

// client returns a browser-like client: cookie jar, no redirect following.
func (h *harness) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *harness) do(c *http.Client, method, path string, form url.Values, hdr ...string) (*http.Response, string) {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// signIn runs the whole login dance and returns a signed-in client.
func (h *harness) signIn(sub string, groups ...string) *http.Client {
	h.t.Helper()
	h.idp.sub, h.idp.groups = sub, groups
	c := h.client()
	resp, _ := h.do(c, "GET", "/auth/login?next=/me", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://idp.example/authorize" {
		h.t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := h.do(c, "GET", "/auth/callback?state=state-1&code=good", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/me" {
		h.t.Fatalf("callback: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	return c
}

func (h *harness) auditActions() string {
	entries, err := h.st.ListAudit(context.Background(), 0, 100)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for i := len(entries) - 1; i >= 0; i-- {
		out = append(out, entries[i].Action)
	}
	return strings.Join(out, " ")
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(h.client(), "GET", "/audit?before=5", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/auth/login?next=%2Faudit%3Fbefore%3D5" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLoginFlowAndLogout(t *testing.T) {
	h := newHarness(t)
	c := h.signIn("ann", "lab-admins", "users")

	resp, body := h.do(c, "GET", "/me", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "ANN") || !strings.Contains(body, "lab-admins") || !strings.Contains(body, "admin") {
		t.Fatalf("/me: %d\n%s", resp.StatusCode, body)
	}
	if resp, body := h.do(c, "GET", "/", nil); resp.StatusCode != 200 || !strings.Contains(body, ">Administration<") {
		t.Fatalf("dashboard: %d", resp.StatusCode)
	}

	if resp, _ := h.do(c, "POST", "/auth/logout", url.Values{}); resp.StatusCode != 200 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ := h.do(c, "GET", "/", nil); resp.StatusCode != http.StatusFound {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
	if got := h.auditActions(); got != "auth.login auth.logout" {
		t.Fatalf("audit: %s", got)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	h.do(c, "GET", "/auth/login", nil)
	resp, _ := h.do(c, "GET", "/auth/callback?state=forged&code=good", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := h.auditActions(); got != "auth.login_failed" {
		t.Fatalf("audit: %s", got)
	}
	// The login cookie was consumed, so replaying the right state fails too.
	if resp, _ := h.do(c, "GET", "/auth/callback?state=state-1&code=good", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay: %d", resp.StatusCode)
	}
}

func TestCallbackWithoutLoginCookie(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do(h.client(), "GET", "/auth/callback?state=state-1&code=good", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUserWithoutRolesSeesNoAccess(t *testing.T) {
	h := newHarness(t)
	c := h.signIn("bob", "random-group")
	resp, body := h.do(c, "GET", "/", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "No access yet") || !strings.Contains(body, "random-group") {
		t.Fatalf("%d\n%s", resp.StatusCode, body)
	}
	// /me still works, so the user can see which groups they sent.
	if resp, _ := h.do(c, "GET", "/me", nil); resp.StatusCode != 200 {
		t.Fatalf("/me: %d", resp.StatusCode)
	}
}

func TestBindingsApplyWithoutReLogin(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("bob", "lab-viewers")

	if resp, _ := h.do(viewer, "GET", "/", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("before binding: %d", resp.StatusCode)
	}
	resp, _ := h.do(admin, "POST", "/settings/access/bindings",
		url.Values{"idp_group": {"lab-viewers"}, "role": {"viewer"}, "scope": {"global"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("create binding: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.do(viewer, "GET", "/", nil); resp.StatusCode != 200 {
		t.Fatalf("after binding: %d", resp.StatusCode)
	}
	// A viewer can read the audit log but not settings.
	if resp, _ := h.do(viewer, "GET", "/audit", nil); resp.StatusCode != 200 {
		t.Fatalf("viewer audit: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "GET", "/settings/access", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer settings: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "POST", "/settings/access/groups", url.Values{"name": {"x"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer create group: %d", resp.StatusCode)
	}
}

func TestHostGroupsAndScopedBinding(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	h.do(admin, "POST", "/settings/access/groups", url.Values{"name": {"media"}, "description": {"Plex"}})
	groups, _ := h.st.ListHostGroups(context.Background())
	if len(groups) != 1 {
		t.Fatalf("groups = %v", groups)
	}
	resp, _ := h.do(admin, "POST", "/settings/access/bindings",
		url.Values{"idp_group": {"lab-media-ops"}, "role": {"operator"}, "scope": {groups[0].ID}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("scoped binding: %d", resp.StatusCode)
	}
	_, body := h.do(admin, "GET", "/settings/access", nil)
	if !strings.Contains(body, "lab-media-ops") || !strings.Contains(body, "host group <strong>media</strong>") {
		t.Fatalf("access page:\n%s", body)
	}

	ops := h.signIn("carl", "lab-media-ops")
	_, body = h.do(ops, "GET", "/me", nil)
	if !strings.Contains(body, "On host group media") {
		t.Fatalf("/me:\n%s", body)
	}

	resp, _ = h.do(admin, "POST", "/settings/access/bindings", url.Values{"idp_group": {"x"}, "role": {"root"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=") {
		t.Fatalf("bad role accepted: %s", loc)
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	resp, _ := h.do(admin, "POST", "/settings/access/groups", url.Values{"name": {"evil"}},
		"Sec-Fetch-Site", "cross-site")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/access/groups", url.Values{"name": {"evil"}},
		"Origin", "https://evil.example")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("origin status %d", resp.StatusCode)
	}
	if groups, _ := h.st.ListHostGroups(context.Background()); len(groups) != 0 {
		t.Fatal("cross-origin POST created a group")
	}
}

func TestAuditVerifyAndPage(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	resp, body := h.do(admin, "POST", "/audit/verify", url.Values{})
	if resp.StatusCode != 200 || !strings.Contains(body, "Chain intact: 1 entries") {
		t.Fatalf("%d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "auth.login") {
		t.Fatal("audit page should list the login")
	}
}

func TestHealthzAndHeaders(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(h.client(), "GET", "/healthz", nil)
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing CSP")
	}
	if resp, _ := h.do(h.client(), "GET", "/static/style.css", nil); resp.StatusCode != 200 {
		t.Fatalf("static: %d", resp.StatusCode)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":               "/",
		"/hosts?x=1":     "/hosts?x=1",
		"//evil.example": "/",
		"https://evil":   "/",
		`/\evil.example`: "/",
		"hosts":          "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStringsClaim(t *testing.T) {
	claims := map[string]any{"groups": []any{"a", 3, "", "b"}, "one": "solo"}
	if got := stringsClaim(claims, "groups"); strings.Join(got, ",") != "a,b" {
		t.Errorf("groups = %v", got)
	}
	if got := stringsClaim(claims, "one"); len(got) != 1 || got[0] != "solo" {
		t.Errorf("one = %v", got)
	}
	if got := stringsClaim(claims, "missing"); got != nil {
		t.Errorf("missing = %v", got)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.5:41234"
	if got := clientIP(r); got != "172.18.0.5" {
		t.Errorf("no XFF: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.8.0.7")
	if got := clientIP(r); got != "10.8.0.7" {
		t.Errorf("XFF: %s", got)
	}
}

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	dgst  = "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac"
	dgst2 = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

func TestParseRef(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Ref
		str  string
	}{
		{"nginx", Ref{"docker.io", "library/nginx", "latest", ""}, "docker.io/library/nginx:latest"},
		{"nginx:1.27", Ref{"docker.io", "library/nginx", "1.27", ""}, "docker.io/library/nginx:1.27"},
		{"library/nginx", Ref{"docker.io", "library/nginx", "latest", ""}, ""},
		{"docker.io/nginx", Ref{"docker.io", "library/nginx", "latest", ""}, ""},
		{"index.docker.io/library/nginx:1", Ref{"docker.io", "library/nginx", "1", ""}, "docker.io/library/nginx:1"},
		{"registry-1.docker.io/nginx", Ref{"docker.io", "library/nginx", "latest", ""}, ""},
		{"Docker.IO/linuxserver/plex", Ref{"docker.io", "linuxserver/plex", "latest", ""}, ""},
		{"linuxserver/plex:1.41.3", Ref{"docker.io", "linuxserver/plex", "1.41.3", ""}, ""},
		{"ghcr.io/home-assistant/home-assistant:2025.1", Ref{"ghcr.io", "home-assistant/home-assistant", "2025.1", ""}, "ghcr.io/home-assistant/home-assistant:2025.1"},
		{"localhost/foo", Ref{"localhost", "foo", "latest", ""}, ""},
		{"localhost:5000/foo", Ref{"localhost:5000", "foo", "latest", ""}, "localhost:5000/foo:latest"},
		{"registry.example:5000/a/b/c:tag@" + dgst, Ref{"registry.example:5000", "a/b/c", "tag", dgst}, "registry.example:5000/a/b/c:tag@" + dgst},
		{"quay.io/x/y@" + dgst, Ref{"quay.io", "x/y", "", dgst}, "quay.io/x/y@" + dgst},
		{"nginx@" + dgst, Ref{"docker.io", "library/nginx", "", dgst}, "docker.io/library/nginx@" + dgst},
		{"10.0.0.5:5000/team/app:v1.2.3-rc.1", Ref{"10.0.0.5:5000", "team/app", "v1.2.3-rc.1", ""}, ""},
		{"my_reg/a__b/c-d--e.f:T_1", Ref{"docker.io", "my_reg/a__b/c-d--e.f", "T_1", ""}, ""},
		{"[::1]:5000/foo", Ref{"[::1]:5000", "foo", "latest", ""}, ""},
	} {
		got, err := ParseRef(c.in)
		if err != nil {
			t.Errorf("ParseRef(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRef(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if c.str != "" && got.String() != c.str {
			t.Errorf("ParseRef(%q).String() = %q, want %q", c.in, got.String(), c.str)
		}
		// The canonical form must parse back to itself.
		if again, err := ParseRef(got.String()); err != nil || again != got {
			t.Errorf("round trip of %q: %+v, %v", got.String(), again, err)
		}
	}
}

func TestParseRefInvalid(t *testing.T) {
	for _, in := range []string{
		"",
		"Nginx",
		"docker.io/Library/nginx",
		"nginx:",
		"nginx:-bad",
		"nginx:a b",
		"nginx@",
		"nginx@sha256:abc",
		"nginx@sha256:" + strings.Repeat("A", 64),
		"sha256:" + dgst[7:],
		dgst[7:],
		"sha256:abc",
		"/nginx",
		"nginx/",
		"a//b",
		"ghcr.io/",
		"-bad.example/x",
		"foo/bar_/baz",
		"foo bar",
		"foo/" + strings.Repeat("a", 260),
		"nginx:" + strings.Repeat("t", 129),
	} {
		if r, err := ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want error", in, r)
		}
	}
}

func TestRefRepo(t *testing.T) {
	r, _ := ParseRef("nginx:1.27@" + dgst)
	if r.Repo() != "docker.io/library/nginx" {
		t.Errorf("Repo() = %q", r.Repo())
	}
}

// fakeRegistry is a registry behind a bearer token service on the same
// server, the way Docker Hub and GHCR work.
type fakeRegistry struct {
	t         *testing.T
	srv       *httptest.Server
	user      string // basic creds the token service requires, if set
	pass      string
	ttl       int // expires_in; 0 omits it
	accessTok bool

	mu          sync.Mutex
	tokenHits   int
	headHits    int
	getHits     int
	manifests   map[string]string // "repo:ref" → body
	noDigestHdr map[string]bool   // repos whose responses lack Docker-Content-Digest
	noHead      map[string]bool   // repos that reject HEAD
	tags        map[string][]string
	pageSize    int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{
		t:           t,
		manifests:   map[string]string{},
		noDigestHdr: map[string]bool{},
		noHead:      map[string]bool{},
		tags:        map[string][]string{},
		pageSize:    2,
		ttl:         300,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) client() *Client {
	return &Client{
		Endpoint:  func(string) string { return f.srv.URL + "/" },
		UserAgent: "baseline-test",
	}
}

func token(scope string) string { return "tok-" + scope }

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("User-Agent") != "baseline-test" {
		f.t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
	}
	if r.URL.Path == "/token" {
		f.tokenHits++
		q := r.URL.Query()
		if q.Get("service") != "fake-registry" || !strings.HasPrefix(q.Get("scope"), "repository:") {
			http.Error(w, "bad service or scope", http.StatusBadRequest)
			return
		}
		if f.user != "" {
			if u, p, ok := r.BasicAuth(); !ok || u != f.user || p != f.pass {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"incorrect username or password"}]}`)
				return
			}
		}
		resp := map[string]any{}
		if f.accessTok {
			resp["access_token"] = token(q.Get("scope"))
		} else {
			resp["token"] = token(q.Get("scope"))
		}
		if f.ttl != 0 {
			resp["expires_in"] = f.ttl
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	rest, ok := strings.CutPrefix(r.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var repo, kind, ref string
	if i := strings.LastIndex(rest, "/manifests/"); i >= 0 {
		repo, kind, ref = rest[:i], "manifest", rest[i+len("/manifests/"):]
	} else if p, ok := strings.CutSuffix(rest, "/tags/list"); ok {
		repo, kind = p, "tags"
	}
	scope := "repository:" + repo + ":pull"
	if r.Header.Get("Authorization") != "Bearer "+token(scope) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake-registry",scope="%s"`, f.srv.URL, scope))
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
		return
	}
	if repo == "limited/app" {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your pull rate limit."}]}`)
		return
	}

	switch kind {
	case "manifest":
		if r.Method == http.MethodHead {
			f.headHits++
			if f.noHead[repo] {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		} else {
			f.getHits++
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.index.v1+json") ||
			!strings.Contains(r.Header.Get("Accept"), "application/vnd.docker.distribution.manifest.v2+json") {
			f.t.Errorf("manifest Accept = %q", r.Header.Get("Accept"))
		}
		body, ok := f.manifests[repo+":"+ref]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown","detail":{"Tag":"`+ref+`"}}]}`)
			return
		}
		sum := sha256.Sum256([]byte(body))
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		if !f.noDigestHdr[repo] {
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodGet {
			fmt.Fprint(w, body)
		}
	case "tags":
		all, ok := f.tags[repo]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`)
			return
		}
		// Real registries page with ?last=; we ignore the client's n and
		// use a tiny page to force several pages.
		start := 0
		if last := r.URL.Query().Get("last"); last != "" {
			for i, tg := range all {
				if tg == last {
					start = i + 1
				}
			}
		}
		end := min(start+f.pageSize, len(all))
		if end < len(all) {
			w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?last=%s&n=%d>; rel="next"`, repo, all[end-1], f.pageSize))
		}
		json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": all[start:end]})
	default:
		http.NotFound(w, r)
	}
}

func mustRef(t *testing.T, s string) Ref {
	t.Helper()
	r, err := ParseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestDigest(t *testing.T) {
	f := newFakeRegistry(t)
	f.manifests["library/nginx:1.27"] = `{"schemaVersion":2,"manifests":[]}`
	f.manifests["library/nginx:"+dgst] = `{"pinned":true}`
	f.manifests["plain/app:v1"] = `{"schemaVersion":2,"config":{}}`
	f.noDigestHdr["plain/app"] = true
	f.manifests["nohead/app:v1"] = `{"nohead":true}`
	f.noHead["nohead/app"] = true
	c := f.client()
	ctx := context.Background()

	got, err := c.Digest(ctx, mustRef(t, "nginx:1.27"))
	if err != nil || got != sha(f.manifests["library/nginx:1.27"]) {
		t.Fatalf("Digest = %q, %v", got, err)
	}
	if f.getHits != 0 {
		t.Errorf("HEAD with a digest header still did %d GETs", f.getHits)
	}

	// No Docker-Content-Digest: GET and hash the body.
	got, err = c.Digest(ctx, mustRef(t, "plain/app:v1"))
	if err != nil || got != sha(f.manifests["plain/app:v1"]) {
		t.Errorf("GET fallback Digest = %q, %v", got, err)
	}
	// HEAD rejected: GET.
	got, err = c.Digest(ctx, mustRef(t, "nohead/app:v1"))
	if err != nil || got != sha(f.manifests["nohead/app:v1"]) {
		t.Errorf("no-HEAD Digest = %q, %v", got, err)
	}
	// A digest-only ref asks by digest.
	got, err = c.Digest(ctx, mustRef(t, "nginx@"+dgst))
	if err != nil || got != sha(`{"pinned":true}`) {
		t.Errorf("by-digest Digest = %q, %v", got, err)
	}

	// Unknown tag: the registry's message, after a GET to fetch it.
	_, err = c.Digest(ctx, mustRef(t, "nginx:9.99"))
	if err == nil || err.Error() != "docker.io/library/nginx:9.99: manifest unknown (404)" {
		t.Errorf("unknown tag error = %v", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 {
		t.Errorf("unknown tag error is not a 404 StatusError: %#v", err)
	}

	// Rate limited: no GET retry, which would cost a pull.
	gets := f.getHits
	_, err = c.Digest(ctx, mustRef(t, "limited/app:1"))
	if err == nil || err.Error() != "docker.io/limited/app:1: rate limited by registry (429)" {
		t.Errorf("429 error = %v", err)
	}
	if f.getHits != gets {
		t.Errorf("429 on HEAD was retried with GET")
	}

	// One token per repository scope, reused across calls.
	if f.tokenHits != 4 {
		t.Errorf("token service hit %d times, want 4 (one per repository)", f.tokenHits)
	}
}

func TestTokenCache(t *testing.T) {
	f := newFakeRegistry(t)
	f.manifests["library/nginx:1"] = "a"
	f.tags["library/nginx"] = []string{"1"}
	c := f.client()
	ref := mustRef(t, "nginx:1")
	for range 2 {
		if _, err := c.Digest(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Tags(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 1 {
		t.Errorf("token service hit %d times, want 1", f.tokenHits)
	}
}

func TestTokenExpiry(t *testing.T) {
	f := newFakeRegistry(t)
	f.manifests["library/nginx:1"] = "a"
	f.ttl = 30
	now := time.Unix(1_800_000_000, 0)
	c := f.client()
	c.now = func() time.Time { return now }
	ref := mustRef(t, "nginx:1")
	digest := func() {
		if _, err := c.Digest(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	digest()
	now = now.Add(20 * time.Second)
	digest()
	if f.tokenHits != 1 {
		t.Fatalf("token refetched before expiry: %d hits", f.tokenHits)
	}
	now = now.Add(15 * time.Second)
	digest()
	if f.tokenHits != 2 {
		t.Errorf("token not refetched after expires_in: %d hits", f.tokenHits)
	}

	// No expires_in: 60s.
	f.ttl = 0
	f.accessTok = true
	c = f.client()
	c.now = func() time.Time { return now }
	digest()
	now = now.Add(50 * time.Second)
	digest()
	if f.tokenHits != 3 {
		t.Fatalf("default TTL: %d hits, want 3", f.tokenHits)
	}
	now = now.Add(11 * time.Second)
	digest()
	if f.tokenHits != 4 {
		t.Errorf("default TTL: %d hits after 61s, want 4", f.tokenHits)
	}
}

func TestCredentials(t *testing.T) {
	f := newFakeRegistry(t)
	f.user, f.pass = "james", "s3cret-pass"
	f.manifests["private/app:1"] = "a"
	ref := mustRef(t, "private/app:1")

	c := f.client()
	_, err := c.Digest(context.Background(), ref)
	if err == nil || !strings.Contains(err.Error(), "unauthorized (401): check registry credentials") {
		t.Errorf("anonymous error = %v", err)
	}

	var asked []string
	c = f.client()
	c.Credentials = func(reg string) (string, string, bool) {
		asked = append(asked, reg)
		return "james", "wrong", true
	}
	_, err = c.Digest(context.Background(), ref)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong") {
		t.Errorf("wrong password error = %v", err)
	}
	if len(asked) == 0 || asked[0] != "docker.io" {
		t.Errorf("Credentials asked for %q", asked)
	}

	c.Credentials = func(string) (string, string, bool) { return "james", "s3cret-pass", true }
	if got, err := c.Digest(context.Background(), ref); err != nil || got != sha("a") {
		t.Errorf("with credentials: %q, %v", got, err)
	}
}

func TestBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Registry Realm"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", dgst)
	}))
	defer srv.Close()
	ref := mustRef(t, "registry.lan:5000/app:1")
	var gotReg string
	c := &Client{
		Endpoint: func(reg string) string { gotReg = reg; return srv.URL },
	}
	if _, err := c.Digest(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("anonymous against Basic: %v", err)
	}
	c.Credentials = func(string) (string, string, bool) { return "u", "p", true }
	if got, err := c.Digest(context.Background(), ref); err != nil || got != dgst {
		t.Errorf("Basic: %q, %v", got, err)
	}
	if gotReg != "registry.lan:5000" {
		t.Errorf("Endpoint asked for %q", gotReg)
	}
}

func TestTags(t *testing.T) {
	f := newFakeRegistry(t)
	want := []string{"1.0", "1.1", "1.2", "2.0", "latest"}
	f.tags["library/nginx"] = want
	c := f.client()
	got, err := c.Tags(context.Background(), mustRef(t, "nginx"))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Tags = %q, %v", got, err)
	}

	_, err = c.Tags(context.Background(), mustRef(t, "ghost/app"))
	if err == nil || err.Error() != "docker.io/ghost/app: repository name not known to registry (404)" {
		t.Errorf("unknown repo error = %v", err)
	}
	_, err = c.Tags(context.Background(), mustRef(t, "limited/app"))
	if err == nil || err.Error() != "docker.io/limited/app: rate limited by registry (429): You have reached your pull rate limit." {
		t.Errorf("429 error = %v", err)
	}
}

func TestTagsPageCap(t *testing.T) {
	f := newFakeRegistry(t)
	f.pageSize = 1
	var all []string
	for i := range 50 {
		all = append(all, fmt.Sprintf("1.%d", i))
	}
	f.tags["big/app"] = all
	got, err := f.client().Tags(context.Background(), mustRef(t, "big/app"))
	if err != nil || len(got) != maxTagPages {
		t.Errorf("Tags returned %d tags, %v; want %d (page cap)", len(got), err, maxTagPages)
	}
}

func TestTagsForeignLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected Authorization")
		}
		w.Header().Set("Link", `<https://evil.example/v2/x/tags/list?last=a>; rel="next"`)
		fmt.Fprint(w, `{"tags":["a"]}`)
	}))
	defer srv.Close()
	c := &Client{Endpoint: func(string) string { return srv.URL }}
	got, err := c.Tags(context.Background(), mustRef(t, "registry.lan/x"))
	if err != nil || !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("Tags = %q, %v", got, err)
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(strings.Repeat("x", maxManifestBody+1)))
		}
	}))
	defer srv.Close()
	c := &Client{Endpoint: func(string) string { return srv.URL }}
	_, err := c.Digest(context.Background(), mustRef(t, "registry.lan/x:1"))
	if err == nil || !strings.Contains(err.Error(), "larger than 8 MiB") {
		t.Errorf("oversized manifest: %v", err)
	}
}

func TestNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	c := &Client{Endpoint: func(string) string { return u }}
	_, err := c.Digest(context.Background(), mustRef(t, "registry.lan/x:1"))
	if err == nil || !strings.HasPrefix(err.Error(), "registry.lan/x:1: ") || strings.Contains(err.Error(), "/v2/") {
		t.Errorf("network error = %v", err)
	}
}

func TestDefaultEndpoint(t *testing.T) {
	var c Client
	for reg, want := range map[string]string{
		"docker.io":         "https://registry-1.docker.io",
		"ghcr.io":           "https://ghcr.io",
		"registry.lan:5000": "https://registry.lan:5000",
	} {
		if got := c.base(reg); got != want {
			t.Errorf("base(%q) = %q, want %q", reg, got, want)
		}
	}
}

func TestParseChallenges(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want []challenge
	}{
		{
			[]string{`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`},
			[]challenge{{"bearer", map[string]string{"realm": "https://auth.docker.io/token", "service": "registry.docker.io", "scope": "repository:library/nginx:pull"}}},
		},
		{
			[]string{`Bearer realm="https://x/token", scope="repository:a/b:pull,push" , service="x"`},
			[]challenge{{"bearer", map[string]string{"realm": "https://x/token", "scope": "repository:a/b:pull,push", "service": "x"}}},
		},
		{
			[]string{`Basic realm="Registry Realm"`},
			[]challenge{{"basic", map[string]string{"realm": "Registry Realm"}}},
		},
		{
			[]string{`BEARER Realm=https://x/token,Service=x`},
			[]challenge{{"bearer", map[string]string{"realm": "https://x/token", "service": "x"}}},
		},
		{
			[]string{`Bearer realm="a\"b", error="insufficient_scope", Basic realm="r"`},
			[]challenge{
				{"bearer", map[string]string{"realm": `a"b`, "error": "insufficient_scope"}},
				{"basic", map[string]string{"realm": "r"}},
			},
		},
		{
			[]string{`Basic realm="r"`, `Bearer realm="t"`},
			[]challenge{{"basic", map[string]string{"realm": "r"}}, {"bearer", map[string]string{"realm": "t"}}},
		},
		{[]string{`Bearer realm="unterminated`}, []challenge{{"bearer", map[string]string{"realm": "unterminated"}}}},
		{[]string{`Negotiate`}, []challenge{{"negotiate", map[string]string{}}}},
		{[]string{""}, nil},
	} {
		if got := parseChallenges(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseChallenges(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestChallengeWithoutScope(t *testing.T) {
	var gotScope string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			gotScope = r.URL.Query().Get("scope")
			fmt.Fprint(w, `{"access_token":"t"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer t" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", dgst2)
	}))
	defer srv.Close()
	c := &Client{Endpoint: func(string) string { return srv.URL }}
	got, err := c.Digest(context.Background(), mustRef(t, "registry.lan/team/app:1"))
	if err != nil || got != dgst2 {
		t.Fatalf("Digest = %q, %v", got, err)
	}
	if gotScope != "repository:team/app:pull" {
		t.Errorf("scope = %q", gotScope)
	}
}

func TestNextLink(t *testing.T) {
	cur := mustURL(t, "https://r.example/v2/a/tags/list?n=1000")
	base := mustURL(t, "https://r.example")
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{`</v2/a/tags/list?last=b&n=1000>; rel="next"`}, "https://r.example/v2/a/tags/list?last=b&n=1000"},
		{[]string{`<https://r.example/v2/a/tags/list?last=b,c>; rel=next`}, "https://r.example/v2/a/tags/list?last=b,c"},
		{[]string{`</first>; rel="first", </v2/a/tags/list?last=z>; rel="next"`}, "https://r.example/v2/a/tags/list?last=z"},
		{[]string{`</v2/a/tags/list?last=b>; rel="prev"`}, ""},
		{[]string{`<https://other.example/v2/a/tags/list?last=b>; rel="next"`}, ""},
		{nil, ""},
	} {
		if got := nextLink(c.in, cur, base); got != c.want {
			t.Errorf("nextLink(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestStatusError(t *testing.T) {
	for _, c := range []struct {
		e    StatusError
		want string
	}{
		{StatusError{401, "authentication required"}, "unauthorized (401): check registry credentials"},
		{StatusError{429, ""}, "rate limited by registry (429)"},
		{StatusError{404, "manifest unknown"}, "manifest unknown (404)"},
		{StatusError{404, ""}, "not found (404)"},
		{StatusError{403, ""}, "access denied (403)"},
		{StatusError{403, "denied: requested access to the resource is denied"}, "denied: requested access to the resource is denied (403)"},
		{StatusError{503, ""}, "service unavailable (503)"},
		{StatusError{599, ""}, "unexpected status (599)"},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.e, got, c.want)
		}
	}
}

func TestStatusErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":[{"code":"DENIED","message":"no\n access"},{"code":"DENIED","message":"no access"},{"code":"NAME_INVALID"}]}`)
	}))
	defer srv.Close()
	c := &Client{Endpoint: func(string) string { return srv.URL }}
	_, err := c.Tags(context.Background(), mustRef(t, "registry.lan/x"))
	if err == nil || err.Error() != "registry.lan/x: no access; name invalid (403)" {
		t.Errorf("error = %v", err)
	}
}

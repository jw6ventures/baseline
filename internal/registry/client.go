package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Response size limits. Real manifests and tag pages are far smaller; the
// limits only stop a broken or hostile registry from exhausting memory.
const (
	maxManifestBody = 8 << 20
	maxTagsBody     = 4 << 20
	maxTokenBody    = 1 << 20
	maxErrorBody    = 64 << 10

	maxTags     = 10000
	maxTagPages = 20

	defaultTokenTTL = 60 * time.Second
)

// manifestAccept lists every manifest type a tag can point at. Without the
// index types, registries convert multi-arch images to a single-arch schema2
// manifest whose digest never matches what the engine pulled.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

var defaultHTTP = &http.Client{Timeout: 30 * time.Second}

// Client talks to registries. The zero value is ready to use; a Client must
// not be copied after first use.
type Client struct {
	HTTP *http.Client // nil: a client with a 30s timeout
	// Credentials returns a username and password (or token) for a registry
	// host; ok=false means anonymous. May be nil.
	Credentials func(registry string) (username, password string, ok bool)
	// Endpoint maps a registry host to its base URL. nil: https://<host>,
	// except docker.io → https://registry-1.docker.io. Tests point it at httptest.
	Endpoint  func(registry string) string
	UserAgent string

	mu     sync.Mutex
	tokens map[string]cachedToken // registry + " " + scope
	now    func() time.Time       // tests move the clock
}

type cachedToken struct {
	value   string
	expires time.Time
}

// StatusError is an error response from a registry or its token service.
// Callers can use errors.As to tell a missing tag from a rate limit.
type StatusError struct {
	Code    int
	Message string // the registry's own message, if it sent one
}

func (e *StatusError) Error() string {
	switch {
	case e.Code == http.StatusUnauthorized:
		return "unauthorized (401): check registry credentials"
	case e.Code == http.StatusTooManyRequests:
		if e.Message != "" {
			return "rate limited by registry (429): " + e.Message
		}
		return "rate limited by registry (429)"
	case e.Message != "":
		return fmt.Sprintf("%s (%d)", e.Message, e.Code)
	case e.Code == http.StatusNotFound:
		return "not found (404)"
	case e.Code == http.StatusForbidden:
		return "access denied (403)"
	}
	if t := http.StatusText(e.Code); t != "" {
		return fmt.Sprintf("%s (%d)", strings.ToLower(t), e.Code)
	}
	return fmt.Sprintf("unexpected status (%d)", e.Code)
}

// Digest returns the manifest digest the registry serves for ref's tag (or
// its digest when it has no tag). It uses HEAD, which Docker Hub doesn't
// count against pull limits, and falls back to GET when the registry
// doesn't answer HEAD with a Docker-Content-Digest.
func (c *Client) Digest(ctx context.Context, ref Ref) (string, error) {
	name := ref.String()
	reference := ref.Tag
	if reference == "" {
		reference = ref.Digest
	}
	if ref.Registry == "" || ref.Repository == "" || reference == "" {
		return "", fmt.Errorf("%s: incomplete image reference", name)
	}
	u := c.base(ref.Registry) + "/v2/" + ref.Repository + "/manifests/" + reference

	resp, err := c.do(ctx, http.MethodHead, ref, u, manifestAccept)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	drain(resp)
	switch {
	case resp.StatusCode == http.StatusOK:
		if d := resp.Header.Get("Docker-Content-Digest"); validDigest(d) {
			return d, nil
		}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusTooManyRequests:
		// GET would fail the same way and, on Docker Hub, cost a pull.
		return "", fmt.Errorf("%s: %w", name, &StatusError{Code: resp.StatusCode})
	}
	// Some registries reject HEAD or omit the header, and HEAD errors carry
	// no body to explain themselves; GET answers both.
	resp, err = c.do(ctx, http.MethodGet, ref, u, manifestAccept)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %w", name, statusError(resp))
	}
	if d := resp.Header.Get("Docker-Content-Digest"); validDigest(d) {
		return d, nil
	}
	body, err := readLimited(resp.Body, maxManifestBody)
	if err != nil {
		return "", fmt.Errorf("%s: manifest: %w", name, err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Tags lists a repository's tags, following pagination up to 10000 tags or
// 20 pages; past that the list is returned truncated.
func (c *Client) Tags(ctx context.Context, ref Ref) ([]string, error) {
	name := ref.Repo()
	if ref.Registry == "" || ref.Repository == "" {
		return nil, fmt.Errorf("%s: incomplete image reference", name)
	}
	base := c.base(ref.Registry)
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%s: bad registry endpoint: %w", name, err)
	}
	next := base + "/v2/" + ref.Repository + "/tags/list?n=1000"
	seen := map[string]bool{}
	var tags []string
	for page := 0; next != "" && page < maxTagPages && len(tags) < maxTags && !seen[next]; page++ {
		seen[next] = true
		resp, err := c.do(ctx, http.MethodGet, ref, next, "application/json")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if resp.StatusCode != http.StatusOK {
			err := statusError(resp)
			drain(resp)
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		body, err := readLimited(resp.Body, maxTagsBody)
		drain(resp)
		if err != nil {
			return nil, fmt.Errorf("%s: tag list: %w", name, err)
		}
		var list struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("%s: malformed tag list", name)
		}
		tags = append(tags, list.Tags...)
		next = nextLink(resp.Header.Values("Link"), resp.Request.URL, baseURL)
	}
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	return tags, nil
}

func (c *Client) base(registry string) string {
	if c.Endpoint != nil {
		return strings.TrimRight(c.Endpoint(registry), "/")
	}
	if registry == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + registry
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// do sends a request with any cached token and, on 401, answers the
// registry's challenge and retries once. A 401 that survives the retry is
// returned as a response for the caller to report.
func (c *Client) do(ctx context.Context, method string, ref Ref, u, accept string) (*http.Response, error) {
	scope := "repository:" + ref.Repository + ":pull"
	resp, err := c.send(ctx, method, u, accept, c.cached(ref.Registry, scope))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenges := parseChallenges(resp.Header.Values("WWW-Authenticate"))
	drain(resp)
	auth, err := c.authorize(ctx, ref.Registry, scope, challenges)
	if err != nil {
		return nil, err
	}
	if auth == "" {
		return nil, &StatusError{Code: http.StatusUnauthorized}
	}
	return c.send(ctx, method, u, accept, auth)
}

func (c *Client) send(ctx context.Context, method, u, accept, auth string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	c.setUA(req)
	resp, err := c.httpClient().Do(req)
	return resp, shortenErr(err)
}

func (c *Client) setUA(req *http.Request) {
	ua := c.UserAgent
	if ua == "" {
		ua = "Baseline"
	}
	req.Header.Set("User-Agent", ua)
}

// shortenErr drops url.Error's method and URL: the caller already prefixes
// the image, and the UI has little room.
func shortenErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (c *Client) cached(registry, scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tokens[registry+" "+scope]
	if !ok {
		return ""
	}
	if !c.clock().Before(t.expires) {
		delete(c.tokens, registry+" "+scope)
		return ""
	}
	return "Bearer " + t.value
}

func (c *Client) store(registry string, scopes []string, value string, ttl time.Duration) {
	// Renew a little early so a token doesn't expire in flight.
	if ttl > 10*time.Second {
		ttl -= 5 * time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		c.tokens = map[string]cachedToken{}
	}
	exp := c.clock().Add(ttl)
	for _, s := range scopes {
		c.tokens[registry+" "+s] = cachedToken{value: value, expires: exp}
	}
}

// authorize turns a 401's challenges into an Authorization header value,
// or "" when it can't (Basic with no credentials, an unknown scheme).
func (c *Client) authorize(ctx context.Context, registry, scope string, challenges []challenge) (string, error) {
	user, pass, haveCreds := "", "", false
	if c.Credentials != nil {
		user, pass, haveCreds = c.Credentials(registry)
	}
	for _, ch := range challenges {
		if ch.scheme != "bearer" || ch.params["realm"] == "" {
			continue
		}
		want := ch.params["scope"]
		if want == "" {
			want = scope
		}
		tok, ttl, err := c.fetchToken(ctx, ch.params["realm"], ch.params["service"], want, user, pass, haveCreds)
		if err != nil {
			return "", err
		}
		// Cache under the scope we look up next time as well as the one the
		// registry named, in case they're spelled differently.
		c.store(registry, []string{scope, want}, tok, ttl)
		return "Bearer " + tok, nil
	}
	for _, ch := range challenges {
		if ch.scheme == "basic" && haveCreds {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
		}
	}
	return "", nil
}

func (c *Client) fetchToken(ctx context.Context, realm, service, scope, user, pass string, haveCreds bool) (string, time.Duration, error) {
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", 0, errors.New("registry sent an unusable token realm")
	}
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	for _, s := range strings.Fields(scope) {
		q.Add("scope", s)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", 0, err
	}
	if haveCreds {
		req.SetBasicAuth(user, pass)
	}
	c.setUA(req)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token service: %w", shortenErr(err))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token service: %w", statusError(resp))
	}
	body, err := readLimited(resp.Body, maxTokenBody)
	if err != nil {
		return "", 0, fmt.Errorf("token service: %w", err)
	}
	var tr struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, errors.New("token service: malformed response")
	}
	tok := tr.Token
	if tok == "" {
		tok = tr.AccessToken
	}
	if tok == "" {
		return "", 0, errors.New("token service: no token in response")
	}
	ttl := defaultTokenTTL
	if tr.ExpiresIn > 0 {
		ttl = time.Duration(tr.ExpiresIn) * time.Second
	}
	return tok, ttl, nil
}

// statusError builds a StatusError from a response, picking up the
// registry's {"errors":[{"code":..,"message":..}]} body when there is one.
func statusError(resp *http.Response) error {
	e := &StatusError{Code: resp.StatusCode}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return e
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var er struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &er) != nil {
		return e
	}
	var msgs []string
	for _, x := range er.Errors {
		m := x.Message
		if m == "" {
			m = strings.ToLower(strings.ReplaceAll(x.Code, "_", " "))
		}
		m = strings.Join(strings.Fields(m), " ")
		if m != "" && len(msgs) < 3 && !slices.Contains(msgs, m) {
			msgs = append(msgs, m)
		}
	}
	e.Message = strings.Join(msgs, "; ")
	if len(e.Message) > 300 {
		e.Message = e.Message[:300] + "…"
	}
	return e
}

// readLimited reads all of r, failing rather than truncating past max: a
// truncated manifest would hash to a wrong digest.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response larger than %d MiB", max>>20)
	}
	return b, nil
}

// drain reads a little of what's left so the connection can be reused.
func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
}

// nextLink returns the rel="next" target of a Link header resolved against
// the current page, or "" when there is none. A link to another host ends
// pagination: following it would send our token there.
func nextLink(values []string, cur, base *url.URL) string {
	for _, v := range values {
		for _, part := range splitLinks(v) {
			part = strings.TrimSpace(part)
			if !strings.HasPrefix(part, "<") {
				continue
			}
			end := strings.IndexByte(part, '>')
			if end < 0 {
				continue
			}
			target, params := part[1:end], part[end+1:]
			next := false
			for _, p := range strings.Split(params, ";") {
				k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
				if strings.EqualFold(strings.TrimSpace(k), "rel") {
					for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(val), `"`)) {
						if strings.EqualFold(rel, "next") {
							next = true
						}
					}
				}
			}
			if !next {
				continue
			}
			u, err := cur.Parse(target)
			if err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
				return ""
			}
			return u.String()
		}
	}
	return ""
}

// splitLinks splits a Link header on the commas between links, not those
// inside <...> or quotes.
func splitLinks(v string) []string {
	var parts []string
	inURL, inQuote, start := false, false, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case inQuote:
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
		case inURL:
			if c == '>' {
				inURL = false
			}
		case c == '<':
			inURL = true
		case c == '"':
			inQuote = true
		case c == ',':
			parts = append(parts, v[start:i])
			start = i + 1
		}
	}
	return append(parts, v[start:])
}

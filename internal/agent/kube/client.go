// Package kube is a small read-only client for the Kubernetes API and the
// cluster-mode collector built on it (docs/architecture.md §2.2). It only
// gets and lists, authenticated with a service-account token, and decodes
// only the fields the agent reports: client-go would pull in a large,
// fast-moving dependency tree for a handful of GETs (§9).
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ServiceAccountDir is where Kubernetes mounts a pod's token and the
	// cluster CA.
	ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	// DefaultTimeout bounds one request (one page of a list).
	DefaultTimeout = 30 * time.Second
	// tokenMaxAge is how long a token read from a file is used before the
	// file is read again. Bound service-account tokens are rotated by the
	// kubelet (hourly by default), well before they expire.
	tokenMaxAge = time.Minute
	// pageSize is the limit of each list request; the API server returns a
	// continue token for the rest.
	pageSize = 250
	// maxBody caps one response. A page of 250 pods with their managed
	// fields is a few megabytes; this only stops a misbehaving server.
	maxBody = 64 << 20
)

// ErrNotInCluster is returned by InCluster outside a pod.
var ErrNotInCluster = errors.New("not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set)")

// Client talks to one API server. It is safe for concurrent use.
type Client struct {
	// BaseURL is the API server, "https://10.43.0.1:443".
	BaseURL string
	// TokenFile is read for the bearer token, again once the copy in
	// memory is a minute old; Token is used when it is empty.
	TokenFile string
	Token     string
	HTTP      *http.Client
	// Timeout bounds each request whose context has no deadline;
	// DefaultTimeout when zero.
	Timeout time.Duration

	mu     sync.Mutex
	token  string    // from TokenFile
	readAt time.Time // when token was read
	now    func() time.Time
}

// New returns a client for the API server at baseURL that verifies the
// server against roots. Set Token or TokenFile on it.
func New(baseURL string, roots *x509.CertPool) *Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     2 * time.Minute,
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Transport: tr}}
}

// InCluster returns a client for the cluster the agent's pod runs in, using
// the pod's service account.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, ErrNotInCluster
	}
	roots, err := LoadCA(ServiceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	c := New("https://"+net.JoinHostPort(host, port), roots)
	c.TokenFile = ServiceAccountDir + "/token"
	if _, err := c.bearer(false); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadCA reads a PEM bundle of CA certificates.
func LoadCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificates", path)
	}
	return pool, nil
}

// bearer returns the token, reading TokenFile again when the copy in memory
// is older than tokenMaxAge, or at once with reread.
func (c *Client) bearer(reread bool) (string, error) {
	if c.TokenFile == "" {
		return c.Token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if !reread && c.token != "" && now().Sub(c.readAt) < tokenMaxAge {
		return c.token, nil
	}
	b, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", fmt.Errorf("service account token: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("service account token: %s is empty", c.TokenFile)
	}
	c.token, c.readAt = t, now()
	return t, nil
}

// Error is a non-2xx answer from the API server, with the message of the
// Status object it sends.
type Error struct {
	Path    string // without the query
	Code    int
	Reason  string // Forbidden, NotFound...; the status text when absent
	Message string
}

func (e *Error) Error() string { return e.Path + ": " + e.Short() }

// Short is the error without the path, short enough for the UI:
// "403 Forbidden: ingresses.networking.k8s.io is forbidden: ...".
func (e *Error) Short() string {
	s := strconv.Itoa(e.Code) + " " + e.Reason
	if e.Message != "" {
		s += ": " + e.Message
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// IsNotFound reports a 404: the object, or the API itself on a cluster that
// doesn't serve it.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == http.StatusNotFound
}

// Get decodes GET path (with any query) into v.
func (c *Client) Get(ctx context.Context, path string, v any) error {
	err := c.get(ctx, path, v, false)
	var e *Error
	if errors.As(err, &e) && e.Code == http.StatusUnauthorized && c.TokenFile != "" {
		// The token may have been rotated since it was read.
		err = c.get(ctx, path, v, true)
	}
	return err
}

func (c *Client) get(ctx context.Context, path string, v any, reread bool) error {
	shown, _, _ := strings.Cut(path, "?")
	token, err := c.bearer(reread)
	if err != nil {
		return err
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", shown, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "baseline-agent")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is the same for every request
		}
		return fmt.Errorf("%s: %w", shown, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%s: %w", shown, err)
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Path: shown, Code: resp.StatusCode, Reason: http.StatusText(resp.StatusCode)}
		var st struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
			Reason  string `json:"reason"`
		}
		if json.Unmarshal(body, &st) == nil && st.Kind == "Status" {
			e.Message = st.Message
			if st.Reason != "" {
				e.Reason = st.Reason
			}
		}
		return e
	}
	if len(body) > maxBody {
		return fmt.Errorf("%s: response larger than %d MB", shown, maxBody>>20)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", shown, err)
	}
	return nil
}

// List gets every item of a list endpoint, a page at a time, decoding each
// into T (which should name only the fields wanted).
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	cont := ""
	restarted := false
	for {
		q := url.Values{"limit": {strconv.Itoa(pageSize)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		err := c.Get(ctx, path+"?"+q.Encode(), &page)
		var e *Error
		if errors.As(err, &e) && e.Code == http.StatusGone && cont != "" && !restarted {
			// The continue token expired (the listing took longer than
			// etcd keeps old revisions): start over, once.
			out, cont, restarted = nil, "", true
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.Metadata.Continue == "" {
			return out, nil
		}
		cont = page.Metadata.Continue
	}
}

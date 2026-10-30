// Package container is a small client for the Docker Engine API, which both
// Docker and Podman serve on a unix socket (docs/agent.md §3.1). It decodes
// only the fields the agent reports; in particular it never decodes a
// container's environment or command line, which hold secrets.
package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTimeout bounds a request whose context has no deadline.
	DefaultTimeout = 30 * time.Second
	// maxBody caps a response: a list of a few hundred containers is well
	// under a megabyte, so this only stops a misbehaving engine.
	maxBody = 32 << 20
)

// Client talks to one engine socket. It is safe for concurrent use.
type Client struct {
	Socket string
	hc     *http.Client

	mu     sync.Mutex
	prefix string // "/v1.47" once Version has run
	libpod string // Podman's own API version, for the libpod endpoints
	kind   string // "docker" or "podman", for error messages
}

// New returns a client for the engine listening on socket.
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     2 * time.Minute,
	}
	kind := "docker"
	if strings.Contains(socket, "podman") {
		kind = "podman"
	}
	return &Client{Socket: socket, hc: &http.Client{Transport: tr}, kind: kind}
}

// Close drops idle connections to the engine.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

// Error is a non-2xx answer from the engine.
type Error struct {
	Engine  string // docker | podman
	Method  string
	Path    string // without the version prefix
	Status  int
	Message string // the engine's "message", or the status text
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s %s: %d %s", e.Engine, e.Method, e.Path, e.Status, e.Message)
}

// IsNotFound reports a 404, e.g. a container removed since it was listed.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// get decodes GET path into v. Versioned requests carry the prefix Version
// negotiated; before that they go unversioned.
func (c *Client) get(ctx context.Context, path string, v any) error {
	c.mu.Lock()
	prefix, kind := c.prefix, c.kind
	c.mu.Unlock()
	return c.do(ctx, http.MethodGet, kind, prefix+path, path, v, nil)
}

// post sends POST path with no body and discards the answer.
func (c *Client) post(ctx context.Context, path string) error {
	c.mu.Lock()
	prefix, kind := c.prefix, c.kind
	c.mu.Unlock()
	return c.do(ctx, http.MethodPost, kind, prefix+path, path, nil, nil)
}

// Restart restarts a container (by name or ID), giving it timeout seconds
// to stop before it is killed (the container.restart action). It and Tag
// are the only requests that change anything.
func (c *Client) Restart(ctx context.Context, name string, timeout int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second+DefaultTimeout)
	defer cancel()
	return c.post(ctx, "/containers/"+url.PathEscape(name)+"/restart?t="+strconv.Itoa(timeout))
}

// Tag points repo:tag at an image, named by ID or reference. compose.update
// uses it to put a service's previous image back.
func (c *Client) Tag(ctx context.Context, image, repo, tag string) error {
	q := url.Values{"repo": {repo}, "tag": {tag}}
	return c.post(ctx, "/images/"+imagePath(image)+"/tag?"+q.Encode())
}

func (c *Client) do(ctx context.Context, method, kind, reqPath, shownPath string, v any, hdr *http.Header) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	// Errors name the path without its query.
	shown, _, _ := strings.Cut(shownPath, "?")
	req, err := http.NewRequestWithContext(ctx, method, "http://engine"+reqPath, nil)
	if err != nil {
		return fmt.Errorf("%s: %s %s: %w", kind, method, shown, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // "dial unix ...: permission denied" says enough
		}
		return fmt.Errorf("%s: %s %s: %w", kind, method, shown, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%s: %s %s: %w", kind, method, shown, err)
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Engine: kind, Method: method, Path: shown, Status: resp.StatusCode}
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &m) == nil && m.Message != "" {
			e.Message = m.Message
		} else {
			e.Message = strings.ToLower(http.StatusText(resp.StatusCode))
		}
		if len(e.Message) > 200 {
			e.Message = e.Message[:200] + "…"
		}
		return e
	}
	if len(body) > maxBody {
		return fmt.Errorf("%s: %s %s: response larger than %d bytes", kind, method, shown, maxBody)
	}
	if hdr != nil {
		*hdr = resp.Header
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: GET %s: %w", kind, shown, err)
	}
	return nil
}

// Version is the engine's /version.
type Version struct {
	Version    string
	APIVersion string
	Podman     bool
	// LibpodAPIVersion is Podman's native API version ("5.2.0"); "" for Docker.
	LibpodAPIVersion string
}

// Version asks the engine what it is and which API version it speaks.
// Later requests use that version: the server's own is always one it
// supports, and the fields read here exist in every version since 1.40.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var doc struct {
		Platform struct {
			Name string `json:"Name"`
		} `json:"Platform"`
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		Components []struct {
			Name    string `json:"Name"`
			Version string `json:"Version"`
			Details struct {
				APIVersion string `json:"APIVersion"`
			} `json:"Details"`
		} `json:"Components"`
	}
	c.mu.Lock()
	kind := c.kind
	c.mu.Unlock()
	var hdr http.Header
	if err := c.do(ctx, http.MethodGet, kind, "/version", "/version", &doc, &hdr); err != nil {
		return Version{}, err
	}
	if doc.APIVersion == "" {
		return Version{}, fmt.Errorf("%s: GET /version: no ApiVersion", kind)
	}
	v := Version{Version: doc.Version, APIVersion: doc.APIVersion, LibpodAPIVersion: hdr.Get("Libpod-Api-Version")}
	v.Podman = v.LibpodAPIVersion != "" || strings.Contains(strings.ToLower(doc.Platform.Name), "podman")
	for _, comp := range doc.Components {
		if comp.Name == "Podman Engine" {
			v.Podman = true
			if v.LibpodAPIVersion == "" {
				v.LibpodAPIVersion = comp.Details.APIVersion
			}
		}
	}
	c.mu.Lock()
	c.prefix = "/v" + strings.TrimPrefix(v.APIVersion, "v")
	c.kind = "docker"
	if v.Podman {
		c.kind = "podman"
		c.libpod = "/v" + strings.TrimPrefix(v.LibpodAPIVersion, "v")
		if v.LibpodAPIVersion == "" {
			c.libpod = c.prefix // the libpod routes accept any version prefix
		}
	}
	c.mu.Unlock()
	return v, nil
}

// Summary is an entry of the container list.
type Summary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
}

// Name is the container's name without Docker's leading "/".
func (s Summary) Name() string {
	if len(s.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

// ListContainers lists every container, running or not.
func (c *Client) ListContainers(ctx context.Context) ([]Summary, error) {
	var out []Summary
	return out, c.get(ctx, "/containers/json?all=1", &out)
}

// Inspect is the part of a container's inspect document the agent uses.
type Inspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Image   string `json:"Image"` // the image ID
	State   struct {
		Status      string  `json:"Status"`
		Running     bool    `json:"Running"`
		Pid         int     `json:"Pid"`
		ExitCode    int     `json:"ExitCode"`
		StartedAt   string  `json:"StartedAt"`
		Health      *Health `json:"Health"`
		Healthcheck *Health `json:"Healthcheck"` // Podman before 4
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Image  string            `json:"Image"` // the reference it was created from
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		// "80/tcp" → bindings; null when exposed but not published.
		Ports    map[string][]PortBinding `json:"Ports"`
		Networks map[string]struct{}      `json:"Networks"` // only the names are reported
	} `json:"NetworkSettings"`
}

type Health struct {
	Status string `json:"Status"`
}

type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// HealthStatus is "" for a container without a healthcheck.
func (i *Inspect) HealthStatus() string {
	switch {
	case i.State.Health != nil && i.State.Health.Status != "":
		return i.State.Health.Status
	case i.State.Healthcheck != nil:
		return i.State.Healthcheck.Status
	}
	return ""
}

// Inspect reads one container's details.
func (c *Client) Inspect(ctx context.Context, id string) (*Inspect, error) {
	var out Inspect
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Image is an entry of the image list.
type Image struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Size        int64    `json:"Size"`
	Created     int64    `json:"Created"` // unix seconds
}

// ListImages lists the engine's images.
func (c *Client) ListImages(ctx context.Context) ([]Image, error) {
	var out []Image
	return out, c.get(ctx, "/images/json", &out)
}

// ImageInspect is the part of an image's inspect document the agent uses.
type ImageInspect struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

// InspectImage reads an image by ID or reference ("nginx:1.27"); a
// reference the engine doesn't have is a 404 (IsNotFound).
func (c *Client) InspectImage(ctx context.Context, ref string) (*ImageInspect, error) {
	var out ImageInspect
	if err := c.get(ctx, "/images/"+imagePath(ref)+"/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// imagePath escapes an image reference for a URL path. Its slashes stay:
// the engines route /images/{name:.*}/..., as the Docker CLI sends them.
func imagePath(ref string) string {
	segs := strings.Split(ref, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// SplitRef splits an image reference into repository and tag, the way the
// tag endpoint takes them: "nginx:1.27" is "nginx" and "1.27", and a
// reference without a tag means "latest". A reference pinned by digest
// ("nginx@sha256:...") can't be tagged, so ok is false.
func SplitRef(ref string) (repo, tag string, ok bool) {
	if ref == "" || strings.Contains(ref, "@") {
		return "", "", false
	}
	// A ":" before the last "/" belongs to a registry's port.
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		return ref[:i], ref[i+1:], ref[i+1:] != "" && i > 0
	}
	return ref, "latest", true
}

// Stats is one reading of a container's resource use, the cgroup v1
// fallback for metrics.
type Stats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"` // ns
		} `json:"cpu_usage"`
	} `json:"cpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// Stats takes one reading without waiting for a second one to compute
// rates, which the caller does itself.
func (c *Client) Stats(ctx context.Context, id string) (*Stats, error) {
	var out Stats
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PodNames maps container IDs to their Podman pod's name, from the libpod
// API; containers outside a pod are left out.
func (c *Client) PodNames(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	prefix, kind := c.libpod, c.kind
	c.mu.Unlock()
	if prefix == "" {
		return nil, fmt.Errorf("%s: not podman", kind)
	}
	var list []struct {
		ID      string `json:"Id"`
		PodName string `json:"PodName"`
	}
	path := "/libpod/containers/json?all=true"
	if err := c.do(ctx, http.MethodGet, kind, prefix+path, path, &list, nil); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, x := range list {
		if x.PodName != "" {
			out[x.ID] = x.PodName
		}
	}
	return out, nil
}

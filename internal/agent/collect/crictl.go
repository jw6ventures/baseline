package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// criSockets are the CRI endpoints tried, in order. k3s and RKE2 run their
// own containerd; a plain containerd socket may also belong to Docker,
// which disables containerd's CRI plugin, so a socket counts only once
// `crictl version` answers on it.
var criSockets = []string{
	"/run/k3s/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/run/crio/crio.sock",
}

// bundledCrictl are crictl binaries that Kubernetes distributions ship
// outside PATH: RKE2's, and k3s's own when its install skipped the
// /usr/local/bin symlinks (INSTALL_K3S_SYMLINK=skip, or a read-only
// /usr/local/bin where it installs to /opt/bin).
var bundledCrictl = []string{
	"/var/lib/rancher/rke2/bin/crictl",
	"/var/lib/rancher/k3s/data/current/bin/crictl",
}

// k3sBinaries are where the k3s installer puts k3s when it isn't on PATH.
// k3s is a multi-call binary: `k3s crictl` is its bundled crictl.
var k3sBinaries = []string{"/usr/local/bin/k3s", "/opt/bin/k3s"}

// crictlCommand finds crictl: on PATH, else the copy a distribution ships
// (`k3s crictl`, RKE2's), returned as the command and the arguments that
// come before crictl's own. ok is false when there is none.
func (e *Env) crictlCommand() (name string, pre []string, ok bool) {
	if e.Has("crictl") {
		return "crictl", nil, true
	}
	if e.Has("k3s") {
		return "k3s", []string{"crictl"}, true
	}
	for _, p := range k3sBinaries {
		if e.Exists(p) {
			return p, []string{"crictl"}, true
		}
	}
	for _, p := range bundledCrictl {
		if e.Exists(p) {
			return p, nil, true
		}
	}
	return "", nil, false
}

// K8sNode collects the "k8s_node" section with crictl (docs/agent.md §3.4).
// ErrAbsent when there's no crictl or no CRI runtime.
func (e *Env) K8sNode(ctx context.Context) (model.K8sNode, error) {
	bin, pre, ok := e.crictlCommand()
	if !ok {
		return model.K8sNode{}, ErrAbsent
	}
	var (
		out    model.K8sNode
		crictl func(args ...string) ([]byte, error)
	)
	for _, sock := range criSockets {
		if !e.Exists(sock) {
			continue
		}
		endpoint := "unix://" + sock
		run := func(args ...string) ([]byte, error) {
			a := append(append([]string{}, pre...), "--runtime-endpoint", endpoint, "--timeout", "20s")
			return e.Run(ctx, bin, append(a, args...)...)
		}
		b, err := run("version")
		if err != nil {
			continue
		}
		name, version := parseCrictlVersion(b)
		out = model.K8sNode{Runtime: criRuntime(name, sock), RuntimeVersion: version, Endpoint: endpoint}
		crictl = run
		break
	}
	if crictl == nil {
		// No socket, or none with CRI enabled (Docker's containerd): not
		// a Kubernetes node.
		return model.K8sNode{}, ErrAbsent
	}

	var pods criPodList
	if err := crictlJSON(crictl, &pods, "pods", "-o", "json"); err != nil {
		return model.K8sNode{}, err
	}
	var ctrs criContainerList
	if err := crictlJSON(crictl, &ctrs, "ps", "-a", "-o", "json"); err != nil {
		return model.K8sNode{}, err
	}
	var imgs criImageList
	if err := crictlJSON(crictl, &imgs, "images", "-o", "json"); err != nil {
		return model.K8sNode{}, err
	}

	out.Images = []model.CRIImage{}
	byID := map[string]model.CRIImage{}
	for _, im := range imgs.Images {
		size, _ := strconv.ParseInt(string(im.Size), 10, 64)
		ci := model.CRIImage{ID: im.ID, Tags: sortedCopy(im.RepoTags), Digests: sortedCopy(im.RepoDigests), SizeBytes: size}
		out.Images = append(out.Images, ci)
		byID[im.ID] = ci
	}

	// A pod's sandbox is recreated after a node restart; the old one stays
	// NotReady until it is cleaned up. Keep the newest per pod.
	type podKey struct{ ns, name string }
	newestPod := map[podKey]criPod{}
	sandbox := map[string]criPod{} // by sandbox ID, for containers without labels
	for _, p := range pods.Items {
		sandbox[p.ID] = p
		k := podKey{p.Metadata.Namespace, p.Metadata.Name}
		if cur, ok := newestPod[k]; !ok || newer(p.Metadata.Attempt, p.CreatedAt, cur.Metadata.Attempt, cur.CreatedAt) {
			newestPod[k] = p
		}
	}
	out.Pods = []model.CRIPod{}
	for _, p := range newestPod {
		out.Pods = append(out.Pods, model.CRIPod{Namespace: p.Metadata.Namespace, Name: p.Metadata.Name,
			State: criPodState(p.State), Created: nanoTime(p.CreatedAt)})
	}

	// A restarted container leaves its exited attempts behind; keep the
	// newest per pod and container name.
	type ctrKey struct{ ns, pod, name string }
	newestCtr := map[ctrKey]criContainer{}
	for _, c := range ctrs.Containers {
		k := ctrKey{c.Labels["io.kubernetes.pod.namespace"], c.Labels["io.kubernetes.pod.name"], c.Labels["io.kubernetes.container.name"]}
		if sb, ok := sandbox[c.PodSandboxID]; ok {
			if k.ns == "" {
				k.ns = sb.Metadata.Namespace
			}
			if k.pod == "" {
				k.pod = sb.Metadata.Name
			}
		}
		if k.name == "" {
			k.name = c.Metadata.Name
		}
		if cur, ok := newestCtr[k]; !ok || newer(c.Metadata.Attempt, c.CreatedAt, cur.Metadata.Attempt, cur.CreatedAt) {
			newestCtr[k] = c
		}
	}
	out.Containers = []model.CRIContainer{}
	for k, c := range newestCtr {
		out.Containers = append(out.Containers, model.CRIContainer{Namespace: k.ns, Pod: k.pod, Name: k.name,
			Image: criImageRef(c, byID), ImageID: c.ImageRef, State: criContainerState(c.State),
			Attempt: c.Metadata.Attempt, Created: nanoTime(c.CreatedAt)})
	}

	sort.Slice(out.Pods, func(i, j int) bool {
		a, b := out.Pods[i], out.Pods[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Containers, func(i, j int) bool {
		a, b := out.Containers[i], out.Containers[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Images, func(i, j int) bool { return out.Images[i].ID < out.Images[j].ID })
	return out, nil
}

func crictlJSON(run func(args ...string) ([]byte, error), v any, args ...string) error {
	b, err := run(args...)
	if err != nil {
		return fmt.Errorf("crictl %s: %s", args[0], firstLine(err))
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("crictl %s: %w", args[0], err)
	}
	return nil
}

// parseCrictlVersion reads `crictl version`, as text ("RuntimeName:
// containerd") or JSON (newer crictl with -o json).
func parseCrictlVersion(b []byte) (name, version string) {
	var doc struct {
		RuntimeName    string `json:"runtimeName"`
		RuntimeVersion string `json:"runtimeVersion"`
	}
	if json.Unmarshal(b, &doc) == nil && doc.RuntimeName != "" {
		return doc.RuntimeName, doc.RuntimeVersion
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "RuntimeName":
			name = strings.TrimSpace(v)
		case "RuntimeVersion":
			version = strings.TrimSpace(v)
		}
	}
	return name, version
}

// criRuntime is "containerd" or "cri-o", from what the runtime says or
// else its socket.
func criRuntime(name, sock string) string {
	switch n := strings.ToLower(name); {
	case strings.Contains(n, "cri-o") || strings.Contains(n, "crio"):
		return "cri-o"
	case strings.Contains(n, "containerd"):
		return "containerd"
	case n != "":
		return n
	case strings.Contains(sock, "crio"):
		return "cri-o"
	}
	return "containerd"
}

// The types below follow crictl's JSON, which is the CRI protobuf
// messages: 64-bit numbers (timestamps in nanoseconds, sizes) are strings.

type criPodList struct {
	Items []criPod `json:"items"`
}

type criPod struct {
	ID       string `json:"id"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Attempt   int    `json:"attempt"`
	} `json:"metadata"`
	State     string     `json:"state"`
	CreatedAt jsonString `json:"createdAt"`
}

type criContainerList struct {
	Containers []criContainer `json:"containers"`
}

type criContainer struct {
	ID           string `json:"id"`
	PodSandboxID string `json:"podSandboxId"`
	Metadata     struct {
		Name    string `json:"name"`
		Attempt int    `json:"attempt"`
	} `json:"metadata"`
	Image struct {
		Image              string `json:"image"`
		UserSpecifiedImage string `json:"userSpecifiedImage"`
	} `json:"image"`
	ImageRef  string            `json:"imageRef"`
	State     string            `json:"state"`
	CreatedAt jsonString        `json:"createdAt"`
	Labels    map[string]string `json:"labels"` // only the io.kubernetes.* names are read
}

type criImageList struct {
	Images []struct {
		ID          string     `json:"id"`
		RepoTags    []string   `json:"repoTags"`
		RepoDigests []string   `json:"repoDigests"`
		Size        jsonString `json:"size"`
	} `json:"images"`
}

// jsonString is a protobuf int64, which JSON carries as a string; a bare
// number is accepted too.
type jsonString string

func (s *jsonString) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err == nil {
		*s = jsonString(v)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = jsonString(n.String())
	return nil
}

// newer reports whether attempt a (created at ca) is newer than b.
func newer(a int, ca jsonString, b int, cb jsonString) bool {
	if a != b {
		return a > b
	}
	na, _ := strconv.ParseInt(string(ca), 10, 64)
	nb, _ := strconv.ParseInt(string(cb), 10, 64)
	return na > nb
}

// nanoTime turns a nanosecond Unix timestamp into RFC 3339 (UTC).
func nanoTime(s jsonString) string {
	n, err := strconv.ParseInt(string(s), 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(0, n).UTC().Format(time.RFC3339)
}

func criPodState(s string) string {
	switch s {
	case "SANDBOX_READY":
		return "ready"
	case "SANDBOX_NOTREADY":
		return "notready"
	}
	return strings.ToLower(strings.TrimPrefix(s, "SANDBOX_"))
}

func criContainerState(s string) string {
	switch s {
	case "CONTAINER_RUNNING":
		return "running"
	case "CONTAINER_EXITED":
		return "exited"
	case "CONTAINER_CREATED":
		return "created"
	}
	return "unknown"
}

// criImageRef is the reference a container runs, for people: the one its
// pod spec names, which containerd 2 reports as userSpecifiedImage. Older
// containerd reports only the image ID, which is looked up in the image
// list for its first tag (or digest when it has no tag).
func criImageRef(c criContainer, images map[string]model.CRIImage) string {
	if c.Image.UserSpecifiedImage != "" {
		return c.Image.UserSpecifiedImage
	}
	ref := c.Image.Image
	if !isImageID(ref) {
		return ref
	}
	for _, id := range []string{ref, "sha256:" + ref, c.ImageRef} {
		if im, ok := images[id]; ok {
			if len(im.Tags) > 0 {
				return im.Tags[0]
			}
			if len(im.Digests) > 0 {
				return im.Digests[0]
			}
		}
	}
	return ref
}

// isImageID reports an image ID ("sha256:<hex>" or bare hex) rather than a
// reference.
func isImageID(s string) bool {
	h := strings.TrimPrefix(s, "sha256:")
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

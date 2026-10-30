package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jw6ventures/baseline/internal/agent/container"
	"github.com/jw6ventures/baseline/internal/model"
)

// ContainerCollector reads every container engine on the host. It is also the
// container metrics sampler (every 90s), sharing the engines it found.
type ContainerCollector struct {
	Env *Env
	// StartPodmanSocket starts podman.socket when the unit exists but isn't
	// active (agent.conf option), at most once per agent run.
	StartPodmanSocket bool

	mu         sync.Mutex
	clients    map[string]*container.Client // by socket path under Root
	engines    []*ctrEngine                 // from the last discovery
	discovered bool
	started    bool     // podman.socket start attempted
	roots      []string // Compose roots, for stacks that aren't running

	smu   sync.Mutex             // serializes Sample
	stats map[string]*ctrMetrics // by container ID
}

// ctrEngine is an engine found on the host; Error is set when /version
// failed and the engine can't be read.
type ctrEngine struct {
	model.ContainerEngine
	client *container.Client
}

// Collect produces the "containers" section. An engine that can't be read is
// reported with its Error and without containers or images, and the section
// still succeeds: the server keeps that engine's earlier copy.
func (c *ContainerCollector) Collect(ctx context.Context) (model.Containers, error) {
	out := model.Containers{
		Engines:    []model.ContainerEngine{},
		Containers: []model.Container{},
		Images:     []model.ContainerImage{},
		Stacks:     []model.ComposeStack{},
	}
	for _, eng := range c.discover(ctx) {
		me := eng.ContainerEngine
		if me.Error == "" {
			ctrs, imgs, err := readCtrEngine(ctx, eng)
			if err != nil {
				me.Error = firstLine(err)
			} else {
				out.Containers = append(out.Containers, ctrs...)
				out.Images = append(out.Images, imgs...)
			}
		}
		out.Engines = append(out.Engines, me)
	}
	out.Stacks = c.Env.composeStacks(out.Containers, out.Engines)
	out.Stacks = append(out.Stacks, c.Env.stoppedStacks(c.composeRoots(), out.Stacks, out.Engines)...)
	sort.Slice(out.Stacks, func(i, j int) bool { return out.Stacks[i].Key() < out.Stacks[j].Key() })

	sort.Slice(out.Engines, func(i, j int) bool { return out.Engines[i].Name < out.Engines[j].Name })
	sort.Slice(out.Containers, func(i, j int) bool {
		a, b := out.Containers[i], out.Containers[j]
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		return a.Name < b.Name
	})
	sort.Slice(out.Images, func(i, j int) bool {
		a, b := out.Images[i], out.Images[j]
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		return a.ID < b.ID
	})
	return out, nil
}

// discover finds the engine sockets and asks each what it is. The result is
// kept for Sample.
func (c *ContainerCollector) discover(ctx context.Context) []*ctrEngine {
	e := c.Env
	c.startPodmanSocket(ctx)

	type candidate struct{ name, kind, path string }
	// Rootful Podman first: with podman-docker, docker.sock is a link to
	// it, and the engine should be found under its own path.
	cands := []candidate{
		{"podman", "podman", "/run/podman/podman.sock"},
		{"docker", "docker", "/var/run/docker.sock"},
		{"docker", "docker", "/run/docker.sock"},
	}
	users := e.passwdNames()
	uids := e.ReadDir("/run/user")
	sort.Slice(uids, func(i, j int) bool { return ctrAtoi(uids[i], -1) < ctrAtoi(uids[j], -1) })
	for _, uid := range uids {
		if _, err := strconv.Atoi(uid); err != nil {
			continue
		}
		user := users[uid]
		if user == "" {
			user = uid
		}
		cands = append(cands, candidate{"podman:" + user, "podman", "/run/user/" + uid + "/podman/podman.sock"})
	}

	var engines []*ctrEngine
	inodes := map[[2]uint64]bool{}
	names := map[string]bool{}
	used := map[string]bool{}
	for _, cd := range cands {
		full := e.path(cd.path)
		fi, err := os.Stat(full) // follows links: the target's identity
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			id := [2]uint64{uint64(st.Dev), st.Ino}
			if inodes[id] {
				continue
			}
			inodes[id] = true
		}
		eng := &ctrEngine{ContainerEngine: model.ContainerEngine{Name: cd.name, Kind: cd.kind, Socket: cd.path}}
		eng.client = c.client(full)
		vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		v, err := eng.client.Version(vctx)
		cancel()
		if err != nil {
			eng.Error = firstLine(err)
		} else {
			eng.Version, eng.APIVersion = v.Version, v.APIVersion
			eng.Kind = "docker"
			if v.Podman {
				eng.Kind = "podman"
				if cd.kind == "docker" { // podman-docker's compatible socket
					eng.Name = "podman"
				}
			}
		}
		if names[eng.Name] {
			continue
		}
		names[eng.Name] = true
		used[full] = true
		engines = append(engines, eng)
	}

	c.mu.Lock()
	for path, cl := range c.clients {
		if !used[path] {
			cl.Close()
			delete(c.clients, path)
		}
	}
	c.engines, c.discovered = engines, true
	c.mu.Unlock()
	return engines
}

// client reuses one client per socket so connections are kept alive
// between collections.
func (c *ContainerCollector) client(socket string) *container.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clients == nil {
		c.clients = map[string]*container.Client{}
	}
	cl, ok := c.clients[socket]
	if !ok {
		cl = container.New(socket)
		c.clients[socket] = cl
	}
	return cl
}

// startPodmanSocket starts rootful Podman's API socket when asked to and
// it's installed but not listening, once per agent run.
func (c *ContainerCollector) startPodmanSocket(ctx context.Context) {
	e := c.Env
	if !c.StartPodmanSocket || e.Exists("/run/podman/podman.sock") || !e.Has("systemctl") ||
		!(e.Exists("/usr/lib/systemd/system/podman.socket") || e.Exists("/lib/systemd/system/podman.socket")) {
		return
	}
	c.mu.Lock()
	tried := c.started
	c.started = true
	c.mu.Unlock()
	if !tried {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		e.Run(sctx, "systemctl", "start", "podman.socket")
		cancel()
	}
}

// passwdNames maps uids to user names from /etc/passwd.
func (e *Env) passwdNames() map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(e.Read("/etc/passwd"), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 3 && f[0] != "" {
			if _, dup := m[f[2]]; !dup {
				m[f[2]] = f[0]
			}
		}
	}
	return m
}

// passwdUser is the name, primary group and home directory of a uid from
// /etc/passwd.
func (e *Env) passwdUser(uid string) (name, gid, home string) {
	for _, line := range strings.Split(e.Read("/etc/passwd"), "\n") {
		if f := strings.Split(line, ":"); len(f) >= 6 && f[0] != "" && f[2] == uid {
			return f[0], f[3], f[5]
		}
	}
	return "", "", ""
}

func ctrAtoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// readCtrEngine lists one engine's containers and images. Any failure fails the
// engine as a whole: a partial list would read as removals.
func readCtrEngine(ctx context.Context, eng *ctrEngine) ([]model.Container, []model.ContainerImage, error) {
	cl := eng.client
	list, err := cl.ListContainers(ctx)
	if err != nil {
		return nil, nil, err
	}
	var pods map[string]string
	if eng.Kind == "podman" {
		pods, _ = cl.PodNames(ctx) // pods are a detail; containers still count
	}
	ctrs := []model.Container{}
	for _, s := range list {
		in, err := cl.Inspect(ctx, s.ID)
		if container.IsNotFound(err) {
			continue // removed since it was listed
		}
		if err != nil {
			return nil, nil, err
		}
		ctr := ctrFromInspect(eng.Name, s, in)
		ctr.Pod = pods[s.ID]
		ctrs = append(ctrs, ctr)
	}
	list2, err := cl.ListImages(ctx)
	if err != nil {
		return nil, nil, err
	}
	imgs := []model.ContainerImage{}
	for _, im := range list2 {
		img := model.ContainerImage{
			Engine:    eng.Name,
			ID:        ctrImageID(im.ID),
			Tags:      ctrRefs(im.RepoTags),
			Digests:   ctrRefs(im.RepoDigests),
			SizeBytes: im.Size,
		}
		if im.Created > 0 {
			img.Created = time.Unix(im.Created, 0).UTC().Format(time.RFC3339)
		}
		imgs = append(imgs, img)
	}
	return ctrs, imgs, nil
}

// ctrFromInspect combines a list entry with its inspect document. Environment
// and command line are never read: they hold secrets.
func ctrFromInspect(engine string, s container.Summary, in *container.Inspect) model.Container {
	c := model.Container{
		Engine:        engine,
		Name:          firstNonEmpty(strings.TrimPrefix(in.Name, "/"), s.Name()),
		ID:            firstNonEmpty(in.ID, s.ID),
		Image:         firstNonEmpty(in.Config.Image, s.Image), // the list shows an ID once the tag moved
		ImageID:       ctrImageID(firstNonEmpty(in.Image, s.ImageID)),
		Created:       ctrTime(in.Created),
		StartedAt:     ctrTime(in.State.StartedAt),
		State:         firstNonEmpty(in.State.Status, s.State),
		Health:        in.HealthStatus(),
		RestartCount:  in.RestartCount,
		RestartPolicy: firstNonEmpty(in.HostConfig.RestartPolicy.Name, "no"),
		Labels:        in.Config.Labels,
	}
	if c.Labels == nil {
		c.Labels = s.Labels
	}
	if len(c.Labels) == 0 {
		c.Labels = nil
	}
	if !in.State.Running {
		c.ExitCode = in.State.ExitCode
	}
	c.ComposeProject = c.Labels["com.docker.compose.project"]
	c.ComposeService = c.Labels["com.docker.compose.service"]
	c.Labels = maskLabelSecrets(c.Labels)

	seen := map[model.ContainerPort]bool{}
	for key, bindings := range in.NetworkSettings.Ports {
		port, proto, _ := strings.Cut(key, "/")
		cp := model.ContainerPort{ContainerPort: ctrAtoi(port, 0), Proto: firstNonEmpty(proto, "tcp")}
		if len(bindings) == 0 {
			seen[cp] = true // exposed, not published
		}
		for _, b := range bindings {
			p := cp
			p.HostIP, p.HostPort = b.HostIP, ctrAtoi(b.HostPort, 0)
			seen[p] = true
		}
	}
	for p := range seen {
		c.Ports = append(c.Ports, p)
	}
	sort.Slice(c.Ports, func(i, j int) bool {
		a, b := c.Ports[i], c.Ports[j]
		if a.ContainerPort != b.ContainerPort {
			return a.ContainerPort < b.ContainerPort
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.HostPort != b.HostPort {
			return a.HostPort < b.HostPort
		}
		return a.HostIP < b.HostIP
	})

	for _, m := range in.Mounts {
		src := m.Source
		if m.Type == "volume" && m.Name != "" {
			src = m.Name
		}
		c.Mounts = append(c.Mounts, model.ContainerMount{Type: m.Type, Source: src, Destination: m.Destination, RW: m.RW})
	}
	sort.Slice(c.Mounts, func(i, j int) bool {
		a, b := c.Mounts[i], c.Mounts[j]
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		return a.Source < b.Source
	})

	for name := range in.NetworkSettings.Networks {
		c.Networks = append(c.Networks, name)
	}
	sort.Strings(c.Networks)
	return c
}

// ctrTime is an engine timestamp in RFC 3339 UTC, "" for Docker's zero
// time ("0001-01-01T00:00:00Z", a container never started).
func ctrTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ctrImageID gives Podman's bare hex IDs Docker's "sha256:" form, so container
// image IDs match the image list on both engines.
func ctrImageID(id string) string {
	if len(id) == 64 && !strings.Contains(id, ":") {
		return "sha256:" + id
	}
	return id
}

func ctrRefs(refs []string) []string {
	var out []string
	for _, r := range refs {
		if r != "" && r != "<none>:<none>" && r != "<none>@<none>" {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// labelSecretSegment matches a label key segment that names a secret:
// traefik's basicauth.users holds password hashes, and some images take
// tokens as labels. "auth" must be a whole segment, so "authors" and
// "forwardauth" (an address) are left alone.
var labelSecretSegment = regexp.MustCompile(`(?i)pass(word|wd)|secret|token|api[_-]?key|private[_-]?key|credential|^(pass|auth|basicauth|digestauth)$`)

// maskLabelSecrets masks the values of labels that look like secrets, and
// passwords in URLs, before they leave the host. The map is copied: the
// engine's response is never changed.
func maskLabelSecrets(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		secret := false
		segs := strings.FieldsFunc(k, func(r rune) bool { return r == '.' || r == '/' })
		if len(segs) > 4 && strings.EqualFold(segs[0], "traefik") {
			// traefik.<proto>.<routers|services|middlewares>.<name>...: a
			// router named "auth" doesn't make its rule a secret.
			segs = append(segs[:3:3], segs[4:]...)
		}
		for _, seg := range segs {
			if labelSecretSegment.MatchString(seg) {
				secret = true
			}
		}
		// basicauth.users and digestauth.users: the hashes are the secret.
		if lk := strings.ToLower(k); strings.Contains(lk, "basicauth.users") || strings.Contains(lk, "digestauth.users") {
			secret = true
		}
		switch {
		case secret && v != "" && !keepComposeValue(v):
			out[k] = "********"
		default:
			out[k] = composeURLPassword.ReplaceAllString(v, "${1}********@")
		}
	}
	return out
}

// Restart restarts a container, found by engine and name as inventory
// reports them (the container.restart action).
func (c *ContainerCollector) Restart(ctx context.Context, engine, name string) error {
	eng, err := c.engine(ctx, engine)
	if err != nil {
		return err
	}
	return eng.client.Restart(ctx, name, 10)
}

// engine finds an engine by the name inventory reports, and fails if it
// can't be read.
func (c *ContainerCollector) engine(ctx context.Context, name string) (*ctrEngine, error) {
	for _, eng := range c.discover(ctx) {
		if eng.Name != name {
			continue
		}
		if eng.Error != "" {
			return nil, fmt.Errorf("%s: %s", name, eng.Error)
		}
		return eng, nil
	}
	return nil, fmt.Errorf("no %s engine on this host", name)
}

// Stack is a Compose stack as compose.pull and compose.update see it: read
// from its engine at the time, with the engine's socket and the stack's
// containers.
type Stack struct {
	model.ComposeStack
	Socket string // the engine's API socket, e.g. /var/run/docker.sock
	// User, UID, GID and Home are the owner of a rootless Podman engine
	// ("podman:<user>"), whose Compose commands run as that user and whose
	// files are written as them; empty for rootful engines.
	User, UID, GID, Home string
	Containers           []model.Container
}

// Stack reads a Compose stack and its containers from the engine, as the
// containers section would report them. Its working directory and files
// come from the containers' labels and the disk, never from a job.
func (c *ContainerCollector) Stack(ctx context.Context, engine, project string) (Stack, error) {
	eng, err := c.engine(ctx, engine)
	if err != nil {
		return Stack{}, err
	}
	list, err := eng.client.ListContainers(ctx)
	if err != nil {
		return Stack{}, err
	}
	ctrs := []model.Container{}
	var dirs []model.ComposeStack // where the engine's stacks run from
	for _, s := range list {
		if d := s.Labels["com.docker.compose.project.working_dir"]; d != "" {
			dirs = append(dirs, model.ComposeStack{WorkingDir: d})
		}
		// The list carries labels too, so only the stack's containers are
		// inspected (podman-compose also sets its own project label).
		if firstNonEmpty(s.Labels["com.docker.compose.project"], s.Labels["io.podman.compose.project"]) != project {
			continue
		}
		in, err := eng.client.Inspect(ctx, s.ID)
		if container.IsNotFound(err) {
			continue
		}
		if err != nil {
			return Stack{}, err
		}
		if ctr := ctrFromInspect(eng.Name, s, in); ctr.ComposeProject == project {
			ctrs = append(ctrs, ctr)
		}
	}
	sort.Slice(ctrs, func(i, j int) bool { return ctrs[i].Name < ctrs[j].Name })
	stacks := c.Env.composeStacks(ctrs, []model.ContainerEngine{eng.ContainerEngine})
	if len(stacks) == 0 {
		// Nothing of it runs: it may be on disk under a Compose root.
		var engines []model.ContainerEngine
		for _, e := range c.discover(ctx) {
			engines = append(engines, e.ContainerEngine)
		}
		for _, st := range c.Env.stoppedStacks(c.composeRoots(), dirs, engines) {
			if st.Engine == engine && st.Project == project {
				stacks = append(stacks, st)
			}
		}
	}
	if len(stacks) == 0 {
		return Stack{}, fmt.Errorf("%w %q on %s", ErrNoStack, project, engine)
	}
	st := Stack{ComposeStack: stacks[0], Socket: eng.Socket, Containers: ctrs}
	if err := c.Env.rootlessUser(&st); err != nil {
		return Stack{}, err
	}
	return st, nil
}

// rootlessUser fills in the user of a rootless Podman stack's engine.
func (e *Env) rootlessUser(st *Stack) error {
	user, ok := strings.CutPrefix(st.Engine, "podman:")
	if !ok {
		return nil
	}
	// The socket is /run/user/<uid>/podman/podman.sock.
	uid, _, _ := strings.Cut(strings.TrimPrefix(st.Socket, "/run/user/"), "/")
	name, gid, home := e.passwdUser(uid)
	if name == "" || name != user || home == "" || gid == "" {
		return fmt.Errorf("%s: user %s (uid %s) isn't in /etc/passwd", st.Engine, user, uid)
	}
	st.User, st.UID, st.GID, st.Home = name, uid, gid, home
	return nil
}

// ErrNoStack: the engine runs no container of the stack.
var ErrNoStack = errors.New("no Compose stack")

// Engine is how a new stack on an engine would be driven: its socket and
// Compose CLI, and for rootless Podman its user. It has no containers or
// files yet.
func (c *ContainerCollector) Engine(ctx context.Context, engine string) (Stack, error) {
	eng, err := c.engine(ctx, engine)
	if err != nil {
		return Stack{}, err
	}
	st := Stack{ComposeStack: model.ComposeStack{Engine: eng.Name, CLI: c.Env.composeCLI(eng.Kind)}, Socket: eng.Socket}
	if err := c.Env.rootlessUser(&st); err != nil {
		return Stack{}, err
	}
	return st, nil
}

// ImageID is the ID of the image ref names on an engine, "" if the engine
// has no such image.
func (c *ContainerCollector) ImageID(ctx context.Context, engine, ref string) (string, error) {
	eng, err := c.engine(ctx, engine)
	if err != nil {
		return "", err
	}
	im, err := eng.client.InspectImage(ctx, ref)
	if container.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ctrImageID(im.ID), nil
}

// Tag points ref at the image with this ID, which is how compose.update
// puts a service's previous image back.
func (c *ContainerCollector) Tag(ctx context.Context, engine, id, ref string) error {
	repo, tag, ok := container.SplitRef(ref)
	if !ok {
		return fmt.Errorf("%q can't be tagged", ref)
	}
	eng, err := c.engine(ctx, engine)
	if err != nil {
		return err
	}
	return eng.client.Tag(ctx, id, repo, tag)
}

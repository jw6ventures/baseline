package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/stackenv"
)

const revision = "11111111-2222-4333-8444-555555555555"

// fileHost is a fake engine for compose.deploy and compose.edit: up starts
// a container per service named in the stack's Compose file ("# svc: <name>"
// lines), down removes them, and every Compose command records the .env it
// could read in the stack's directory.
type fileHost struct {
	mu       sync.Mutex
	dir      string // the stack's working directory once it runs
	file     string
	running  bool
	adopted  bool // the stack ran before Baseline touched it
	stopped  bool // the stack is on disk under a Compose root, nothing running
	ups      int  // compose up runs
	state    func(service string) (state, health string, exit int)
	envSeen  map[string]string // subcommand → the .env it saw ("<none>")
	codes    map[string]int    // subcommand → exit status
	services []string
	fe       *fakeExec
	rootless bool // the engine is alice's rootless Podman, podman:alice
}

func newFileHost() *fileHost {
	h := &fileHost{envSeen: map[string]string{}, codes: map[string]int{}}
	h.fe = &fakeExec{fn: h.exec}
	return h
}

func (h *fileHost) runner(t *testing.T) *Runner {
	r := newRunner(t, h.fe)
	r.Containers = h
	r.pollEvery = 5 * time.Millisecond
	r.ComposeRoot = filepath.Join(t.TempDir(), "stacks")
	return r
}

func (h *fileHost) exec(_ context.Context, c Cmd, _, _ io.Writer) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := slices.IndexFunc(c.Args, func(a string) bool {
		return slices.Contains([]string{"config", "pull", "up", "down", "stop", "logs"}, a)
	})
	if i < 0 {
		return 127, nil
	}
	sub := c.Args[i]
	env, err := os.ReadFile(filepath.Join(c.Dir, ".env"))
	if err != nil {
		h.envSeen[sub] = "<none>"
	} else {
		h.envSeen[sub] = string(env)
	}
	if code := h.codes[sub]; code != 0 {
		return code, nil
	}
	switch sub {
	case "up":
		h.ups++
		h.dir, h.running = c.Dir, true
		h.file = c.Args[slices.Index(c.Args, "-f")+1]
		b, _ := os.ReadFile(h.file)
		h.services = nil
		for _, l := range strings.Split(string(b), "\n") {
			if _, s, ok := strings.Cut(l, "# svc: "); ok {
				h.services = append(h.services, s)
			}
		}
	case "down", "stop":
		h.running = false
	}
	return 0, nil
}

func (h *fileHost) Engine(_ context.Context, engine string) (collect.Stack, error) {
	switch {
	case h.rootless && engine == "podman:alice":
		return collect.Stack{ComposeStack: model.ComposeStack{Engine: engine, CLI: "podman-compose"},
			Socket: "/run/user/1000/podman/podman.sock", User: "alice", UID: "1000", GID: "1000", Home: "/home/alice"}, nil
	case !h.rootless && engine == "docker":
		return collect.Stack{ComposeStack: model.ComposeStack{Engine: "docker", CLI: "docker compose"}, Socket: "/var/run/docker.sock"}, nil
	}
	return collect.Stack{}, fmt.Errorf("no %s engine on this host", engine)
}

func (h *fileHost) Stack(_ context.Context, engine, project string) (collect.Stack, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !(h.running || h.stopped) || project != "app" {
		return collect.Stack{}, fmt.Errorf("%w %q on %s", collect.ErrNoStack, project, engine)
	}
	st, _ := h.Engine(context.Background(), engine)
	st.Project, st.WorkingDir, st.Services = project, h.dir, h.services
	st.ConfigFiles = []model.ComposeFile{{Path: h.file}}
	if !h.running {
		st.Stopped = true
		return st, nil
	}
	for i, s := range h.services {
		c := model.Container{Engine: engine, Name: "app-" + s + "-1", ID: fmt.Sprint("c", i), State: "running",
			ComposeProject: project, ComposeService: s}
		if h.state != nil {
			c.State, c.Health, c.ExitCode = h.state(s)
		}
		st.Containers = append(st.Containers, c)
	}
	return st, nil
}

func (h *fileHost) Restart(context.Context, string, string) error { return nil }
func (h *fileHost) ImageID(context.Context, string, string) (string, error) {
	return "", nil
}
func (h *fileHost) Tag(context.Context, string, string, string) error { return nil }

// adopt puts a stack on the host that Baseline didn't deploy, with a plain .env.
func (h *fileHost) adopt(t *testing.T, compose, env string) {
	dir := t.TempDir()
	h.dir, h.file, h.running, h.adopted = dir, filepath.Join(dir, "docker-compose.yml"), true, true
	os.WriteFile(h.file, []byte(compose), 0o640)
	if env != "" {
		os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600)
	}
	for _, l := range strings.Split(compose, "\n") {
		if _, s, ok := strings.Cut(l, "# svc: "); ok {
			h.services = append(h.services, s)
		}
	}
}

// stop puts a stack on the host under a Compose root that doesn't run.
func (h *fileHost) stop(t *testing.T, compose string) {
	h.adopt(t, compose, "")
	h.running, h.stopped, h.adopted = false, true, false
}

// withEnv is a job's parameters and files with a new .env.
func withEnv(p action.StackFileParams, f *agentv1.StackFiles, env string) (action.StackFileParams, *agentv1.StackFiles) {
	p.Env, f.Env = true, []byte(env)
	return p, f
}

func runFiles(t *testing.T, r *Runner, n int, name string, p action.StackFileParams, files *agentv1.StackFiles) ([]*agentv1.JobEvent, *agentv1.JobEvent) {
	t.Helper()
	raw, _ := json.Marshal(p)
	id := jobID(n)
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: name, ParamsJson: raw, StackFiles: files})
	return untilResult(t, r, id)
}

func stackResult(t *testing.T, b []byte) action.StackFileResult {
	t.Helper()
	var res action.StackFileResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("result %q: %v", b, err)
	}
	return res
}

const appCompose = "services:\n  web:\n    image: nginx\n    # svc: web\n  worker:\n    image: app\n    # svc: worker\n"

func TestComposeDeploy(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	env := "DB_PASSWORD=hunter2\nAPI_KEY=abc\n"
	p, files := withEnv(action.StackFileParams{Engine: "docker", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}, &agentv1.StackFiles{Compose: []byte(appCompose)}, env)
	evs, res := runFiles(t, r, 300, action.ComposeDeploy, p, files)
	checkResult(t, res, "succeeded", 0, "")
	dir := filepath.Join(r.ComposeRoot, "app")
	if got := stackResult(t, res.GetResultJson()); got.WorkingDir != dir || !slices.Equal(got.Services, []string{"web", "worker"}) {
		t.Errorf("result = %+v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "compose.yaml")); string(b) != appCompose {
		t.Errorf("compose.yaml = %q", b)
	}
	for _, sub := range []string{"config", "pull", "up"} {
		if h.envSeen[sub] != env {
			t.Errorf("compose %s saw .env %q, want the secrets", sub, h.envSeen[sub])
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, ".env")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf(".env mode: %v %v", fi, err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode: %v %v", fi, err)
	}
	if strings.Contains(outputOf(evs, ""), "hunter2") {
		t.Error("the job's output shows a secret")
	}
	base := "DOCKER_HOST=unix:///var/run/docker.sock docker compose -p app -f " + dir + "/compose.yaml --project-directory " + dir + " "
	if got := h.fe.lines(); !slices.Equal(got, []string{base + "config --quiet", base + "pull", base + "up -d"}) {
		t.Errorf("commands = %q", got)
	}

	// A Compose-only edit keeps the .env and the previous file.
	h.envSeen = map[string]string{}
	p2 := action.StackFileParams{Engine: "docker", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose + "# v2\n")), BaseSHA256: stackenv.SHA256([]byte(appCompose))}
	_, res = runFiles(t, r, 301, action.ComposeEdit, p2, &agentv1.StackFiles{Compose: []byte(appCompose + "# v2\n")})
	checkResult(t, res, "succeeded", 0, "")
	if h.envSeen["up"] != env {
		t.Errorf("the edit's up saw .env %q", h.envSeen["up"])
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"+prevSuffix)); string(b) != appCompose {
		t.Errorf("previous compose.yaml kept as %q", b)
	}
}

func TestComposeDeployRefused(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	ok, okFiles := withEnv(action.StackFileParams{Engine: "docker", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}, &agentv1.StackFiles{Compose: []byte(appCompose)}, "A=1\n")
	badEnv, badEnvFiles := withEnv(ok, &agentv1.StackFiles{Compose: []byte(appCompose)}, "not a line\n")
	for i, c := range []struct {
		name  string
		p     action.StackFileParams
		files *agentv1.StackFiles
		want  string
	}{
		{"compose hash", ok, &agentv1.StackFiles{Compose: []byte(appCompose + "x"), Env: []byte("A=1\n")}, "Compose file doesn't match"},
		{"bad env", badEnv, badEnvFiles, "isn't KEY=VALUE"},
	} {
		_, res := runFiles(t, r, 310+i, action.ComposeDeploy, c.p, c.files)
		checkResult(t, res, "failed", -1, c.want)
	}
	if len(h.fe.lines()) != 0 {
		t.Errorf("ran %q", h.fe.lines())
	}
	if _, err := os.Stat(filepath.Join(r.ComposeRoot, "app")); !os.IsNotExist(err) {
		t.Error("a refused deploy left its directory")
	}

	// A stack of that name already runs.
	h.adopt(t, appCompose, "")
	_, res := runFiles(t, r, 320, action.ComposeDeploy, ok, okFiles)
	checkResult(t, res, "failed", -1, "already runs")
}

func TestComposeDeployToRoot(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	state := filepath.Join(t.TempDir(), "state")
	r.Dir, r.ComposeRoot = filepath.Join(state, "jobs"), filepath.Join(state, "stacks")
	root := filepath.Join(t.TempDir(), "srv", "stacks")
	p := action.StackFileParams{Engine: "docker", Project: "app", Revision: revision, Root: root,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}
	files := &agentv1.StackFiles{Compose: []byte(appCompose)}
	_, res := runFiles(t, r, 330, action.ComposeDeploy, p, files)
	checkResult(t, res, "succeeded", 0, "")
	if got := stackResult(t, res.GetResultJson()); got.WorkingDir != filepath.Join(root, "app") {
		t.Errorf("deployed to %s", got.WorkingDir)
	}
	if _, err := os.Stat(filepath.Join(root, "app", "compose.yaml")); err != nil {
		t.Error(err)
	}

	// The agent checks the server's pick itself.
	for i, c := range []struct{ root, want string }{
		{"/etc/stacks", "system directory"},
		{filepath.Join(state, "certs"), "state directory"},
		{"relative", "absolute"},
	} {
		h := newFileHost()
		r2 := h.runner(t)
		r2.Dir, r2.ComposeRoot = r.Dir, r.ComposeRoot
		p.Root = c.root
		_, res := runFiles(t, r2, 340+i, action.ComposeDeploy, p, files)
		checkResult(t, res, "failed", -1, c.want)
		if len(h.fe.lines()) != 0 {
			t.Errorf("%s: ran %q", c.root, h.fe.lines())
		}
	}
	// Its own compose_root is fine even inside the state directory.
	h = newFileHost()
	r3 := h.runner(t)
	r3.Dir, r3.ComposeRoot = filepath.Join(state, "jobs3"), r.ComposeRoot
	p.Root = r.ComposeRoot
	_, res = runFiles(t, r3, 350, action.ComposeDeploy, p, files)
	checkResult(t, res, "succeeded", 0, "")
}

func TestComposeDeployRollsBack(t *testing.T) {
	p := action.StackFileParams{Engine: "docker", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}
	files := &agentv1.StackFiles{Compose: []byte(appCompose)}
	h := newFileHost()
	h.state = func(s string) (string, string, int) {
		if s == "worker" {
			return "exited", "", 1
		}
		return "running", "", 0
	}
	r := h.runner(t)
	_, res := runFiles(t, r, 330, action.ComposeDeploy, p, files)
	checkResult(t, res, "rolled_back", -1, "app-worker-1 exited with status 1")
	if got := stackResult(t, res.GetResultJson()); !got.RolledBack {
		t.Errorf("result = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(r.ComposeRoot, "app")); !os.IsNotExist(err) {
		t.Error("the failed stack's directory is still there")
	}
	if h.running {
		t.Error("the failed stack wasn't taken down")
	}

	// A one-off that exits 0 did its job.
	h = newFileHost()
	h.state = func(s string) (string, string, int) {
		if s == "worker" {
			return "exited", "", 0
		}
		return "running", "", 0
	}
	r = h.runner(t)
	_, res = runFiles(t, r, 331, action.ComposeDeploy, p, files)
	checkResult(t, res, "succeeded", 0, "")

	// A Compose file that doesn't check out starts nothing.
	h = newFileHost()
	h.codes["config"] = 15
	r = h.runner(t)
	_, res = runFiles(t, r, 332, action.ComposeDeploy, p, files)
	checkResult(t, res, "failed", -1, "doesn't check out")
	if got := h.fe.lines(); len(got) != 1 {
		t.Errorf("commands = %q", got)
	}
}

func TestComposeEditEnv(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	h.adopt(t, appCompose, "A=1\n")
	os.Chmod(filepath.Join(h.dir, ".env"), 0o644)
	p, files := withEnv(action.StackFileParams{Engine: "docker", Project: "app", Revision: revision}, &agentv1.StackFiles{}, "B=3\nC=4\n")
	_, res := runFiles(t, r, 340, action.ComposeEdit, p, files)
	checkResult(t, res, "succeeded", 0, "")
	if h.envSeen["up"] != "B=3\nC=4\n" {
		t.Errorf("up saw .env %q", h.envSeen["up"])
	}
	if fi, err := os.Stat(filepath.Join(h.dir, ".env")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf(".env is %v %v, want root-only", fi, err)
	}
	if b, _ := os.ReadFile(h.file); string(b) != appCompose {
		t.Error("an .env edit changed the Compose file")
	}
	if got := h.fe.lines(); len(got) != 2 || !strings.HasSuffix(got[1], "up -d --remove-orphans") {
		t.Errorf("commands = %q", got)
	}

	// A failure puts the previous one back.
	h.state = func(s string) (string, string, int) { return "running", "unhealthy", 0 }
	p, files = withEnv(p, &agentv1.StackFiles{}, "Z=9\n")
	_, res = runFiles(t, r, 341, action.ComposeEdit, p, files)
	checkResult(t, res, "rolled_back", -1, "unhealthy")
	if b, _ := os.ReadFile(filepath.Join(h.dir, ".env")); string(b) != "B=3\nC=4\n" {
		t.Errorf(".env after the rollback = %q", b)
	}

	// A stack that had no .env has none again after a rollback.
	h = newFileHost()
	h.state = func(s string) (string, string, int) { return "running", "unhealthy", 0 }
	r = h.runner(t)
	h.adopt(t, appCompose, "")
	_, res = runFiles(t, r, 342, action.ComposeEdit, p, files)
	checkResult(t, res, "rolled_back", -1, "unhealthy")
	if _, err := os.Stat(filepath.Join(h.dir, ".env")); !os.IsNotExist(err) {
		t.Errorf("the rollback left a .env: %v", err)
	}
}

func TestComposeEditCompose(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	h.adopt(t, appCompose, "A=1\n")
	next := appCompose + "  cache:\n    image: redis\n    # svc: cache\n"
	p := action.StackFileParams{Engine: "docker", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(next)), BaseSHA256: stackenv.SHA256([]byte("something else"))}
	_, res := runFiles(t, r, 350, action.ComposeEdit, p, &agentv1.StackFiles{Compose: []byte(next)})
	checkResult(t, res, "failed", -1, "changed on the host since")

	p.BaseSHA256 = stackenv.SHA256([]byte(appCompose))
	h.state = func(s string) (string, string, int) {
		if s == "cache" {
			return "exited", "", 2
		}
		return "running", "", 0
	}
	_, res = runFiles(t, r, 351, action.ComposeEdit, p, &agentv1.StackFiles{Compose: []byte(next)})
	checkResult(t, res, "rolled_back", -1, "app-cache-1 exited with status 2")
	if b, _ := os.ReadFile(h.file); string(b) != appCompose {
		t.Errorf("compose file after the rollback = %q", b)
	}
	if fi, _ := os.Stat(h.file); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode())
	}
	if h.envSeen["up"] != "A=1\n" {
		t.Errorf("up saw .env %q", h.envSeen["up"])
	}

	h.state = nil
	_, res = runFiles(t, r, 352, action.ComposeEdit, p, &agentv1.StackFiles{Compose: []byte(next)})
	checkResult(t, res, "succeeded", 0, "")
	if got := stackResult(t, res.GetResultJson()); !slices.Equal(got.Services, []string{"cache", "web", "worker"}) {
		t.Errorf("result = %+v", got)
	}
}

func runStart(t *testing.T, r *Runner, n int) *agentv1.JobEvent {
	t.Helper()
	raw, _ := json.Marshal(action.ComposeParams{Engine: "docker", Project: "app"})
	id := jobID(n)
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: action.ComposeStart, ParamsJson: raw})
	_, res := untilResult(t, r, id)
	return res
}

func TestComposeStart(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	h.stop(t, appCompose)
	res := runStart(t, r, 400)
	checkResult(t, res, "succeeded", 0, "")
	var got action.ComposeResult
	json.Unmarshal(res.GetResultJson(), &got)
	if len(got.Services) != 2 || got.Services[0].Service != "web" || !h.running {
		t.Errorf("result %+v, running %v", got, h.running)
	}
	base := "DOCKER_HOST=unix:///var/run/docker.sock docker compose -p app -f " + h.file + " --project-directory " + h.dir + " "
	if lines := h.fe.lines(); !slices.Equal(lines, []string{base + "config --quiet", base + "up -d"}) {
		t.Errorf("commands = %q", lines)
	}
	// It runs now.
	checkResult(t, runStart(t, r, 401), "failed", -1, "running already")
}

func TestComposeStartRollsBack(t *testing.T) {
	for i, c := range []struct {
		name    string
		stopped bool // nothing of it on the engine, or its containers stopped
		undo    string
	}{{"on disk", true, "down"}, {"stopped containers", false, "stop"}} {
		h := newFileHost()
		r := h.runner(t)
		h.stop(t, appCompose)
		// The stack's own check finds its containers exited; once up, they
		// run but are unhealthy.
		h.state = func(string) (string, string, int) {
			if h.ups == 0 {
				return "exited", "", 1
			}
			return "running", "unhealthy", 0
		}
		if !c.stopped {
			h.running, h.stopped = true, false
		}
		res := runStart(t, r, 410+i)
		checkResult(t, res, "rolled_back", -1, "rolled back")
		if lines := h.fe.lines(); len(lines) == 0 {
			t.Fatalf("%s: ran nothing", c.name)
		}
		if lines := h.fe.lines(); !strings.HasSuffix(lines[len(lines)-1], " "+c.undo) {
			t.Errorf("%s: commands = %q", c.name, lines)
		}
	}
}

func TestComposeEditStoppedDoesntStart(t *testing.T) {
	h := newFileHost()
	r := h.runner(t)
	h.stop(t, appCompose)
	p, files := withEnv(action.StackFileParams{Engine: "docker", Project: "app", Revision: revision}, &agentv1.StackFiles{}, "A=1\n")
	evs, res := runFiles(t, r, 420, action.ComposeEdit, p, files)
	checkResult(t, res, "succeeded", 0, "")
	if h.running || slices.ContainsFunc(h.fe.lines(), func(l string) bool { return strings.HasSuffix(l, " up -d --remove-orphans") }) {
		t.Errorf("the edit started it: %q", h.fe.lines())
	}
	if !strings.Contains(outputOf(evs, ""), "isn't running") {
		t.Error("output doesn't say it isn't running")
	}
}

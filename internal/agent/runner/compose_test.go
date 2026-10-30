package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
)

// imageID is a well-formed image ID made of one repeated hex digit.
func imageID(c string) string { return "sha256:" + strings.Repeat(c, 64) }

var (
	appOld, appNew = imageID("a"), imageID("b")
	dbOld, dbNew   = imageID("c"), imageID("d")
	jobImage       = imageID("e")
)

// composeHost is a fake engine with a Compose stack, driven by the fake
// Exec the way the Compose CLI would drive it: pull moves references to
// what the registry has, up recreates containers on what their references
// name, and tag moves a reference back.
type composeHost struct {
	mu       sync.Mutex
	st       collect.Stack
	images   map[string]string // reference → image ID on the engine
	registry map[string]string // reference → image ID a pull brings
	// status is a recreated container's state and health on the n-th look
	// at the stack since up (from 1); nil is running without a healthcheck.
	status   func(service, imageID string, n int) (state, health string)
	looks    int
	recreate map[string]bool // containers up recreated
	tags     []string        // "id ref"
	tagErr   error
	tagNoop  bool // Tag succeeds without moving the reference
	stackErr error
	upCodes  []int // exit status of each up, in turn; 0 after
	pullCode int
	nextID   int
	fe       *fakeExec
}

func newComposeHost() *composeHost {
	h := &composeHost{
		st: collect.Stack{
			ComposeStack: model.ComposeStack{Engine: "docker", Project: "web", WorkingDir: "/srv/web",
				Services: []string{"app", "db", "migrate"}, CLI: "docker compose",
				ConfigFiles: []model.ComposeFile{{Path: "/srv/web/compose.yaml"}, {Path: "/srv/web/compose.prod.yaml"}}},
			Socket: "/var/run/docker.sock",
			Containers: []model.Container{
				{Engine: "docker", Name: "web-app-1", ID: "c1", Image: "ghcr.io/acme/app:2", ImageID: appOld,
					State: "running", Health: "healthy", ComposeProject: "web", ComposeService: "app"},
				{Engine: "docker", Name: "web-app-2", ID: "c2", Image: "ghcr.io/acme/app:2", ImageID: appOld,
					State: "running", Health: "healthy", ComposeProject: "web", ComposeService: "app"},
				{Engine: "docker", Name: "web-db-1", ID: "c3", Image: "postgres:16", ImageID: dbOld,
					State: "running", ComposeProject: "web", ComposeService: "db"},
				// A one-off that ran and exited: not expected to be running.
				{Engine: "docker", Name: "web-migrate-1", ID: "c4", Image: "ghcr.io/acme/migrate:2", ImageID: jobImage,
					State: "exited", ComposeProject: "web", ComposeService: "migrate"},
			},
		},
		images:   map[string]string{"ghcr.io/acme/app:2": appOld, "postgres:16": dbOld, "ghcr.io/acme/migrate:2": jobImage},
		registry: map[string]string{},
		recreate: map[string]bool{},
	}
	h.fe = &fakeExec{fn: h.exec}
	return h
}

func (h *composeHost) runner(t *testing.T) *Runner {
	r := newRunner(t, h.fe)
	r.Containers = h
	r.pollEvery = 5 * time.Millisecond
	return r
}

// exec handles the Compose CLI's subcommands; the arguments after one are
// its options and services.
func (h *composeHost) exec(_ context.Context, c Cmd, stdout, _ io.Writer) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := slices.IndexFunc(c.Args, func(a string) bool { return a == "pull" || a == "up" || a == "logs" })
	if i < 0 {
		return 127, nil
	}
	var services []string
	for _, a := range c.Args[i+1:] {
		if !strings.HasPrefix(a, "-") && a != "50" {
			services = append(services, a)
		}
	}
	selected := func(svc string) bool { return len(services) == 0 || slices.Contains(services, svc) }
	switch c.Args[i] {
	case "pull":
		for _, ctr := range h.st.Containers {
			if id, ok := h.registry[ctr.Image]; ok && selected(ctr.ComposeService) {
				h.images[ctr.Image] = id
			}
		}
		fmt.Fprintln(stdout, "Pulled")
		return h.pullCode, nil
	case "logs":
		fmt.Fprintln(stdout, "web-app-1  | panic: config")
		return 0, nil
	}
	for j := range h.st.Containers {
		ctr := &h.st.Containers[j]
		if !selected(ctr.ComposeService) || ctr.ImageID == h.images[ctr.Image] {
			continue
		}
		h.nextID++
		ctr.ID, ctr.ImageID = fmt.Sprintf("n%d", h.nextID), h.images[ctr.Image]
		h.recreate[ctr.Name] = true
	}
	h.looks = 0
	code := 0
	if len(h.upCodes) > 0 {
		code, h.upCodes = h.upCodes[0], h.upCodes[1:]
	}
	return code, nil
}

func (h *composeHost) Engine(context.Context, string) (collect.Stack, error) {
	return collect.Stack{}, errors.New("not here")
}

func (h *composeHost) Restart(context.Context, string, string) error { return errors.New("not here") }

func (h *composeHost) Stack(_ context.Context, engine, project string) (collect.Stack, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stackErr != nil {
		return collect.Stack{}, h.stackErr
	}
	if engine != h.st.Engine || project != h.st.Project {
		return collect.Stack{}, fmt.Errorf("no Compose stack %q on %s", project, engine)
	}
	h.looks++
	st := h.st
	st.Containers = slices.Clone(h.st.Containers)
	for i := range st.Containers {
		c := &st.Containers[i]
		if h.recreate[c.Name] {
			c.State, c.Health = "running", ""
			if h.status != nil {
				c.State, c.Health = h.status(c.ComposeService, c.ImageID, h.looks)
			}
			if c.State == "exited" {
				c.ExitCode = 1
			}
		}
	}
	return st, nil
}

func (h *composeHost) ImageID(_ context.Context, engine, ref string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.images[ref], nil
}

func (h *composeHost) Tag(_ context.Context, engine, id, ref string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tags = append(h.tags, id+" "+ref)
	if h.tagErr != nil || h.tagNoop {
		return h.tagErr
	}
	h.images[ref] = id
	return nil
}

func composeResult(t *testing.T, b []byte) action.ComposeResult {
	t.Helper()
	var res action.ComposeResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("result %q: %v", b, err)
	}
	return res
}

const composeBase = "DOCKER_HOST=unix:///var/run/docker.sock docker compose -p web -f /srv/web/compose.yaml " +
	"-f /srv/web/compose.prod.yaml --project-directory /srv/web "

func TestComposeUpdateAlreadyCurrent(t *testing.T) {
	h := newComposeHost()
	r := h.runner(t)
	var col collected
	r.Collect = col.collect
	id := jobID(50)
	start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web"}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if got := h.fe.lines(); !slices.Equal(got, []string{composeBase + "pull"}) {
		t.Errorf("commands = %q", got)
	}
	if h.fe.cmds[0].Dir != "/srv/web" {
		t.Errorf("dir = %q", h.fe.cmds[0].Dir)
	}
	cr := composeResult(t, res.GetResultJson())
	want := []action.ComposeService{
		{Service: "app", Image: "ghcr.io/acme/app:2", From: appOld, To: appOld},
		{Service: "db", Image: "postgres:16", From: dbOld, To: dbOld},
		{Service: "migrate", Image: "ghcr.io/acme/migrate:2", From: jobImage, To: jobImage},
	}
	if !cr.Current || cr.RolledBack || !slices.Equal(cr.Services, want) {
		t.Errorf("result = %+v", cr)
	}
	if info := outputOf(evs, "info"); !strings.Contains(info, "Already current: no service has a new image.\n") {
		t.Errorf("info = %q", info)
	}
	if got := col.get(); len(got) != 1 || got[0] != id+": containers,ports" {
		t.Errorf("collect = %q", got)
	}
}

func TestComposeUpdate(t *testing.T) {
	h := newComposeHost()
	h.registry["ghcr.io/acme/app:2"] = appNew
	h.registry["postgres:16"] = dbNew // not selected
	// The new app's healthcheck starts, then passes.
	h.status = func(_, _ string, n int) (string, string) {
		if n < 3 {
			return "running", "starting"
		}
		return "running", "healthy"
	}
	r := h.runner(t)
	id := jobID(51)
	start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web","services":["app"],"health_timeout":30}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if got := h.fe.lines(); !slices.Equal(got, []string{composeBase + "pull app", composeBase + "up -d --no-deps app"}) {
		t.Errorf("commands = %q", got)
	}
	cr := composeResult(t, res.GetResultJson())
	if cr.Current || cr.RolledBack || !slices.Equal(cr.Services, []action.ComposeService{
		{Service: "app", Image: "ghcr.io/acme/app:2", From: appOld, To: appNew, Changed: true}}) {
		t.Errorf("result = %+v", cr)
	}
	if h.images["postgres:16"] != dbOld || len(h.tags) != 0 {
		t.Errorf("images %v tags %v", h.images, h.tags)
	}
	// Healthy twice in a row: looks 3 and 4.
	if h.looks < 4 {
		t.Errorf("looked %d times", h.looks)
	}
	info := outputOf(evs, "info")
	for _, s := range []string{"Pulling images for web (app)…\n", "$ " + composeBase + "pull app\n",
		"app: ghcr.io/acme/app:2 has a new image, aaaaaaaaaaaa → bbbbbbbbbbbb\n",
		"Waiting up to 30s for app to be running and healthy…\n", "Running and healthy.\n", "Updated app.\n"} {
		if !strings.Contains(info, s) {
			t.Errorf("info lacks %q:\n%s", s, info)
		}
	}
}

func TestComposeUpdateWholeStack(t *testing.T) {
	h := newComposeHost()
	h.registry["postgres:16"] = dbNew
	h.registry["ghcr.io/acme/migrate:2"] = imageID("f")
	// The one-off exits again, as it should: only what ran is waited for.
	h.status = func(svc, _ string, _ int) (string, string) {
		if svc == "migrate" {
			return "exited", ""
		}
		return "running", ""
	}
	r := h.runner(t)
	id := jobID(52)
	start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web"}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if got := h.fe.lines(); !slices.Equal(got, []string{composeBase + "pull", composeBase + "up -d"}) {
		t.Errorf("commands = %q", got)
	}
	cr := composeResult(t, res.GetResultJson())
	var changed []string
	for _, s := range cr.Services {
		if s.Changed {
			changed = append(changed, s.Service)
		}
	}
	if !slices.Equal(changed, []string{"db", "migrate"}) {
		t.Errorf("result = %+v", cr)
	}
	if !strings.Contains(outputOf(evs, "info"), "Waiting up to 2m0s for app, db to be running and healthy…\n") {
		t.Errorf("info = %q", outputOf(evs, "info"))
	}
}

func TestComposeUpdateRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status func(svc, image string, n int) (string, string)
		up     []int
		why    string
	}{
		{"unhealthy", func(_, image string, n int) (string, string) {
			if image == appOld {
				return "running", "healthy"
			}
			if n < 2 {
				return "running", "starting"
			}
			return "running", "unhealthy"
		}, nil, "web-app-1 is unhealthy"},
		{"exits", func(_, image string, _ int) (string, string) {
			if image == appOld {
				return "running", "healthy"
			}
			return "exited", ""
		}, nil, "web-app-1 exited with status 1"},
		{"up fails", nil, []int{1}, "compose up exited with status 1"},
	} {
		h := newComposeHost()
		h.registry["ghcr.io/acme/app:2"] = appNew
		h.status, h.upCodes = tc.status, tc.up
		r := h.runner(t)
		id := jobID(53)
		start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web","services":["app","db"]}`)
		evs, res := untilResult(t, r, id)
		checkResult(t, res, "rolled_back", -1, "rolled back: "+tc.why)
		if got := h.fe.lines(); !slices.Equal(got, []string{composeBase + "pull app db", composeBase + "up -d --no-deps app db",
			composeBase + "logs --tail 50 app", composeBase + "up -d --no-deps app"}) {
			t.Errorf("%s: commands = %q", tc.name, got)
		}
		if !slices.Equal(h.tags, []string{appOld + " ghcr.io/acme/app:2"}) {
			t.Errorf("%s: tags = %q", tc.name, h.tags)
		}
		for _, c := range h.st.Containers {
			if c.ComposeService == "app" && c.ImageID != appOld {
				t.Errorf("%s: %s runs %s", tc.name, c.Name, c.ImageID)
			}
		}
		cr := composeResult(t, res.GetResultJson())
		if !cr.RolledBack || cr.Current || len(cr.Services) != 2 || !cr.Services[0].Changed || cr.Services[0].To != appNew {
			t.Errorf("%s: result = %+v", tc.name, cr)
		}
		info := outputOf(evs, "info")
		for _, s := range []string{"Rolling back app.\n", "Tagging aaaaaaaaaaaa as ghcr.io/acme/app:2 again\n",
			"Rolled back: app run their previous images again. The new images are kept.\n"} {
			if !strings.Contains(info, s) {
				t.Errorf("%s: info lacks %q:\n%s", tc.name, s, info)
			}
		}
		if !strings.Contains(outputOf(evs, "stdout"), "web-app-1  | panic: config\n") {
			t.Errorf("%s: no logs", tc.name)
		}
		if rec, _ := r.load(id); rec.State != "rolled_back" {
			t.Errorf("%s: journal = %+v", tc.name, rec)
		}
	}
}

func TestComposeRollbackFails(t *testing.T) {
	unhealthy := func(_, _ string, _ int) (string, string) { return "running", "unhealthy" }
	for _, tc := range []struct {
		name    string
		tagErr  error
		tagNoop bool
		up      []int
		err     string
		cmds    int
	}{
		{"tag", errors.New("docker: POST /images/sha256:aaaa/tag: 404 No such image"), false, nil,
			"web-app-1 is unhealthy; rolling back failed too: docker: POST /images/sha256:aaaa/tag: 404 No such image", 3},
		{"up", nil, false, []int{0, 1}, "web-app-1 is unhealthy; rolling back failed too: compose up exited with status 1", 4},
		// Everything succeeds, but the new image still runs.
		{"check", nil, true, nil, "web-app-1 is unhealthy; rolling back failed too: web-app-1 still runs bbbbbbbbbbbb; " +
			"web-app-2 still runs bbbbbbbbbbbb", 4},
	} {
		h := newComposeHost()
		h.registry["ghcr.io/acme/app:2"] = appNew
		h.status, h.tagErr, h.tagNoop, h.upCodes = unhealthy, tc.tagErr, tc.tagNoop, tc.up
		r := h.runner(t)
		id := jobID(54)
		start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web","services":["app"]}`)
		_, res := untilResult(t, r, id)
		checkResult(t, res, "failed", -1, tc.err)
		if len(h.fe.lines()) != tc.cmds {
			t.Errorf("%s: commands = %q", tc.name, h.fe.lines())
		}
		if cr := composeResult(t, res.GetResultJson()); cr.RolledBack {
			t.Errorf("%s: result = %+v", tc.name, cr)
		}
	}
}

func TestComposeCancelledWhileWaitingRollsBack(t *testing.T) {
	h := newComposeHost()
	h.registry["ghcr.io/acme/app:2"] = appNew
	waiting := make(chan struct{})
	var once sync.Once
	h.status = func(_, image string, _ int) (string, string) {
		if image == appOld {
			return "running", "healthy"
		}
		once.Do(func() { close(waiting) })
		return "running", "starting"
	}
	r := h.runner(t)
	id := jobID(55)
	start(r, id, action.ComposeUpdate, `{"engine":"docker","project":"web","services":["app"]}`)
	<-waiting
	r.Cancel(id)
	_, res := untilResult(t, r, id)
	checkResult(t, res, "cancelled", -1, "cancelled")
	if cr := composeResult(t, res.GetResultJson()); !cr.RolledBack || !slices.Equal(h.tags, []string{appOld + " ghcr.io/acme/app:2"}) {
		t.Errorf("result = %+v, tags %q", cr, h.tags)
	}
	if got := h.fe.lines(); len(got) != 4 || got[3] != composeBase+"up -d --no-deps app" {
		t.Errorf("commands = %q", got)
	}
}

func TestComposePull(t *testing.T) {
	h := newComposeHost()
	h.registry["postgres:16"] = dbNew
	r := h.runner(t)
	id := jobID(56)
	start(r, id, action.ComposePull, `{"engine":"docker","project":"web","services":["db","app"]}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if got := h.fe.lines(); !slices.Equal(got, []string{composeBase + "pull app db"}) {
		t.Errorf("commands = %q", got)
	}
	cr := composeResult(t, res.GetResultJson())
	if cr.Current || !slices.Equal(cr.Services, []action.ComposeService{
		{Service: "app", Image: "ghcr.io/acme/app:2", From: appOld, To: appOld},
		{Service: "db", Image: "postgres:16", From: dbOld, To: dbNew, Changed: true}}) {
		t.Errorf("result = %+v", cr)
	}
	if !strings.Contains(outputOf(evs, "info"), "Pulled new images for db; nothing was restarted.\n") {
		t.Errorf("info = %q", outputOf(evs, "info"))
	}
	for _, c := range h.st.Containers {
		if h.recreate[c.Name] {
			t.Errorf("%s was recreated", c.Name)
		}
	}

	// Pulled again: the update is still staged.
	start(r, jobID(57), action.ComposePull, `{"engine":"docker","project":"web","services":["db"]}`)
	_, res = untilResult(t, r, jobID(57))
	if cr := composeResult(t, res.GetResultJson()); !cr.Services[0].Changed || cr.Current {
		t.Errorf("staged = %+v", cr)
	}

	h.pullCode = 18
	start(r, jobID(58), action.ComposePull, `{"engine":"docker","project":"web"}`)
	_, res = untilResult(t, r, jobID(58))
	checkResult(t, res, "failed", 18, "compose pull exited with status 18")
}

func TestComposeRefused(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		change       func(h *composeHost)
		err          string
	}{
		{"orphaned", `{"engine":"docker","project":"web"}`, func(h *composeHost) {
			h.st.Orphaned, h.st.ConfigFiles = true, nil
		}, "the stack web wasn't started from Compose files on this host (orphaned), so it can't be updated"},
		{"file error", `{"engine":"docker","project":"web"}`, func(h *composeHost) {
			h.st.Orphaned, h.st.ConfigFiles[1].Error = true, "not found"
		}, "the stack web can't be updated: its Compose file /srv/web/compose.prod.yaml: not found"},
		{"relative file", `{"engine":"docker","project":"web"}`, func(h *composeHost) {
			h.st.ConfigFiles[1].Path = "compose.prod.yaml"
		}, "its Compose file compose.prod.yaml isn't an absolute path"},
		{"no CLI", `{"engine":"docker","project":"web"}`, func(h *composeHost) { h.st.CLI = "" },
			"no Compose CLI for docker is installed on this host"},
		{"no working dir", `{"engine":"docker","project":"web"}`, func(h *composeHost) { h.st.WorkingDir = "" },
			"the stack web has no working directory"},
		{"unknown service", `{"engine":"docker","project":"web","services":["app","cache"]}`, nil,
			`the stack web has no service "cache" (it has app, db, migrate)`},
		{"unknown stack", `{"engine":"docker","project":"blog"}`, nil, `no Compose stack "blog" on docker`},
		{"engine", `{"engine":"docker","project":"web"}`, func(h *composeHost) {
			h.stackErr = errors.New("docker: GET /containers/json: 500 boom")
		}, "docker: GET /containers/json: 500 boom"},
	} {
		h := newComposeHost()
		if tc.change != nil {
			tc.change(h)
		}
		r := h.runner(t)
		start(r, jobID(59), action.ComposeUpdate, tc.params)
		_, res := untilResult(t, r, jobID(59))
		checkResult(t, res, "failed", -1, tc.err)
		if len(h.fe.lines()) != 0 {
			t.Errorf("%s: ran %q", tc.name, h.fe.lines())
		}
	}

	r := newRunner(t, &fakeExec{})
	start(r, jobID(60), action.ComposePull, `{"engine":"docker","project":"web"}`)
	_, res := untilResult(t, r, jobID(60))
	checkResult(t, res, "failed", -1, "containers can't be managed")
}

func TestComposeRootless(t *testing.T) {
	h := newComposeHost()
	h.st.Engine, h.st.CLI, h.st.Socket = "podman:alice", "podman-compose", "/run/user/1000/podman/podman.sock"
	h.st.User, h.st.UID, h.st.Home = "alice", "1000", "/home/alice"
	h.st.WorkingDir, h.st.ConfigFiles = "/home/alice/web", []model.ComposeFile{{Path: "/home/alice/web/compose.yml"}}
	h.registry["postgres:16"] = dbNew
	r := h.runner(t)
	id := jobID(61)
	start(r, id, action.ComposeUpdate, `{"engine":"podman:alice","project":"web","services":["db"]}`)
	_, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	env := "DOCKER_HOST=unix:///run/user/1000/podman/podman.sock XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/alice "
	base := env + "runuser -u alice -- podman-compose -p web -f /home/alice/web/compose.yml "
	if got := h.fe.lines(); !slices.Equal(got, []string{base + "pull db", base + "up -d --no-deps db"}) {
		t.Errorf("commands = %q", got)
	}
	if h.fe.cmds[1].Dir != "/home/alice/web" {
		t.Errorf("dir = %q", h.fe.cmds[1].Dir)
	}
}

func TestComposeCmd(t *testing.T) {
	st := collect.Stack{ComposeStack: model.ComposeStack{Engine: "podman", Project: "blog", WorkingDir: "/srv/blog",
		ConfigFiles: []model.ComposeFile{{Path: "/srv/blog/compose.yml"}}}, Socket: "/run/podman/podman.sock"}
	for _, tc := range []struct{ cli, want string }{
		{"docker compose", "docker compose -p blog -f /srv/blog/compose.yml --project-directory /srv/blog up -d"},
		{"docker-compose", "docker-compose -p blog -f /srv/blog/compose.yml --project-directory /srv/blog up -d"},
		{"podman compose", "podman compose -p blog -f /srv/blog/compose.yml up -d"},
		{"podman-compose", "podman-compose -p blog -f /srv/blog/compose.yml up -d"},
	} {
		st.CLI = tc.cli
		c := composeCmd(st, "up", "-d")
		if got := c.String(); got != "DOCKER_HOST=unix:///run/podman/podman.sock "+tc.want || c.Dir != "/srv/blog" {
			t.Errorf("%s: %s (in %s)", tc.cli, got, c.Dir)
		}
	}
}

func TestWaitHealthyTimesOut(t *testing.T) {
	h := newComposeHost()
	h.recreate["web-app-1"] = true
	h.status = func(_, _ string, _ int) (string, string) { return "restarting", "" }
	r := h.runner(t)
	r.setup()
	out := newOutput(r, jobID(62))
	defer out.close()
	why := r.waitHealthy(context.Background(), action.ComposeParams{Engine: "docker", Project: "web"}, []string{"app", "db"}, out, false)
	if why != "not running and healthy within 0s: web-app-1 is restarting" {
		t.Errorf("why = %q", why)
	}

	h.recreate = map[string]bool{}
	h.st.Containers = h.st.Containers[2:]
	why = r.waitHealthy(context.Background(), action.ComposeParams{Engine: "docker", Project: "web"}, []string{"app"}, out, false)
	if why != "not running and healthy within 0s: app has no container" {
		t.Errorf("why = %q", why)
	}
}

func TestComposeWaitsForAnotherComposeJob(t *testing.T) {
	h := newComposeHost()
	r := h.runner(t)
	r.setup()
	r.stacks <- struct{}{}
	id := jobID(63)
	start(r, id, action.ComposePull, `{"engine":"docker","project":"web"}`)
	for {
		ev := next(t, r)
		if strings.Contains(string(ev.GetData()), "Waiting for another Compose job") {
			break
		}
	}
	<-r.stacks
	_, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
}

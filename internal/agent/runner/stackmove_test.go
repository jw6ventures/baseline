package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

func runStackDir(t *testing.T, r *Runner, n int, name string, p action.ComposeParams) *agentv1.JobEvent {
	t.Helper()
	p.Engine, p.Project = "docker", "app"
	raw, _ := json.Marshal(p)
	id := jobID(n)
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: name, ParamsJson: raw})
	_, res := untilResult(t, r, id)
	return res
}

// dirRunner is a runner whose state directory is apart from the stacks.
func dirRunner(t *testing.T, h *fileHost) *Runner {
	r := h.runner(t)
	r.Dir = filepath.Join(t.TempDir(), "state", "jobs")
	return r
}

func TestComposeArchive(t *testing.T) {
	for i, c := range []struct {
		name    string
		stopped bool
		cmds    []string
	}{{"running", false, []string{"down"}}, {"on disk", true, nil}} {
		// Both archive to the same .archive, likely in the same second.
		h := newFileHost()
		r := dirRunner(t, h)
		if c.stopped {
			h.stop(t, appCompose)
		} else {
			h.adopt(t, appCompose, "A=1\n")
		}
		old := h.dir
		res := runStackDir(t, r, 500+i, action.ComposeArchive, action.ComposeParams{})
		checkResult(t, res, "succeeded", 0, "")
		got := stackResult(t, res.GetResultJson())
		if filepath.Dir(got.WorkingDir) != filepath.Join(filepath.Dir(old), ".archive") ||
			!strings.HasPrefix(filepath.Base(got.WorkingDir), "app-") {
			t.Errorf("%s: archived to %s", c.name, got.WorkingDir)
		}
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Errorf("%s: %s is still there: %v", c.name, old, err)
		}
		if b, err := os.ReadFile(filepath.Join(got.WorkingDir, "docker-compose.yml")); err != nil || string(b) != appCompose {
			t.Errorf("%s: archived Compose file %q, %v", c.name, b, err)
		}
		var subs []string
		for _, l := range h.fe.lines() {
			subs = append(subs, l[strings.LastIndex(l, " ")+1:])
		}
		if !slices.Equal(subs, c.cmds) || h.running {
			t.Errorf("%s: commands %q, running %v", c.name, h.fe.lines(), h.running)
		}
	}
}

func TestComposeArchiveRefusesFilesOutside(t *testing.T) {
	h := newFileHost()
	r := dirRunner(t, h)
	h.adopt(t, appCompose, "")
	h.file = filepath.Join(t.TempDir(), "compose.yaml")
	os.WriteFile(h.file, []byte(appCompose), 0o644)
	checkResult(t, runStackDir(t, r, 510, action.ComposeArchive, action.ComposeParams{}), "failed", -1, "outside")
	if len(h.fe.lines()) != 0 || !h.running {
		t.Errorf("commands %q, running %v", h.fe.lines(), h.running)
	}
}

func TestComposeMove(t *testing.T) {
	h := newFileHost()
	r := dirRunner(t, h)
	h.adopt(t, appCompose, "A=1\n")
	old := h.dir
	dest := filepath.Join(t.TempDir(), "fast")
	res := runStackDir(t, r, 520, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10})
	checkResult(t, res, "succeeded", 0, "")
	dir := filepath.Join(dest, "app")
	file := filepath.Join(dir, "docker-compose.yml")
	if got := stackResult(t, res.GetResultJson()); got.WorkingDir != dir || got.ComposeFile != file || len(got.Services) != 2 {
		t.Errorf("result = %+v", got)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("%s is still there: %v", old, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".env")); string(b) != "A=1\n" {
		t.Errorf(".env = %q", b)
	}
	from := "DOCKER_HOST=unix:///var/run/docker.sock docker compose -p app -f " + filepath.Join(old, "docker-compose.yml") + " --project-directory " + old + " "
	to := "DOCKER_HOST=unix:///var/run/docker.sock docker compose -p app -f " + file + " --project-directory " + dir + " "
	if lines := h.fe.lines(); !slices.Equal(lines, []string{from + "down", to + "config --quiet", to + "up -d"}) {
		t.Errorf("commands = %q", lines)
	}
	if !h.running || h.dir != dir {
		t.Errorf("running %v in %s", h.running, h.dir)
	}
	// It's there now.
	checkResult(t, runStackDir(t, r, 521, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10}), "failed", -1, "already")
}

func TestComposeMoveRollsBack(t *testing.T) {
	h := newFileHost()
	r := dirRunner(t, h)
	h.adopt(t, appCompose, "")
	old := h.dir
	dest := t.TempDir()
	// Moved, its containers don't come up healthy.
	h.state = func(string) (string, string, int) {
		if h.dir == filepath.Join(dest, "app") {
			return "running", "unhealthy", 0
		}
		return "running", "healthy", 0
	}
	res := runStackDir(t, r, 530, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10})
	checkResult(t, res, "rolled_back", -1, "rolled back")
	if got := stackResult(t, res.GetResultJson()); got.WorkingDir != old || !got.RolledBack {
		t.Errorf("result = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(old, "docker-compose.yml")); err != nil {
		t.Errorf("not moved back: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "app")); !os.IsNotExist(err) {
		t.Errorf("left in %s: %v", dest, err)
	}
	if !h.running || h.dir != old {
		t.Errorf("running %v in %s, want %s", h.running, h.dir, old)
	}
}

func TestComposeMoveStopped(t *testing.T) {
	h := newFileHost()
	r := dirRunner(t, h)
	h.stop(t, appCompose)
	dest := t.TempDir()
	res := runStackDir(t, r, 540, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10})
	checkResult(t, res, "succeeded", 0, "")
	if h.running || h.ups != 0 {
		t.Errorf("the move started it: %q", h.fe.lines())
	}
	if _, err := os.Stat(filepath.Join(dest, "app", "docker-compose.yml")); err != nil {
		t.Error(err)
	}
}

func TestComposeMoveRefused(t *testing.T) {
	h := newFileHost()
	r := dirRunner(t, h)
	h.adopt(t, appCompose, "")
	dest := t.TempDir()
	os.Mkdir(filepath.Join(dest, "app"), 0o700)
	checkResult(t, runStackDir(t, r, 550, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10}), "failed", -1, "already exists")
	// Into the agent's state directory.
	checkResult(t, runStackDir(t, r, 551, action.ComposeMove, action.ComposeParams{Dest: r.Dir, HealthTimeout: 10}), "failed", -1, "state directory")
	if len(h.fe.lines()) != 0 {
		t.Errorf("commands %q", h.fe.lines())
	}
}

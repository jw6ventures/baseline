package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/stackenv"
)

// TestMain lets the test binary stand in for `baseline-agent stackfile`,
// which runAsUser runs through /proc/self/exe.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "stackfile" {
		if err := ServeFileOp(os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// asAlice records the file operations run as a rootless stack's user and
// runs them in the test.
type asAlice struct {
	mu  sync.Mutex
	ops []string
}

func (a *asAlice) run(_ context.Context, st collect.Stack, op fileOp) (fileRes, error) {
	a.mu.Lock()
	a.ops = append(a.ops, st.User+" "+op.Op+" "+filepath.Base(op.Path))
	a.mu.Unlock()
	return doFileOp(op), nil
}

func TestComposeRootlessFiles(t *testing.T) {
	h := newFileHost()
	h.rootless = true
	r := h.runner(t)
	r.Dir = filepath.Join(t.TempDir(), "state", "jobs")
	a := &asAlice{}
	r.asUser = a.run
	root := filepath.Join(t.TempDir(), "home", "alice", "stacks")
	env := "DB_PASSWORD=hunter2\n"
	p, files := withEnv(action.StackFileParams{Engine: "podman:alice", Project: "app", Revision: revision, Root: root,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}, &agentv1.StackFiles{Compose: []byte(appCompose)}, env)
	_, res := runFiles(t, r, 600, action.ComposeDeploy, p, files)
	checkResult(t, res, "succeeded", 0, "")
	want := []string{"alice lstat app", "alice mkdirall stacks", "alice mkdir app", "alice write compose.yaml", "alice write .env"}
	if !slices.Equal(a.ops, want) {
		t.Errorf("file operations = %q, want %q", a.ops, want)
	}
	for _, l := range h.fe.lines() {
		if !strings.Contains(l, "XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/alice runuser -u alice -- podman-compose -p app") {
			t.Errorf("command %q doesn't run as alice", l)
		}
	}

	// An edit reads and writes as alice too.
	a.ops = nil
	p2, files2 := withEnv(action.StackFileParams{Engine: "podman:alice", Project: "app", Revision: revision,
		ComposeSHA256: stackenv.SHA256([]byte(appCompose + "# v2\n")), BaseSHA256: stackenv.SHA256([]byte(appCompose))},
		&agentv1.StackFiles{Compose: []byte(appCompose + "# v2\n")}, "DB_PASSWORD=new\n")
	_, res = runFiles(t, r, 601, action.ComposeEdit, p2, files2)
	checkResult(t, res, "succeeded", 0, "")
	want = []string{"alice read compose.yaml", "alice stat .env", "alice read .env",
		"alice write compose.yaml.baseline-prev", "alice write compose.yaml", "alice write .env"}
	if !slices.Equal(a.ops, want) {
		t.Errorf("file operations = %q, want %q", a.ops, want)
	}
	if h.envSeen["up"] != "DB_PASSWORD=new\n" {
		t.Errorf("up saw .env %q", h.envSeen["up"])
	}
}

func TestComposeRootlessFailedFileOp(t *testing.T) {
	h := newFileHost()
	h.rootless = true
	r := h.runner(t)
	r.asUser = func(_ context.Context, _ collect.Stack, op fileOp) (fileRes, error) {
		if op.Op == "lstat" {
			return fileRes{Err: "lstat: no such file or directory", Errno: int(syscall.ENOENT)}, nil
		}
		return fileRes{Err: "mkdir " + op.Path + ": permission denied", Errno: int(syscall.EACCES)}, nil
	}
	p := action.StackFileParams{Engine: "podman:alice", Project: "app", Revision: revision, Root: "/srv/stacks",
		ComposeSHA256: stackenv.SHA256([]byte(appCompose))}
	_, res := runFiles(t, r, 610, action.ComposeDeploy, p, &agentv1.StackFiles{Compose: []byte(appCompose)})
	checkResult(t, res, "failed", -1, "alice can't write to /srv/stacks")
	if len(h.fe.lines()) != 0 {
		t.Errorf("ran %q", h.fe.lines())
	}
}

// TestRunAsUser runs the real helper as nobody: what it may touch is up to
// the kernel. It needs root.
func TestRunAsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const nobody = 65534
	base := t.TempDir()
	os.Chmod(filepath.Dir(base), 0o755)
	os.Chmod(base, 0o755)
	mine := filepath.Join(base, "mine") // nobody's own directory
	os.Mkdir(mine, 0o700)
	os.Chown(mine, nobody, nobody)
	secret := filepath.Join(base, "secret")
	os.WriteFile(secret, []byte("root only"), 0o600)
	os.Symlink(secret, filepath.Join(mine, "compose.yaml"))

	st := collect.Stack{User: "nobody", UID: "65534", GID: "65534", Home: "/"}
	fsys := (&Runner{}).files(context.Background(), st)
	if err := fsys.write(filepath.Join(mine, ".env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(mine, ".env"))
	if err != nil || fi.Sys().(*syscall.Stat_t).Uid != nobody || fi.Mode().Perm() != 0o600 {
		t.Errorf(".env written as %+v, %v", fi.Sys(), err)
	}
	if b, mode, err := fsys.read(filepath.Join(mine, ".env")); string(b) != "A=1\n" || mode != 0o600 || err != nil {
		t.Errorf("read = %q %v %v", b, mode, err)
	}
	if _, _, err := fsys.read(filepath.Join(mine, "compose.yaml")); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("read through a link to a root-only file: %v", err)
	}
	if err := fsys.write(filepath.Join(base, "root.yaml"), []byte("x"), 0o644); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("write to a root directory: %v", err)
	}
	if _, err := fsys.stat(filepath.Join(mine, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat of a missing file: %v", err)
	}
	if b, _ := os.ReadFile(secret); string(b) != "root only" {
		t.Errorf("secret = %q", b)
	}
}

func TestComposeRootlessArchiveAndMove(t *testing.T) {
	run := func(r *Runner, n int, name string, p action.ComposeParams) *agentv1.JobEvent {
		p.Engine, p.Project = "podman:alice", "app"
		raw, _ := json.Marshal(p)
		r.Start(context.Background(), &agentv1.RunJob{JobId: jobID(n), Action: name, ParamsJson: raw})
		_, res := untilResult(t, r, jobID(n))
		return res
	}
	h := newFileHost()
	h.rootless = true
	r := dirRunner(t, h)
	a := &asAlice{}
	r.asUser = a.run
	h.adopt(t, appCompose, "")
	dest := filepath.Join(t.TempDir(), "alice-stacks")
	res := run(r, 620, action.ComposeMove, action.ComposeParams{Dest: dest, HealthTimeout: 10})
	checkResult(t, res, "succeeded", 0, "")
	if len(a.ops) != 3 || a.ops[0] != "alice lstat app" || a.ops[1] != "alice mkdirall alice-stacks" || !strings.HasPrefix(a.ops[2], "alice rename ") {
		t.Errorf("move's file operations = %q", a.ops)
	}
	if _, err := os.Stat(filepath.Join(dest, "app", "docker-compose.yml")); err != nil {
		t.Error(err)
	}
	h.dir, h.file = filepath.Join(dest, "app"), filepath.Join(dest, "app", "docker-compose.yml")
	a.ops = nil
	res = run(r, 621, action.ComposeArchive, action.ComposeParams{})
	checkResult(t, res, "succeeded", 0, "")
	if len(a.ops) != 3 || a.ops[1] != "alice mkdirall .archive" || !strings.HasPrefix(a.ops[2], "alice rename ") {
		t.Errorf("archive's file operations = %q", a.ops)
	}
	for _, l := range h.fe.lines() {
		if !strings.Contains(l, "runuser -u alice --") {
			t.Errorf("command %q doesn't run as alice", l)
		}
	}
}

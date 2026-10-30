package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

const scriptParams = `{"script_id":"s1","name":"cleanup","version":1}`

func sum(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

func startScript(r *Runner, id string, s *agentv1.Script) {
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: action.ScriptRun,
		ParamsJson: []byte(scriptParams), Script: s})
}

func TestScriptRefused(t *testing.T) {
	for _, tc := range []struct {
		script *agentv1.Script
		err    string
	}{
		{nil, "the server sent no script"},
		{&agentv1.Script{Interpreter: "/bin/sh", Body: []byte("echo hi"), Sha256: sum("echo bye")}, "doesn't match its SHA-256"},
		{&agentv1.Script{Interpreter: "/bin/sh", Body: []byte("echo hi"), Sha256: strings.ToUpper(sum("echo hi"))}, "doesn't match its SHA-256"},
		{&agentv1.Script{Interpreter: "/bin/sh", Body: []byte("echo hi")}, "doesn't match its SHA-256"},
		{&agentv1.Script{Interpreter: "/usr/bin/perl", Body: []byte("print 1"), Sha256: sum("print 1")}, `interpreter "/usr/bin/perl" isn't allowed`},
		{&agentv1.Script{Interpreter: "sh", Body: []byte("echo"), Sha256: sum("echo")}, "isn't allowed"},
		{&agentv1.Script{Interpreter: "", Body: []byte("echo"), Sha256: sum("echo")}, "isn't allowed"},
	} {
		fe := &fakeExec{}
		r := newRunner(t, fe)
		r.TempDir = t.TempDir()
		startScript(r, jobID(20), tc.script)
		_, res := untilResult(t, r, jobID(20))
		checkResult(t, res, "failed", -1, tc.err)
		if len(fe.lines()) != 0 {
			t.Errorf("%q: ran %q", tc.err, fe.lines())
		}
		if ents, _ := os.ReadDir(r.TempDir); len(ents) != 0 {
			t.Errorf("%q: left %v", tc.err, ents)
		}
	}
}

func TestScriptRuns(t *testing.T) {
	body := `printf 'args:%s|%s|%s\n' "$1" "$2" "$3"
printf 'x:%s\n' "$BASELINE_PARAM_X"
printf 'job:%s\n' "$BASELINE_JOB_ID"
printf 'other:%s\n' "${OTHER-unset}"
printf 'lower:%s\n' "${baseline_x-unset}"
printf 'mode:%s\n' "$(stat -c %a "$0")"
printf 'pwd:%s\n' "$(pwd)"
echo oops >&2
`
	r := newRunner(t, nil) // real processes
	r.TempDir = t.TempDir()
	id := jobID(21)
	startScript(r, id, &agentv1.Script{Interpreter: "/bin/sh", Body: []byte(body), Sha256: sum(body),
		Args: []string{"a b", "", "$(id)"},
		Env: map[string]string{"BASELINE_PARAM_X": "1\x002", "BASELINE_JOB_ID": id, "OTHER": "no",
			"baseline_x": "no", "PATH": "/tmp/evil", "LD_PRELOAD": "/tmp/evil.so", "BASELINE_A=B": "no"}})
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	want := "args:a b||$(id)\nx:12\njob:" + id + "\nother:unset\nlower:unset\nmode:700\npwd:/\n"
	if out := outputOf(evs, "stdout"); out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if out := outputOf(evs, "stderr"); out != "oops\n" {
		t.Errorf("stderr = %q", out)
	}
	if info := outputOf(evs, "info"); !strings.HasPrefix(info, "$ /bin/sh a b  $(id) (sha256 "+sum(body)[:12]+")\n") {
		t.Errorf("info = %q", info)
	}
	if ents, _ := os.ReadDir(r.TempDir); len(ents) != 0 {
		t.Errorf("script file left behind: %v", ents)
	}
}

func TestScriptExitStatus(t *testing.T) {
	body := "echo before\nexit 7\n"
	r := newRunner(t, nil)
	r.TempDir = t.TempDir()
	startScript(r, jobID(22), &agentv1.Script{Interpreter: "/bin/sh", Body: []byte(body), Sha256: sum(body)})
	evs, res := untilResult(t, r, jobID(22))
	checkResult(t, res, "failed", 7, "the script exited with status 7")
	if outputOf(evs, "stdout") != "before\n" {
		t.Errorf("stdout = %q", outputOf(evs, "stdout"))
	}
	if ents, _ := os.ReadDir(r.TempDir); len(ents) != 0 {
		t.Errorf("script file left behind: %v", ents)
	}
}

func TestScriptCancelled(t *testing.T) {
	body := "echo ready\nsleep 30\n"
	r := newRunner(t, nil)
	r.TempDir = t.TempDir()
	id := jobID(23)
	startScript(r, id, &agentv1.Script{Interpreter: "/bin/sh", Body: []byte(body), Sha256: sum(body)})
	// Wait for the script to start, then cancel it.
	for {
		ev := next(t, r)
		if ev.GetType() == agentv1.JobEvent_OUTPUT && ev.GetStream() == "stdout" {
			break
		}
	}
	t0 := time.Now()
	r.Cancel(id)
	_, res := untilResult(t, r, id)
	checkResult(t, res, "cancelled", -1, "cancelled")
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("cancel took %v", d)
	}
	if ents, _ := os.ReadDir(r.TempDir); len(ents) != 0 {
		t.Errorf("script file left behind: %v", ents)
	}
}

func TestScriptBadTempDir(t *testing.T) {
	r := newRunner(t, &fakeExec{})
	r.TempDir = "/nonexistent/baseline-test"
	startScript(r, jobID(24), &agentv1.Script{Interpreter: "/bin/sh", Body: []byte("true"), Sha256: sum("true")})
	_, res := untilResult(t, r, jobID(24))
	checkResult(t, res, "failed", -1, "script file:")
}

func TestScriptTimeoutFromParams(t *testing.T) {
	started := make(chan struct{})
	r := newRunner(t, blockingExec(started))
	r.TempDir = t.TempDir()
	id := jobID(25)
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: action.ScriptRun,
		ParamsJson: []byte(`{"script_id":"s1","name":"x","version":1,"timeout_s":1}`),
		Script:     &agentv1.Script{Interpreter: "/bin/sh", Body: []byte("true"), Sha256: sum("true")}})
	_, res := untilResult(t, r, id)
	checkResult(t, res, "timed_out", -1, "timed out after 1s")
}

// Run -------------------------------------------------------------------------

// syncBuffer is a bytes.Buffer safe to read while a command writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRunExitCodeAndStreams(t *testing.T) {
	for _, tc := range []struct {
		script         string
		code           int
		stdout, stderr string
	}{
		{"echo out; echo err >&2", 0, "out\n", "err\n"},
		{"echo out; exit 3", 3, "out\n", ""},
		{"printf x >&2; exit 255", 255, "", "x"},
		{"kill -9 $$", -1, "", ""},
	} {
		var stdout, stderr syncBuffer
		code, err := Run(context.Background(), Cmd{Name: "/bin/sh", Args: []string{"-c", tc.script}}, &stdout, &stderr)
		if err != nil || code != tc.code || stdout.String() != tc.stdout || stderr.String() != tc.stderr {
			t.Errorf("%q = %d %v %q %q", tc.script, code, err, stdout.String(), stderr.String())
		}
	}
}

func TestRunEnvAndDir(t *testing.T) {
	t.Setenv("BASELINE_TEST_LEAK", "leaked")
	var stdout syncBuffer
	code, err := Run(context.Background(), Cmd{Name: "/bin/sh",
		Args: []string{"-c", `echo "$FOO|$LANG|$HOME|${BASELINE_TEST_LEAK-unset}|$(pwd)"`}, Env: []string{"FOO=bar"}},
		&stdout, &stdout)
	if err != nil || code != 0 || stdout.String() != "bar|C.UTF-8|/root|unset|/\n" {
		t.Errorf("%d %v %q", code, err, stdout.String())
	}
	dir := t.TempDir()
	stdout = syncBuffer{}
	Run(context.Background(), Cmd{Name: "/bin/sh", Args: []string{"-c", "pwd"}, Dir: dir}, &stdout, &stdout)
	if strings.TrimSpace(stdout.String()) != dir {
		t.Errorf("pwd = %q, want %q", stdout.String(), dir)
	}
}

func TestRunNotFound(t *testing.T) {
	code, err := Run(context.Background(), Cmd{Name: "/nonexistent/baseline-test"}, &syncBuffer{}, &syncBuffer{})
	if code != -1 || err == nil {
		t.Errorf("%d %v", code, err)
	}
}

// Cancelling stops the whole process group, not only the shell.
func TestRunCancelKillsGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout syncBuffer
	type ret struct {
		code int
		err  error
	}
	done := make(chan ret, 1)
	go func() {
		code, err := Run(ctx, Cmd{Name: "/bin/sh", Args: []string{"-c", "sleep 30 & echo $!; wait"}}, &stdout, &stdout)
		done <- ret{code, err}
	}()
	var pid int
	for deadline := time.Now().Add(5 * time.Second); pid == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no pid")
		}
		if s, ok := strings.CutSuffix(stdout.String(), "\n"); ok {
			pid, _ = strconv.Atoi(s)
		}
	}
	t0 := time.Now()
	cancel()
	var r ret
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("Run took %v after cancel", d)
	}
	if !errors.Is(r.err, context.Canceled) {
		t.Errorf("err = %v (code %d)", r.err, r.code)
	}
	// The background sleep is gone (or a zombie waiting for init).
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) || err != nil || strings.Contains(string(stat), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sleep %d survived the cancel: %s", pid, stat)
		}
	}
}

func TestRunDeadline(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, Cmd{Name: "sleep", Args: []string{"30"}}, &syncBuffer{}, &syncBuffer{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestCmdString(t *testing.T) {
	c := Cmd{Name: "apt-get", Args: []string{"-y", "dist-upgrade"}, Env: []string{"A=1", "B=2"}}
	if s := c.String(); s != "A=1 B=2 apt-get -y dist-upgrade" {
		t.Errorf("%q", s)
	}
	if s := (Cmd{Name: "true"}).String(); s != "true" {
		t.Errorf("%q", s)
	}
	// String doesn't change the Cmd.
	if len(c.Env) != 2 || len(c.Args) != 2 {
		t.Errorf("%+v", c)
	}
}

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

// jobID is a well-formed job ID.
func jobID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// fakeExec records commands and runs fn (or succeeds silently).
type fakeExec struct {
	mu   sync.Mutex
	cmds []Cmd
	fn   func(ctx context.Context, c Cmd, stdout, stderr io.Writer) (int, error)
}

func (f *fakeExec) exec(ctx context.Context, c Cmd, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, c)
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, c, stdout, stderr)
	}
	return 0, nil
}

// lines are the recorded commands as strings.
func (f *fakeExec) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.cmds {
		out = append(out, c.String())
	}
	return out
}

// collected records the Collect hook's calls.
type collected struct {
	mu    sync.Mutex
	calls []string // "jobID: section,section"
}

func (c *collected) collect(id string, sections []string) {
	c.mu.Lock()
	c.calls = append(c.calls, id+": "+strings.Join(sections, ","))
	c.mu.Unlock()
}

func (c *collected) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// newRunner is a Runner that allows everything, on boot "boot-1", whose
// Reboot fails the test.
func newRunner(t *testing.T, fe *fakeExec) *Runner {
	t.Helper()
	r := &Runner{
		Dir:    t.TempDir(),
		Policy: action.Policy{Jobs: true, AllowScripts: true},
		BootID: func() string { return "boot-1" },
		Reboot: func(context.Context) error {
			t.Error("unexpected reboot")
			return nil
		},
	}
	if fe != nil {
		r.Exec = fe.exec
	}
	return r
}

func start(r *Runner, id, name, params string) {
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: name, ParamsJson: []byte(params)})
}

// next waits for the next event and marks it sent.
func next(t *testing.T, r *Runner) *agentv1.JobEvent {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		if ev := r.Next(); ev != nil {
			r.Sent(ev)
			return ev
		}
		select {
		case <-r.Ready():
		case <-timeout:
			t.Fatal("no event within 10s")
		}
	}
}

// untilResult drains events until a RESULT for job id arrives, returning
// everything read (the RESULT last).
func untilResult(t *testing.T, r *Runner, id string) ([]*agentv1.JobEvent, *agentv1.JobEvent) {
	t.Helper()
	var evs []*agentv1.JobEvent
	for {
		ev := next(t, r)
		evs = append(evs, ev)
		if ev.GetType() == agentv1.JobEvent_RESULT && ev.GetJobId() == id {
			return evs, ev
		}
	}
}

// waitIdle waits for every job goroutine to end.
func waitIdle(t *testing.T, r *Runner) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); r.Running(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("jobs still running after 10s")
		}
	}
}

// outputOf concatenates the OUTPUT data of a stream ("" for all).
func outputOf(evs []*agentv1.JobEvent, stream string) string {
	var b strings.Builder
	for _, ev := range evs {
		if ev.GetType() == agentv1.JobEvent_OUTPUT && (stream == "" || ev.GetStream() == stream) {
			b.Write(ev.GetData())
		}
	}
	return b.String()
}

func count(evs []*agentv1.JobEvent, typ agentv1.JobEvent_Type) int {
	n := 0
	for _, ev := range evs {
		if ev.GetType() == typ {
			n++
		}
	}
	return n
}

func checkResult(t *testing.T, res *agentv1.JobEvent, state string, exit int32, errSub string) {
	t.Helper()
	if res.GetState() != state || res.GetExitCode() != exit || !strings.Contains(res.GetError(), errSub) ||
		(errSub == "" && res.GetError() != "") {
		t.Errorf("result = %s exit %d %q, want %s exit %d %q", res.GetState(), res.GetExitCode(), res.GetError(),
			state, exit, errSub)
	}
}

func TestServiceRestart(t *testing.T) {
	fe := &fakeExec{fn: func(_ context.Context, c Cmd, stdout, stderr io.Writer) (int, error) {
		if c.Args[0] == "restart" {
			fmt.Fprint(stdout, "restarted\n")
			fmt.Fprint(stderr, "a warning\n")
			return 0, nil
		}
		fmt.Fprint(stdout, "● nginx.service - nginx\n")
		return 3, nil // status's exit code isn't the job's
	}}
	r := newRunner(t, fe)
	var col collected
	r.Collect = col.collect
	id := jobID(1)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	evs, res := untilResult(t, r, id)

	checkResult(t, res, "succeeded", 0, "")
	if got := fe.lines(); !slices.Equal(got, []string{"systemctl restart nginx.service",
		"systemctl status --no-pager --lines=10 nginx.service"}) {
		t.Errorf("commands = %q", got)
	}
	if evs[0].GetType() != agentv1.JobEvent_STARTED || evs[0].GetJobId() != id || count(evs, agentv1.JobEvent_STARTED) != 1 {
		t.Errorf("first event = %v", evs[0])
	}
	var seq uint64
	for _, ev := range evs {
		if ev.GetType() == agentv1.JobEvent_OUTPUT {
			if seq++; ev.GetSeq() != seq || ev.GetJobId() != id {
				t.Errorf("OUTPUT seq %d, want %d", ev.GetSeq(), seq)
			}
		}
	}
	if seq == 0 {
		t.Fatal("no output")
	}
	info := outputOf(evs, "info")
	if !strings.HasPrefix(info, "$ systemctl restart nginx.service\n") ||
		!strings.Contains(info, "$ systemctl status --no-pager --lines=10 nginx.service\n") {
		t.Errorf("info = %q", info)
	}
	if out := outputOf(evs, "stdout"); out != "restarted\n● nginx.service - nginx\n" {
		t.Errorf("stdout = %q", out)
	}
	if out := outputOf(evs, "stderr"); out != "a warning\n" {
		t.Errorf("stderr = %q", out)
	}
	if got := col.get(); !slices.Equal(got, []string{id + ": " + strings.Join(action.MustGet(action.ServiceRestart).Sections, ",")}) {
		t.Errorf("collect = %q", got)
	}
	waitIdle(t, r)
	rec, err := r.load(id)
	if err != nil || rec.State != "succeeded" || rec.Action != action.ServiceRestart || rec.BootID != "boot-1" ||
		rec.Finished.IsZero() || rec.Started.IsZero() {
		t.Errorf("journal = %+v %v", rec, err)
	}
}

func TestServiceVerbs(t *testing.T) {
	for _, name := range []string{action.ServiceStart, action.ServiceStop} {
		fe := &fakeExec{}
		r := newRunner(t, fe)
		start(r, jobID(1), name, `{"unit":"ssh.service"}`)
		_, res := untilResult(t, r, jobID(1))
		checkResult(t, res, "succeeded", 0, "")
		verb := strings.TrimPrefix(name, "service.")
		if got := fe.lines(); len(got) != 2 || got[0] != "systemctl "+verb+" ssh.service" {
			t.Errorf("%s: commands = %q", name, got)
		}
	}
}

func TestServiceRestartFails(t *testing.T) {
	fe := &fakeExec{fn: func(_ context.Context, c Cmd, _, stderr io.Writer) (int, error) {
		if c.Args[0] == "restart" {
			fmt.Fprint(stderr, "Job for nginx.service failed.\n")
			return 5, nil
		}
		return 3, nil
	}}
	r := newRunner(t, fe)
	var col collected
	r.Collect = col.collect
	start(r, jobID(2), action.ServiceRestart, `{"unit":"nginx.service"}`)
	evs, res := untilResult(t, r, jobID(2))
	checkResult(t, res, "failed", 5, "systemctl restart failed")
	if len(fe.lines()) != 2 {
		t.Errorf("status wasn't shown: %q", fe.lines())
	}
	if info := outputOf(evs, "info"); !strings.HasSuffix(info, "\nsystemctl restart failed\n") {
		t.Errorf("info = %q", info)
	}
	// A failed job may still have changed something.
	if len(col.get()) != 1 {
		t.Errorf("collect = %q", col.get())
	}
}

func TestServiceExecError(t *testing.T) {
	fe := &fakeExec{fn: func(context.Context, Cmd, io.Writer, io.Writer) (int, error) {
		return -1, errors.New("exec: \"systemctl\": executable file not found in $PATH")
	}}
	r := newRunner(t, fe)
	start(r, jobID(3), action.ServiceRestart, `{"unit":"nginx"}`)
	_, res := untilResult(t, r, jobID(3))
	checkResult(t, res, "failed", -1, "systemctl: exec:")
	if len(fe.lines()) != 1 {
		t.Errorf("commands = %q", fe.lines())
	}
}

func TestPolicyRejects(t *testing.T) {
	for _, tc := range []struct {
		policy       action.Policy
		name, params string
		why          string
	}{
		{action.Policy{}, action.ServiceRestart, `{"unit":"nginx"}`, "too old"},
		{action.Policy{Jobs: true, AllowActions: []string{action.CategoryPatch}}, action.ServiceRestart, `{"unit":"nginx"}`, `"service" actions`},
		{action.Policy{Jobs: true, AllowActions: []string{}}, action.HostReboot, `{}`, `"reboot" actions`},
		{action.Policy{Jobs: true}, action.ScriptRun, `{"script_id":"s","version":1}`, "allow_scripts"},
		{action.Policy{Jobs: true, AllowActions: []string{action.CategoryContainer}}, action.ComposeUpdate,
			`{"engine":"docker","project":"web"}`, `"compose" actions`},
		{action.Policy{Jobs: true}, "vm.snapshot", `{}`, "unknown action"},
	} {
		fe := &fakeExec{}
		r := newRunner(t, fe)
		r.Policy = tc.policy
		var col collected
		r.Collect = col.collect
		id := jobID(4)
		start(r, id, tc.name, tc.params)
		evs, res := untilResult(t, r, id)
		checkResult(t, res, "rejected", -1, tc.why)
		if len(evs) != 1 || len(fe.lines()) != 0 || len(col.get()) != 0 {
			t.Errorf("%s: events %v, commands %q, collect %q", tc.name, evs, fe.lines(), col.get())
		}
		// The journal remembers the refusal.
		waitIdle(t, r)
		r.Policy = action.Policy{Jobs: true, AllowScripts: true}
		start(r, id, tc.name, tc.params)
		_, res = untilResult(t, r, id)
		checkResult(t, res, "rejected", -1, tc.why)
		if len(fe.lines()) != 0 {
			t.Errorf("%s: ran after a rejection: %q", tc.name, fe.lines())
		}
	}
}

func TestInvalidParamsFail(t *testing.T) {
	for _, tc := range []struct{ name, params, err string }{
		{action.ServiceRestart, `{"unit":"-H"}`, "isn't a unit name"},
		{action.ServiceRestart, `{"unit":"nginx","x":1}`, "unknown field"},
		{action.HostReboot, `{"delay_s":1}`, "between 5 seconds"},
		{action.PkgUpgrade, `{"mode":"selected"}`, "at least one package"},
	} {
		fe := &fakeExec{}
		r := newRunner(t, fe)
		start(r, jobID(5), tc.name, tc.params)
		evs, res := untilResult(t, r, jobID(5))
		checkResult(t, res, "failed", -1, tc.err)
		if len(evs) != 1 || len(fe.lines()) != 0 {
			t.Errorf("%s %s: events %v, commands %q", tc.name, tc.params, evs, fe.lines())
		}
	}
}

func TestMalformedJobIDIgnored(t *testing.T) {
	fe := &fakeExec{}
	r := newRunner(t, fe)
	for _, id := range []string{"", "job-1", "00000000-0000-4000-8000-00000000000A", "00000000-0000-4000-8000-0000000000001",
		"../../etc/passwd", "00000000-0000-4000-8000-000000000001/x"} {
		start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
		if ev := r.Next(); ev != nil || r.Running() {
			t.Errorf("%q: event %v, running %v", id, ev, r.Running())
		}
	}
	if ents, _ := os.ReadDir(r.Dir); len(ents) != 0 || len(fe.lines()) != 0 {
		t.Errorf("journal %v, commands %q", ents, fe.lines())
	}
}

func TestStartIsIdempotent(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	fe := &fakeExec{fn: func(_ context.Context, c Cmd, stdout, _ io.Writer) (int, error) {
		if c.Args[0] == "restart" {
			close(started)
			<-release
		}
		return 0, nil
	}}
	r := newRunner(t, fe)
	id := jobID(6)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	<-started
	// Resent while running: ignored.
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	if !r.Running() {
		t.Error("not running")
	}
	close(release)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if count(evs, agentv1.JobEvent_STARTED) != 1 || len(fe.lines()) != 2 {
		t.Errorf("ran %d times: %q", count(evs, agentv1.JobEvent_STARTED), fe.lines())
	}
	waitIdle(t, r)

	// Resent after it finished: the journal answers.
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	if ev := next(t, r); ev.GetType() != agentv1.JobEvent_RESULT || ev.GetJobId() != id {
		t.Fatalf("resend got %v", ev)
	} else {
		checkResult(t, ev, "succeeded", 0, "")
	}
	if r.Next() != nil || len(fe.lines()) != 2 {
		t.Errorf("ran again: %q", fe.lines())
	}

	// So does a new agent process on the same journal.
	r2 := newRunner(t, fe)
	r2.Dir = r.Dir
	start(r2, id, action.ServiceRestart, `{"unit":"nginx"}`)
	evs, res = untilResult(t, r2, id)
	checkResult(t, res, "succeeded", 0, "")
	if len(evs) != 1 || len(fe.lines()) != 2 {
		t.Errorf("new process ran it again: %q", fe.lines())
	}
}

func TestFailedResultIsRemembered(t *testing.T) {
	fe := &fakeExec{fn: func(_ context.Context, c Cmd, _, _ io.Writer) (int, error) {
		if c.Args[0] == "restart" {
			return 1, nil
		}
		return 0, nil
	}}
	r := newRunner(t, fe)
	id := jobID(7)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	_, res := untilResult(t, r, id)
	checkResult(t, res, "failed", 1, "systemctl restart failed")
	waitIdle(t, r)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	_, res = untilResult(t, r, id)
	checkResult(t, res, "failed", 1, "systemctl restart failed")
	if len(fe.lines()) != 2 {
		t.Errorf("commands = %q", fe.lines())
	}
}

func TestRecoverAfterRestart(t *testing.T) {
	result := json.RawMessage(`{"rebooting":true}`)
	for _, tc := range []struct {
		state, journalBoot, boot string
		want, err                string
	}{
		{"running", "boot-1", "boot-1", "failed", "the agent restarted while the job ran"},
		{"running", "boot-0", "boot-1", "failed", "the agent restarted while the job ran"},
		{"rebooting", "boot-0", "boot-1", "succeeded", ""},
		{"rebooting", "boot-1", "boot-1", "failed", "the host didn't reboot"},
		{"rebooting", "boot-0", "", "failed", "the host didn't reboot"},
		{"cancelled", "boot-1", "boot-1", "cancelled", "cancelled"},
		{"rolled_back", "boot-1", "boot-1", "rolled_back", "rolled back"},
	} {
		dir := t.TempDir()
		id := jobID(8)
		old := &Runner{Dir: dir}
		rec := record{ID: id, Action: action.HostReboot, State: tc.state, BootID: tc.journalBoot,
			Started: time.Now().Add(-time.Minute), Result: result}
		switch tc.state {
		case "cancelled":
			rec.Error = "cancelled"
		case "rolled_back":
			rec.Error = "rolled back: web-app-1 is unhealthy"
		}
		if err := old.save(rec); err != nil {
			t.Fatal(err)
		}

		fe := &fakeExec{}
		r := newRunner(t, fe)
		r.Dir = dir
		r.BootID = func() string { return tc.boot }
		start(r, id, action.HostReboot, `{"delay_s":5}`)
		evs, res := untilResult(t, r, id)
		checkResult(t, res, tc.want, 0, tc.err)
		if len(evs) != 1 || string(res.GetResultJson()) != string(result) || len(fe.lines()) != 0 {
			t.Errorf("%s/%s/%s: events %v result %s", tc.state, tc.journalBoot, tc.boot, evs, res.GetResultJson())
		}
		// The journal now holds the final state.
		got, err := r.load(id)
		if err != nil || got.State != tc.want || (tc.state == stateRunning || tc.state == stateRebooting) && got.Finished.IsZero() {
			t.Errorf("%s/%s/%s: journal = %+v %v", tc.state, tc.journalBoot, tc.boot, got, err)
		}
	}
}

func TestHostRebootCancelledDuringDelay(t *testing.T) {
	fe := &fakeExec{}
	r := newRunner(t, fe)
	var col collected
	r.Collect = col.collect
	id := jobID(9)
	start(r, id, action.HostReboot, `{"delay_s":5}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "rebooting", 0, "")
	if evs[0].GetType() != agentv1.JobEvent_STARTED || !strings.Contains(outputOf(evs, "info"), "The host reboots in 5 seconds.") {
		t.Errorf("events = %v", evs)
	}
	if rec, err := r.load(id); err != nil || rec.State != stateRebooting || rec.BootID != "boot-1" {
		t.Errorf("journal = %+v %v", rec, err)
	}
	if got := col.get(); len(got) != 1 || !strings.HasPrefix(got[0], id+": os,reboot,") {
		t.Errorf("collect = %q", got)
	}
	// A resend while waiting is ignored.
	start(r, id, action.HostReboot, `{"delay_s":5}`)
	if ev := r.Next(); ev != nil {
		t.Errorf("resend: %v", ev)
	}

	r.Cancel(id)
	_, res = untilResult(t, r, id)
	checkResult(t, res, "cancelled", 0, "cancelled before the reboot")
	waitIdle(t, r)
	if rec, _ := r.load(id); rec.State != "cancelled" {
		t.Errorf("journal = %+v", rec)
	}
	// newRunner's Reboot fails the test if called.
}

func TestRebootAfter(t *testing.T) {
	rebooted := make(chan struct{})
	r := newRunner(t, nil)
	r.Reboot = func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("reboot without a deadline")
		}
		close(rebooted)
		return nil
	}
	r.setup()
	id := jobID(10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.rebootAfter(ctx, record{ID: id, Action: action.HostReboot, State: stateRunning, BootID: "boot-1",
			Result: json.RawMessage(`{"x":1}`)}, 50*time.Millisecond)
		close(done)
	}()
	ev := next(t, r)
	checkResult(t, ev, "rebooting", 0, "")
	if string(ev.GetResultJson()) != `{"x":1}` {
		t.Errorf("result = %s", ev.GetResultJson())
	}
	select {
	case <-rebooted:
	case <-time.After(5 * time.Second):
		t.Fatal("no reboot")
	}
	// It waits for the host to go down without reporting anything more.
	select {
	case <-done:
		t.Error("rebootAfter returned after rebooting")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	<-done
	if ev := r.Next(); ev != nil {
		t.Errorf("event after reboot: %v", ev)
	}
	if rec, _ := r.load(id); rec.State != stateRebooting {
		t.Errorf("journal = %+v", rec)
	}

	// The agent comes back on a new boot and the server resends the job.
	r2 := newRunner(t, nil)
	r2.Dir = r.Dir
	r2.BootID = func() string { return "boot-2" }
	start(r2, id, action.HostReboot, `{"delay_s":5}`)
	_, res := untilResult(t, r2, id)
	checkResult(t, res, "succeeded", 0, "")
}

func TestRebootAfterFails(t *testing.T) {
	r := newRunner(t, nil)
	r.Reboot = func(context.Context) error { return errors.New("permission denied") }
	r.setup()
	id := jobID(11)
	done := make(chan struct{})
	go func() {
		r.rebootAfter(context.Background(), record{ID: id, State: stateRunning}, time.Millisecond)
		close(done)
	}()
	checkResult(t, next(t, r), "rebooting", 0, "")
	checkResult(t, next(t, r), "failed", -1, "reboot: permission denied")
	<-done
	if rec, _ := r.load(id); rec.State != "failed" {
		t.Errorf("journal = %+v", rec)
	}
}

// blockingExec signals started and waits for the job to end.
func blockingExec(started chan struct{}) *fakeExec {
	var once sync.Once
	return &fakeExec{fn: func(ctx context.Context, _ Cmd, _, _ io.Writer) (int, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return -1, ctx.Err()
	}}
}

func TestCancelRunningJob(t *testing.T) {
	started := make(chan struct{})
	fe := blockingExec(started)
	r := newRunner(t, fe)
	var col collected
	r.Collect = col.collect
	id := jobID(12)
	start(r, id, action.ServiceRestart, `{"unit":"nginx"}`)
	<-started
	r.Cancel(id)
	r.Cancel(jobID(99)) // unknown: nothing happens
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "cancelled", -1, "cancelled")
	if !strings.HasSuffix(outputOf(evs, "info"), "\ncancelled\n") {
		t.Errorf("info = %q", outputOf(evs, "info"))
	}
	waitIdle(t, r)
	if rec, _ := r.load(id); rec.State != "cancelled" {
		t.Errorf("journal = %+v", rec)
	}
	// A stopped job may have changed something: inventory is collected again.
	if len(col.get()) != 1 {
		t.Errorf("collect = %q", col.get())
	}
}

func TestParentContextCancels(t *testing.T) {
	started := make(chan struct{})
	r := newRunner(t, blockingExec(started))
	ctx, cancel := context.WithCancel(context.Background())
	id := jobID(13)
	r.Start(ctx, &agentv1.RunJob{JobId: id, Action: action.ServiceStop, ParamsJson: []byte(`{"unit":"nginx"}`)})
	<-started
	cancel()
	_, res := untilResult(t, r, id)
	checkResult(t, res, "cancelled", -1, "cancelled")
}

func TestJobTimesOut(t *testing.T) {
	started := make(chan struct{})
	r := newRunner(t, blockingExec(started))
	id := jobID(14)
	t0 := time.Now()
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: action.ServiceRestart,
		ParamsJson: []byte(`{"unit":"nginx"}`), TimeoutSeconds: 1})
	_, res := untilResult(t, r, id)
	checkResult(t, res, "timed_out", -1, "timed out after 1s")
	if d := time.Since(t0); d < time.Second || d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

type fakeContainers struct {
	Containers // Compose methods aren't used here
	mu         sync.Mutex
	calls      []string
	err        error
}

func (f *fakeContainers) Restart(_ context.Context, engine, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, engine+"/"+name)
	return f.err
}

func TestContainerRestart(t *testing.T) {
	fc := &fakeContainers{}
	r := newRunner(t, nil)
	r.Containers = fc
	start(r, jobID(15), action.ContainerRestart, `{"engine":"podman:alice","name":"web"}`)
	evs, res := untilResult(t, r, jobID(15))
	checkResult(t, res, "succeeded", 0, "")
	if !slices.Equal(fc.calls, []string{"podman:alice/web"}) ||
		outputOf(evs, "info") != "Restarting container web (podman:alice)\nRestarted.\n" {
		t.Errorf("calls %q, info %q", fc.calls, outputOf(evs, "info"))
	}

	fc.err = errors.New("no such container")
	start(r, jobID(16), action.ContainerRestart, `{"engine":"docker","name":"db"}`)
	_, res = untilResult(t, r, jobID(16))
	checkResult(t, res, "failed", -1, "no such container")

	r2 := newRunner(t, nil)
	start(r2, jobID(17), action.ContainerRestart, `{"engine":"docker","name":"db"}`)
	_, res = untilResult(t, r2, jobID(17))
	checkResult(t, res, "failed", -1, "containers can't be managed")
}

func TestJournalWriteFailure(t *testing.T) {
	fe := &fakeExec{}
	r := newRunner(t, fe)
	// The journal "directory" is a file, so nothing can be written there.
	r.Dir = r.Dir + "/file"
	if err := os.WriteFile(r.Dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	start(r, jobID(18), action.ServiceRestart, `{"unit":"nginx"}`)
	evs, res := untilResult(t, r, jobID(18))
	checkResult(t, res, "failed", -1, "can't write the job journal")
	if len(evs) != 1 || len(fe.lines()) != 0 {
		t.Errorf("ran without a journal: %q", fe.lines())
	}
}

func TestPrune(t *testing.T) {
	r := &Runner{Dir: t.TempDir()}
	for i, age := range []time.Duration{time.Hour, keepJournal + time.Hour} {
		rec := record{ID: jobID(i), State: "succeeded"}
		if err := r.save(rec); err != nil {
			t.Fatal(err)
		}
		mt := time.Now().Add(-age)
		os.Chtimes(r.path(rec.ID), mt, mt)
	}
	r.prune(time.Now())
	if _, err := r.load(jobID(0)); err != nil {
		t.Error("recent job pruned")
	}
	if _, err := r.load(jobID(1)); err == nil {
		t.Error("old job kept")
	}
}

// Package runner executes jobs on the agent (docs/agent.md §5): typed
// actions and library scripts, under the host's local policy. Jobs outlive
// the connection that delivered them; their events wait in an outbox until
// a stream sends them. A journal in the state directory makes job IDs
// idempotency keys: a job the agent already ran is answered from the
// journal, never run again, including across restarts and reboots.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
)

const (
	// keepJournal is how long finished jobs are remembered.
	keepJournal = 30 * 24 * time.Hour
	// maxOutput caps the output the agent sends per job; the server keeps
	// a little less.
	maxOutput = 6 << 20
	// maxOutbox caps output waiting for a connection. Results always fit.
	maxOutbox = 16 << 20
)

// Containers manages containers and Compose stacks
// (collect.ContainerCollector). Engines and stacks are named as inventory
// reports them.
type Containers interface {
	Restart(ctx context.Context, engine, name string) error
	// Stack reads a Compose stack and its containers from the engine.
	Stack(ctx context.Context, engine, project string) (collect.Stack, error)
	// ImageID is the ID of the image ref names, "" if the engine has none.
	ImageID(ctx context.Context, engine, ref string) (string, error)
	// Tag points ref at the image with this ID.
	Tag(ctx context.Context, engine, id, ref string) error
	// Engine is how a new stack would be driven on an engine: its socket
	// and Compose CLI, without containers or files.
	Engine(ctx context.Context, engine string) (collect.Stack, error)
}

type Runner struct {
	Dir        string // the job journal, e.g. /var/lib/baseline/jobs
	Env        *collect.Env
	Containers Containers
	Policy     action.Policy
	Log        *jw6_utils.Utils
	// Exec runs a command, streaming its output; nil runs real processes.
	Exec ExecFunc
	// BootID identifies the current boot; nil reads it from Env.
	BootID func() string
	// Reboot reboots the host; nil runs `systemctl reboot`.
	Reboot func(ctx context.Context) error
	// Collect, when set, asks for inventory sections to be collected again
	// for a job that may have changed them.
	Collect func(jobID string, sections []string)
	// TempDir holds scripts while they run; "" is os.TempDir().
	TempDir string
	// ComposeRoot is where compose.deploy puts new stacks.
	ComposeRoot string
	// Kube runs the Kubernetes actions; set on a cluster-mode agent, which
	// runs no other action.
	Kube Kube
	// pollEvery is how often compose.update checks the updated containers;
	// 0 is every 2 seconds.
	pollEvery time.Duration
	// asUser runs a file operation as a rootless stack's user; nil runs
	// the stackfile helper.
	asUser func(ctx context.Context, st collect.Stack, op fileOp) (fileRes, error)

	once   sync.Once
	mu     sync.Mutex
	active map[string]context.CancelFunc
	pkg    chan struct{} // one package-manager job at a time
	stacks chan struct{} // one Compose job at a time
	box    *outbox
}

var reJobID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r *Runner) setup() {
	r.once.Do(func() {
		r.active = map[string]context.CancelFunc{}
		r.pkg = make(chan struct{}, 1)
		r.stacks = make(chan struct{}, 1)
		r.box = newOutbox()
		if r.Exec == nil {
			r.Exec = Run
		}
		if r.BootID == nil {
			r.BootID = func() string { return r.Env.Identity().BootID }
		}
		if r.Reboot == nil {
			r.Reboot = func(ctx context.Context) error {
				_, err := r.Env.Run(ctx, "systemctl", "reboot")
				return err
			}
		}
		if err := os.MkdirAll(r.Dir, 0o700); err != nil {
			r.logf(jw6_utils.Error, "job journal: %v", err)
		}
		r.prune(time.Now())
	})
}

// Ready signals that events are waiting to be sent.
func (r *Runner) Ready() <-chan struct{} {
	r.setup()
	return r.box.ready
}

// Next returns the oldest unsent event, or nil.
func (r *Runner) Next() *agentv1.JobEvent {
	r.setup()
	return r.box.peek()
}

// Sent removes an event once a stream accepted it.
func (r *Runner) Sent(ev *agentv1.JobEvent) { r.box.pop(ev) }

// Start runs a job the server sent, unless it is already running or ran
// before, in which case the journal answers. ctx bounds the job; it should
// outlive the connection.
func (r *Runner) Start(ctx context.Context, rj *agentv1.RunJob) {
	r.setup()
	id := rj.GetJobId()
	if !reJobID.MatchString(id) {
		r.logf(jw6_utils.Warn, "ignored a job with a malformed ID %q", id)
		return
	}
	r.mu.Lock()
	if _, running := r.active[id]; running {
		r.mu.Unlock()
		return
	}
	if rec, err := r.load(id); err == nil {
		r.mu.Unlock()
		r.recover(rec)
		return
	}
	jctx, cancel := context.WithCancel(ctx)
	r.active[id] = cancel
	r.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			r.mu.Lock()
			delete(r.active, id)
			r.mu.Unlock()
		}()
		r.run(jctx, rj)
	}()
}

// Cancel stops a running job (best effort).
func (r *Runner) Cancel(jobID string) {
	r.setup()
	r.mu.Lock()
	cancel := r.active[jobID]
	r.mu.Unlock()
	if cancel != nil {
		r.logf(jw6_utils.Info, "Cancelling job %s", jobID)
		cancel()
	}
}

// Running reports whether any job is running.
func (r *Runner) Running() bool {
	r.setup()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active) > 0
}

// record is a job's journal entry.
type record struct {
	ID       string          `json:"id"`
	Action   string          `json:"action"`
	State    string          `json:"state"` // running | rebooting | a final state
	BootID   string          `json:"boot_id"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished,omitzero"`
	ExitCode int             `json:"exit_code"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    string          `json:"error,omitempty"`
}

const (
	stateRunning   = "running"
	stateRebooting = "rebooting"
	// stateRolledBack is final: compose.update put the previous images back
	// after the update failed.
	stateRolledBack = "rolled_back"
)

func (r *Runner) path(id string) string { return filepath.Join(r.Dir, id+".json") }

func (r *Runner) load(id string) (record, error) {
	var rec record
	b, err := os.ReadFile(r.path(id))
	if err != nil {
		return rec, err
	}
	return rec, json.Unmarshal(b, &rec)
}

func (r *Runner) save(rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := r.path(rec.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path(rec.ID))
}

// prune forgets jobs that finished long ago.
func (r *Runner) prune(now time.Time) {
	ents, err := os.ReadDir(r.Dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > keepJournal {
			os.Remove(filepath.Join(r.Dir, e.Name()))
		}
	}
}

// recover answers for a job the journal already knows and that isn't
// running in this process.
func (r *Runner) recover(rec record) {
	switch rec.State {
	case stateRebooting:
		if boot := r.BootID(); boot != "" && boot != rec.BootID {
			rec.State = "succeeded"
			r.logf(jw6_utils.Info, "Job %s: the host rebooted as asked", rec.ID)
		} else {
			rec.State, rec.Error = "failed", "the host didn't reboot (the agent restarted before it could)"
		}
		r.finish(rec)
	case stateRunning:
		rec.State, rec.Error = "failed", "the agent restarted while the job ran, which stopped it"
		r.finish(rec)
	default:
		r.emitResult(rec)
	}
}

// finish records a final result and reports it.
func (r *Runner) finish(rec record) {
	rec.Finished = time.Now()
	if err := r.save(rec); err != nil {
		r.logf(jw6_utils.Error, "job %s: journal: %v", rec.ID, err)
	}
	r.emitResult(rec)
}

func (r *Runner) emitResult(rec record) {
	r.box.push(&agentv1.JobEvent{JobId: rec.ID, Type: agentv1.JobEvent_RESULT, State: rec.State,
		ExitCode: int32(rec.ExitCode), ResultJson: rec.Result, Error: rec.Error})
}

// outcome is what an action reports.
type outcome struct {
	failed   bool
	exitCode int
	result   any
	err      string
	// state, when set, is the final state of a failed job instead of
	// "failed" (stateRolledBack).
	state string
	// reboot asks for the host to reboot after delay, ending the job when
	// it comes back.
	reboot bool
	delay  time.Duration
}

func failed(format string, args ...any) outcome {
	return outcome{failed: true, exitCode: -1, err: fmt.Sprintf(format, args...)}
}

func (r *Runner) run(ctx context.Context, rj *agentv1.RunJob) {
	id, name := rj.GetJobId(), rj.GetAction()
	rec := record{ID: id, Action: name, State: stateRunning, BootID: r.BootID(), Started: time.Now()}
	if ok, why := r.Policy.Allows(name); !ok {
		r.logf(jw6_utils.Warn, "Refused job %s (%s): %s", id, name, why)
		rec.State, rec.Error, rec.ExitCode = "rejected", why, -1
		r.finish(rec)
		return
	}
	spec, _ := action.Get(name)
	if r.Kube != nil && spec.Category != action.CategoryKubernetes {
		why := "a Kubernetes cluster agent runs only Kubernetes actions"
		r.logf(jw6_utils.Warn, "Refused job %s (%s): %s", id, name, why)
		rec.State, rec.Error, rec.ExitCode = "rejected", why, -1
		r.finish(rec)
		return
	}
	params, err := action.Validate(name, rj.GetParamsJson())
	if err != nil {
		rec.State, rec.Error, rec.ExitCode = "failed", err.Error(), -1
		r.finish(rec)
		return
	}
	if err := r.save(rec); err != nil {
		// Without the journal a resent job could run twice.
		rec.State, rec.Error, rec.ExitCode = "failed", "can't write the job journal: "+err.Error(), -1
		r.emitResult(rec)
		return
	}
	r.logf(jw6_utils.Info, "Running job %s: %s", id, action.Describe(name, params))
	r.box.push(&agentv1.JobEvent{JobId: id, Type: agentv1.JobEvent_STARTED})

	timeout := time.Duration(rj.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = action.Timeout(name, params)
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := newOutput(r, id)
	var o outcome
	switch name {
	case action.PkgUpgrade:
		var p action.UpgradeParams
		json.Unmarshal(params, &p)
		o = r.upgrade(tctx, p, out)
	case action.ServiceRestart, action.ServiceStart, action.ServiceStop:
		var p action.UnitParams
		json.Unmarshal(params, &p)
		o = r.service(tctx, name, p.Unit, out)
	case action.ContainerRestart:
		var p action.ContainerParams
		json.Unmarshal(params, &p)
		o = r.restartContainer(tctx, p, out)
	case action.HostReboot:
		var p action.RebootParams
		json.Unmarshal(params, &p)
		out.info("The host reboots in %d seconds. The job ends when the agent is back.\n", p.DelaySeconds)
		o = outcome{reboot: true, delay: time.Duration(p.DelaySeconds) * time.Second}
	case action.ScriptRun:
		o = r.script(tctx, rj.GetScript(), out)
	case action.ComposePull, action.ComposeUpdate:
		var p action.ComposeParams
		json.Unmarshal(params, &p)
		o = r.compose(tctx, name, p, out)
	case action.ComposeStart:
		var p action.ComposeParams
		json.Unmarshal(params, &p)
		o = r.start(tctx, p, out)
	case action.ComposeArchive:
		var p action.ComposeParams
		json.Unmarshal(params, &p)
		o = r.archive(tctx, p, out)
	case action.ComposeMove:
		var p action.ComposeParams
		json.Unmarshal(params, &p)
		o = r.move(tctx, p, out)
	case action.ComposeDeploy:
		var p action.StackFileParams
		json.Unmarshal(params, &p)
		o = r.deploy(tctx, p, rj.GetStackFiles(), out)
	case action.ComposeEdit:
		var p action.StackFileParams
		json.Unmarshal(params, &p)
		o = r.edit(tctx, p, rj.GetStackFiles(), out)
	case action.K8sRestart, action.K8sScale, action.K8sSetImage, action.K8sDeletePod, action.K8sSuspend,
		action.K8sResume, action.K8sTrigger:
		var p action.K8sParams
		json.Unmarshal(params, &p)
		o = r.kubeWorkload(tctx, name, p, out)
	case action.K8sDeploy, action.K8sEdit:
		var p action.K8sManifestParams
		json.Unmarshal(params, &p)
		o = r.kubeManifest(tctx, name, p, rj.GetStackFiles(), out)
	default:
		o = failed("this agent doesn't know the action %q", name)
	}
	switch {
	case errors.Is(tctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		o.failed, o.err = true, fmt.Sprintf("timed out after %v", timeout)
		rec.State = "timed_out"
	case ctx.Err() != nil:
		o.failed, o.err = true, "cancelled"
		rec.State = "cancelled"
	}
	if o.err != "" {
		out.info("\n%s\n", o.err)
	}
	out.close()

	rec.ExitCode, rec.Error = o.exitCode, o.err
	if o.result != nil {
		rec.Result, _ = json.Marshal(o.result)
	}
	// Even a failed, cancelled or timed-out job may have changed something
	// (a package upgrade stopped half-way).
	if r.Collect != nil {
		r.Collect(id, spec.Sections)
	}
	if rec.State == stateRunning && !o.failed && o.reboot {
		r.rebootAfter(ctx, rec, o.delay)
		return
	}
	if rec.State == stateRunning {
		rec.State = "succeeded"
		if o.failed {
			rec.State = "failed"
			if o.state != "" {
				rec.State = o.state
			}
		}
	}
	r.logf(jw6_utils.Info, "Job %s %s", id, rec.State)
	r.finish(rec)
}

// rebootAfter reports the job as waiting for the reboot, then reboots. The
// next agent finds the journal entry and reports success once the server
// sends the job again.
func (r *Runner) rebootAfter(ctx context.Context, rec record, delay time.Duration) {
	rec.State = stateRebooting
	if err := r.save(rec); err != nil {
		rec.State, rec.Error = "failed", "can't write the job journal: "+err.Error()
		r.finish(rec)
		return
	}
	r.emitResult(rec)
	r.logf(jw6_utils.Info, "Job %s: rebooting in %v", rec.ID, delay)
	select {
	case <-ctx.Done():
		rec.State, rec.Error = "cancelled", "cancelled before the reboot"
		r.finish(rec)
		return
	case <-time.After(delay):
	}
	rctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := r.Reboot(rctx); err != nil {
		rec.State, rec.Error, rec.ExitCode = "failed", "reboot: "+err.Error(), -1
		r.finish(rec)
		return
	}
	// Stay "running" until the host goes down, so a resend is ignored.
	<-ctx.Done()
}

func (r *Runner) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if r.Log != nil {
		r.Log.Log("Agent", "jobs", level, fmt.Sprintf(format, args...))
	}
}

// outbox holds job events until a stream sends them.
type outbox struct {
	mu     sync.Mutex
	events []*agentv1.JobEvent
	bytes  int
	ready  chan struct{}
}

func newOutbox() *outbox { return &outbox{ready: make(chan struct{}, 1)} }

func (o *outbox) push(ev *agentv1.JobEvent) {
	o.mu.Lock()
	if ev.GetType() == agentv1.JobEvent_OUTPUT && o.bytes+len(ev.GetData()) > maxOutbox {
		o.mu.Unlock()
		return // the server reads the result; output is best effort
	}
	o.events = append(o.events, ev)
	o.bytes += len(ev.GetData())
	o.mu.Unlock()
	select {
	case o.ready <- struct{}{}:
	default:
	}
}

func (o *outbox) peek() *agentv1.JobEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.events) == 0 {
		return nil
	}
	return o.events[0]
}

func (o *outbox) pop(ev *agentv1.JobEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.events) > 0 && o.events[0] == ev {
		o.events = o.events[1:]
		o.bytes -= len(ev.GetData())
	}
}

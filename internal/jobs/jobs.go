// Package jobs dispatches the jobs of approved changes to agents and records
// what the agents report back (docs/change-management.md §2): one host at a
// time by default, stopping a change at its first failure, sending
// unfinished jobs again when an agent reconnects, and giving up on jobs
// whose host never answers. It also tells live viewers (SSE) when a job's
// output or state changes.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

// Every is how often the dispatcher looks for work when nothing nudges it.
const Every = 5 * time.Second

// Hub reaches connected agents (internal/gateway).
type Hub interface {
	Online(agentID string) bool
	// Send delivers a message to an agent's stream; false if the agent
	// isn't connected or its stream is stuck.
	Send(agentID string, msg *agentv1.ServerMessage) bool
}

type Dispatcher struct {
	st      *store.Store
	hub     Hub
	log     *jw6_utils.Utils
	changes *change.Manager
	// Secrets opens the .env files of Compose deploys and edits
	// (BASELINE_SECRET_KEY).
	Secrets *oidc.CookieCodec

	nudge chan struct{}

	mu       sync.Mutex
	watchers map[string]map[chan struct{}]struct{} // by job ID
}

func New(st *store.Store, hub Hub, log *jw6_utils.Utils) *Dispatcher {
	d := &Dispatcher{st: st, hub: hub, log: log, changes: change.New(st, log), nudge: make(chan struct{}, 1),
		watchers: map[string]map[chan struct{}]struct{}{}}
	d.changes.Nudge = d.Nudge
	return d
}

// Changes is the change manager the dispatcher starts changes with; its
// Run does the scheduled work (patch groups, Compose auto-updates).
func (d *Dispatcher) Changes() *change.Manager { return d.changes }

// Run dispatches until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		d.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.nudge:
		}
	}
}

// Nudge asks for a dispatch pass now: a change was approved, a job ended,
// an agent connected.
func (d *Dispatcher) Nudge() {
	select {
	case d.nudge <- struct{}{}:
	default:
	}
}

// Pass starts approved changes whose time has come (internal/change),
// gives up on jobs whose host never answered, and sends queued jobs to
// their agents within each change's concurrency, its window, and the
// freezes on their hosts.
func (d *Dispatcher) Pass(ctx context.Context) {
	gate, err := d.changes.Advance(ctx)
	if err != nil {
		d.errorf(ctx, "start changes: %v", err)
		return
	}
	now := time.Now()
	late, err := d.st.ExpireJobs(ctx)
	if err != nil {
		d.errorf(ctx, "expire jobs: %v", err)
	}
	for _, r := range late {
		d.hub.Send(r.AgentID, cancelJob(r.ID))
		d.changed(r.ID)
	}
	queued, err := d.st.QueuedJobs(ctx)
	if err != nil {
		d.errorf(ctx, "queued jobs: %v", err)
		return
	}
	open := map[string]int{}
	for _, q := range queued {
		if _, ok := open[q.ChangeID]; !ok {
			open[q.ChangeID] = q.Open
		}
		// A host that is offline doesn't hold up the others; its job
		// waits (ExpireJobs gives up after an hour).
		if open[q.ChangeID] >= q.Concurrency || !d.hub.Online(q.AgentID) {
			continue
		}
		// Only Emergency changes run under a freeze; nothing starts that
		// wouldn't finish before the window closes.
		if _, frozen := gate.Frozen[q.HostID]; frozen && q.Kind != store.KindEmergency {
			continue
		}
		if !q.WindowEndsAt.IsZero() && now.Add(action.Expected(q.Action, q.Params)).After(q.WindowEndsAt) {
			continue
		}
		msg, err := d.runJob(ctx, q.Job)
		if err != nil {
			d.logf(jw6_utils.Warn, "Can't send job %s to %s: %v", q.ID, q.Hostname, err)
			if _, err := d.st.FinishJob(ctx, store.System, q.HostID, q.ID, store.JobResult{State: store.JobFailed, Error: err.Error()}); err != nil {
				d.errorf(ctx, "fail job %s: %v", q.ID, err)
			}
			d.changed(q.ID)
			continue
		}
		ok, err := d.st.MarkDispatched(ctx, q.Job)
		if err != nil {
			d.errorf(ctx, "dispatch job %s: %v", q.ID, err)
			continue
		}
		if !ok {
			continue
		}
		open[q.ChangeID]++
		// If the stream drops before the agent reads this, the job is sent
		// again when it reconnects.
		if d.hub.Send(q.AgentID, msg) {
			d.logf(jw6_utils.Info, "Sent job %s (%s, %s) to %s", q.ID, q.ChangeRef(), q.Summary(), q.Hostname)
		}
		d.changed(q.ID)
	}
}

// Connected sends an agent the jobs it was given but hasn't finished, as
// far as the server knows: the agent runs new ones, ignores ones it is
// running, and answers for ones it finished. Then it dispatches anything
// that waited for the host.
func (d *Dispatcher) Connected(ctx context.Context, hostID, agentID string) {
	open, err := d.st.OpenJobs(ctx, hostID)
	if err != nil {
		d.errorf(ctx, "open jobs for %s: %v", hostID, err)
		return
	}
	for _, j := range open {
		msg, err := d.runJob(ctx, j)
		if err != nil {
			d.errorf(ctx, "job %s: %v", j.ID, err)
			continue
		}
		d.hub.Send(agentID, msg)
	}
	d.Nudge()
}

// Event records a JobEvent from a host's agent.
func (d *Dispatcher) Event(ctx context.Context, hostID, agentID string, ev *agentv1.JobEvent) {
	id := ev.GetJobId()
	var err error
	notify := false
	switch ev.GetType() {
	case agentv1.JobEvent_STARTED:
		notify, err = d.st.JobStarted(ctx, hostID, id)
	case agentv1.JobEvent_OUTPUT:
		stream := ev.GetStream()
		if stream != "stdout" && stream != "stderr" {
			stream = "info"
		}
		if ev.GetSeq() == 0 {
			return
		}
		notify, err = d.st.AppendJobOutput(ctx, hostID, id, int64(ev.GetSeq()), stream, string(ev.GetData()))
	case agentv1.JobEvent_RESULT:
		r := store.JobResult{State: ev.GetState(), Result: ev.GetResultJson(), Error: ev.GetError()}
		if r.State != store.JobRejected && r.State != store.JobRebooting {
			code := int(ev.GetExitCode())
			r.ExitCode = &code
		}
		var finished bool
		finished, err = d.st.FinishJob(ctx, store.Actor{ID: "agent:" + agentID}, hostID, id, r)
		notify = true
		if finished {
			d.logf(jw6_utils.Info, "Job %s on host %s: %s", id, hostID, r.State)
			d.Nudge()
		}
	}
	if errors.Is(err, store.ErrNotFound) {
		d.logf(jw6_utils.Warn, "Agent %s reported on job %s, which isn't one of its host's jobs", agentID, id)
		return
	}
	if err != nil {
		d.errorf(ctx, "job %s event: %v", id, err)
		return
	}
	if notify {
		d.changed(id)
	}
}

// Cancel asks agents to stop jobs, e.g. after their change was cancelled.
// Their results arrive as usual.
func (d *Dispatcher) Cancel(refs []store.JobRef) {
	for _, r := range refs {
		d.hub.Send(r.AgentID, cancelJob(r.ID))
		d.changed(r.ID)
	}
	d.Nudge()
}

// runJob builds the RunJob message for a job.
func (d *Dispatcher) runJob(ctx context.Context, j store.Job) (*agentv1.ServerMessage, error) {
	rj := &agentv1.RunJob{JobId: j.ID, Action: j.Action, ParamsJson: j.Params, TimeoutSeconds: uint32(j.TimeoutS), ChangeId: j.ChangeID}
	if j.Action == action.ScriptRun {
		var p action.ScriptParams
		if err := json.Unmarshal(j.Params, &p); err != nil {
			return nil, err
		}
		v, err := d.st.GetScriptVersion(ctx, j.ScriptID, j.ScriptVersion)
		if err != nil {
			return nil, fmt.Errorf("script %s v%d: %w", p.Name, j.ScriptVersion, err)
		}
		args, env, err := action.ScriptArgs(v.Params, p.Args)
		if err != nil {
			return nil, err
		}
		env["BASELINE_JOB_ID"] = j.ID
		env["BASELINE_CHANGE"] = j.ChangeRef()
		// The names before the rename to Baseline, for existing scripts and
		// for agents not updated yet, which pass only JCMDB_ variables on.
		env["JCMDB_JOB_ID"] = j.ID
		env["JCMDB_CHANGE"] = j.ChangeRef()
		rj.Script = &agentv1.Script{Interpreter: v.Interpreter, Body: []byte(v.Body), Sha256: v.SHA256, Args: args, Env: env}
	}
	if j.Action == action.ComposeDeploy || j.Action == action.ComposeEdit {
		var p action.StackFileParams
		if err := json.Unmarshal(j.Params, &p); err != nil {
			return nil, err
		}
		rev, err := d.st.ComposeRevision(ctx, p.Revision)
		if err != nil {
			return nil, fmt.Errorf("the stack's files: %w", err)
		}
		files := &agentv1.StackFiles{}
		if rev.HasCompose {
			files.Compose = []byte(rev.Compose)
		}
		if rev.HasEnv {
			if d.Secrets == nil {
				return nil, errors.New("the server has no key to open the stack's .env with")
			}
			enc, err := d.st.RevisionEnv(ctx, p.Revision)
			if err == nil {
				files.Env, err = stackenv.Open(d.Secrets, p.Revision, enc)
			}
			if err != nil {
				return nil, fmt.Errorf("the stack's .env: %w", err)
			}
		}
		rj.StackFiles = files
	}
	return &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_RunJob{RunJob: rj}}, nil
}

func cancelJob(id string) *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_CancelJob{CancelJob: &agentv1.CancelJob{JobId: id}}}
}

// Watching ----------------------------------------------------------------------

// Watch returns a channel that receives a value whenever the job's state or
// output changes, and a function to stop watching. Notifications coalesce:
// the watcher reads the database for what's new.
func (d *Dispatcher) Watch(jobID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	d.mu.Lock()
	if d.watchers[jobID] == nil {
		d.watchers[jobID] = map[chan struct{}]struct{}{}
	}
	d.watchers[jobID][ch] = struct{}{}
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		delete(d.watchers[jobID], ch)
		if len(d.watchers[jobID]) == 0 {
			delete(d.watchers, jobID)
		}
		d.mu.Unlock()
	}
}

func (d *Dispatcher) changed(jobID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for ch := range d.watchers[jobID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (d *Dispatcher) logf(level jw6_utils.LogLevel, format string, args ...any) {
	d.log.Log("Jobs", "dispatch", level, fmt.Sprintf(format, args...))
}

func (d *Dispatcher) errorf(ctx context.Context, format string, args ...any) {
	if ctx.Err() == nil {
		d.logf(jw6_utils.Error, format, args...)
	}
}

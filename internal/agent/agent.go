package agent

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/agent/runner"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
)

// CollectFunc produces one inventory section.
type CollectFunc func(ctx context.Context) (any, error)

// Collectors maps each section to its collector on a real host. SMART
// readings go to sampler (when set) as metrics; containers is shared with
// the container metrics sampler.
func Collectors(env *collect.Env, sampler *collect.Sampler, containers *collect.ContainerCollector) map[string]CollectFunc {
	smart := &collect.SMART{Env: env}
	if containers == nil {
		containers = &collect.ContainerCollector{Env: env}
	}
	return map[string]CollectFunc{
		model.SectionOS:         func(ctx context.Context) (any, error) { return env.OS(ctx) },
		model.SectionHardware:   func(ctx context.Context) (any, error) { return env.Hardware(ctx) },
		model.SectionPackages:   func(ctx context.Context) (any, error) { return env.Packages(ctx) },
		model.SectionUpdates:    func(ctx context.Context) (any, error) { return env.Updates(ctx) },
		model.SectionContainers: func(ctx context.Context) (any, error) { return containers.Collect(ctx) },
		model.SectionServices:   func(ctx context.Context) (any, error) { return env.Services(ctx) },
		model.SectionPorts:      func(ctx context.Context) (any, error) { return env.Ports(ctx) },
		model.SectionReboot:     func(ctx context.Context) (any, error) { return env.Reboot(ctx) },
		model.SectionCerts:      func(ctx context.Context) (any, error) { return env.Certs(ctx, nil) },
		model.SectionVMs:        func(ctx context.Context) (any, error) { return env.VMs(ctx) },
		model.SectionK8sNode:    func(ctx context.Context) (any, error) { return env.K8sNode(ctx) },
		model.SectionSmart: func(ctx context.Context) (any, error) {
			s, samples, err := smart.Collect(ctx)
			if err == nil && sampler != nil {
				sampler.AddSMART(samples)
			}
			return s, err
		},
	}
}

// Defaults until the server's Config arrives (it normally does at once).
var defaultIntervals = map[string]time.Duration{
	model.SectionOS:         time.Hour,
	model.SectionHardware:   24 * time.Hour,
	model.SectionPackages:   15 * time.Minute,
	model.SectionUpdates:    6 * time.Hour,
	model.SectionSmart:      30 * time.Minute,
	model.SectionContainers: time.Minute,
	model.SectionServices:   5 * time.Minute,
	model.SectionPorts:      5 * time.Minute,
	model.SectionReboot:     15 * time.Minute,
	model.SectionCerts:      6 * time.Hour,
	model.SectionVMs:        5 * time.Minute,
	model.SectionK8sNode:    5 * time.Minute,
	model.SectionK8s:        5 * time.Minute,
}

const (
	defaultMetricsEvery = time.Minute
	// Container metrics are cheaper to keep coarser (docs/agent.md §1.2).
	containerMetricsEvery = 90 * time.Second
	// maxBufferedBatches is about six hours of host and container metrics
	// at the default intervals, kept while the server is unreachable.
	maxBufferedBatches = 360 + 240
)

// Host is what Hello says about the machine: who it is and what it has.
// *collect.Env is the real host; a cluster-mode agent describes itself.
type Host interface {
	Identity() collect.Identity
	Capabilities() []string
}

type Agent struct {
	Server     string
	State      *State
	Env        Host
	Collectors map[string]CollectFunc
	Sampler    *collect.Sampler // nil: no metrics
	// ContainerSampler takes container metrics every 90s; nil: none.
	ContainerSampler interface {
		Sample(ctx context.Context, now time.Time) []collect.Sample
	}
	Updater *Updater // nil: self-update disabled
	// Integrations lets the server have this agent poll systems on its
	// network for it, such as a UniFi console (agent.conf integrations).
	Integrations bool
	// Polls answer the server's IntegrationPolls of other kinds, whatever
	// Integrations says: a cluster agent's "k8s.pods" and "k8s.logs".
	Polls map[string]PollFunc
	// ContainerLogs reads container logs for the server (agent.conf
	// container_logs); nil: it doesn't, and doesn't say it can.
	ContainerLogs LogReader
	// Runner runs jobs; nil: the agent reports no policy and the server
	// sends it none.
	Runner  *runner.Runner
	Version string
	Log     *jw6_utils.Utils

	// Backoff bounds for reconnecting; tests shorten them.
	MinBackoff, MaxBackoff time.Duration
	// MetricsEvery overrides the default sampling interval until the server
	// sets one; tests shorten it.
	MetricsEvery time.Duration

	mu      sync.Mutex
	cache   map[string]section // last collected copy of each section
	metrics *metricRing
	every   chan time.Duration // new metrics interval from the server

	confirmOnce sync.Once
	confirmed   chan struct{} // closed once an updated agent reached the server
	installed   atomic.Bool   // a new binary is in place: restart, however the session ended

	runCtx    context.Context // jobs run under it, across sessions
	recollect chan collectRequest
}

// collectRequest asks for sections to be collected again after a job, and
// sent tagged with it.
type collectRequest struct {
	jobID    string
	sections []string
}

// errReconnect ends a session on purpose, e.g. to use a renewed cert.
var errReconnect = errors.New("reconnecting")

// Run keeps a session open until ctx ends, reconnecting with exponential
// backoff and jitter. It returns ErrRestart after installing an update and
// ErrProbation when an updated agent couldn't reach the server in time.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.cache = map[string]section{}
	a.metrics = newMetricRing(maxBufferedBatches)
	a.every = make(chan time.Duration, 1)
	a.confirmed = make(chan struct{})
	a.runCtx = ctx
	a.recollect = make(chan collectRequest, 64)
	if a.Runner != nil {
		a.Runner.Collect = func(jobID string, sections []string) {
			select {
			case a.recollect <- collectRequest{jobID, sections}:
			default:
			}
		}
	}

	var expired atomic.Bool
	if a.Updater != nil {
		if from, ok := a.Updater.Probation(a.Version); ok {
			a.logf(jw6_utils.Info, "Updated from %s; this version must reach the server within %v or it is rolled back", from, ProbationTime)
			go func() {
				select {
				case <-a.confirmed:
				case <-ctx.Done():
				case <-time.After(ProbationTime):
					expired.Store(true)
					cancel()
				}
			}()
		} else {
			a.confirmOnce.Do(func() { close(a.confirmed) })
		}
	}
	if a.Sampler != nil {
		go a.sampleLoop(ctx)
	}
	if a.ContainerSampler != nil {
		go a.containerSampleLoop(ctx)
	}

	minB, maxB := a.MinBackoff, a.MaxBackoff
	if minB == 0 {
		minB, maxB = time.Second, time.Minute
	}
	backoff := minB
	for {
		start := time.Now()
		err := a.session(ctx)
		if a.installed.Load() {
			return ErrRestart
		}
		if ctx.Err() != nil {
			if expired.Load() {
				return ErrProbation
			}
			return nil
		}
		if time.Since(start) > time.Minute || errors.Is(err, errReconnect) {
			backoff = minB
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		switch code := status.Code(err); {
		case errors.Is(err, errReconnect):
			wait = 0
		case code == codes.PermissionDenied || code == codes.Unauthenticated:
			// Only an admin can fix this (re-enroll); don't hammer the server.
			a.logf(jw6_utils.Error, "server rejected this agent: %v (retrying in 5m)", status.Convert(err).Message())
			wait = 5 * time.Minute
		default:
			a.logf(jw6_utils.Warn, "connection lost: %v (retrying in %v)", err, wait.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			if expired.Load() {
				return ErrProbation
			}
			return nil
		case <-time.After(wait):
		}
		backoff = min(backoff*2, maxB)
	}
}

// updateRefused says why this agent won't update itself, or "" if it will.
func (a *Agent) updateRefused() string {
	switch {
	case a.Updater == nil:
		return "self-update is unavailable on this agent (see its log)"
	case a.Updater.Off:
		return ErrSelfUpdateOff.Error()
	}
	return ""
}

// confirm ends an updated agent's probation once the server has answered.
func (a *Agent) confirm() {
	a.confirmOnce.Do(func() {
		close(a.confirmed)
		if a.Updater != nil {
			a.Updater.Confirm()
			a.logf(jw6_utils.Info, "Update to %s confirmed", a.Version)
		}
	})
}

type section struct {
	payload []byte
	hash    string
}

type collected struct {
	name  string
	s     section
	err   error
	force bool
	jobID string // collected again after this job
}

func (a *Agent) session(ctx context.Context) error {
	tlsCfg, err := a.State.TLS(a.Server)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(a.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 15 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(32<<20)),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := agentv1.NewAgentGatewayClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}

	// Hello carries the hashes of what was collected before; the server
	// asks for anything it doesn't have, which after a restart is all of it.
	hashes := a.hashes()
	id := a.Env.Identity()
	hello := &agentv1.Hello{
		AgentVersion:  a.Version,
		Identity:      &agentv1.HostIdentity{MachineId: id.MachineID, DmiUuid: id.DMIUUID, Hostname: id.Hostname},
		BootId:        id.BootID,
		BootTimeUnix:  id.BootTime.Unix(),
		Capabilities:  a.capabilities(),
		SectionHashes: hashes,
		Arch:          runtime.GOARCH,
	}
	if a.Runner != nil {
		p := a.Runner.Policy
		hello.Policy = &agentv1.Policy{AllowScripts: p.AllowScripts, RestrictActions: p.AllowActions != nil, AllowedActions: p.AllowActions,
			SelfUpdateOff: p.SelfUpdateOff}
	}
	if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: hello}}); err != nil {
		return err
	}
	if a.Updater != nil {
		if v, msg, ok := a.Updater.Failure(); ok {
			a.logf(jw6_utils.Warn, "Update to %s failed: %s", v, msg)
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_UpdateResult{
				UpdateResult: &agentv1.UpdateResult{Version: v, Error: msg}}}); err != nil {
				return err
			}
			a.Updater.ClearFailure()
		}
	}

	msgs := make(chan *agentv1.ServerMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collection runs on its own goroutine: an update check refreshes
	// repository metadata and can take minutes, which mustn't hold up
	// heartbeats, metrics or the server's requests.
	work := newQueue()
	results := make(chan collected)
	go a.collectLoop(ctx, work, results)

	sent := map[string]string{} // hash of what the server has, per section
	for name, h := range hashes {
		sent[name] = h // assume current until the server asks
	}
	send := func(r collected) error {
		// Updates are always sent, so the server knows when they were
		// last checked even when nothing changed.
		if !r.force && r.name != model.SectionUpdates && sent[r.name] == r.s.hash {
			return nil
		}
		if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Inventory{Inventory: &agentv1.InventorySection{
			Section: r.name, SchemaVersion: model.SchemaVersion, ContentHash: r.s.hash, PayloadJson: r.s.payload, JobId: r.jobID,
		}}}); err != nil {
			return err
		}
		sent[r.name] = r.s.hash
		return nil
	}

	intervals := map[string]time.Duration{}
	for k, v := range defaultIntervals {
		intervals[k] = v
	}
	timers := map[string]*time.Timer{}
	schedule := func(name string) {
		if t := timers[name]; t != nil {
			t.Stop()
		}
		timers[name] = time.AfterFunc(intervals[name], func() { work.add(name, false, "") })
	}
	for _, name := range model.Sections {
		if _, ok := a.Collectors[name]; ok {
			schedule(name)
		}
	}
	defer func() {
		for _, t := range timers {
			t.Stop()
		}
	}()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	renewCheck := time.NewTicker(time.Hour)
	defer renewCheck.Stop()
	var pendingKey *ecdsa.PrivateKey
	requestRenewal := func() error {
		if pendingKey != nil || !a.State.RenewDue(time.Now()) {
			return nil
		}
		key, csr, err := pki.GenerateKey()
		if err != nil {
			return err
		}
		pendingKey = key
		a.logf(jw6_utils.Info, "Client certificate expires %s; requesting a new one", a.State.Cert.NotAfter.Format(time.DateOnly))
		return stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_CertRenew{CertRenew: &agentv1.CertRenewRequest{CsrDer: csr}}})
	}
	if err := requestRenewal(); err != nil {
		return err
	}
	flushMetrics := func() error {
		for b := a.metrics.peek(); b != nil; b = a.metrics.peek() {
			b.SentUnix = time.Now().Unix()
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Metrics{Metrics: b}}); err != nil {
				return err
			}
			a.metrics.pop(b)
		}
		return nil
	}
	if err := flushMetrics(); err != nil {
		return err
	}
	// Job events wait for a connection; results are never dropped.
	var jobEvents <-chan struct{}
	flushJobs := func() error {
		if a.Runner == nil {
			return nil
		}
		for ev := a.Runner.Next(); ev != nil; ev = a.Runner.Next() {
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_JobEvent{JobEvent: ev}}); err != nil {
				return err
			}
			a.Runner.Sent(ev)
		}
		return nil
	}
	if a.Runner != nil {
		jobEvents = a.Runner.Ready()
	}
	if err := flushJobs(); err != nil {
		return err
	}
	a.logf(jw6_utils.Info, "Connected to %s", a.Server)

	// High security hosts re-collect hardware as soon as the kernel reports
	// a device or link coming or going.
	var stopWatching context.CancelFunc
	defer func() {
		if stopWatching != nil {
			stopWatching()
		}
	}()

	// Integration polls run beside everything else; their results come
	// back here to be sent.
	polled := make(chan *agentv1.IntegrationResult, 4)
	// Container logs the server asked for are read beside everything
	// else too, and end with the session.
	logChunks := make(chan *agentv1.LogChunk, 16)
	var logs logStreams

	var updating bool
	updateDone := make(chan error, 1)
	var updateVersion string
	// An update that arrives while a job runs waits for it: restarting
	// would stop the job.
	var deferred *agentv1.UpdateAgent
	startUpdate := func(u *agentv1.UpdateAgent) {
		updating, updateVersion = true, u.GetVersion()
		a.logf(jw6_utils.Info, "Server asked for an update from %s to %s", a.Version, u.GetVersion())
		go func() {
			err := a.Updater.Install(ctx, client, u, a.Version)
			if err == nil {
				a.installed.Store(true)
			}
			updateDone <- err
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return err
		case r := <-results:
			switch {
			case errors.Is(r.err, collect.ErrAbsent):
				a.logf(jw6_utils.Debug, "collect %s: %v", r.name, r.err)
			case r.err != nil:
				a.logf(jw6_utils.Warn, "collect %s: %v", r.name, r.err)
			default:
				if err := send(r); err != nil {
					return err
				}
			}
			schedule(r.name)
		case <-a.metrics.ready:
			if err := flushMetrics(); err != nil {
				return err
			}
		case <-jobEvents:
			if err := flushJobs(); err != nil {
				return err
			}
		case req := <-a.recollect:
			for _, name := range req.sections {
				if _, ok := a.Collectors[name]; ok {
					work.add(name, false, req.jobID)
				}
			}
		case c := <-logChunks:
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_LogChunk{LogChunk: c}}); err != nil {
				return err
			}
		case res := <-polled:
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_IntegrationResult{IntegrationResult: res}}); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{}}}); err != nil {
				return err
			}
			if deferred != nil && !updating && !a.Runner.Running() {
				u := deferred
				deferred = nil
				startUpdate(u)
			}
		case <-renewCheck.C:
			if err := requestRenewal(); err != nil {
				return err
			}
		case err := <-updateDone:
			updating = false
			if err == nil {
				a.logf(jw6_utils.Info, "Installed baseline-agent %s; restarting into it", updateVersion)
				return ErrRestart
			}
			a.logf(jw6_utils.Error, "Update to %s failed: %v", updateVersion, err)
			if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_UpdateResult{
				UpdateResult: &agentv1.UpdateResult{Version: updateVersion, Error: err.Error()}}}); err != nil {
				return err
			}
		case m := <-msgs:
			a.confirm()
			switch msg := m.GetMsg().(type) {
			case *agentv1.ServerMessage_Config:
				for name, secs := range msg.Config.GetIntervalSeconds() {
					if _, known := intervals[name]; known && secs >= 60 {
						if d := time.Duration(secs) * time.Second; d != intervals[name] {
							intervals[name] = d
							schedule(name)
						}
					}
				}
				// A cluster-mode agent has no hardware to watch.
				if hs, ok := a.Env.(highSecurityHost); ok {
					_, collects := a.Collectors[model.SectionHardware]
					on := msg.Config.GetHighSecurity() && collects
					if hs.SetHighSecurity(on) {
						work.add(model.SectionHardware, false, "")
					}
					switch {
					case on && stopWatching == nil:
						stopWatching = a.watchDevices(ctx, hs, func() { work.add(model.SectionHardware, false, "") })
					case !on && stopWatching != nil:
						stopWatching()
						stopWatching = nil
					}
				}
				// Stacks under the Compose roots that aren't running are
				// listed with the containers.
				if cr, ok := a.ContainerSampler.(composeRooted); ok && cr.SetComposeRoots(msg.Config.GetComposeRoots()) {
					work.add(model.SectionContainers, false, "")
				}
				if hb := msg.Config.GetHeartbeatSeconds(); hb >= 5 {
					heartbeat.Reset(time.Duration(hb) * time.Second)
				}
				if s := msg.Config.GetMetricsSeconds(); s >= 10 {
					select {
					case a.every <- time.Duration(s) * time.Second:
					default:
					}
				}
			case *agentv1.ServerMessage_RequestInventory:
				names := msg.RequestInventory.GetSections()
				if len(names) == 0 {
					names = model.Sections
				}
				for _, name := range names {
					if _, ok := a.Collectors[name]; ok {
						work.add(name, true, "")
					}
				}
			case *agentv1.ServerMessage_RunJob:
				if a.Runner == nil {
					continue // the server sends no jobs to an agent without a policy
				}
				a.Runner.Start(a.runCtx, msg.RunJob)
			case *agentv1.ServerMessage_IntegrationPoll:
				go func(p *agentv1.IntegrationPoll) {
					res := a.pollIntegration(ctx, p)
					select {
					case polled <- res:
					case <-ctx.Done():
					}
				}(msg.IntegrationPoll)
			case *agentv1.ServerMessage_StartLogs:
				a.startLogs(ctx, &logs, msg.StartLogs, logChunks)
			case *agentv1.ServerMessage_StopLogs:
				logs.stop(msg.StopLogs.GetRequestId())
			case *agentv1.ServerMessage_CancelJob:
				if a.Runner != nil {
					a.Runner.Cancel(msg.CancelJob.GetJobId())
				}
			case *agentv1.ServerMessage_CertRenew:
				key := pendingKey
				pendingKey = nil
				if e := msg.CertRenew.GetError(); e != "" || key == nil {
					a.logf(jw6_utils.Error, "certificate renewal failed: %s", e)
					continue
				}
				if err := a.State.SaveCert(key, msg.CertRenew.GetClientCertDer()); err != nil {
					a.logf(jw6_utils.Error, "saving renewed certificate: %v", err)
					continue
				}
				a.logf(jw6_utils.Info, "Certificate renewed until %s; reconnecting with it", a.State.Cert.NotAfter.Format(time.DateOnly))
				return errReconnect
			case *agentv1.ServerMessage_UpdateAgent:
				u := msg.UpdateAgent
				if updating || u.GetVersion() == a.Version {
					continue
				}
				if reason := a.updateRefused(); reason != "" {
					a.logf(jw6_utils.Warn, "Refused an update to %s: %s", u.GetVersion(), reason)
					if err := stream.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_UpdateResult{UpdateResult: &agentv1.UpdateResult{
						Version: u.GetVersion(), Error: reason}}}); err != nil {
						return err
					}
					continue
				}
				if a.Runner != nil && a.Runner.Running() {
					a.logf(jw6_utils.Info, "Update to %s waits for the running job to finish", u.GetVersion())
					deferred = u
					continue
				}
				startUpdate(u)
			}
		}
	}
}

// collectLoop runs queued collections one at a time until ctx ends.
func (a *Agent) collectLoop(ctx context.Context, q *queue, out chan<- collected) {
	for {
		name, force, jobID, ok := q.next(ctx)
		if !ok {
			return
		}
		s, err := a.collect(ctx, name)
		select {
		case out <- collected{name: name, s: s, err: err, force: force, jobID: jobID}:
		case <-ctx.Done():
			return
		}
	}
}

// composeRooted is a container collector the server can tell its
// Compose roots.
type composeRooted interface {
	SetComposeRoots(roots []string) bool
}

// highSecurityHost is a Host the server can mark high security: it then
// collects more hardware and reports devices as they come and go
// (*collect.Env).
type highSecurityHost interface {
	SetHighSecurity(on bool) bool
	WatchDevices(ctx context.Context, changed func()) error
}

// Device events come in bursts (a USB stick is a device, an interface, a
// SCSI host, a disk and its partitions): hardware is collected once they
// pause, or deviceSettleMax after the first.
const (
	deviceSettle    = 500 * time.Millisecond
	deviceSettleMax = 3 * time.Second
)

// watchDevices calls recollect after each burst of device events until the
// returned func is called or ctx ends.
func (a *Agent) watchDevices(ctx context.Context, h highSecurityHost, recollect func()) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	s := &settler{quiet: deviceSettle, max: deviceSettleMax, fire: recollect}
	go func() {
		err := h.WatchDevices(ctx, s.poke)
		if err != nil && !errors.Is(err, collect.ErrAbsent) && ctx.Err() == nil {
			a.logf(jw6_utils.Warn, "Can't watch for devices, so hardware is only polled: %v", err)
		}
	}()
	return func() {
		cancel()
		s.stop()
	}
}

// settler calls fire once pokes pause for quiet, or max after the first
// poke of a burst.
type settler struct {
	quiet, max time.Duration
	fire       func()

	mu    sync.Mutex
	timer *time.Timer
	first time.Time
	gen   int
}

func (s *settler) poke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.timer == nil {
		s.first = now
	} else {
		s.timer.Stop()
	}
	wait := min(s.quiet, max(s.max-now.Sub(s.first), 0))
	s.gen++
	gen := s.gen
	s.timer = time.AfterFunc(wait, func() {
		s.mu.Lock()
		current := gen == s.gen
		if current {
			s.timer = nil
		}
		s.mu.Unlock()
		if current {
			s.fire()
		}
	})
}

func (s *settler) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.gen++
}

func (a *Agent) collect(ctx context.Context, name string) (section, error) {
	fn, ok := a.Collectors[name]
	if !ok {
		return section{}, fmt.Errorf("no collector for %s", name)
	}
	v, err := fn(ctx)
	if err != nil {
		return section{}, err
	}
	payload, hash, err := model.Encode(v)
	if err != nil {
		return section{}, err
	}
	s := section{payload, hash}
	a.mu.Lock()
	a.cache[name] = s
	a.mu.Unlock()
	return s, nil
}

func (a *Agent) hashes() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := map[string]string{}
	for name, s := range a.cache {
		h[name] = s.hash
	}
	return h
}

// sampleLoop takes metrics on a ticker whether or not the server is
// reachable; the ring holds them until a session sends them.
func (a *Agent) sampleLoop(ctx context.Context) {
	every := a.MetricsEvery
	if every == 0 {
		every = defaultMetricsEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	a.sample(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.sample(now)
		case d := <-a.every:
			if d != every {
				every = d
				t.Reset(d)
			}
		}
	}
}

// containerSampleLoop takes container metrics every 90s, into the same
// buffer as host metrics.
func (a *Agent) containerSampleLoop(ctx context.Context) {
	t := time.NewTicker(containerMetricsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.push(now, a.ContainerSampler.Sample(ctx, now))
		}
	}
}

func (a *Agent) sample(now time.Time) { a.push(now, a.Sampler.Sample(now)) }

func (a *Agent) push(now time.Time, samples []collect.Sample) {
	if len(samples) == 0 {
		return
	}
	b := &agentv1.MetricBatch{TsUnix: now.Unix(), Metrics: make([]*agentv1.Metric, len(samples))}
	for i, s := range samples {
		b.Metrics[i] = &agentv1.Metric{Kind: s.Kind, Name: s.Name, Instance: s.Instance, Value: s.Value}
	}
	a.metrics.push(b)
}

func (a *Agent) logf(level jw6_utils.LogLevel, format string, args ...any) {
	a.Log.Log("Agent", "run", level, fmt.Sprintf(format, args...))
}

// queue is the collector's work list: each section at most once, with a
// forced send if any request for it was forced, and tagged with the job
// that asked for it, if one did.
type queue struct {
	mu    sync.Mutex
	order []string
	items map[string]queued
	wake  chan struct{}
}

type queued struct {
	force bool
	jobID string
}

func newQueue() *queue { return &queue{items: map[string]queued{}, wake: make(chan struct{}, 1)} }

func (q *queue) add(name string, force bool, jobID string) {
	q.mu.Lock()
	if it, ok := q.items[name]; ok {
		it.force = it.force || force
		if jobID != "" {
			it.jobID = jobID
		}
		q.items[name] = it
	} else {
		q.order = append(q.order, name)
		q.items[name] = queued{force, jobID}
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue) next(ctx context.Context) (string, bool, string, bool) {
	for {
		q.mu.Lock()
		if len(q.order) > 0 {
			name := q.order[0]
			q.order = q.order[1:]
			it := q.items[name]
			delete(q.items, name)
			q.mu.Unlock()
			return name, it.force, it.jobID, true
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", false, "", false
		case <-q.wake:
		}
	}
}

// metricRing buffers metric batches, dropping the oldest when full.
type metricRing struct {
	mu      sync.Mutex
	batches []*agentv1.MetricBatch
	max     int
	ready   chan struct{}
}

func newMetricRing(max int) *metricRing {
	return &metricRing{max: max, ready: make(chan struct{}, 1)}
}

func (r *metricRing) push(b *agentv1.MetricBatch) {
	r.mu.Lock()
	if len(r.batches) >= r.max {
		r.batches = r.batches[1:]
	}
	r.batches = append(r.batches, b)
	r.mu.Unlock()
	select {
	case r.ready <- struct{}{}:
	default:
	}
}

func (r *metricRing) peek() *agentv1.MetricBatch {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.batches) == 0 {
		return nil
	}
	return r.batches[0]
}

// pop removes b once it was sent, unless the ring already dropped it.
func (r *metricRing) pop(b *agentv1.MetricBatch) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.batches) > 0 && r.batches[0] == b {
		r.batches = r.batches[1:]
	}
}

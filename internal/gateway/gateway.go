// Package gateway is the agent-facing gRPC service (docs/architecture.md §3):
// enrollment, the long-lived Connect stream, and a hub that lets the rest of
// the server reach connected agents.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/release"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	helloTimeout     = 30 * time.Second
	heartbeatSeconds = 30
	metricsSeconds   = 60
	seenEvery        = 15 * time.Second
	maxMessageBytes  = 32 << 20
	releaseChunk     = 256 << 10
	maxMetrics       = 5000 // per batch
)

// DefaultIntervals is how often agents collect each section, in seconds
// (docs/agent.md §1).
var DefaultIntervals = map[string]uint32{
	model.SectionOS:         3600,
	model.SectionHardware:   24 * 3600,
	model.SectionPackages:   15 * 60,
	model.SectionUpdates:    6 * 3600,
	model.SectionSmart:      30 * 60,
	model.SectionContainers: 60,
	model.SectionServices:   5 * 60,
	model.SectionPorts:      5 * 60,
	model.SectionReboot:     15 * 60,
	model.SectionCerts:      6 * 3600,
	model.SectionVMs:        5 * 60,
	model.SectionK8sNode:    5 * 60,
	model.SectionK8s:        5 * 60,
}

// highSecurityHardware is how often high security hosts poll hardware, in
// seconds: a backstop for the kernel events their agents watch.
const highSecurityHardware = 5 * 60

// agentConfig is what an agent is told to collect. High security hosts
// collect hardware more often, peripherals and link state included, and
// again whenever a device or link comes or goes. Compose roots are where
// it looks for stacks that aren't running.
func agentConfig(set store.AgentSettings) *agentv1.Config {
	intervals := DefaultIntervals
	if set.HighSecurity {
		intervals = maps.Clone(DefaultIntervals)
		intervals[model.SectionHardware] = highSecurityHardware
	}
	return &agentv1.Config{IntervalSeconds: intervals, HeartbeatSeconds: heartbeatSeconds, MetricsSeconds: metricsSeconds,
		HighSecurity: set.HighSecurity, ComposeRoots: set.ComposeRoots}
}

// metricKinds are the kinds of metric the server accepts.
var metricKinds = map[string]bool{"cpu": true, "load": true, "mem": true, "disk": true, "fs": true, "net": true, "smart": true,
	"container": true}

type Gateway struct {
	agentv1.UnimplementedAgentGatewayServer

	st  *store.Store
	ca  *pki.Authority
	log *jw6_utils.Utils

	mu       sync.Mutex
	sessions map[string]*session     // by agent ID
	polls    map[string]*pendingPoll // integration polls awaiting results, by request ID
	logs     map[string]*logStream   // container logs being read, by request ID

	// Checker, when set, is nudged when a host's containers change, so new
	// images are checked on their registry within seconds.
	Checker interface{ Trigger() }
	// Vulns, when set, learns when a host's OS, packages or updates changed,
	// so they are matched against vulnerability data again.
	Vulns interface{ HostChanged(hostID string) }
	// Jobs, when set, receives job events and learns when agents connect,
	// to send them their unfinished jobs (internal/jobs).
	Jobs JobSink
}

// JobSink is the part of internal/jobs the gateway feeds.
type JobSink interface {
	Connected(ctx context.Context, hostID, agentID string)
	Event(ctx context.Context, hostID, agentID string, ev *agentv1.JobEvent)
}

type session struct {
	hostID    string
	agentID   string
	serial    string // the cert this stream authenticated with
	renewed   bool   // one renewal per stream; the agent reconnects after it
	bootID    string
	machineID string
	arch      string   // GOARCH; empty for agents too old to update themselves
	cluster   bool     // a cluster-mode agent (model.CapK8sCluster)
	noUpdate  bool     // agent.conf has self_update = off
	caps      []string // capabilities from Hello
	send      chan *agentv1.ServerMessage
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{} // closed once the stream has recorded its disconnect
}

// errIdentityInUse rejects a second machine presenting a cert that a live
// stream already uses, typically a clone of an enrolled VM. Letting it
// replace the first would make the two knock each other off forever.
var errIdentityInUse = status.Error(codes.FailedPrecondition,
	"another machine is connected with this agent's identity (a cloned VM?); re-enroll this one with --force")

func New(st *store.Store, ca *pki.Authority, log *jw6_utils.Utils) *Gateway {
	return &Gateway{st: st, ca: ca, log: log, sessions: map[string]*session{}, polls: map[string]*pendingPoll{}, logs: map[string]*logStream{}}
}

// TLSConfig accepts agents with or without a client cert: Enroll has none
// yet, and Connect checks for one itself.
func (g *Gateway) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{g.ca.ServerCert()},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    g.ca.ClientCAs(),
		MinVersion:   tls.VersionTLS13,
	}
}

// NewServer returns a gRPC server with the gateway registered.
func (g *Gateway) NewServer() *grpc.Server {
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(g.TLSConfig())),
		grpc.MaxRecvMsgSize(maxMessageBytes),
		// Pings find dead streams fast, which matters after a reboot: the
		// host's new stream is refused while its old one looks alive.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 15 * time.Second, PermitWithoutStream: true}),
	)
	agentv1.RegisterAgentGatewayServer(srv, g)
	// Agents from before the rename to Baseline call the service by its old
	// name until they update.
	legacy := agentv1.AgentGateway_ServiceDesc
	legacy.ServiceName = LegacyServiceName
	srv.RegisterService(&legacy, g)
	return srv
}

// LegacyServiceName is the gateway service's name before the rename to
// Baseline, which agents not updated yet still dial.
const LegacyServiceName = "jcmdb.agent.v1.AgentGateway"

// Serve listens on addr until ctx ends.
func (g *Gateway) Serve(ctx context.Context, addr string) error {
	if err := g.st.ResetConnections(ctx); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := g.NewServer()
	go func() {
		<-ctx.Done()
		g.mu.Lock()
		for _, s := range g.sessions {
			s.cancel()
		}
		g.mu.Unlock()
		stopped := make(chan struct{})
		go func() { srv.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			srv.Stop()
		}
	}()
	g.logf(jw6_utils.Info, "Agent gateway on %s", addr)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// Enroll exchanges an enrollment token and a CSR for a client cert.
func (g *Gateway) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	ip := peerIP(ctx)
	secret, _, err := pki.ParseToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id := req.GetIdentity()
	var cert *x509.Certificate
	res, err := g.st.Enroll(ctx, store.EnrollRequest{
		SecretHash:   pki.HashTokenSecret(secret),
		MachineID:    id.GetMachineId(),
		DMIUUID:      id.GetDmiUuid(),
		Hostname:     id.GetHostname(),
		AgentVersion: req.GetAgentVersion(),
		IP:           ip,
	}, func(agentID string) (string, time.Time, error) {
		c, err := g.ca.IssueClient(req.GetCsrDer(), agentID)
		if err != nil {
			return "", time.Time{}, err
		}
		cert = c
		return pki.SerialHex(c), c.NotAfter, nil
	})
	if errors.Is(err, store.ErrTokenInvalid) {
		g.st.Audit(ctx, store.Actor{ID: "anonymous", IP: ip}, store.AuditEvent{
			Action: "host.enroll_failed", ObjectType: "host",
			Details: map[string]any{"hostname": id.GetHostname(), "machine_id": id.GetMachineId(), "reason": err.Error()},
		})
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if err != nil {
		// Details stay in the server log: the caller isn't authenticated.
		g.logf(jw6_utils.Error, "enroll %s: %v", id.GetHostname(), err)
		return nil, status.Error(codes.InvalidArgument, "enrollment failed; see the server log")
	}
	g.logf(jw6_utils.Info, "Enrolled host %s (%s) from %s", id.GetHostname(), res.HostID, ip)
	return &agentv1.EnrollResponse{
		AgentId:          res.AgentID,
		ClientCertDer:    cert.Raw,
		CaCertDer:        g.ca.CACert().Raw,
		ReleasePublicKey: g.ca.ReleasePublicKey(),
	}, nil
}

// authenticate checks the client cert of an mTLS call against the database.
func (g *Gateway) authenticate(ctx context.Context) (store.AgentHost, string, error) {
	agentID, serial, err := clientIdentity(ctx)
	if err != nil {
		return store.AgentHost{}, "", status.Error(codes.Unauthenticated, err.Error())
	}
	host, err := g.st.AuthenticateAgent(ctx, agentID, serial)
	switch {
	case errors.Is(err, store.ErrRevoked):
		return host, "", status.Error(codes.PermissionDenied, "this host has been revoked; re-enroll it with a new token")
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrUnknownCert):
		return host, "", status.Error(codes.Unauthenticated, "unknown agent or certificate; re-enroll it")
	case err != nil:
		return host, "", status.Error(codes.Unavailable, "server error")
	}
	return host, serial, nil
}

// Connect is an agent's long-lived stream.
func (g *Gateway) Connect(stream agentv1.AgentGateway_ConnectServer) error {
	ctx := stream.Context()
	host, serial, err := g.authenticate(ctx)
	if err != nil {
		return err
	}
	agentID := host.AgentID

	first, err := recvWithTimeout(stream, helloTimeout)
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "the first message must be Hello")
	}

	id := hello.GetIdentity()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := &session{hostID: host.HostID, agentID: agentID, serial: serial, bootID: hello.GetBootId(), machineID: id.GetMachineId(),
		arch: hello.GetArch(), cluster: slices.Contains(hello.GetCapabilities(), model.CapK8sCluster),
		noUpdate: hello.GetPolicy().GetSelfUpdateOff(), caps: hello.GetCapabilities(),
		send: make(chan *agentv1.ServerMessage, 16), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	old, ok := g.register(sess)
	if !ok {
		g.logf(jw6_utils.Warn, "Refused a second machine using agent %s (%s): boot ID %s, machine-id %s",
			agentID, host.Hostname, hello.GetBootId(), id.GetMachineId())
		if err := g.st.FlagIdentityConflict(ctx, host.HostID, agentID, peerIP(ctx), hello.GetBootId(), id.GetMachineId(), id.GetHostname()); err != nil {
			g.logf(jw6_utils.Error, "flag identity conflict: %v", err)
		}
		return errIdentityInUse
	}
	defer close(sess.done)
	defer g.unregister(sess)
	// A stream this one replaced may be recording its disconnect right now.
	// Let it finish first, or it would mark the host offline after this
	// stream marked it online.
	if old != nil {
		select {
		case <-old.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	var bootTime time.Time
	if hello.GetBootTimeUnix() > 0 {
		bootTime = time.Unix(hello.GetBootTimeUnix(), 0)
	}
	stored, err := g.st.AgentConnected(ctx, host.HostID, agentID, store.Hello{
		AgentVersion: hello.GetAgentVersion(), MachineID: id.GetMachineId(), DMIUUID: id.GetDmiUuid(),
		Hostname: id.GetHostname(), BootID: hello.GetBootId(), BootTime: bootTime,
		Capabilities: hello.GetCapabilities(), Arch: hello.GetArch(), IP: peerIP(ctx), Policy: policy(hello.GetPolicy()),
	})
	if errors.Is(err, store.ErrRevoked) {
		return status.Error(codes.PermissionDenied, "this host has been revoked; re-enroll it with a new token")
	}
	if err != nil {
		g.logf(jw6_utils.Error, "agent %s connect: %v", agentID, err)
		return status.Error(codes.Unavailable, "server error")
	}
	defer func() {
		// The stream context is gone; use a fresh one to record the disconnect.
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		if g.current(sess) {
			g.st.AgentDisconnected(dctx, host.HostID)
		}
	}()
	g.logf(jw6_utils.Info, "Agent connected: %s (%s, agent %s)", id.GetHostname(), host.HostID, hello.GetAgentVersion())

	// Sender: gRPC streams aren't safe for concurrent Send.
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				sendErr <- nil
				return
			case m := <-sess.send:
				if err := stream.Send(m); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	// The buffer is empty here, so these never block.
	sess.send <- &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_Config{Config: agentConfig(stored.Settings)}}
	if stale := staleSections(hello.GetSectionHashes(), stored.Hashes); len(stale) > 0 {
		sess.send <- requestInventory(stale)
	}
	if stored.UpdateTarget != "" {
		g.sendUpdate(sess, stored.UpdateTarget)
	}
	if g.Jobs != nil && hello.GetPolicy() != nil {
		go g.Jobs.Connected(ctx, host.HostID, agentID)
	}

	recvErr := make(chan error, 1)
	go func() {
		lastSeen := time.Now()
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if time.Since(lastSeen) > seenEvery {
				lastSeen = time.Now()
				g.st.AgentSeen(ctx, host.HostID)
			}
			if err := g.handle(ctx, sess, msg); err != nil {
				recvErr <- err
				return
			}
		}
	}()

	select {
	case err := <-recvErr:
		if status.Code(err) == codes.Canceled || errors.Is(err, context.Canceled) {
			err = nil
		}
		g.logf(jw6_utils.Info, "Agent disconnected: %s (%v)", id.GetHostname(), errOrEOF(err))
		return nil
	case err := <-sendErr:
		return err
	case <-ctx.Done():
		// The connection dropped, or the server ended the stream: a newer
		// stream from the same machine, a revocation, or shutdown.
		if g.current(sess) {
			g.logf(jw6_utils.Info, "Agent disconnected: %s (connection closed)", id.GetHostname())
		}
		return status.Error(codes.Aborted, "stream closed by server")
	}
}

func (g *Gateway) handle(ctx context.Context, sess *session, msg *agentv1.AgentMessage) error {
	switch m := msg.GetMsg().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		return g.st.AgentSeen(ctx, sess.hostID)
	case *agentv1.AgentMessage_Inventory:
		return g.ingest(ctx, sess, m.Inventory)
	case *agentv1.AgentMessage_CertRenew:
		if sess.renewed {
			return status.Error(codes.FailedPrecondition, "one certificate renewal per connection")
		}
		sess.renewed = true
		resp := &agentv1.CertRenewResponse{}
		cert, err := g.ca.IssueClient(m.CertRenew.GetCsrDer(), sess.agentID)
		if err == nil {
			err = g.st.RenewCert(ctx, sess.hostID, sess.agentID, sess.serial, pki.SerialHex(cert), cert.NotAfter)
		}
		if errors.Is(err, store.ErrRevoked) {
			return status.Error(codes.PermissionDenied, "this host has been revoked")
		}
		if err != nil {
			g.logf(jw6_utils.Error, "cert renewal for %s: %v", sess.agentID, err)
			resp.Error = err.Error()
		} else {
			resp.ClientCertDer = cert.Raw
			g.logf(jw6_utils.Info, "Renewed cert for agent %s until %s", sess.agentID, cert.NotAfter.Format(time.DateOnly))
		}
		select {
		case sess.send <- &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_CertRenew{CertRenew: resp}}:
		case <-ctx.Done():
			return ctx.Err()
		}
	case *agentv1.AgentMessage_Metrics:
		g.ingestMetrics(ctx, sess, m.Metrics)
	case *agentv1.AgentMessage_UpdateResult:
		if e := m.UpdateResult.GetError(); e != "" {
			g.logf(jw6_utils.Warn, "Agent %s failed to update to %s: %s", sess.agentID, m.UpdateResult.GetVersion(), e)
			if err := g.st.AgentUpdateFailed(ctx, sess.hostID, sess.agentID, m.UpdateResult.GetVersion(), e); err != nil {
				g.logf(jw6_utils.Error, "record update failure: %v", err)
			}
		}
	case *agentv1.AgentMessage_JobEvent:
		if g.Jobs != nil {
			g.Jobs.Event(ctx, sess.hostID, sess.agentID, m.JobEvent)
		}
	case *agentv1.AgentMessage_IntegrationResult:
		g.pollResult(sess, m.IntegrationResult)
	case *agentv1.AgentMessage_LogChunk:
		g.logChunk(sess, m.LogChunk)
	case *agentv1.AgentMessage_Hello:
		return status.Error(codes.InvalidArgument, "duplicate Hello")
	}
	return nil
}

// ingestMetrics stores a batch. Timestamps are corrected for the agent's
// clock skew, measured from when it sent the batch; bad batches are dropped
// rather than ending the stream.
func (g *Gateway) ingestMetrics(ctx context.Context, sess *session, b *agentv1.MetricBatch) {
	now := time.Now()
	ts := time.Unix(b.GetTsUnix(), 0)
	if sent := b.GetSentUnix(); sent > 0 {
		if skew := now.Sub(time.Unix(sent, 0)); skew > 2*time.Second || skew < -2*time.Second {
			ts = ts.Add(skew.Truncate(time.Second))
		}
	}
	// Agents buffer about six hours; partitions start yesterday.
	if ts.Before(now.Add(-24*time.Hour)) || ts.After(now.Add(5*time.Minute)) {
		g.logf(jw6_utils.Debug, "Dropped a metrics batch from %s stamped %s", sess.agentID, ts.Format(time.RFC3339))
		return
	}
	ms := b.GetMetrics()
	if len(ms) > maxMetrics {
		ms = ms[:maxMetrics]
	}
	samples := make([]store.MetricSample, 0, len(ms))
	for _, m := range ms {
		v := m.GetValue()
		if !metricKinds[m.GetKind()] || m.GetName() == "" || len(m.GetName()) > 64 || len(m.GetInstance()) > 256 ||
			math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		samples = append(samples, store.MetricSample{Kind: m.GetKind(), Name: m.GetName(), Instance: m.GetInstance(), Value: v})
	}
	if err := g.st.IngestMetrics(ctx, sess.hostID, ts, samples); err != nil && ctx.Err() == nil {
		g.logf(jw6_utils.Error, "metrics from %s: %v", sess.agentID, err)
	}
}

// sendUpdate offers a connected agent the release it should move to.
func (g *Gateway) sendUpdate(sess *session, version string) {
	ctx, cancel := context.WithTimeout(sess.ctx, 10*time.Second)
	defer cancel()
	fail := func(reason string) {
		g.logf(jw6_utils.Warn, "Can't update agent %s to %s: %s", sess.agentID, version, reason)
		if err := g.st.AgentUpdateFailed(ctx, sess.hostID, sess.agentID, version, reason); err != nil {
			g.logf(jw6_utils.Error, "record update failure: %v", err)
		}
	}
	switch {
	case sess.cluster:
		fail("a cluster-mode agent is updated by changing its image in the cluster")
		return
	case sess.arch == "":
		fail("this agent is too old to update itself; re-run install.sh on the host")
		return
	case sess.noUpdate:
		fail("self-update is off in this host's agent.conf (self_update = off); re-run install.sh on the host")
		return
	}
	rel, err := g.st.GetRelease(ctx, version, sess.arch)
	if errors.Is(err, store.ErrNotFound) {
		fail(fmt.Sprintf("no %s build of %s is published", sess.arch, version))
		return
	}
	if err != nil {
		g.logf(jw6_utils.Error, "release %s/%s: %v", version, sess.arch, err)
		return
	}
	sigs, err := release.Signatures(rel.Path)
	if err != nil {
		g.logf(jw6_utils.Error, "release %s/%s signatures: %v", version, sess.arch, err)
		return
	}
	msg := &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_UpdateAgent{UpdateAgent: &agentv1.UpdateAgent{
		Version: rel.Version, Arch: rel.Arch, Sha256: rel.SHA256, Signature: rel.Signature, Size: rel.Size,
		Signatures: sigs,
	}}}
	select {
	case sess.send <- msg:
		g.logf(jw6_utils.Info, "Asked agent %s to update to %s", sess.agentID, version)
	case <-ctx.Done():
	}
}

// DownloadRelease streams a published agent binary to an authenticated
// agent. The agent checks the hash and signature itself.
func (g *Gateway) DownloadRelease(req *agentv1.ReleaseRequest, stream agentv1.AgentGateway_DownloadReleaseServer) error {
	ctx := stream.Context()
	host, _, err := g.authenticate(ctx)
	if err != nil {
		return err
	}
	rel, err := g.st.GetRelease(ctx, req.GetVersion(), req.GetArch())
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.NotFound, "no such release")
	}
	if err != nil {
		return status.Error(codes.Unavailable, "server error")
	}
	f, err := os.Open(rel.Path)
	if err != nil {
		g.logf(jw6_utils.Error, "release %s/%s: %v", rel.Version, rel.Arch, err)
		return status.Error(codes.Unavailable, "release file unavailable")
	}
	defer f.Close()
	g.logf(jw6_utils.Info, "Agent %s (%s) is downloading %s for %s", host.AgentID, host.Hostname, rel.Version, rel.Arch)
	buf := make([]byte, releaseChunk)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if err := stream.Send(&agentv1.ReleaseChunk{Data: buf[:n]}); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Error(codes.Unavailable, "reading release")
		}
	}
}

// ingest validates and stores one section. A malformed section is logged
// and dropped rather than ending the stream: one bad collector shouldn't
// take the whole host offline.
func (g *Gateway) ingest(ctx context.Context, sess *session, inv *agentv1.InventorySection) error {
	payload := inv.GetPayloadJson()
	if err := validate(inv.GetSection(), inv.GetSchemaVersion(), inv.GetContentHash(), payload); err != nil {
		g.logf(jw6_utils.Warn, "agent %s sent a bad %q section: %v", sess.agentID, inv.GetSection(), err)
		return nil
	}
	changed, err := g.st.IngestSection(ctx, sess.hostID, sess.agentID, inv.GetSection(), inv.GetContentHash(), payload, inv.GetJobId())
	if err != nil {
		g.logf(jw6_utils.Error, "ingest %s from %s: %v", inv.GetSection(), sess.agentID, err)
		return nil
	}
	if changed {
		g.logf(jw6_utils.Debug, "Stored %s for host %s (%d bytes)", inv.GetSection(), sess.hostID, len(payload))
		switch inv.GetSection() {
		case model.SectionContainers:
			if g.Checker != nil {
				g.Checker.Trigger()
			}
		case model.SectionOS, model.SectionPackages, model.SectionUpdates:
			if g.Vulns != nil {
				g.Vulns.HostChanged(sess.hostID)
			}
		}
	}
	return nil
}

func validate(section string, schema uint32, hash string, payload []byte) error {
	if schema != model.SchemaVersion {
		return fmt.Errorf("schema version %d, server speaks %d", schema, model.SchemaVersion)
	}
	if model.Hash(payload) != hash {
		return errors.New("content hash does not match payload")
	}
	var v any
	switch section {
	case model.SectionOS:
		v = &model.OS{}
	case model.SectionHardware:
		v = &model.Hardware{}
	case model.SectionPackages:
		v = &model.Packages{}
	case model.SectionUpdates:
		v = &model.Updates{}
	case model.SectionSmart:
		v = &model.Smart{}
	case model.SectionContainers:
		v = &model.Containers{}
	case model.SectionServices:
		v = &model.Services{}
	case model.SectionPorts:
		v = &model.Ports{}
	case model.SectionReboot:
		v = &model.Reboot{}
	case model.SectionCerts:
		v = &model.Certs{}
	case model.SectionVMs:
		v = &model.VMs{}
	case model.SectionK8sNode:
		v = &model.K8sNode{}
	case model.SectionK8s:
		v = &model.K8s{}
	default:
		return errors.New("unknown section")
	}
	return json.Unmarshal(payload, v)
}

// staleSections lists sections whose server copy differs from the agent's.
func staleSections(agent, server map[string]string) []string {
	var out []string
	for _, s := range model.Sections {
		if agent[s] == "" || agent[s] != server[s] {
			out = append(out, s)
		}
	}
	return out
}

// policy converts the local policy an agent reports. Agents that predate
// jobs send none.
func policy(p *agentv1.Policy) *action.Policy {
	if p == nil {
		return nil
	}
	out := &action.Policy{Jobs: true, AllowScripts: p.GetAllowScripts(), SelfUpdateOff: p.GetSelfUpdateOff()}
	if p.GetRestrictActions() {
		out.AllowActions = []string{}
		for _, c := range p.GetAllowedActions() {
			if slices.Contains(action.Categories, c) && !slices.Contains(out.AllowActions, c) {
				out.AllowActions = append(out.AllowActions, c)
			}
		}
	}
	return out
}

func requestInventory(sections []string) *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_RequestInventory{
		RequestInventory: &agentv1.RequestInventory{Sections: sections},
	}}
}

// Hub -----------------------------------------------------------------------

// register makes s the agent's session. A reconnect from the same boot
// replaces a half-dead stream; a different boot while the old stream is
// still alive is another machine with the same cert, and is refused. (After
// a real reboot the old stream dies within a keepalive interval, and the
// agent's retry gets in.) It returns the stream it replaced, if any.
func (g *Gateway) register(s *session) (*session, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.sessions[s.agentID]
	if old != nil {
		if old.bootID != s.bootID || old.machineID != s.machineID {
			return nil, false
		}
		old.cancel()
	}
	g.sessions[s.agentID] = s
	return old, true
}

func (g *Gateway) unregister(s *session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions[s.agentID] == s {
		delete(g.sessions, s.agentID)
	}
}

func (g *Gateway) current(s *session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur := g.sessions[s.agentID]
	return cur == nil || cur == s
}

// Online reports whether an agent has a live stream to this server.
func (g *Gateway) Online(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions[agentID] != nil
}

// RequestInventory asks a connected agent to collect and resend sections
// (all when empty). It returns false if the agent isn't connected.
func (g *Gateway) RequestInventory(agentID string, sections []string) bool {
	g.mu.Lock()
	s := g.sessions[agentID]
	g.mu.Unlock()
	if s == nil {
		return false
	}
	for _, sec := range sections {
		if !slices.Contains(model.Sections, sec) {
			return false
		}
	}
	select {
	case s.send <- requestInventory(sections):
		return true
	default:
		return false
	}
}

// Configure sends a connected agent its config again after the host's
// settings changed (high security, Compose roots). It returns false if the agent isn't connected; it
// gets the new config when it next connects.
func (g *Gateway) Configure(agentID string, set store.AgentSettings) bool {
	return g.Send(agentID, &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_Config{Config: agentConfig(set)}})
}

// UpdateAgent offers a connected agent its pending update target, if it has
// one. It returns false if the agent isn't connected; it gets the offer when
// it next connects.
func (g *Gateway) UpdateAgent(agentID string) bool {
	g.mu.Lock()
	s := g.sessions[agentID]
	g.mu.Unlock()
	if s == nil {
		return false
	}
	go func() {
		target, err := g.st.AgentUpdateTarget(s.ctx, s.hostID)
		if err != nil || target == "" {
			return
		}
		g.sendUpdate(s, target)
	}()
	return true
}

// Send delivers a message to a connected agent, waiting a few seconds for
// room on its stream. It returns false if the agent isn't connected or the
// message couldn't be queued.
func (g *Gateway) Send(agentID string, msg *agentv1.ServerMessage) bool {
	g.mu.Lock()
	s := g.sessions[agentID]
	g.mu.Unlock()
	if s == nil {
		return false
	}
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case s.send <- msg:
		return true
	case <-s.ctx.Done():
	case <-t.C:
		g.logf(jw6_utils.Warn, "Agent %s's stream is backed up; dropped a message", agentID)
	}
	return false
}

// Disconnect ends an agent's stream, e.g. after it was revoked.
func (g *Gateway) Disconnect(agentID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.sessions[agentID]; s != nil {
		s.cancel()
	}
}

// Helpers -------------------------------------------------------------------

// clientIdentity reads the verified client cert: its common name is the
// agent ID, and its serial is checked against the database.
func clientIdentity(ctx context.Context) (agentID, serial string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", errors.New("no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return "", "", errors.New("a client certificate is required; enroll this agent first")
	}
	leaf := info.State.VerifiedChains[0][0]
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return "", "", errors.New("certificate is not a client certificate")
	}
	return leaf.Subject.CommonName, pki.SerialHex(leaf), nil
}

func recvWithTimeout(stream agentv1.AgentGateway_ConnectServer, d time.Duration) (*agentv1.AgentMessage, error) {
	type result struct {
		m   *agentv1.AgentMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := stream.Recv()
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-time.After(d):
		return nil, status.Error(codes.DeadlineExceeded, "no Hello received")
	}
}

// peerIP is the address the connection came from. Behind Traefik TCP
// passthrough that is Traefik itself.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func errOrEOF(err error) any {
	if err == nil {
		return "EOF"
	}
	return err
}

func (g *Gateway) logf(level jw6_utils.LogLevel, format string, args ...any) {
	g.log.Log("Gateway", "agent", level, fmt.Sprintf(format, args...))
}

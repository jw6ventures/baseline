package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/agent/runner"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/release"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestMetricsReachTheServer(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "mx")
	os.WriteFile(filepath.Join(h.env.Root, "proc/loadavg"), []byte("0.25 0.20 0.10 1/100 42\n"), 0o644)
	stateDir := t.TempDir()
	agentID, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := agent.LoadState(stateDir)
	a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: h.collectors(), Version: "test", Log: quiet,
		Sampler: &collect.Sampler{Env: h.env}, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Run(runCtx)

	eventually(t, "load average stored", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || hosts[0].AgentID != agentID {
			return false
		}
		d, err := e.st.QueryMetrics(ctx, store.MetricQuery{HostID: hosts[0].ID, Kind: "load", Names: []string{"load1"},
			From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Minute), Step: time.Minute})
		return err == nil && len(d.Lines) == 1 && d.Lines[0].Values[len(d.Times)-1] == 0.25
	})
}

// selfUpdateEnv publishes a release for this platform and enrolls an agent
// whose "binary" is a file in a temp dir.
type selfUpdateEnv struct {
	*env
	stateDir, binary string
	host             *fakeHost
	agentID, hostID  string
	keys             []ed25519.PublicKey // the release keys "built into" the agent
	signed           bool                // Publish found a valid CI signature
}

// releaseKey stands in for the CI signing key.
func releaseKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeRelease writes an agent binary into agentDir as the image build
// does, with a .sig signed by keys (none: an unsigned build).
func writeRelease(t *testing.T, agentDir, version string, data []byte, keys ...ed25519.PrivateKey) {
	bin := filepath.Join(agentDir, release.Prefix+runtime.GOARCH)
	os.WriteFile(bin, data, 0o755)
	if len(keys) == 0 {
		return
	}
	sum := sha256.Sum256(data)
	var sigs [][]byte
	for _, k := range keys {
		sigs = append(sigs, ed25519.Sign(k, pki.ReleaseStatement(version, runtime.GOARCH, hex.EncodeToString(sum[:]))))
	}
	os.WriteFile(bin+release.SigSuffix, pki.FormatReleaseSignatures(sigs), 0o644)
}

func newSelfUpdate(t *testing.T) *selfUpdateEnv {
	k := releaseKey(t)
	return newSelfUpdateSigned(t, []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, k)
}

// newSelfUpdateSigned publishes 2.0 signed by signers, for agents trusting keys.
func newSelfUpdateSigned(t *testing.T, keys []ed25519.PublicKey, signers ...ed25519.PrivateKey) *selfUpdateEnv {
	e := start(t)
	ctx := context.Background()
	agentDir, dataDir := t.TempDir(), t.TempDir()
	writeRelease(t, agentDir, "2.0", []byte("new agent binary"), signers...)
	pub, err := release.Publish(ctx, e.st, e.ca, keys, agentDir, dataDir, "2.0")
	if err != nil || len(pub) != 1 {
		t.Fatalf("publish: %v %v", pub, err)
	}
	s := &selfUpdateEnv{env: e, stateDir: t.TempDir(), host: newFakeHost(t, "mu"), keys: keys, signed: pub[0].Signed}
	s.binary = filepath.Join(t.TempDir(), "baseline-agent")
	os.WriteFile(s.binary, []byte("old agent binary"), 0o755)
	if s.agentID, err = agent.Enroll(ctx, e.addr, e.token(0), s.stateDir, "1.0", s.host.env); err != nil {
		t.Fatal(err)
	}
	return s
}

// run starts an agent claiming version. The fake "binary" can't run, so
// asking it for its version answers with the version being installed.
func (s *selfUpdateEnv) run(t *testing.T, version, reports string) (*agent.Agent, chan error, context.CancelFunc) {
	st, _ := agent.LoadState(s.stateDir)
	u, err := agent.NewUpdater(s.stateDir, s.binary, s.keys, func(_ context.Context, name string, args ...string) ([]byte, error) {
		if len(args) == 1 && args[0] == "version" {
			return []byte(reports + "\n"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &agent.Agent{Server: s.addr, State: st, Env: s.host.env, Collectors: s.host.collectors(), Version: version, Log: quiet,
		Updater: u, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(cancel)
	eventually(t, "agent "+version+" online", func() bool {
		hosts, _ := s.st.ListHosts(context.Background())
		if len(hosts) == 1 && hosts[0].Connected && hosts[0].AgentVersion == version {
			s.hostID = hosts[0].ID
			return true
		}
		return false
	})
	return a, done, cancel
}

func TestSelfUpdate(t *testing.T) {
	s := newSelfUpdate(t)
	ctx := context.Background()
	if !s.signed {
		t.Fatal("Publish didn't find the CI signature")
	}
	_, done, _ := s.run(t, "1.0", "2.0")

	changed, err := s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0")
	if err != nil || len(changed) != 1 {
		t.Fatalf("%v %v", changed, err)
	}
	if !s.gw.UpdateAgent(s.agentID) {
		t.Fatal("agent not connected")
	}
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrRestart) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent didn't install the update")
	}
	if b, _ := os.ReadFile(s.binary); string(b) != "new agent binary" {
		t.Fatalf("binary = %q", b)
	}
	if b, _ := os.ReadFile(s.binary + ".prev"); string(b) != "old agent binary" {
		t.Fatalf("previous binary = %q", b)
	}
	if _, err := os.Stat(filepath.Join(s.stateDir, "update-pending.json")); err != nil {
		t.Fatal("no probation marker")
	}

	// systemd starts the new binary: it connects, which ends probation and
	// completes the update on the server.
	s.run(t, "2.0", "2.0")
	eventually(t, "probation over", func() bool {
		_, err := os.Stat(filepath.Join(s.stateDir, "update-pending.json"))
		return os.IsNotExist(err)
	})
	// The 1.0 stream recording its disconnect mustn't mark the host offline
	// after 2.0 connected.
	time.Sleep(500 * time.Millisecond)
	h, _ := s.st.GetHost(ctx, s.hostID)
	if h.AgentUpdateTarget != "" || h.AgentUpdateError != "" || !h.Connected {
		t.Fatalf("host = %+v", h)
	}
}

func TestSelfUpdateRefusesBadSignature(t *testing.T) {
	s := newSelfUpdate(t)
	ctx := context.Background()
	rel, _ := s.st.GetRelease(ctx, "2.0", runtime.GOARCH)
	rel.Version, rel.Signature = "3.0", []byte(strings.Repeat("x", 64))
	if _, err := s.st.PublishRelease(ctx, rel); err != nil {
		t.Fatal(err)
	}
	s.run(t, "1.0", "3.0")
	s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "3.0")
	s.gw.UpdateAgent(s.agentID)
	eventually(t, "failure recorded", func() bool {
		h, _ := s.st.GetHost(ctx, s.hostID)
		return strings.Contains(h.AgentUpdateError, "signature") && h.AgentUpdateTarget == ""
	})
	if b, _ := os.ReadFile(s.binary); string(b) != "old agent binary" {
		t.Fatalf("binary replaced: %q", b)
	}
	if _, err := os.Stat(s.binary + ".new"); !os.IsNotExist(err) {
		t.Fatal("download left behind")
	}
}

// refusesUpdate requests 2.0 and expects the agent to refuse it for its
// signature, keeping the old binary.
func (s *selfUpdateEnv) refusesUpdate(t *testing.T) {
	ctx := context.Background()
	s.run(t, "1.0", "2.0")
	s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0")
	s.gw.UpdateAgent(s.agentID)
	eventually(t, "failure recorded", func() bool {
		h, _ := s.st.GetHost(ctx, s.hostID)
		return strings.Contains(h.AgentUpdateError, "signature") && h.AgentUpdateTarget == ""
	})
	if b, _ := os.ReadFile(s.binary); string(b) != "old agent binary" {
		t.Fatalf("binary replaced: %q", b)
	}
}

// The server's own release key (in /data/pki) can't sign an update an
// agent accepts: a release without a CI signature is refused, though the
// server still sends its own signature for agents older than CI signing.
func TestSelfUpdateRefusesServerSignature(t *testing.T) {
	trusted := releaseKey(t)
	s := newSelfUpdateSigned(t, []ed25519.PublicKey{trusted.Public().(ed25519.PublicKey)})
	rel, _ := s.st.GetRelease(context.Background(), "2.0", runtime.GOARCH)
	if !ed25519.Verify(s.ca.ReleasePublicKey(), pki.ReleaseStatement("2.0", rel.Arch, rel.SHA256), rel.Signature) {
		t.Fatal("no server signature for older agents")
	}
	if s.signed {
		t.Fatal("Publish reports an unsigned release as signed")
	}
	s.refusesUpdate(t)
}

// A release signed with a key the agent wasn't built with is refused.
func TestSelfUpdateRefusesUntrustedKey(t *testing.T) {
	trusted := releaseKey(t)
	s := newSelfUpdateSigned(t, []ed25519.PublicKey{trusted.Public().(ed25519.PublicKey)}, releaseKey(t))
	if s.signed {
		t.Fatal("Publish accepts a signature by an untrusted key")
	}
	s.refusesUpdate(t)
}

// During a key rotation the agent trusts two keys. A release signed by
// either is accepted, even next to a signature it can't verify.
func TestSelfUpdateKeyRotation(t *testing.T) {
	oldKey, newKey := releaseKey(t), releaseKey(t)
	trusted := []ed25519.PublicKey{oldKey.Public().(ed25519.PublicKey), newKey.Public().(ed25519.PublicKey)}
	s := newSelfUpdateSigned(t, trusted, releaseKey(t), newKey)
	_, done, _ := s.run(t, "1.0", "2.0")
	s.st.RequestAgentUpdate(context.Background(), store.System, []string{s.hostID}, "2.0")
	s.gw.UpdateAgent(s.agentID)
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrRestart) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent didn't install the update")
	}
}

func TestPendingUpdateSentOnConnect(t *testing.T) {
	s := newSelfUpdate(t)
	ctx := context.Background()
	_, done, cancel := s.run(t, "1.0", "2.0")
	cancel()
	<-done
	eventually(t, "offline", func() bool { return !s.gw.Online(s.agentID) })

	// Requested while the agent is away: it updates when it comes back.
	if got, _ := s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0"); len(got) != 1 {
		t.Fatal("not requested")
	}
	st, _ := agent.LoadState(s.stateDir)
	u, _ := agent.NewUpdater(s.stateDir, s.binary, s.keys, func(context.Context, string, ...string) ([]byte, error) { return []byte("2.0"), nil })
	a := &agent.Agent{Server: s.addr, State: st, Env: s.host.env, Collectors: s.host.collectors(), Version: "1.0", Log: quiet, Updater: u}
	runCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	if err := a.Run(runCtx); !errors.Is(err, agent.ErrRestart) {
		t.Fatalf("Run = %v", err)
	}
}

// offAgent runs agent 1.0 with self_update = off. With report set it sends
// the setting in Hello like a real agent; without, only the agent knows.
func (s *selfUpdateEnv) offAgent(t *testing.T, report bool) {
	st, _ := agent.LoadState(s.stateDir)
	u, err := agent.NewUpdater(s.stateDir, s.binary, s.keys, func(context.Context, string, ...string) ([]byte, error) { return []byte("2.0"), nil })
	if err != nil {
		t.Fatal(err)
	}
	u.Off = true
	a := &agent.Agent{Server: s.addr, State: st, Env: s.host.env, Collectors: s.host.collectors(), Version: "1.0", Log: quiet,
		Updater: u, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	if report {
		a.Runner = &runner.Runner{Dir: t.TempDir(), Env: s.host.env, Log: quiet,
			Policy: action.Policy{Jobs: true, AllowScripts: true, SelfUpdateOff: true}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Run(ctx)
}

func TestSelfUpdateOffRefusedByAgent(t *testing.T) {
	s := newSelfUpdate(t)
	ctx := context.Background()
	// An agent that doesn't tell the server still refuses on its own.
	_, done, cancel := s.run(t, "1.0", "2.0")
	cancel()
	<-done
	eventually(t, "offline", func() bool { return !s.gw.Online(s.agentID) })
	s.offAgent(t, false)
	eventually(t, "online", func() bool { return s.gw.Online(s.agentID) })
	if got, _ := s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0"); len(got) != 1 {
		t.Fatal("not requested")
	}
	s.gw.UpdateAgent(s.agentID)
	eventually(t, "refusal recorded", func() bool {
		h, _ := s.st.GetHost(ctx, s.hostID)
		return strings.Contains(h.AgentUpdateError, "self_update = off") && h.AgentUpdateTarget == ""
	})
	if b, _ := os.ReadFile(s.binary); string(b) != "old agent binary" {
		t.Fatalf("binary replaced: %q", b)
	}
}

func TestSelfUpdateOffSkippedByServer(t *testing.T) {
	s := newSelfUpdate(t)
	ctx := context.Background()
	_, done, cancel := s.run(t, "1.0", "2.0")
	cancel()
	<-done
	eventually(t, "offline", func() bool { return !s.gw.Online(s.agentID) })

	// Asked for before the owner turned updates off: the server drops the
	// target when the agent reports the setting, without sending it.
	if got, _ := s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0"); len(got) != 1 {
		t.Fatal("not requested")
	}
	s.offAgent(t, true)
	eventually(t, "target dropped", func() bool {
		h, _ := s.st.GetHost(ctx, s.hostID)
		return h.Policy.SelfUpdateOff && strings.Contains(h.AgentUpdateError, "self_update = off") && h.AgentUpdateTarget == ""
	})
	// New requests skip the host.
	if got, err := s.st.RequestAgentUpdate(ctx, store.System, []string{s.hostID}, "2.0"); err != nil || len(got) != 0 {
		t.Fatalf("requested again: %v %v", got, err)
	}
	if b, _ := os.ReadFile(s.binary); string(b) != "old agent binary" {
		t.Fatalf("binary replaced: %q", b)
	}
}

package gateway_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/gateway"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

var quiet = &jw6_utils.Utils{LogLevel: jw6_utils.Fatal}

type env struct {
	t    *testing.T
	st   *store.Store
	ca   *pki.Authority
	gw   *gateway.Gateway
	addr string
}

func start(t *testing.T) *env {
	st, _ := storetest.New(t)
	ca, err := pki.Load(t.TempDir(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(st, ca, quiet)
	if err := st.MaintainMetrics(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := gw.NewServer()
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	return &env{t: t, st: st, ca: ca, gw: gw, addr: ln.Addr().String()}
}

func (e *env) token(maxUses int) string {
	secret := pki.NewTokenSecret()
	_, err := e.st.CreateEnrollmentToken(context.Background(), store.System, "", store.EnrollmentToken{
		Name: "test", MaxUses: maxUses, ExpiresAt: time.Now().Add(time.Hour),
	}, pki.HashTokenSecret(secret))
	if err != nil {
		e.t.Fatal(err)
	}
	return pki.FormatToken(secret, e.ca.CAFingerprint())
}

// fakeHost is a minimal filesystem for Identity, plus collectors whose
// output the test controls.
type fakeHost struct {
	env *collect.Env
	mu  sync.Mutex
	pkg string
}

func newFakeHost(t *testing.T, machineID string) *fakeHost {
	root := t.TempDir()
	for p, c := range map[string]string{
		"/etc/machine-id":                 machineID,
		"/sys/class/dmi/id/product_uuid":  "dmi-" + machineID,
		"/proc/sys/kernel/hostname":       "host-" + machineID,
		"/proc/sys/kernel/random/boot_id": "boot-1",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(c), 0o644)
	}
	return &fakeHost{
		env: &collect.Env{
			Root: root,
			Run:  func(context.Context, string, ...string) ([]byte, error) { return nil, os.ErrNotExist },
			Has:  func(string) bool { return false },
		},
		pkg: "1.0",
	}
}

func (h *fakeHost) collectors() map[string]agent.CollectFunc {
	return map[string]agent.CollectFunc{
		model.SectionOS: func(context.Context) (any, error) {
			return model.OS{Hostname: "web1", ID: "ubuntu", PrettyName: "Ubuntu 24.04", Kernel: "6.8.0"}, nil
		},
		model.SectionHardware: func(context.Context) (any, error) {
			return model.Hardware{CPU: model.CPU{Model: "Test CPU", Threads: 4}}, nil
		},
		model.SectionPackages: func(context.Context) (any, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return model.Packages{Managers: []string{"apt"}, Packages: []model.Package{{Manager: "apt", Name: "curl", Version: h.pkg}}}, nil
		},
	}
}

func (h *fakeHost) setPkg(v string) {
	h.mu.Lock()
	h.pkg = v
	h.mu.Unlock()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (e *env) runAgent(h *fakeHost, stateDir string, tweak func(*agent.State)) (context.CancelFunc, *agent.Agent) {
	st, err := agent.LoadState(stateDir)
	if err != nil {
		e.t.Fatal(err)
	}
	if tweak != nil {
		tweak(st)
	}
	a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: h.collectors(), Version: "test",
		Log: quiet, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
	return cancel, a
}

func TestEnrollConnectInventoryRefreshRevoke(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m1")
	stateDir := t.TempDir()

	agentID, err := agent.Enroll(ctx, e.addr, e.token(1), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"agent-id", "agent.key", "agent.crt", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := os.Stat(filepath.Join(stateDir, "agent.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("agent.key mode %v", st.Mode().Perm())
	}

	e.runAgent(h, stateDir, nil)

	var hostID string
	eventually(t, "host online with three sections", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || !hosts[0].Connected || hosts[0].PackageCount != 1 || hosts[0].Kernel != "6.8.0" {
			return false
		}
		hostID = hosts[0].ID
		_, _, err := e.st.HostSection(ctx, hostID, model.SectionHardware)
		return err == nil
	})
	host, _ := e.st.GetHost(ctx, hostID)
	if host.AgentID != agentID || host.MachineID != "m1" || host.DMIUUID != "dmi-m1" || host.BootID != "boot-1" || host.AgentVersion != "test" {
		t.Fatalf("host = %+v", host)
	}
	if !e.gw.Online(agentID) {
		t.Fatal("hub doesn't see the agent")
	}

	// "Refresh now": the agent re-collects and the change lands in history.
	h.setPkg("2.0")
	if !e.gw.RequestInventory(agentID, []string{model.SectionPackages}) {
		t.Fatal("RequestInventory failed")
	}
	eventually(t, "package upgrade in history", func() bool {
		hist, _ := e.st.HostHistory(ctx, hostID, 10)
		return len(hist) > 0 && hist[0].Section == "packages" && strings.Contains(string(hist[0].Diff), `"to": "2.0"`)
	})

	// Revoking ends the stream and keeps the agent out.
	if err := e.st.RevokeHost(ctx, store.System, hostID); err != nil {
		t.Fatal(err)
	}
	e.gw.Disconnect(agentID)
	eventually(t, "agent offline", func() bool { return !e.gw.Online(agentID) })
	time.Sleep(300 * time.Millisecond) // a reconnect attempt would show up as online
	if e.gw.Online(agentID) {
		t.Fatal("revoked agent reconnected")
	}
}

func TestAgentRenewsCertAndReconnects(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m2")
	stateDir := t.TempDir()
	agentID, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := agent.LoadState(stateDir)
	oldSerial := pki.SerialHex(first.Cert)

	// Pretend the cert is 80 days into its 90: renewal is due.
	e.runAgent(h, stateDir, func(s *agent.State) {
		s.Cert.NotBefore = time.Now().Add(-80 * 24 * time.Hour)
		s.Cert.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	})

	eventually(t, "renewed cert on disk and in use", func() bool {
		st, err := agent.LoadState(stateDir)
		if err != nil || pki.SerialHex(st.Cert) == oldSerial {
			return false
		}
		// Reconnecting with the new cert clears the previous serial.
		_, err = e.st.AuthenticateAgent(ctx, agentID, oldSerial)
		return errors.Is(err, store.ErrUnknownCert) && e.gw.Online(agentID)
	})
}

func TestEnrollRejections(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m3")

	tok := e.token(1)
	if _, err := agent.Enroll(ctx, e.addr, tok, t.TempDir(), "test", h.env); err != nil {
		t.Fatal(err)
	}
	_, err := agent.Enroll(ctx, e.addr, tok, t.TempDir(), "test", h.env)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("used-up token: %v", err)
	}

	// A token naming a different CA: the agent refuses the server.
	other, _ := pki.Load(t.TempDir(), nil)
	secret, _, _ := pki.ParseToken(e.token(1))
	_, err = agent.Enroll(ctx, e.addr, pki.FormatToken(secret, other.CAFingerprint()), t.TempDir(), "test", h.env)
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("foreign CA: %v", err)
	}

	entries, _ := e.st.ListAudit(ctx, 0, 10)
	var actions []string
	for _, a := range entries {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, " "), "host.enroll_failed") {
		t.Fatalf("audit = %v", actions)
	}
}

func TestConnectWithoutClientCertRejected(t *testing.T) {
	e := start(t)
	h := newFakeHost(t, "m4")
	stateDir := t.TempDir()
	if _, err := agent.Enroll(context.Background(), e.addr, e.token(0), stateDir, "test", h.env); err != nil {
		t.Fatal(err)
	}
	// A cert from a different CA for the same agent ID is refused at TLS.
	st, _ := agent.LoadState(stateDir)
	other, _ := pki.Load(t.TempDir(), nil)
	_, csr, _ := pki.GenerateKey()
	forged, _ := other.IssueClient(csr, st.AgentID)
	st.Cert = forged
	a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: h.collectors(), Version: "test", Log: quiet}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go a.Run(ctx)
	time.Sleep(time.Second)
	if e.gw.Online(st.AgentID) {
		t.Fatal("forged cert accepted")
	}
}

// Two machines with the same agent state (a cloned VM) must not knock each
// other off: the second is refused and the host is flagged.
func TestClonedAgentIsRefused(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m5")
	stateDir := t.TempDir()
	agentID, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	e.runAgent(h, stateDir, nil)
	eventually(t, "first agent online", func() bool { return e.gw.Online(agentID) })

	clone := newFakeHost(t, "m5")
	os.WriteFile(filepath.Join(clone.env.Root, "/proc/sys/kernel/random/boot_id"), []byte("boot-clone"), 0o644)
	e.runAgent(clone, stateDir, nil)

	var hostID string
	eventually(t, "host flagged", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) == 1 && hosts[0].DuplicateIdentity {
			hostID = hosts[0].ID
			return true
		}
		return false
	})
	// The original keeps its stream: its boot ID is still the one on record.
	time.Sleep(500 * time.Millisecond)
	host, _ := e.st.GetHost(ctx, hostID)
	if host.BootID != "boot-1" || !host.Connected {
		t.Fatalf("original lost its session: %+v", host)
	}
	entries, _ := e.st.ListAudit(ctx, 0, 20)
	n := 0
	for _, a := range entries {
		if a.Action == "host.identity_conflict" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("identity_conflict audited %d times", n)
	}
}

// A reconnect from the same boot (e.g. after a network blip, before the
// server noticed the old stream died) replaces the old stream.
func TestReconnectFromSameBootReplacesStream(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m6")
	stateDir := t.TempDir()
	agentID, _ := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env)
	stop1, _ := e.runAgent(h, stateDir, nil)
	eventually(t, "online", func() bool { return e.gw.Online(agentID) })
	e.runAgent(h, stateDir, nil) // same boot ID
	time.Sleep(300 * time.Millisecond)
	stop1()
	eventually(t, "still online via the second agent", func() bool { return e.gw.Online(agentID) })
	hosts, _ := e.st.ListHosts(ctx)
	if hosts[0].DuplicateIdentity {
		t.Fatal("same-boot reconnect flagged as a clone")
	}
}

// watchHost is a fakeHost whose kernel device events the test sends.
type watchHost struct {
	*collect.Env
	events   chan struct{}
	watching atomic.Int32
}

func (w *watchHost) WatchDevices(ctx context.Context, changed func()) error {
	w.watching.Add(1)
	defer w.watching.Add(-1)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.events:
			changed()
		}
	}
}

func TestHighSecurityConfig(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "m1")
	w := &watchHost{Env: h.env, events: make(chan struct{})}
	stateDir := t.TempDir()
	agentID, err := agent.Enroll(ctx, e.addr, e.token(1), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	var usb atomic.Value // []model.USBDevice plugged in
	usb.Store([]model.USBDevice{})
	collectors := h.collectors()
	collectors[model.SectionHardware] = func(context.Context) (any, error) {
		hw := model.Hardware{CPU: model.CPU{Model: "Test CPU", Threads: 4}}
		if h.env.HighSecurity.Load() {
			hw.Peripherals = &model.Peripherals{USB: usb.Load().([]model.USBDevice), Displays: []model.Display{}}
		}
		return hw, nil
	}
	run := func() context.CancelFunc {
		st, err := agent.LoadState(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		a := &agent.Agent{Server: e.addr, State: st, Env: w, Collectors: collectors, Version: "test",
			Log: quiet, MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { a.Run(ctx); close(done) }()
		stop := func() { cancel(); <-done }
		t.Cleanup(stop)
		return stop
	}
	var hostID string
	stored := func() string {
		b, _, _ := e.st.HostSection(ctx, hostID, model.SectionHardware)
		return string(b)
	}
	stop := run()
	eventually(t, "host online", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || !hosts[0].Connected {
			return false
		}
		hostID = hosts[0].ID
		_, _, err := e.st.HostSection(ctx, hostID, model.SectionHardware)
		return err == nil
	})
	if h.env.HighSecurity.Load() || w.watching.Load() != 0 || strings.Contains(stored(), "peripherals") {
		t.Fatal("high security collection on an ordinary host")
	}

	// Turning the flag on reaches the connected agent, which re-collects
	// and starts watching for devices.
	if _, err := e.st.SetHostHighSecurity(ctx, store.System, hostID, true); err != nil {
		t.Fatal(err)
	}
	if !e.gw.Configure(agentID, store.AgentSettings{HighSecurity: true}) {
		t.Fatal("Configure failed")
	}
	eventually(t, "peripherals in the hardware section", func() bool { return strings.Contains(stored(), `"peripherals"`) })
	eventually(t, "watching for devices", func() bool { return w.watching.Load() == 1 })
	if gateway.DefaultIntervals[model.SectionHardware] != 24*3600 {
		t.Fatal("the high security interval leaked into the defaults")
	}

	// A stick plugged in reaches the server within seconds, not at the
	// next 5-minute poll; a burst of events is one collection.
	usb.Store([]model.USBDevice{{Name: "1-1", VendorID: "0781", ProductID: "5581"}})
	for range 5 {
		w.events <- struct{}{}
	}
	eventually(t, "the stick in the hardware section", func() bool { return strings.Contains(stored(), `"1-1"`) })

	// A restarted agent is told again when it connects.
	stop()
	h.env.SetHighSecurity(false)
	eventually(t, "watching stopped with the session", func() bool { return w.watching.Load() == 0 })
	run()
	eventually(t, "high security back on after reconnecting", func() bool {
		return h.env.HighSecurity.Load() && w.watching.Load() == 1
	})

	// Turning it off stops the watching.
	if !e.gw.Configure(agentID, store.AgentSettings{}) {
		t.Fatal("Configure failed")
	}
	eventually(t, "watching stopped", func() bool { return w.watching.Load() == 0 && !h.env.HighSecurity.Load() })
	eventually(t, "peripherals gone", func() bool { return !strings.Contains(stored(), "peripherals") })
}

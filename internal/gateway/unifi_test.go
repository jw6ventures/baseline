package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/gateway"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/unifi"
	"github.com/jw6ventures/baseline/internal/unifi/unifitest"
)

// The server has a host's agent poll a UniFi console only that host
// reaches, and gets back what the agent found.
func TestAgentPollsUniFi(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	con := unifitest.New(t)
	cfg, _ := json.Marshal(unifi.Config{URL: con.URL, TLSFingerprint: con.Fingerprint, Protect: true})

	run := func(machineID string, integrations bool) string {
		stateDir := t.TempDir()
		h := newFakeHost(t, machineID)
		if _, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env); err != nil {
			t.Fatal(err)
		}
		st, _ := agent.LoadState(stateDir)
		a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: h.collectors(), Version: "test", Log: quiet,
			MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, Integrations: integrations}
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { a.Run(runCtx); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		var hostID string
		eventually(t, "agent "+machineID+" connected", func() bool {
			hosts, _ := e.st.ListHosts(ctx)
			for _, h := range hosts {
				if h.AgentID == st.AgentID && h.Connected {
					hostID = h.ID
				}
			}
			return hostID != "" && e.gw.Online(st.AgentID)
		})
		return hostID
	}

	able := run("m-able", true)
	out, err := e.gw.PollIntegration(ctx, able, "unifi", model.CapUniFi, cfg, unifitest.Key, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var snap model.UniFi
	if err := json.Unmarshal(out, &snap); err != nil || len(snap.Sites) != 1 || len(snap.Sites[0].Devices) != 2 || len(snap.Protect) != 1 {
		t.Fatalf("snapshot: %s %v", out, err)
	}
	// The agent's error comes back as the poll's.
	if _, err := e.gw.PollIntegration(ctx, able, "unifi", model.CapUniFi, cfg, "wrong", 30*time.Second); err == nil ||
		!strings.Contains(err.Error(), "refused the API key") {
		t.Fatalf("bad key: %v", err)
	}
	// An agent with integrations = off isn't asked.
	off := run("m-off", false)
	if _, err := e.gw.PollIntegration(ctx, off, "unifi", model.CapUniFi, cfg, unifitest.Key, time.Second); !errors.Is(err, gateway.ErrNoCapability) {
		t.Fatalf("integrations off: %v", err)
	}
	if _, err := e.gw.PollIntegration(ctx, "00000000-0000-0000-0000-000000000000", "unifi", model.CapUniFi, cfg, unifitest.Key, time.Second); !errors.Is(err, gateway.ErrAgentOffline) {
		t.Fatalf("offline: %v", err)
	}
}

package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/runner"
	"github.com/jw6ventures/baseline/internal/jobs"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

// TestJobsRunOnAgents drives jobs end to end: a change approved in the
// store, the dispatcher sending it, a real agent running it with a fake
// systemctl, output and result back, and the inventory change it caused
// attributed to the change.
func TestJobsRunOnAgents(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	d := jobs.New(e.st, e.gw, quiet)
	e.gw.Jobs = d
	dctx, stop := context.WithCancel(ctx)
	defer stop()
	go d.Run(dctx)

	h := newFakeHost(t, "m4")
	h.env.Has = func(name string) bool { return name == "systemctl" }
	var mu sync.Mutex
	enabled := "disabled"
	cols := h.collectors()
	cols[model.SectionServices] = func(context.Context) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		return model.Services{Units: []model.Service{{Name: "nginx.service", Active: "active", Enabled: enabled}}}, nil
	}
	var runs atomic.Int32
	exec := func(_ context.Context, c runner.Cmd, stdout, _ io.Writer) (int, error) {
		cmd := c.Name + " " + strings.Join(c.Args, " ")
		if cmd == "systemctl enable nginx.service" || cmd == "systemctl restart nginx.service" {
			runs.Add(1)
			mu.Lock()
			enabled = "enabled"
			mu.Unlock()
			fmt.Fprintln(stdout, "done:", cmd)
		}
		return 0, nil
	}

	stateDir := t.TempDir()
	agentID, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := agent.LoadState(stateDir)
	r := &runner.Runner{Dir: t.TempDir(), Env: h.env, Exec: exec, Log: quiet, BootID: func() string { return "boot-1" },
		Policy: action.Policy{Jobs: true, AllowScripts: false, AllowActions: []string{action.CategoryService}}}
	a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: cols, Version: "test", Log: quiet, Runner: r}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Run(runCtx)

	var hostID string
	eventually(t, "host online with services", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || !hosts[0].Connected {
			return false
		}
		hostID = hosts[0].ID
		svcs, _ := e.st.HostServices(ctx, hostID)
		return len(svcs) == 1
	})
	hst, _ := e.st.GetHost(ctx, hostID)
	if !hst.Policy.Jobs || hst.Policy.AllowScripts || strings.Join(hst.Policy.AllowActions, ",") != "service" {
		t.Fatalf("policy = %+v", hst.Policy)
	}

	u, _ := e.st.UpsertUser(ctx, "ann", "ann@example.com", "Ann")
	ann := store.UserActor(u.ID, "")
	newChange := func(name string, params any) store.Change {
		t.Helper()
		raw, _ := json.Marshal(params)
		norm, err := action.Validate(name, raw)
		if err != nil {
			t.Fatal(err)
		}
		c, err := e.st.CreateChange(ctx, ann, store.NewChange{Title: name, Risk: action.Low, SelfApprove: true,
			Steps: []store.PlanStep{{Action: name, Params: norm, Summary: name, HostIDs: []string{hostID}}}})
		if err != nil {
			t.Fatal(err)
		}
		d.Nudge()
		return c
	}
	waitChange := func(c store.Change, state string) store.Job {
		t.Helper()
		eventually(t, c.Ref()+" "+state, func() bool {
			c, _ = e.st.GetChange(ctx, c.ID)
			return c.State == state
		})
		js, _ := e.st.ListJobs(ctx, store.JobFilter{ChangeID: c.ID})
		return js[0]
	}

	c := newChange(action.ServiceRestart, action.UnitParams{Unit: "nginx"})
	j := waitChange(c, store.ChangeImplemented)
	if j.State != store.JobSucceeded || !j.ExitCode.Valid || j.ExitCode.Int64 != 0 || j.StartedAt.IsZero() {
		t.Fatalf("job = %+v", j)
	}
	eventually(t, "output stored", func() bool {
		out, _ := e.st.JobOutput(ctx, j.ID, 0, 100)
		var all strings.Builder
		for _, o := range out {
			all.WriteString(o.Chunk)
		}
		return strings.Contains(all.String(), "done: systemctl restart nginx.service") &&
			strings.Contains(all.String(), "$ systemctl restart nginx.service")
	})
	// The agent collected services again for the job: the change is named.
	eventually(t, "service change attributed", func() bool {
		hist, _ := e.st.HostHistory(ctx, hostID, 10)
		return len(hist) > 0 && hist[0].Section == model.SectionServices && hist[0].ChangeID == c.ID
	})

	// The local policy refuses reboots, whatever the server asks.
	c = newChange(action.HostReboot, nil)
	j = waitChange(c, store.ChangeFailed)
	if j.State != store.JobRejected || !strings.Contains(j.Error, "allow_actions") {
		t.Fatalf("rejected job = %+v", j)
	}

	// A job sent again is answered from the agent's journal, not rerun.
	before := runs.Load()
	resend := &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_RunJob{RunJob: &agentv1.RunJob{
		JobId: j.ID, Action: action.ServiceRestart, ParamsJson: []byte(`{"unit":"nginx.service"}`)}}}
	first, _ := e.st.ListJobs(ctx, store.JobFilter{HostID: hostID, States: []string{store.JobSucceeded}})
	resend.GetRunJob().JobId = first[0].ID
	if !e.gw.Send(agentID, resend) {
		t.Fatal("send failed")
	}

	// A job sent while the agent was away runs when it reconnects.
	c = newChange(action.ServiceStart, action.UnitParams{Unit: "nginx"})
	waitChange(c, store.ChangeImplemented)
	if got := runs.Load(); got != before {
		t.Fatalf("systemctl restart/enable ran %d more times", got-before)
	}
	c2, _ := e.st.CreateChange(ctx, ann, store.NewChange{Title: "later", Risk: action.Low, SelfApprove: true,
		Steps: []store.PlanStep{{Action: action.ServiceRestart, Params: json.RawMessage(`{"unit":"nginx.service"}`), Summary: "x",
			HostIDs: []string{hostID}}}})
	e.st.StartChange(ctx, c2.ID, time.Time{})
	q, _ := e.st.QueuedJobs(ctx)
	if len(q) != 1 {
		t.Fatalf("queued = %d", len(q))
	}
	// Dispatched in the database, but the message never reached the agent.
	if ok, _ := e.st.MarkDispatched(ctx, q[0].Job); !ok {
		t.Fatal("mark dispatched")
	}
	e.gw.Disconnect(agentID)
	waitChange(c2, store.ChangeImplemented)
	if got := runs.Load(); got != before+1 {
		t.Fatalf("resent job ran %d times", got-before)
	}
	if v, _ := e.st.VerifyAudit(ctx); !v.OK() {
		t.Fatalf("audit: %+v", v)
	}
}

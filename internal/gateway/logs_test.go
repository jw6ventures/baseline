package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/container"
	"github.com/jw6ventures/baseline/internal/gateway"
	"github.com/jw6ventures/baseline/internal/model"
)

// fakeLogs is an engine's log: lines, then with follow, a line every few
// milliseconds until stopped.
type fakeLogs struct {
	stopped chan string // the container whose followed read ended
}

func (f *fakeLogs) Logs(ctx context.Context, engine, ctr string, opt container.LogsOptions, emit func(container.LogLine)) error {
	if ctr == "gone" {
		return errors.New("docker: GET /containers/gone/json: 404 No such container: gone")
	}
	for i := range opt.Tail {
		emit(container.LogLine{Stream: "stdout", Text: fmt.Sprintf("%s/%s line %d", engine, ctr, i)})
	}
	emit(container.LogLine{Stream: "stderr", Text: "warning"})
	if !opt.Follow {
		return nil
	}
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			f.stopped <- ctr
			return nil
		case <-time.After(5 * time.Millisecond):
			emit(container.LogLine{Stream: "stdout", Text: fmt.Sprintf("new %d", i)})
		}
	}
}

// Container logs travel from the agent's engine to the server: the end of
// a log, a followed log until the reader goes away (which stops the agent
// reading it), and errors.
func TestContainerLogs(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	stateDir := t.TempDir()
	if _, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "1.0", clusterSelf{}); err != nil {
		t.Fatal(err)
	}
	st, _ := agent.LoadState(stateDir)
	logs := &fakeLogs{stopped: make(chan string, 1)}
	a := &agent.Agent{Server: e.addr, State: st, Env: clusterSelf{}, Version: "1.0", Log: quiet,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, ContainerLogs: logs}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	defer func() { cancel(); <-done }()

	var hostID string
	eventually(t, "agent online", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || !hosts[0].Connected {
			return false
		}
		hostID = hosts[0].ID
		return true
	})

	read := func(req model.ContainerLogsRequest) (lines []model.ContainerLogLine, final model.ContainerLogEvent) {
		t.Helper()
		rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
		defer rcancel()
		events, err := e.gw.StreamContainerLogs(rctx, hostID, req)
		if err != nil {
			t.Fatal(err)
		}
		for ev := range events {
			lines = append(lines, ev.Lines...)
			final = ev
		}
		return lines, final
	}
	lines, final := read(model.ContainerLogsRequest{Engine: "podman:alice", Container: "web", Tail: 3})
	if !final.Done || final.Error != "" || len(lines) != 4 || lines[0].Text != "podman:alice/web line 0" || lines[3].Stream != "stderr" {
		t.Fatalf("tail: %+v %+v", lines, final)
	}
	if _, final := read(model.ContainerLogsRequest{Engine: "docker", Container: "gone"}); !final.Done ||
		final.Error != "docker: GET /containers/gone/json: 404 No such container: gone" {
		t.Fatalf("missing container: %+v", final)
	}

	// Following: new lines arrive until the reader stops.
	rctx, rcancel := context.WithCancel(ctx)
	events, err := e.gw.StreamContainerLogs(rctx, hostID, model.ContainerLogsRequest{Engine: "docker", Container: "follow", Tail: 1, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	timeout := time.After(10 * time.Second)
	for n < 10 {
		select {
		case ev := <-events:
			for _, l := range ev.Lines {
				if l.Text == fmt.Sprintf("new %d", n) {
					n++
				}
			}
		case <-timeout:
			t.Fatalf("only %d new lines", n)
		}
	}
	rcancel()
	select {
	case ctr := <-logs.stopped:
		if ctr != "follow" {
			t.Fatalf("stopped %s", ctr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent kept reading a log nobody follows")
	}

	// A host whose agent isn't connected isn't asked.
	if _, err := e.gw.StreamContainerLogs(ctx, "no-such-host", model.ContainerLogsRequest{}); !errors.Is(err, gateway.ErrAgentOffline) {
		t.Fatalf("offline host: %v", err)
	}
}

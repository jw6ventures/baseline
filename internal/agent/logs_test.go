package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/agent/container"
)

// floodLogs writes lines as fast as it can until told to stop, or n lines.
type floodLogs struct {
	n     int
	block chan struct{} // closed: return
}

func (f *floodLogs) Logs(ctx context.Context, _, _ string, _ container.LogsOptions, emit func(container.LogLine)) error {
	line := strings.Repeat("x", 1000)
	for range f.n {
		emit(container.LogLine{Stream: "stdout", Text: line})
	}
	select {
	case <-f.block:
	case <-ctx.Done():
	}
	return nil
}

// A container that writes faster than the server reads has lines dropped
// and counted rather than held without bound, chunks stay small, and the
// log ends with a final chunk.
func TestLogsBacklog(t *testing.T) {
	f := &floodLogs{n: 5000, block: make(chan struct{})}
	a := &Agent{ContainerLogs: f}
	out := make(chan *agentv1.LogChunk) // nobody reads yet
	var streams logStreams
	ctx := context.Background()
	a.startLogs(ctx, &streams, &agentv1.StartLogs{RequestId: "r1", Engine: "docker", Container: "noisy", Tail: 10, Follow: true}, out)
	time.Sleep(300 * time.Millisecond) // the flood is buffered, then dropped
	close(f.block)
	var lines, dropped uint64
	var seq uint64
	for c := range out {
		if c.GetSeq() != seq+1 {
			t.Fatalf("seq %d after %d", c.GetSeq(), seq)
		}
		seq = c.GetSeq()
		size := 0
		for _, l := range c.GetLines() {
			size += len(l.GetText())
		}
		if size > logChunkBytes {
			t.Fatalf("chunk of %d bytes", size)
		}
		lines += uint64(len(c.GetLines()))
		dropped += c.GetDropped()
		if c.GetDone() {
			break
		}
	}
	// At most the backlog and the chunk being sent were held.
	if lines+dropped != 5000 || dropped == 0 || lines*1000 > logBacklogBytes+2*logChunkBytes {
		t.Fatalf("%d lines sent, %d dropped", lines, dropped)
	}
	// The stream forgets the log once its last chunk is sent.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		streams.mu.Lock()
		n := len(streams.running)
		streams.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the log is still marked running")
		}
	}
}

// Logs off, and too many at once, are refused with a final chunk.
func TestLogsRefused(t *testing.T) {
	ctx := context.Background()
	out := make(chan *agentv1.LogChunk, 1)
	var streams logStreams
	(&Agent{}).startLogs(ctx, &streams, &agentv1.StartLogs{RequestId: "off"}, out)
	if c := <-out; !c.GetDone() || !strings.Contains(c.GetError(), "container_logs = off") {
		t.Fatalf("logs off: %v", c)
	}
	f := &floodLogs{block: make(chan struct{})}
	defer close(f.block)
	a := &Agent{ContainerLogs: f}
	for i := range maxLogStreams {
		a.startLogs(ctx, &streams, &agentv1.StartLogs{RequestId: string(rune('a' + i)), Follow: true}, out)
	}
	a.startLogs(ctx, &streams, &agentv1.StartLogs{RequestId: "one-too-many", Follow: true}, out)
	if c := <-out; c.GetRequestId() != "one-too-many" || !c.GetDone() || !strings.Contains(c.GetError(), "as many logs as it allows") {
		t.Fatalf("too many: %v", c)
	}
	streams.stop("a")
}

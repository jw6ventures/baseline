package agent

import (
	"context"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/agent/container"
)

// LogReader reads container logs for the server
// (collect.ContainerCollector).
type LogReader interface {
	Logs(ctx context.Context, engine, ctr string, opt container.LogsOptions, emit func(container.LogLine)) error
}

const (
	// maxLogStreams bounds the logs read at once; more are refused.
	maxLogStreams = 8
	// maxLogFollow bounds a followed log whatever the server asks.
	maxLogFollow = time.Hour
	// maxLogTail bounds the lines read from the end.
	maxLogTail = 5000
	// logFlushEvery is how often lines are sent while a log is followed.
	logFlushEvery = 250 * time.Millisecond
	// logChunkBytes is about the most text one LogChunk carries.
	logChunkBytes = 64 << 10
	// logBacklogBytes is how much text waits for the server before lines
	// are dropped (and counted), so a noisy container can't hold up the
	// agent's stream or its memory.
	logBacklogBytes = 1 << 20
)

// logStreams are the logs being read, by request ID.
type logStreams struct {
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

func (l *logStreams) stop(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cancel := l.running[id]; cancel != nil {
		cancel()
	}
}

// startLogs reads a container's log for the server in the background,
// sending its LogChunks to out until the log ends, the server stops it,
// or the session ends (sessCtx).
func (a *Agent) startLogs(sessCtx context.Context, streams *logStreams, req *agentv1.StartLogs, out chan<- *agentv1.LogChunk) {
	id := req.GetRequestId()
	fail := func(msg string) {
		go func() {
			select {
			case out <- &agentv1.LogChunk{RequestId: id, Seq: 1, Done: true, Error: msg}:
			case <-sessCtx.Done():
			}
		}()
	}
	if a.ContainerLogs == nil {
		fail("container logs are off in this host's agent.conf (container_logs = off)")
		return
	}
	streams.mu.Lock()
	if streams.running == nil {
		streams.running = map[string]context.CancelFunc{}
	}
	if _, dup := streams.running[id]; dup {
		streams.mu.Unlock()
		return
	}
	if len(streams.running) >= maxLogStreams {
		streams.mu.Unlock()
		fail("this host's agent is already streaming as many logs as it allows; close one and try again")
		return
	}
	follow := min(time.Duration(req.GetMaxSeconds())*time.Second, maxLogFollow)
	if follow <= 0 {
		follow = maxLogFollow
	}
	readCtx, cancel := context.WithTimeout(sessCtx, follow)
	streams.running[id] = cancel
	streams.mu.Unlock()

	go func() {
		defer func() {
			streams.mu.Lock()
			delete(streams.running, id)
			streams.mu.Unlock()
			cancel()
		}()
		a.streamLogs(sessCtx, readCtx, req, out)
	}()
}

// streamLogs reads one log under readCtx and sends it in chunks.
func (a *Agent) streamLogs(sessCtx, readCtx context.Context, req *agentv1.StartLogs, out chan<- *agentv1.LogChunk) {
	var (
		mu      sync.Mutex
		pending []*agentv1.LogLine
		size    int
		dropped uint64
	)
	full := make(chan struct{}, 1)
	emit := func(l container.LogLine) {
		mu.Lock()
		if size >= logBacklogBytes {
			dropped++
		} else {
			pending = append(pending, &agentv1.LogLine{Stream: l.Stream, Text: l.Text})
			size += len(l.Text)
		}
		big := size >= logChunkBytes
		mu.Unlock()
		if big {
			select {
			case full <- struct{}{}:
			default:
			}
		}
	}
	opt := container.LogsOptions{Tail: min(int(req.GetTail()), maxLogTail), Follow: req.GetFollow()}
	readErr := make(chan error, 1)
	go func() {
		readErr <- a.ContainerLogs.Logs(readCtx, req.GetEngine(), req.GetContainer(), opt, emit)
	}()

	var seq uint64
	// send sends what is pending, a chunk at a time; with done it sends
	// everything and then the final chunk.
	send := func(done bool, errMsg string) bool {
		for {
			mu.Lock()
			var lines []*agentv1.LogLine
			n := 0
			for len(pending) > 0 && (n == 0 || n+len(pending[0].Text) <= logChunkBytes) {
				n += len(pending[0].Text)
				lines = append(lines, pending[0])
				pending = pending[1:]
			}
			size -= n
			d := dropped
			dropped = 0
			last := len(pending) == 0
			mu.Unlock()
			if len(lines) == 0 && d == 0 && !done {
				return true
			}
			seq++
			c := &agentv1.LogChunk{RequestId: req.GetRequestId(), Seq: seq, Lines: lines, Dropped: d}
			if done && last {
				c.Done, c.Error = true, errMsg
			}
			select {
			case out <- c:
			case <-sessCtx.Done():
				return false
			}
			if last {
				return true
			}
		}
	}

	tick := time.NewTicker(logFlushEvery)
	defer tick.Stop()
	for {
		select {
		case err := <-readErr:
			msg := ""
			if err != nil {
				msg = err.Error()
				a.logf(jw6_utils.Warn, "reading the log of %s/%s for the server: %v", req.GetEngine(), req.GetContainer(), err)
			}
			send(true, msg)
			return
		case <-full:
			if !send(false, "") {
				return
			}
		case <-tick.C:
			if !send(false, "") {
				return
			}
		}
	}
}

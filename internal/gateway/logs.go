package gateway

import (
	"context"
	"crypto/rand"
	"slices"
	"sync"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/model"
)

// maxLogQueue is how much log text waits for a slow reader (a browser on
// a poor connection) before lines are dropped and counted.
const maxLogQueue = 2 << 20

// logStream is a container log the server asked an agent for.
type logStream struct {
	agentID string
	wake    chan struct{}

	mu      sync.Mutex
	queue   []model.ContainerLogEvent
	size    int
	dropped uint64 // dropped here, to report with the next event
	done    bool   // the final chunk arrived
}

// StreamContainerLogs has a host's agent read a container's log and passes
// it on as it arrives. The channel is closed after the final event (Done)
// or when ctx ends, which also tells the agent to stop. Logs pass through
// and are never stored.
func (g *Gateway) StreamContainerLogs(ctx context.Context, hostID string, req model.ContainerLogsRequest) (<-chan model.ContainerLogEvent, error) {
	g.mu.Lock()
	var sess *session
	for _, s := range g.sessions {
		if s.hostID == hostID {
			sess = s
		}
	}
	if sess == nil {
		g.mu.Unlock()
		return nil, ErrAgentOffline
	}
	if !slices.Contains(sess.caps, model.CapContainerLogs) {
		g.mu.Unlock()
		return nil, ErrNoLogs
	}
	id := rand.Text()
	ls := &logStream{agentID: sess.agentID, wake: make(chan struct{}, 1)}
	g.logs[id] = ls
	g.mu.Unlock()
	unregister := func() {
		g.mu.Lock()
		delete(g.logs, id)
		g.mu.Unlock()
	}

	start := &agentv1.StartLogs{RequestId: id, Engine: req.Engine, Container: req.Container,
		Tail: uint32(max(req.Tail, 0)), Follow: req.Follow, MaxSeconds: uint32(max(req.MaxSeconds, 0))}
	if !g.Send(sess.agentID, &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_StartLogs{StartLogs: start}}) {
		unregister()
		return nil, ErrAgentOffline
	}
	out := make(chan model.ContainerLogEvent)
	go func() {
		defer close(out)
		defer unregister()
		for {
			ls.mu.Lock()
			if len(ls.queue) > 0 {
				ev := ls.queue[0]
				ls.queue = ls.queue[1:]
				for _, l := range ev.Lines {
					ls.size -= len(l.Text)
				}
				ls.mu.Unlock()
				select {
				case out <- ev:
					if ev.Done {
						return
					}
					continue
				case <-ctx.Done():
				}
			} else {
				ls.mu.Unlock()
				select {
				case <-ls.wake:
					continue
				case <-sess.ctx.Done():
					select {
					case out <- model.ContainerLogEvent{Done: true, Error: "the host's agent disconnected"}:
					case <-ctx.Done():
					}
					return
				case <-ctx.Done():
				}
			}
			// The reader went away: tell the agent to stop reading.
			go g.Send(sess.agentID, &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_StopLogs{StopLogs: &agentv1.StopLogs{RequestId: id}}})
			return
		}
	}()
	return out, nil
}

// logChunk queues a chunk for the log waiting for it. Chunks for logs that
// weren't asked of this agent are dropped.
func (g *Gateway) logChunk(sess *session, c *agentv1.LogChunk) {
	g.mu.Lock()
	ls := g.logs[c.GetRequestId()]
	g.mu.Unlock()
	if ls == nil || ls.agentID != sess.agentID {
		if !c.GetDone() {
			g.logf(jw6_utils.Debug, "agent %s sent log lines nobody is reading; stopping them", sess.agentID)
			go g.Send(sess.agentID, &agentv1.ServerMessage{Msg: &agentv1.ServerMessage_StopLogs{StopLogs: &agentv1.StopLogs{RequestId: c.GetRequestId()}}})
		}
		return
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.done {
		return
	}
	n := 0
	for _, l := range c.GetLines() {
		n += len(l.GetText())
	}
	if !c.GetDone() && ls.size+n > maxLogQueue {
		ls.dropped += uint64(len(c.GetLines())) + c.GetDropped()
		return
	}
	ev := model.ContainerLogEvent{Dropped: ls.dropped + c.GetDropped(), Done: c.GetDone(), Error: c.GetError()}
	ls.dropped = 0
	for _, l := range c.GetLines() {
		ev.Lines = append(ev.Lines, model.ContainerLogLine{Stream: l.GetStream(), Text: l.GetText()})
	}
	ls.size += n
	ls.done = c.GetDone()
	ls.queue = append(ls.queue, ev)
	select {
	case ls.wake <- struct{}{}:
	default:
	}
}

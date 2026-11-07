package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Container logs are read from the host's agent when someone asks, shown or
// streamed as they arrive, and never stored. They may hold anything the
// application prints, so reading them needs the operator role on the host,
// and each read is audited, like Kubernetes pod logs.

// ContainerLogStreamer has a host's agent read a container's log
// (internal/gateway).
type ContainerLogStreamer interface {
	StreamContainerLogs(ctx context.Context, hostID string, req model.ContainerLogsRequest) (<-chan model.ContainerLogEvent, error)
}

// SetContainerLogs lets the server read container logs through agents.
func (s *Server) SetContainerLogs(l ContainerLogStreamer) { s.ctrLogs = l }

const (
	// ctrLogReadTimeout bounds reading the end of a log (not followed).
	ctrLogReadTimeout = 30 * time.Second
	// ctrLogFollowFor is how long a followed log streams before it stops;
	// the page offers to start it again.
	ctrLogFollowFor = 30 * time.Minute
	// ctrLogMaxBytes caps the text a read that isn't followed returns.
	ctrLogMaxBytes = 4 << 20
)

// logTail reads the tail parameter: the default when absent, capped.
func logTail(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("tail"))
	if err != nil || n < 0 {
		return model.DefaultContainerLogLines
	}
	return min(n, model.MaxContainerLogLines)
}

// streamCtrLogs checks the host can read the container's log, audits the
// read and starts it.
func (s *Server) streamCtrLogs(ctx context.Context, r *http.Request, c store.ContainerRow, h store.Host, tail int, follow bool, via string) (<-chan model.ContainerLogEvent, error) {
	switch {
	case s.ctrLogs == nil:
		return nil, errors.New("the server can't reach agents")
	case !h.Connected:
		return nil, errors.New("the host's agent is offline")
	case !slices.Contains(h.Capabilities, model.CapContainerLogs):
		return nil, errors.New("the host's agent doesn't read container logs: it is too old, or container_logs is off in its agent.conf")
	}
	if err := s.store.Audit(r.Context(), s.actor(r), store.AuditEvent{Action: "container.logs_view", ObjectType: "ci", ObjectID: c.CIID,
		Details: map[string]any{"host": h.ID, "engine": c.Engine, "container": c.Name, "tail": tail, "follow": follow, "via": via}}); err != nil {
		return nil, err
	}
	req := model.ContainerLogsRequest{Engine: c.Engine, Container: c.Name, Tail: tail, Follow: follow}
	if follow {
		req.MaxSeconds = int(ctrLogFollowFor / time.Second)
	}
	return s.ctrLogs.StreamContainerLogs(ctx, h.ID, req)
}

// ctrLogs is a container log read to its end.
type ctrLogs struct {
	Lines     []model.ContainerLogLine
	Dropped   uint64
	Truncated bool // more than ctrLogMaxBytes
}

// readCtrLogs reads the end of a container's log.
func (s *Server) readCtrLogs(r *http.Request, c store.ContainerRow, h store.Host, tail int, via string) (ctrLogs, error) {
	var out ctrLogs
	ctx, cancel := context.WithTimeout(r.Context(), ctrLogReadTimeout)
	defer cancel()
	events, err := s.streamCtrLogs(ctx, r, c, h, tail, false, via)
	if err != nil {
		return out, err
	}
	size := 0
	for ev := range events {
		out.Dropped += ev.Dropped
		for _, l := range ev.Lines {
			if size += len(l.Text); size > ctrLogMaxBytes {
				out.Truncated = true
				break
			}
			out.Lines = append(out.Lines, l)
		}
		if ev.Error != "" {
			return out, errors.New(ev.Error)
		}
		if ev.Done || out.Truncated {
			return out, nil
		}
	}
	if ctx.Err() != nil {
		return out, errors.New("the host's agent didn't send the log in time")
	}
	return out, nil
}

// Page -----------------------------------------------------------------------

type ctrLogsView struct {
	C      store.ContainerRow
	Host   store.Host
	Tail   int
	Follow bool
	Logs   *ctrLogs
	Error  string
	// Minutes is how long a followed log streams.
	Minutes int
}

// containerLogs shows the end of a container's log, or with follow, a page
// that streams it (logs.js, from containerLogEvents).
func (s *Server) containerLogs(w http.ResponseWriter, r *http.Request) {
	c, h, ok := s.loadContainer(w, r, rbac.Operator)
	if !ok {
		return
	}
	v := ctrLogsView{C: c, Host: h, Tail: logTail(r), Follow: r.URL.Query().Get("follow") != "", Minutes: int(ctrLogFollowFor / time.Minute)}
	if !v.Follow {
		logs, err := s.readCtrLogs(r, c, h, v.Tail, "page")
		if err != nil {
			v.Error = err.Error()
		}
		v.Logs = &logs
	}
	s.pages.render(w, http.StatusOK, "container_logs", s.data(r, c.Name+" logs", v))
}

// containerLogEvents follows a container's log as Server-Sent Events:
// "lines" events ({"l": [{"s": stream, "t": text}], "d": dropped}) and a
// final "done" ({"error": ...}). It doesn't resume after a reconnect: the
// page starts a new read instead.
func (s *Server) containerLogEvents(w http.ResponseWriter, r *http.Request) {
	c, h, ok := s.loadContainer(w, r, rbac.Operator)
	if !ok {
		return
	}
	ctx := r.Context()
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // the server's write timeout would cut the stream
	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream")
	hdr.Set("Cache-Control", "no-cache")
	hdr.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// No retry: an EventSource that reconnected would read the tail again.
	fmt.Fprint(w, "retry: 86400000\n\n")

	done := func(msg string) {
		b, _ := json.Marshal(map[string]string{"error": msg})
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", b)
		rc.Flush()
	}
	events, err := s.streamCtrLogs(ctx, r, c, h, logTail(r), true, "page")
	if err != nil {
		done(err.Error())
		return
	}
	rc.Flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			// A comment keeps proxies from closing a quiet stream.
			fmt.Fprint(w, ": ping\n\n")
			if rc.Flush() != nil {
				return
			}
		case ev, open := <-events:
			if !open {
				done("")
				return
			}
			if len(ev.Lines) > 0 || ev.Dropped > 0 {
				b, _ := json.Marshal(struct {
					L []model.ContainerLogLine `json:"l"`
					D uint64                   `json:"d,omitempty"`
				}{ev.Lines, ev.Dropped})
				fmt.Fprintf(w, "event: lines\ndata: %s\n\n", b)
			}
			if ev.Done {
				done(ev.Error)
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

// API ------------------------------------------------------------------------

// containerLogsJSON is GET /containers/{id}/logs without follow.
type containerLogsJSON struct {
	Container string                   `json:"container"`
	Lines     []model.ContainerLogLine `json:"lines"`
	Dropped   uint64                   `json:"dropped,omitempty"`
	Truncated bool                     `json:"truncated,omitempty"`
}

// apiContainerLogs is GET /containers/{id}/logs?tail=&follow=1. Without
// follow it answers the end of the log as JSON; with it, it streams the
// log as newline-delimited JSON objects, {"s": stream, "t": text} per line,
// {"dropped": n} when lines were left out, and a last {"done": true} with
// "error" when the log couldn't be read.
func (s *Server) apiContainerLogs(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetContainer(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	var h store.Host
	if err == nil {
		h, err = s.apiLoadHost(r, c.HostID, rbac.Operator)
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	tail := logTail(r)
	if !queryBool(r, "follow") {
		logs, err := s.readCtrLogs(r, c, h, tail, "api")
		if err != nil {
			s.respond(w, r, nil, failf(http.StatusBadGateway, "%s", err))
			return
		}
		if logs.Lines == nil {
			logs.Lines = []model.ContainerLogLine{}
		}
		writeJSON(w, http.StatusOK, containerLogsJSON{Container: c.CIID, Lines: logs.Lines, Dropped: logs.Dropped, Truncated: logs.Truncated})
		return
	}
	ctx := r.Context()
	events, err := s.streamCtrLogs(ctx, r, c, h, tail, true, "api")
	if err != nil {
		s.respond(w, r, nil, failf(http.StatusBadGateway, "%s", err))
		return
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	rc.Flush()
	for ev := range events {
		if ev.Dropped > 0 {
			enc.Encode(map[string]uint64{"dropped": ev.Dropped})
		}
		for _, l := range ev.Lines {
			enc.Encode(l)
		}
		if ev.Done {
			end := map[string]any{"done": true}
			if ev.Error != "" {
				end["error"] = ev.Error
			}
			enc.Encode(end)
		}
		if rc.Flush() != nil {
			return
		}
	}
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Jobs is the dispatcher (internal/jobs) as the web UI uses it.
type Jobs interface {
	Nudge()
	Cancel(refs []store.JobRef)
	Watch(jobID string) (<-chan struct{}, func())
}

// SetJobs connects the dispatcher.
func (s *Server) SetJobs(j Jobs) { s.jobs = j }

type jobListView struct {
	List *listView
}

var jobFilters = map[string][]string{
	"open":   {store.JobQueued, store.JobDispatched, store.JobRunning},
	"failed": {store.JobFailed, store.JobTimedOut, store.JobRejected},
	"all":    nil,
}

func (s *Server) jobList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "job")
	if !ok {
		return
	}
	s.renderList(w, r, "jobs", "Jobs", jobListView{List: v}, v)
}

// loadJob fetches the job in the path, if the user may see its host.
func (s *Server) loadJob(w http.ResponseWriter, r *http.Request) (store.Job, store.Host, bool) {
	j, err := s.store.GetJob(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such job.")
		return j, store.Host{}, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return j, store.Host{}, false
	}
	h, err := s.store.GetHost(r.Context(), j.HostID)
	if err != nil {
		s.serverError(w, r, err)
		return j, h, false
	}
	if !principal(r).Grants.HasOn(rbac.Viewer, h.GroupIDs) {
		s.errorPage(w, r, http.StatusNotFound, "No such job.")
		return j, h, false
	}
	return j, h, true
}

type jobView struct {
	Job     store.Job
	Host    store.Host
	Online  bool
	Output  []store.OutputChunk
	LastID  int64
	More    bool // output beyond what the page shows
	Upgrade *action.UpgradeResult
	Params  map[string]any
}

// pageOutput is how much output the job page renders; the rest is in the
// raw download.
const pageOutput = 4000

func (s *Server) jobPage(w http.ResponseWriter, r *http.Request) {
	j, h, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	v := jobView{Job: j, Host: h, Online: s.hub != nil && s.hub.Online(h.AgentID)}
	var err error
	if v.Output, err = s.store.JobOutput(r.Context(), j.ID, 0, pageOutput+1); err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(v.Output) > pageOutput {
		v.Output, v.More = v.Output[:pageOutput], true
	}
	if n := len(v.Output); n > 0 {
		v.LastID = v.Output[n-1].ID
	}
	if j.Action == action.PkgUpgrade && len(j.Result) > 0 {
		var u action.UpgradeResult
		if json.Unmarshal(j.Result, &u) == nil {
			v.Upgrade = &u
		}
	}
	json.Unmarshal(j.Params, &v.Params)
	s.pages.render(w, http.StatusOK, "job", s.data(r, j.Summary()+" on "+h.DisplayName(), v))
}

// jobRaw serves the whole output as text.
func (s *Server) jobRaw(w http.ResponseWriter, r *http.Request) {
	j, h, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="job-%s-%s.txt"`, h.DisplayName(), j.ID[:8]))
	var after int64
	for {
		chunks, err := s.store.JobOutput(r.Context(), j.ID, after, 1000)
		if err != nil {
			return
		}
		for _, c := range chunks {
			fmt.Fprint(w, c.Chunk)
			after = c.ID
		}
		if len(chunks) < 1000 {
			return
		}
	}
}

// jobEvents streams a job's output and state as Server-Sent Events until it
// ends. Each output event carries the chunk's ID, so a reconnecting
// EventSource resumes where it left off (Last-Event-ID).
func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request) {
	j, _, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // the server's write timeout would cut the stream
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	last, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	if last == 0 {
		last, _ = strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	}
	var watch <-chan struct{}
	if s.jobs != nil {
		ch, stop := s.jobs.Watch(j.ID)
		defer stop()
		watch = ch
	}
	state := r.URL.Query().Get("state")
	for {
		chunks, err := s.store.JobOutput(ctx, j.ID, last, 500)
		if err != nil {
			return
		}
		for _, c := range chunks {
			b, _ := json.Marshal(map[string]string{"s": c.Stream, "t": c.Chunk})
			fmt.Fprintf(w, "id: %d\nevent: output\ndata: %s\n\n", c.ID, b)
			last = c.ID
		}
		cur, err := s.store.GetJob(ctx, j.ID)
		if err != nil {
			return
		}
		if cur.State != state {
			state = cur.State
			b, _ := json.Marshal(map[string]any{"state": cur.State, "final": cur.Final(), "reboot": cur.AwaitingReboot})
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		}
		if err := rc.Flush(); err != nil {
			return
		}
		if len(chunks) == 500 {
			continue
		}
		if cur.Final() {
			fmt.Fprint(w, "event: done\ndata: {}\n\n")
			rc.Flush()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-watch:
		case <-time.After(15 * time.Second):
			// A comment keeps proxies from closing an idle stream, and
			// the state is read again in case a notification was missed.
			fmt.Fprint(w, ": ping\n\n")
		}
	}
}

// jobStateClass maps a job state to a tag style.
func jobStateClass(state string) string {
	switch state {
	case store.JobSucceeded:
		return "ok"
	case store.JobFailed, store.JobTimedOut, store.JobRejected, store.JobRolledBack:
		return "warn"
	case store.JobRunning, store.JobDispatched:
		return "caution"
	}
	return ""
}

// changeStateClass maps a change state to a tag style.
func changeStateClass(state string) string {
	switch state {
	case store.ChangeImplemented, store.ChangeClosed:
		return "ok"
	case store.ChangeFailed, store.ChangeRejected, store.ChangeRolledBack:
		return "warn"
	case store.ChangeSubmitted, store.ChangeInProgress, store.ChangeApproved, store.ChangeScheduled, store.ChangeReview:
		return "caution"
	}
	return ""
}

// humanState turns in_progress into "in progress".
func humanState(s string) string { return strings.ReplaceAll(s, "_", " ") }

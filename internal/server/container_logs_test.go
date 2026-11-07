package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// fakeCtrLogs answers log reads the way a host's agent would, and records
// what was asked.
type fakeCtrLogs struct {
	mu   sync.Mutex
	reqs []model.ContainerLogsRequest
}

func (f *fakeCtrLogs) StreamContainerLogs(ctx context.Context, hostID string, req model.ContainerLogsRequest) (<-chan model.ContainerLogEvent, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if req.Container == "offline" {
		return nil, errors.New("the host's agent isn't connected")
	}
	out := make(chan model.ContainerLogEvent)
	go func() {
		defer close(out)
		evs := []model.ContainerLogEvent{
			{Lines: []model.ContainerLogLine{{Stream: "stdout", Text: "2026-11-07T10:00:00Z GET / 200"}, {Stream: "stderr", Text: "<b>oops</b>"}}},
			{Dropped: 3, Lines: []model.ContainerLogLine{{Stream: "stdout", Text: "later"}}},
			{Done: true},
		}
		if req.Follow {
			evs[2].Error = "the host's agent disconnected"
		}
		for _, ev := range evs {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (f *fakeCtrLogs) last() model.ContainerLogsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

// Container logs: operators read the end of a log or follow it, viewers
// can't, every read is audited, and the API serves both.
func TestContainerLogsPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fake := &fakeCtrLogs{}
	h.srv.SetContainerLogs(fake)
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	h.ingest(plex, model.SectionContainers, containersFixture())
	h.connect(plex, []string{"docker", model.CapContainerLogs}, nil)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	ops := h.signIn("carl", "media-ops")
	viewer := h.signIn("vera", "viewers")

	_, body := h.list(ops, "/containers")
	cpath := firstLink(t, body, `/containers/[0-9a-f-]{36}`)
	if _, body := h.do(ops, "GET", cpath, nil); !strings.Contains(body, cpath+`/logs">Logs</a>`) {
		t.Fatalf("container page lacks Logs:\n%s", body)
	}
	if _, body := h.do(viewer, "GET", cpath, nil); strings.Contains(body, ">Logs</a>") {
		t.Fatal("a viewer is offered logs")
	}
	if resp, _ := h.do(viewer, "GET", cpath+"/logs", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer read logs: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "GET", cpath+"/logs/events", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer followed logs: %d", resp.StatusCode)
	}

	// The end of the log, escaped, with stderr marked.
	_, body = h.do(ops, "GET", cpath+"/logs?tail=50", nil)
	for _, want := range []string{`<span class="stdout">2026-11-07T10:00:00Z GET / 200`, `<span class="stderr">&lt;b&gt;oops&lt;/b&gt;`,
		"3 lines were left out", "later"} {
		if !strings.Contains(body, want) {
			t.Fatalf("logs page lacks %q:\n%s", want, body)
		}
	}
	if r := fake.last(); r.Engine != "docker" || r.Container != "media-plex-1" || r.Tail != 50 || r.Follow {
		t.Fatalf("read %+v", r)
	}
	if !strings.Contains(h.auditActions(), "container.logs_view") {
		t.Fatal("reading logs wasn't audited")
	}
	h.do(ops, "GET", cpath+"/logs?tail=999999", nil)
	if r := fake.last(); r.Tail != model.MaxContainerLogLines {
		t.Fatalf("tail not capped: %d", r.Tail)
	}

	// Following: the page streams from the events endpoint.
	_, body = h.do(ops, "GET", cpath+"/logs?tail=20&follow=1", nil)
	if !strings.Contains(body, `data-src="`+cpath+`/logs/events?tail=20"`) || !strings.Contains(body, "/static/logs.js") {
		t.Fatalf("follow page:\n%s", body)
	}
	resp, body := h.do(ops, "GET", cpath+"/logs/events?tail=20", nil)
	if resp.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(body, "event: lines\ndata: ") ||
		!strings.Contains(body, `\u003cb\u003eoops`) || !strings.Contains(body, `"d":3`) ||
		!strings.Contains(body, "event: done\ndata: {\"error\":\"the host's agent disconnected\"}") {
		t.Fatalf("events %s:\n%s", resp.Header.Get("Content-Type"), body)
	}
	if r := fake.last(); !r.Follow || r.Tail != 20 || r.MaxSeconds != 1800 {
		t.Fatalf("follow %+v", r)
	}

	// The API, with an operator token.
	token := h.mintToken(ops, "logs", "operator")
	id := strings.TrimPrefix(cpath, "/containers/")
	var got containerLogsJSON
	if resp := h.api(token, "GET", "/containers/"+id+"/logs?tail=5", nil, &got); resp.StatusCode != 200 ||
		len(got.Lines) != 3 || got.Dropped != 3 || got.Lines[1].Stream != "stderr" {
		t.Fatalf("api logs %d %+v", resp.StatusCode, got)
	}
	req, _ := http.NewRequest("GET", h.ts.URL+apiPrefix+"/containers/"+id+"/logs?follow=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	aresp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer aresp.Body.Close()
	if aresp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("follow content type %q", aresp.Header.Get("Content-Type"))
	}
	var objs []map[string]any
	sc := bufio.NewScanner(aresp.Body)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("ndjson line %q: %v", sc.Text(), err)
		}
		objs = append(objs, m)
	}
	if len(objs) != 5 || objs[0]["t"] != "2026-11-07T10:00:00Z GET / 200" || objs[2]["dropped"] != 3.0 ||
		objs[4]["done"] != true || objs[4]["error"] != "the host's agent disconnected" {
		t.Fatalf("ndjson %v", objs)
	}
	viewerToken := h.mintToken(viewer, "v", "viewer")
	if resp := h.api(viewerToken, "GET", "/containers/"+id+"/logs", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer api logs: %d", resp.StatusCode)
	}
}

// A host whose agent doesn't read logs says why instead of asking it.
func TestContainerLogsUnavailable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fake := &fakeCtrLogs{}
	h.srv.SetContainerLogs(fake)
	plex := h.addHost("plex")
	h.ingest(plex, model.SectionContainers, containersFixture())
	h.connect(plex, []string{"docker"}, nil)
	admin := h.signIn("ann", "lab-admins")
	_, body := h.list(admin, "/containers")
	cpath := firstLink(t, body, `/containers/[0-9a-f-]{36}`)
	if _, body := h.do(admin, "GET", cpath+"/logs", nil); !strings.Contains(body, "container_logs is off") {
		t.Fatalf("logs page:\n%s", body)
	}
	if len(fake.reqs) != 0 {
		t.Fatal("an agent without the capability was asked")
	}
	h.st.AgentDisconnected(ctx, plex.HostID)
	if _, body := h.do(admin, "GET", cpath+"/logs/events", nil); !strings.Contains(body, `event: done`) ||
		!strings.Contains(body, "offline") {
		t.Fatalf("offline events:\n%s", body)
	}
}

package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/inventory"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestActivityStream(t *testing.T) {
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	comments := []store.Comment{
		{Body: "first", At: t0.Add(time.Minute)},
		{Body: "note", Internal: true, At: t0.Add(3 * time.Minute)},
		{Body: "with transition", At: t0.Add(2 * time.Minute)},
	}
	history := []store.ItemEvent{ // newest first, as the store returns them
		{At: t0.Add(2 * time.Minute), Transition: "Start progress",
			Diff: inventory.Diff{Changed: []inventory.Change{{Field: "status", From: "To do", To: "In progress"}}}},
		{At: t0.Add(90 * time.Second), Migration: "workflow"},
		{At: t0, Initial: true},
	}
	all, filters, f := activityStream(comments, history, "bogus")
	if f != activityAll {
		t.Fatalf("filter %q", f)
	}
	var kinds []string
	for _, e := range all {
		kinds = append(kinds, e.Kind)
	}
	if got := strings.Join(kinds, " "); got != "note comment transition migration comment created" {
		t.Fatalf("order: %s", got)
	}
	if m := all[2].Move(); m == nil || m.To != "In progress" || !all[2].RestEmpty() {
		t.Fatalf("transition move: %+v", all[2])
	}
	counts := map[string]int{}
	for _, f := range filters {
		counts[f.Key] = f.Count
	}
	if counts[activityAll] != 6 || counts[activityComments] != 2 || counts[activityNotes] != 1 || counts[activityHistory] != 3 {
		t.Fatalf("counts: %v", counts)
	}
	notes, _, _ := activityStream(comments, history, activityNotes)
	if len(notes) != 1 || notes[0].Comment.Body != "note" {
		t.Fatalf("notes: %+v", notes)
	}
}

func TestWorkItemRecordView(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	admin := h.signIn("ann", "lab-admins")
	h.do(admin, "POST", "/projects", url.Values{"key": {"ops"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"]}, "default_type": {typeID["incident"]}})
	h.do(admin, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"NAS offline"},
		"priority": {"high"}, "due": {"2026-11-01"}})
	h.do(admin, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"Flaky PSU"}, "priority": {"low"}})

	// Header: key fields and transitions, nothing related yet.
	_, body := h.do(admin, "GET", "/work/OPS-1", nil)
	for _, want := range []string{`class="panel record-header"`, "<dt>Priority</dt>", "<dt>Due</dt><dd>2026-11-01</dd>",
		"Start progress → In progress", `aria-current="page">Configuration items</a>`, "None linked.", "Created"} {
		if !strings.Contains(body, want) {
			t.Fatalf("record view lacks %q:\n%s", want, body)
		}
	}

	h.do(admin, "POST", "/work/OPS-1/transition", url.Values{"transition": {h.transitionID("OPS-1", "Start progress")}})
	h.do(admin, "POST", "/work/OPS-1/comments", url.Values{"body": {"Rebooted it"}})
	h.do(admin, "POST", "/work/OPS-1/comments", url.Values{"body": {"PSU fan is loud"}, "internal": {"1"}})

	// Linking from a related list comes back to that list.
	resp, _ := h.do(admin, "POST", "/work/OPS-1/links", url.Values{"other": {"OPS-2"}, "kind": {"relates"},
		"direction": {"out"}, "rel": {"links"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=") || !strings.HasSuffix(loc, "&rel=links") {
		t.Fatalf("link item: %s", loc)
	}
	resp, _ = h.do(admin, "POST", "/work/OPS-1/links", url.Values{"other": {"OPS-2"}, "kind": {"relates"},
		"direction": {"out"}, "rel": {"nonsense"}})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "rel=") {
		t.Fatalf("unknown list kept: %s", loc)
	}

	// With nothing asked, the first list with rows opens.
	_, body = h.do(admin, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, `aria-current="page">Linked items (1)`) || !strings.Contains(body, "Flaky PSU") {
		t.Fatalf("default related list:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/work/OPS-1?rel=children", nil)
	if !strings.Contains(body, "Add a child item") || strings.Contains(body, "Link item</button>") {
		t.Fatalf("children list:\n%s", body)
	}

	// The activity stream mixes comments, work notes and history, newest first.
	for _, want := range []string{"<strong>Start progress</strong>: To do → In progress", "Rebooted it", "work note", "added link"} {
		if !strings.Contains(body, want) {
			t.Fatalf("activity lacks %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "PSU fan is loud") > strings.Index(body, "Rebooted it") ||
		strings.Index(body, "Rebooted it") > strings.Index(body, "<strong>Start progress</strong>") {
		t.Fatalf("activity order:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/work/OPS-1?rel=children&activity=notes", nil)
	if !strings.Contains(body, "PSU fan is loud") || strings.Contains(body, "Rebooted it") ||
		strings.Contains(body, "<strong>Start progress</strong>") {
		t.Fatalf("work notes only:\n%s", body)
	}
	// Filter links keep the open related list, and the other way round.
	if !strings.Contains(body, `href="/work/OPS-1?activity=history&amp;rel=children#activity"`) ||
		!strings.Contains(body, `href="/work/OPS-1?activity=notes&amp;rel=cis#related"`) {
		t.Fatalf("tab links:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/work/OPS-1?activity=history", nil)
	if strings.Contains(body, "Rebooted it") || !strings.Contains(body, "<strong>Start progress</strong>") {
		t.Fatalf("history only:\n%s", body)
	}
}

func TestSLAPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	h.do(admin, "POST", "/projects", url.Values{"key": {"ops"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"]}, "default_type": {typeID["incident"]}})

	if resp, _ := h.do(viewer, "GET", "/settings/slas", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saw SLA settings: %d", resp.StatusCode)
	}
	resp, body := h.do(admin, "POST", "/settings/slas", url.Values{"name": {"Incidents"}, "response_high": {"soon"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "durations such as") || !strings.Contains(body, `value="soon"`) {
		t.Fatalf("bad target: %d\n%s", resp.StatusCode, body)
	}
	resp, _ = h.do(admin, "POST", "/settings/slas", url.Values{"name": {"Incidents"}, "type": {typeID["incident"]}, "enabled": {"1"},
		"response_high": {"30m"}, "resolution_high": {"1d4h"}, "resolution_low": {"2d"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create policy: %d", resp.StatusCode)
	}
	resp, body = h.do(admin, "POST", "/settings/slas", url.Values{"name": {"Again"}, "type": {typeID["incident"]}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already covers") {
		t.Fatalf("same scope: %d", resp.StatusCode)
	}
	_, body = h.do(admin, "GET", "/settings/slas", nil)
	if !strings.Contains(body, "respond 30m") || !strings.Contains(body, "resolve 1d4h") || !strings.Contains(body, "resolve 2d") {
		t.Fatalf("policies:\n%s", body)
	}

	h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"NAS offline"}, "priority": {"high"}})
	_, body = h.do(viewer, "GET", "/work/OPS-1?rel=slas", nil)
	for _, want := range []string{"<dt>Response SLA</dt>", "<dt>Resolution SLA</dt>", `aria-current="page">SLAs (2)`,
		"<td>Incidents</td><td>30m</td>", `<span class="tag caution">running</span>`, "left"} {
		if !strings.Contains(body, want) {
			t.Fatalf("record view lacks %q:\n%s", want, body)
		}
	}
	h.do(viewer, "POST", "/work/OPS-1/transition", url.Values{"transition": {h.transitionID("OPS-1", "Start progress")}})
	_, body = h.do(viewer, "GET", "/work/OPS-1?rel=slas", nil)
	if strings.Contains(body, "<dt>Response SLA</dt>") || !strings.Contains(body, `<span class="tag ok">met</span>`) {
		t.Fatalf("response met:\n%s", body)
	}
	if !strings.Contains(h.auditActions(), "sla_policy.create") {
		t.Fatalf("audit: %s", h.auditActions())
	}
}

package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// transitionID is the ID of the transition called name out of the item's
// status.
func (h *harness) transitionID(ref, name string) string {
	h.t.Helper()
	it, err := h.st.GetWorkItemByRef(context.Background(), ref)
	if err != nil {
		h.t.Fatal(err)
	}
	ts, err := h.st.ItemTransitions(context.Background(), it)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, t := range ts {
		if t.Name == name {
			return t.ID
		}
	}
	h.t.Fatalf("%s has no transition %q out of %s", ref, name, it.StatusName)
	return ""
}

func TestWorkItemPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-viewers", Role: rbac.Viewer, ScopeGroupID: media.ID})
	web := h.addHost("web1")
	nas, err := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "nas", Name: "nas1", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}

	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")

	// Before there's a project, there's nothing to file into.
	if resp, _ := h.do(viewer, "GET", "/work/new", nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("new item without projects: %d", resp.StatusCode)
	}
	// Only admins set up projects and ticket types.
	if resp, _ := h.do(viewer, "POST", "/projects", url.Values{"key": {"OPS"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer created a project: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "GET", "/settings/ticket-types", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saw ticket type settings: %d", resp.StatusCode)
	}
	resp, body := h.do(admin, "POST", "/settings/ticket-types", url.Values{"key": {"Bad Key"}, "name": {"x"}, "base_kind": {"generic"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "lower-case") {
		t.Fatalf("bad type key: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/ticket-types", url.Values{"key": {"outage"}, "name": {"Outage"}, "base_kind": {"incident"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("new type: %d", resp.StatusCode)
	}

	resp, body = h.do(admin, "POST", "/projects", url.Values{"key": {"ops"}, "name": {"Operations"}, "kind": {"service_desk"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "at least one ticket type") {
		t.Fatalf("project without types: %d\n%s", resp.StatusCode, body)
	}
	resp, _ = h.do(admin, "POST", "/projects", url.Values{"key": {"ops"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"], typeID["problem"]}, "default_type": {typeID["incident"]}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/projects/OPS") {
		t.Fatalf("create project: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = h.do(admin, "POST", "/projects", url.Values{"key": {"OPS"}, "name": {"Again"}, "kind": {"software"},
		"types": {typeID["task"]}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate project: %d", resp.StatusCode)
	}

	// A viewer files an incident; the form offers the project's types.
	_, body = h.do(viewer, "GET", "/work/new?project=OPS", nil)
	if !strings.Contains(body, "Incident") || !strings.Contains(body, "Problem") || strings.Contains(body, ">Task<") {
		t.Fatalf("new item form:\n%s", body)
	}
	resp, body = h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {""}, "priority": {"high"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Enter a title") {
		t.Fatalf("no title: %d", resp.StatusCode)
	}
	resp, _ = h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["task"]}, "title": {"x"}, "priority": {"high"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("type not offered: %d", resp.StatusCode)
	}
	resp, _ = h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"NAS offline"},
		"description": {"No ping since 02:00"}, "priority": {"high"}, "impact": {"high"}, "due": {"2026-11-01"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/work/OPS-1?") {
		t.Fatalf("create item: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.do(admin, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["problem"]}, "title": {"Flaky PSU"}, "priority": {"medium"}})

	_, body = h.do(viewer, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, "NAS offline") || !strings.Contains(body, "No ping since 02:00") || !strings.Contains(body, "VIC") ||
		!strings.Contains(body, "2026-11-01") || !strings.Contains(body, "Stop watching") {
		t.Fatalf("item page:\n%s", body)
	}
	if resp, _ := h.do(viewer, "GET", "/work/OPS-99", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing item: %d", resp.StatusCode)
	}

	// Edit: assignee, parent; a parent loop is refused.
	var annID string
	users, _ := h.st.ListUsers(ctx)
	for _, u := range users {
		if u.OIDCSub == "ann" {
			annID = u.ID
		}
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1", url.Values{"title": {"NAS offline"}, "description": {"No ping since 02:00"},
		"priority": {"critical"}, "impact": {"high"}, "assignee": {annID}, "parent": {"ops-2"}, "due": {"2026-11-01"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit: %d", resp.StatusCode)
	}
	resp, body = h.do(viewer, "POST", "/work/OPS-2", url.Values{"title": {"Flaky PSU"}, "priority": {"medium"}, "parent": {"OPS-1"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "one below it") {
		t.Fatalf("parent loop: %d", resp.StatusCode)
	}
	_, body = h.do(viewer, "GET", "/work/OPS-2", nil)
	if !strings.Contains(body, `href="/work/OPS-1"`) { // a child
		t.Fatalf("parent page:\n%s", body)
	}

	// Status moves by the workflow's transitions, with a resolution when done.
	_, body = h.do(viewer, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, "Start progress → In progress") || !strings.Contains(body, "Done → Done") {
		t.Fatalf("transitions on the page:\n%s", body)
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/transition", url.Values{"transition": {h.transitionID("OPS-1", "Done")}, "resolution": {"nope"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bad resolution: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/transition", url.Values{"transition": {h.transitionID("OPS-1", "Start progress")}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=Now+In+progress") {
		t.Fatalf("start progress: %s", loc)
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/transition", url.Values{"transition": {h.transitionID("OPS-2", "Start progress")}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("another item's transition: %s", resp.Header.Get("Location"))
	}

	// Comments and work notes.
	h.do(viewer, "POST", "/work/OPS-1/comments", url.Values{"body": {"Rebooted it"}})
	h.do(viewer, "POST", "/work/OPS-1/comments", url.Values{"body": {"PSU fan is loud"}, "internal": {"1"}})

	// Links: an agentless CI, a host, a change and another item.
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/cis", url.Values{"ci": {nas}, "role": {"affected"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("link CI: %s", resp.Header.Get("Location"))
	}
	h.do(viewer, "POST", "/work/OPS-1/cis", url.Values{"ci": {web.HostID}, "role": {"caused_by"}})
	var annActor store.Actor
	annActor = store.UserActor(annID, "")
	c, err := h.st.CreateChange(ctx, annActor, store.NewChange{Title: "Replace PSU", Risk: action.Low, Concurrency: 1,
		Steps: []store.PlanStep{{Action: action.ServiceRestart, Params: []byte(`{"unit":"smb"}`), Summary: "restart", HostIDs: []string{web.HostID}}}})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/changes", url.Values{"change": {c.Ref()}, "kind": {"fixes"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("link change: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(viewer, "POST", "/work/OPS-1/links", url.Values{"other": {"OPS-2"}, "kind": {"caused_by"}, "direction": {"out"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("link item: %s", resp.Header.Get("Location"))
	}
	_, body = h.do(viewer, "GET", "/work/OPS-1", nil)
	for _, want := range []string{"In progress", "Rebooted it", "work note", "nas1", "web1", c.Ref(), "caused by", "OPS-2", "changed priority, assignee, parent"} {
		if !strings.Contains(body, want) {
			t.Fatalf("item page lacks %q:\n%s", want, body)
		}
	}

	// The CI and the change show the item.
	if _, body := h.do(viewer, "GET", "/cis/"+nas, nil); !strings.Contains(body, "OPS-1") {
		t.Fatalf("CI page:\n%s", body)
	}
	if _, body := h.do(viewer, "GET", "/changes/"+c.ID, nil); !strings.Contains(body, "OPS-1") {
		t.Fatalf("change page:\n%s", body)
	}

	// A user who can't see web1 sees the item but not the host or the change.
	scoped := h.signIn("sam", "media-viewers")
	_, body = h.do(scoped, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, "nas1") || strings.Contains(body, "web1") || strings.Contains(body, c.Ref()) {
		t.Fatalf("scoped item page:\n%s", body)
	}
	resp, _ = h.do(scoped, "POST", "/work/OPS-2/cis", url.Values{"ci": {web.HostID}, "role": {"affected"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("scoped user linked a hidden CI: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(scoped, "POST", "/work/OPS-2/changes", url.Values{"change": {c.Ref()}, "kind": {"fixes"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("scoped user linked a hidden change: %s", resp.Header.Get("Location"))
	}

	// Lists.
	_, body = h.list(viewer, "/work?assignee=me")
	if strings.Contains(body, "OPS-1") {
		t.Fatalf("assigned to vic:\n%s", body)
	}
	_, body = h.list(admin, "/work?assignee=me&project=ops")
	if !strings.Contains(body, "OPS-1") || strings.Contains(body, "Flaky PSU") {
		t.Fatalf("assigned to ann:\n%s", body)
	}
	_, body = h.do(viewer, "GET", "/projects", nil)
	if !strings.Contains(body, "Operations") || strings.Contains(body, "New project") {
		t.Fatalf("projects:\n%s", body)
	}

	// Archive the project: no new items.
	resp, _ = h.do(admin, "POST", "/projects/OPS", url.Values{"name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"], typeID["problem"]}, "archived": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("archive: %d", resp.StatusCode)
	}
	resp, _ = h.do(viewer, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"x"}, "priority": {"low"}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("archived project took an item: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "GET", "/work/OPS-3", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("OPS-3 exists: %d", resp.StatusCode)
	}

	for _, want := range []string{"ticket_type.create", "project.create", "work_item.create", "work_item.update", "work_item.transition",
		"work_item.comment", "work_item.link_ci", "work_item.link_change", "work_item.link", "project.update"} {
		if !strings.Contains(h.auditActions(), want) {
			t.Fatalf("audit lacks %s: %s", want, h.auditActions())
		}
	}
}

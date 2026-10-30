package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// list GETs a list page, following its redirect to the canonical URL.
func (h *harness) list(c *http.Client, path string, hdr ...string) (*http.Response, string) {
	h.t.Helper()
	for range 3 {
		resp, body := h.do(c, "GET", path, nil, hdr...)
		if resp.StatusCode != http.StatusSeeOther {
			if resp.StatusCode != http.StatusOK {
				h.t.Fatalf("GET %s: %d\n%s", path, resp.StatusCode, body)
			}
			return resp, body
		}
		path = resp.Header.Get("Location")
	}
	h.t.Fatalf("GET %s: redirect loop", path)
	return nil, ""
}

func TestListTablesAreValid(t *testing.T) {
	types := []store.CIType{{Key: "host", Label: "Host"}, {Key: "nas", Label: "NAS"}}
	var fields []store.FieldDef
	for _, ft := range store.FieldTypes {
		fields = append(fields, store.FieldDef{Key: "f_" + ft, Label: ft, Type: ft, Options: []string{"a", "b"}})
	}
	// A key the registry can't put in SQL is left out.
	fields = append(fields, store.FieldDef{Key: "x'; DROP TABLE ci; --", Label: "bad", Type: store.FieldText})
	work := workTable(nil, nil, nil, nil, fields, projectLabels{})
	if work.Field("cf_f_ci_ref") == nil || work.Field("cf_f_multiselect").Type != list.Tags || len(work.Fields) != len(workTable(nil, nil, nil, nil, nil, projectLabels{}).Fields)+len(store.FieldTypes) {
		t.Errorf("custom fields: %d fields", len(work.Fields))
	}
	for _, tb := range append([]*list.Table{hostTable, ciTable(types), changeTable, jobTable, workTable(nil, nil, nil, nil, nil, projectLabels{}), projectTable(projectLabels{}), work},
		goTables()...) {
		if err := tb.Validate(); err != nil {
			t.Error(err)
		}
	}
}

// goTables are the tables of the later lists, with values Go would have
// worked out (list.Lookup) for ids no row has.
func goTables() []*list.Table {
	id := map[string]string{"00000000-0000-0000-0000-000000000000": "x"}
	at := map[string]string{"00000000-0000-0000-0000-000000000000": "2026-10-01T02:00:00Z"}
	return []*list.Table{containerTable(id), stackTable, updateHostTable, packageTable, vmTable,
		windowTable(windowFacts{Schedule: id, Next: at, Closes: at, State: map[string]string{"x": "open"}}, true),
		modelTable(id), alertTable, auditTable}
}

// Every field of every table runs: filtered, sorted and grouped by, as
// the database sees it.
func TestListFieldsRunInSQL(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.addHost("plex", media.ID)
	types, err := h.st.CITypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// One custom field of each type, and an item whose values are all
	// wrong for their types: the guards read them as empty.
	ticketTypes, _ := h.st.ListTicketTypes(ctx)
	if _, err := h.st.CreateProject(ctx, store.System, store.ProjectInput{Key: "OPS", Name: "Ops", Kind: "service_desk",
		TypeIDs: []string{ticketTypes[0].ID}}); err != nil {
		t.Fatal(err)
	}
	p, _ := h.st.GetProject(ctx, "OPS")
	stray := map[string]any{}
	for _, ft := range store.FieldTypes {
		if _, err := h.st.SaveFieldDef(ctx, store.System, "", store.FieldDef{Key: "f_" + ft, Label: ft, Type: ft, Options: []string{"a"}}); err != nil {
			t.Fatal(err)
		}
		stray["f_"+ft] = "not-a-" + ft
	}
	if _, _, err := h.st.CreateWorkItem(ctx, store.System, "", store.WorkItemInput{ProjectID: p.ID, TypeID: ticketTypes[0].ID,
		Title: "stray", Priority: "low", Custom: stray}); err != nil {
		t.Fatal(err)
	}
	projects, _ := h.st.ListProjects(ctx, true)
	fields, _ := h.st.ListFieldDefs(ctx)
	work := workTable(projects, ticketTypes, nil, nil, fields, projectLabels{})
	var all []string
	for _, f := range work.Fields {
		all = append(all, f.Key)
	}
	st, err := list.Build(work, list.Query{Cols: all, Sort: list.Sort{Field: "cf_f_number"}}, list.Options{Viewer: list.Viewer{Global: true, UserID: "u"}})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := h.st.ListRows(ctx, st); err != nil || len(res.Rows) != 1 {
		t.Fatalf("stray custom values: %+v %v", res, err)
	}
	for _, tb := range append([]*list.Table{hostTable, ciTable(types), changeTable, jobTable, work}, goTables()...) {
		var cols []string
		for _, f := range tb.Fields {
			cols = append(cols, f.Key)
		}
		for _, f := range tb.Fields {
			q := list.Query{Cols: cols, Sort: list.Sort{Field: f.Key, Desc: true}}
			if f.Groupable() {
				q.GroupBy = f.Key
			}
			if f.Filterable() {
				for _, op := range f.Type.Ops() {
					c := list.Cond{Field: f.Key, Op: op}
					if op.NeedsValue() {
						c.Value = map[list.Type]string{list.Text: "x", list.Number: "1", list.Tags: "x"}[f.Type]
						switch {
						case f.Type == list.Enum:
							c.Value = f.Options[0].Value
						case op == list.Within || op == list.Older:
							c.Value = "7d"
						case f.Type == list.Time:
							c.Value = "2026-10-01"
						}
					}
					q.Groups = append(q.Groups, []list.Cond{c})
				}
			}
			q.Search = "o'neil"
			st, err := list.Build(tb, q, list.Options{Viewer: list.Viewer{HostIDs: []string{"x"}, Global: true, UserID: "u"}})
			if err != nil {
				t.Fatalf("%s.%s: %v", tb.Key, f.Key, err)
			}
			if _, err := h.st.ListRows(ctx, st); err != nil {
				t.Fatalf("%s.%s: %v\n%s", tb.Key, f.Key, err, st.SQL)
			}
		}
	}
}

func TestListPagesFilterAndScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.addHost("plex", media.ID)
	h.addHost("jellyfin", media.ID)
	h.addHost("dns1")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	admin := h.signIn("ann", "lab-admins")

	_, body := h.list(admin, "/hosts")
	for _, want := range []string{"plex", "jellyfin", "dns1", `id="list"`, "htmx.min.js", "Save list", "1–3 of 3"} {
		if !strings.Contains(body, want) {
			t.Fatalf("hosts lacks %q:\n%s", want, body)
		}
	}
	// A condition, the quick search, and a stale field in an old link.
	_, body = h.list(admin, "/hosts?cf=groups&co=has&cv=media&cf=bogus&co=eq&cv=1&sort=-name")
	if !strings.Contains(body, "plex") || strings.Contains(body, ">dns1<") || !strings.Contains(body, "There is no field") ||
		!strings.Contains(body, "Groups has media") || strings.Index(body, ">plex<") > strings.Index(body, ">jellyfin<") {
		t.Fatalf("filtered hosts:\n%s", body)
	}
	_, body = h.list(admin, "/hosts?q=jelly")
	if strings.Contains(body, ">plex<") || !strings.Contains(body, ">jellyfin<") {
		t.Fatalf("search:\n%s", body)
	}
	// OR groups.
	_, body = h.list(admin, "/hosts?cf=name&co=eq&cv=plex&cg=0&cf=name&co=eq&cv=dns1&cg=1&sort=name")
	if !strings.Contains(body, ">plex<") || !strings.Contains(body, ">dns1<") || strings.Contains(body, ">jellyfin<") {
		t.Fatalf("or groups:\n%s", body)
	}
	// Grouped, and swapped by htmx: just the list, no layout.
	// What the builder form sends redirects to the canonical URL; htmx
	// gets it as the URL to push instead.
	form := "/hosts?sort=name&q=&group=&cf=status&co=eq&cv=online&cg=0&cf=&co=contains&cv=&cg=0&cols=name&cols=status"
	resp, _ := h.do(admin, "GET", form, nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/hosts?cf=status&cg=0&co=eq&cols=name%2Cstatus&cv=online&sort=name" {
		t.Fatalf("canonical: %d %s", resp.StatusCode, loc)
	}
	resp, _ = h.do(admin, "GET", form, nil, "HX-Request", "true")
	if resp.StatusCode != 200 || resp.Header.Get("HX-Push-Url") == "" {
		t.Fatalf("htmx canonical: %d %q", resp.StatusCode, resp.Header.Get("HX-Push-Url"))
	}
	_, body = h.list(admin, "/hosts?group=status&sort=name", "HX-Request", "true")
	if strings.Contains(body, "<html") || !strings.Contains(body, `class="group-row"`) || !strings.Contains(body, "Status: ") {
		t.Fatalf("htmx fragment:\n%s", body)
	}

	ops := h.signIn("carl", "media-ops")
	_, body = h.list(ops, "/hosts?cf=name&co=contains&cv=n&sort=name")
	if strings.Contains(body, "dns1") || !strings.Contains(body, "jellyfin") {
		t.Fatalf("scoped list:\n%s", body)
	}
	// Bulk actions are admin-only on hosts.
	if strings.Contains(body, "With selected") {
		t.Fatal("operator offered host bulk actions")
	}
}

func TestListLegacyLinks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.signIn("ann", "lab-admins")
	actor := store.System
	for _, in := range []store.CIInput{
		{Type: "nas", Name: "synology", Status: "active"},
		{Type: "ups", Name: "apc", Status: "retired"},
	} {
		if _, err := h.st.CreateCI(ctx, actor, in); err != nil {
			t.Fatal(err)
		}
	}
	_, body := h.list(admin, "/cis")
	if !strings.Contains(body, "synology") || strings.Contains(body, ">apc<") {
		t.Fatalf("default CI list hides retired:\n%s", body)
	}
	_, body = h.list(admin, "/cis?status=all")
	if !strings.Contains(body, ">apc<") {
		t.Fatalf("status=all:\n%s", body)
	}
	_, body = h.list(admin, "/cis?type=ups&status=retired")
	if strings.Contains(body, "synology") || !strings.Contains(body, ">apc<") {
		t.Fatalf("type and status:\n%s", body)
	}
	_, body = h.list(admin, "/changes?show=approval")
	if !strings.Contains(body, `aria-current="page">Awaiting approval`) {
		t.Fatalf("show=approval:\n%s", body)
	}
	_, body = h.list(admin, "/jobs?show=failed")
	if !strings.Contains(body, `aria-current="page">Failed`) {
		t.Fatalf("show=failed:\n%s", body)
	}
}

// The later lists' old addresses, and the audit log's scope.
func TestLaterListsLegacyAndScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.addHost("plex", media.ID)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	admin := h.signIn("ann", "lab-admins")
	for path, crumb := range map[string]string{
		"/alerts?view=history":             "State is resolved",
		"/vms?platform=libvirt":            "Platform is libvirt",
		"/containers?updates=1":            "Has an update is true",
		"/updates/packages?security=1":     "Security is true",
		"/audit?before=3":                  "# &lt; 3",
		"/containers?view=stacks&env=none": "Environment is empty",
		"/change-models?show=pending":      "State is awaiting approval",
		"/windows?show=freezes":            "Kind is freeze",
	} {
		if _, body := h.list(admin, path); !strings.Contains(body, crumb) {
			t.Errorf("%s lacks %q:\n%s", path, crumb, body)
		}
	}
	_, body := h.list(admin, "/audit?cf=action&co=eq&cv=host_group.create&sort=-id")
	if !strings.Contains(body, ">host_group.create<") || strings.Contains(body, ">auth.login<") {
		t.Fatalf("audit list:\n%s", body)
	}
	entries, _ := h.st.ListAudit(ctx, 0, 1)
	// The page needs a global role, and so does a cell of it.
	ops := h.signIn("carl", "media-ops")
	if resp, _ := h.do(ops, "GET", "/audit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped operator opened the audit log: %d", resp.StatusCode)
	}
	if resp, _ := h.do(ops, "GET", fmt.Sprintf("/lists/audit/rows/%d/action", entries[0].ID), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("scoped operator read an audit cell: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "GET", fmt.Sprintf("/lists/audit/rows/%d/action", entries[0].ID), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin read an audit cell: %d", resp.StatusCode)
	}
}

func TestSavedLists(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")

	query := "cf=status&co=eq&cv=online&sort=name&cols=name,status"
	resp, _ := h.do(admin, "POST", "/lists/host/saved", url.Values{"name": {"Up"}, "shared": {"1"}, "query": {query}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "list=") {
		t.Fatalf("save: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = h.do(viewer, "POST", "/lists/host/saved", url.Values{"name": {"Mine"}, "query": {query}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("personal save: %d", resp.StatusCode)
	}
	// Viewers can't share; names are unique per owner.
	resp, _ = h.do(viewer, "POST", "/lists/host/saved", url.Values{"name": {"Shared"}, "shared": {"1"}, "query": {query}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("viewer shared: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(admin, "POST", "/lists/host/saved", url.Values{"name": {"up"}, "shared": {"1"}, "query": {query}})
	if !strings.Contains(resp.Header.Get("Location"), "already") {
		t.Fatalf("duplicate: %s", resp.Header.Get("Location"))
	}

	_, body := h.list(viewer, "/hosts")
	if !strings.Contains(body, ">Up <span") || !strings.Contains(body, ">Mine</a>") {
		t.Fatalf("viewer's lists:\n%s", body)
	}
	_, body = h.list(admin, "/hosts")
	if strings.Contains(body, "Mine") {
		t.Fatal("a personal list leaked to another user")
	}

	lists, _ := h.st.SavedLists(ctx, "host", "")
	if len(lists) != 1 || lists[0].Name != "Up" || len(lists[0].Conditions) != 1 || lists[0].Columns[1] != "status" {
		t.Fatalf("stored: %+v", lists)
	}
	// Only its creator or an admin deletes a shared list.
	if resp, _ := h.do(viewer, "POST", "/lists/host/saved/"+lists[0].ID+"/delete", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "POST", "/lists/host/saved/"+lists[0].ID+"/delete", url.Values{"back": {"sort=name"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin delete: %d", resp.StatusCode)
	}
	if !strings.Contains(h.auditActions(), "saved_list.create saved_list.create saved_list.delete") {
		t.Fatalf("audit: %s", h.auditActions())
	}
}

func TestListInlineEditAndBulk(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	id, _ := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "nas", Name: "synology", Status: "active", Tags: []string{"a"}})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")

	_, body := h.list(admin, "/cis?sort=name&cols=name,owner,tags")
	if !strings.Contains(body, "/lists/ci/rows/"+id+"/owner/edit") {
		t.Fatalf("no edit button:\n%s", body)
	}
	// The discovered host CI isn't editable in place.
	if strings.Contains(body, "/lists/ci/rows/"+plex.HostID+"/owner") {
		t.Fatal("discovered CI offered inline edit")
	}
	_, body = h.do(admin, "GET", "/lists/ci/rows/"+id+"/owner/edit", nil)
	if !strings.Contains(body, `hx-post="/lists/ci/rows/`+id+`/owner"`) {
		t.Fatalf("edit form:\n%s", body)
	}
	resp, body := h.do(admin, "POST", "/lists/ci/rows/"+id+"/owner", url.Values{"value": {"James"}})
	if resp.StatusCode != 200 || !strings.Contains(body, "James") {
		t.Fatalf("save: %d\n%s", resp.StatusCode, body)
	}
	h.do(admin, "POST", "/lists/ci/rows/"+id+"/tags", url.Values{"value": {"b, c"}})
	if resp, _ := h.do(admin, "POST", "/lists/ci/rows/"+id+"/status", url.Values{"value": {"missing"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad status: %d", resp.StatusCode)
	}
	c, _ := h.st.GetCI(ctx, id)
	if c.Owner != "James" || strings.Join(c.Tags, ",") != "b,c" {
		t.Fatalf("ci: %+v", c)
	}
	if resp, _ := h.do(viewer, "POST", "/lists/ci/rows/"+id+"/owner", url.Values{"value": {"x"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer edit: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "POST", "/lists/ci/rows/"+plex.HostID+"/owner", url.Values{"value": {"x"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("discovered edit: %d", resp.StatusCode)
	}

	// Bulk: the discovered CI is skipped, the manual one changes.
	resp, _ = h.do(admin, "POST", "/lists/ci/bulk", url.Values{"action": {"status"}, "value": {"retired"},
		"id": {id, plex.HostID}, "back": {"sort=name"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "1+CI") || !strings.Contains(loc, "Skipped+1") {
		t.Fatalf("bulk: %s", loc)
	}
	if c, _ := h.st.GetCI(ctx, id); c.Status != "retired" {
		t.Fatalf("status: %s", c.Status)
	}
	resp, _ = h.do(admin, "POST", "/lists/host/bulk", url.Values{"action": {"add_group"}, "value": {media.ID}, "id": {plex.HostID}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=") {
		t.Fatalf("host bulk: %s", loc)
	}
	if hst, _ := h.st.GetHost(ctx, plex.HostID); len(hst.GroupIDs) != 1 {
		t.Fatalf("groups: %v", hst.GroupIDs)
	}
	if resp, _ := h.do(viewer, "POST", "/lists/host/bulk", url.Values{"action": {"add_group"}, "value": {media.ID}, "id": {plex.HostID}}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("viewer bulk: %s", resp.Header.Get("Location"))
	}
}

func TestWorkList(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	resp, _ := h.do(admin, "POST", "/projects", url.Values{"key": {"ops"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"], typeID["problem"]}, "default_type": {typeID["incident"]}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create project: %d", resp.StatusCode)
	}
	projects, _ := h.st.ListProjects(ctx, false)
	var vicID string
	users, _ := h.st.ListUsers(ctx)
	for _, u := range users {
		if u.OIDCSub == "vic" {
			vicID = u.ID
		}
	}
	add := func(title, typ, priority, assignee string) string {
		id, _, err := h.st.CreateWorkItem(ctx, store.System, "", store.WorkItemInput{ProjectID: projects[0].ID, TypeID: typeID[typ],
			Title: title, Priority: priority, AssigneeID: assignee})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	nas := add("NAS offline", "incident", "low", vicID)
	psu := add("Flaky PSU", "problem", "critical", "")
	old := add("Old ticket", "incident", "medium", "")
	oldItem, _ := h.st.GetWorkItem(ctx, old)
	ts, _ := h.st.ItemTransitions(ctx, oldItem)
	i := slices.IndexFunc(ts, func(t store.WfTransition) bool { return t.Name == "Done" })
	if err := h.st.TransitionWorkItem(ctx, store.System, store.Runner{}, old, ts[i].ID, store.TransitionInput{Resolution: "Fixed"}); err != nil {
		t.Fatal(err)
	}

	// The default lists open items, most urgent first.
	_, body := h.list(viewer, "/work")
	if !strings.Contains(body, "NAS offline") || strings.Contains(body, "Old ticket") ||
		strings.Index(body, "Flaky PSU") > strings.Index(body, "NAS offline") {
		t.Fatalf("default work list:\n%s", body)
	}
	// Old filters still work: mine, unassigned, every status, a project.
	_, body = h.list(viewer, "/work?assignee=me")
	if !strings.Contains(body, "NAS offline") || strings.Contains(body, "Flaky PSU") {
		t.Fatalf("assigned to me:\n%s", body)
	}
	_, body = h.list(admin, "/work?assignee=me")
	if strings.Contains(body, "NAS offline") {
		t.Fatalf("ann sees vic's items as hers:\n%s", body)
	}
	_, body = h.list(viewer, "/work?assignee=none&project=ops")
	if strings.Contains(body, "NAS offline") || !strings.Contains(body, "Flaky PSU") {
		t.Fatalf("unassigned:\n%s", body)
	}
	_, body = h.list(viewer, "/work?status=all")
	if !strings.Contains(body, "Old ticket") {
		t.Fatalf("all statuses:\n%s", body)
	}
	_, body = h.list(viewer, "/work?show=done")
	if !strings.Contains(body, "Old ticket") || strings.Contains(body, "NAS offline") {
		t.Fatalf("done view:\n%s", body)
	}

	// Anyone who can file items edits the title and priority in place.
	resp, body = h.do(viewer, "POST", "/lists/work/rows/"+nas+"/title", url.Values{"value": {"NAS unreachable"}})
	if resp.StatusCode != 200 || !strings.Contains(body, "NAS unreachable") {
		t.Fatalf("save title: %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := h.do(viewer, "POST", "/lists/work/rows/"+nas+"/priority", url.Values{"value": {"urgent-ish"}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad priority: %d", resp.StatusCode)
	}
	if it, _ := h.st.GetWorkItem(ctx, nas); it.Title != "NAS unreachable" || it.Priority != "low" {
		t.Fatalf("item: %+v", it)
	}

	// The status column is the workflow status's name.
	_, body = h.list(viewer, "/work?show=all")
	if !strings.Contains(body, "To do") {
		t.Fatalf("status names:\n%s", body)
	}

	// Bulk: close both open items with a resolution, then reprioritize.
	resp, _ = h.do(viewer, "POST", "/lists/work/bulk", url.Values{"action": {"transition"}, "value": {"Done::Won't do"}, "id": {nas, psu}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=") {
		t.Fatalf("bulk status: %s", loc)
	}
	for _, id := range []string{nas, psu} {
		if it, _ := h.st.GetWorkItem(ctx, id); it.Status != store.StatusDone || it.Resolution != "Won't do" {
			t.Fatalf("closed: %+v", it)
		}
	}
	h.do(viewer, "POST", "/lists/work/bulk", url.Values{"action": {"priority"}, "value": {"high"}, "id": {nas}})
	if it, _ := h.st.GetWorkItem(ctx, nas); it.Priority != "high" {
		t.Fatalf("priority: %s", it.Priority)
	}
}

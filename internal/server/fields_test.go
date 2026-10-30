package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestCustomFieldPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	lab, _ := h.st.CreateHostGroup(ctx, store.System, "lab", "")
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-viewers", Role: rbac.Viewer, ScopeGroupID: media.ID})
	secret := h.addHost("vault1", lab.ID)
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	scoped := h.signIn("sam", "media-viewers")

	// Only admins define fields and groups.
	for _, path := range []string{"/settings/fields", "/settings/field-groups", "/settings/field-groups/new"} {
		if resp, _ := h.do(viewer, "GET", path, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("viewer opened %s: %d", path, resp.StatusCode)
		}
	}
	resp, body := h.do(admin, "POST", "/settings/fields", url.Values{"key": {"Env"}, "label": {"Environment"}, "type": {"select"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "lower-case") {
		t.Fatalf("bad key: %d", resp.StatusCode)
	}
	resp, body = h.do(admin, "POST", "/settings/fields", url.Values{"key": {"env"}, "label": {"Environment"}, "type": {"select"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "one per line") {
		t.Fatalf("select without options: %d", resp.StatusCode)
	}
	for _, f := range []url.Values{
		{"key": {"env"}, "label": {"Environment"}, "type": {"select"}, "options": {"prod\ntest\n\nprod"}},
		{"key": {"vendor_ticket"}, "label": {"Vendor ticket"}, "type": {"text"}},
		{"key": {"server"}, "label": {"Server"}, "type": {"ci_ref"}},
		{"key": {"cost"}, "label": {"Cost"}, "type": {"number"}},
	} {
		if resp, body := h.do(admin, "POST", "/settings/fields", f); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("create field %s: %d\n%s", f.Get("key"), resp.StatusCode, body)
		}
	}
	defs, _ := h.st.ListFieldDefs(ctx)
	fieldID := map[string]string{}
	for _, f := range defs {
		fieldID[f.Key] = f.ID
	}
	if _, body = h.do(admin, "GET", "/settings/fields", nil); !strings.Contains(body, "prod, test") || !strings.Contains(body, "Vendor ticket") {
		t.Fatalf("fields page:\n%s", body)
	}

	// A group with env required (default prod), the ticket and the server,
	// in the order of their positions.
	resp, body = h.do(admin, "POST", "/settings/field-groups", url.Values{"name": {"Ops"},
		"field":                 {fieldID["env"], fieldID["vendor_ticket"], fieldID["server"], fieldID["cost"]},
		"pos_" + fieldID["env"]: {"2"}, "req_" + fieldID["env"]: {"1"}, "def_" + fieldID["env"]: {"prod"},
		"pos_" + fieldID["vendor_ticket"]: {"1"}, "pos_" + fieldID["server"]: {"3"}, "pos_" + fieldID["cost"]: {"4"},
		"def_" + fieldID["cost"]: {"lots"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "The default for Cost") {
		t.Fatalf("bad default: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/field-groups", url.Values{"name": {"Ops"},
		"field":                 {fieldID["env"], fieldID["vendor_ticket"], fieldID["server"]},
		"pos_" + fieldID["env"]: {"2"}, "req_" + fieldID["env"]: {"1"}, "def_" + fieldID["env"]: {"prod"},
		"pos_" + fieldID["vendor_ticket"]: {"1"}, "pos_" + fieldID["server"]: {"3"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create group: %d", resp.StatusCode)
	}
	groups, _ := h.st.ListFieldGroups(ctx)
	if len(groups) != 1 || len(groups[0].Fields) != 3 || groups[0].Fields[0].Key != "vendor_ticket" || groups[0].Fields[1].Default != "prod" {
		t.Fatalf("group: %+v", groups)
	}
	ops := groups[0].ID

	h.do(admin, "POST", "/projects", url.Values{"key": {"OPS"}, "name": {"Operations"}, "kind": {"service_desk"},
		"types": {typeID["incident"], typeID["task"]}, "default_type": {typeID["incident"]}})
	if resp, _ := h.do(viewer, "GET", "/projects/OPS/types/incident", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer opened a project type: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "GET", "/projects/OPS/types/bug", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a type the project doesn't offer: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/projects/OPS/types/incident/groups", url.Values{"group": {ops}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("apply group: %s", resp.Header.Get("Location"))
	}
	if _, body = h.do(admin, "GET", "/projects/OPS/types/incident", nil); !strings.Contains(body, `value="`+ops+`" checked`) {
		t.Fatalf("project type page:\n%s", body)
	}

	// The form shows the group, with the default filled in; env is
	// required and the server must be a CI the user may see.
	_, body = h.do(viewer, "GET", "/work/new?project=OPS", nil)
	if !strings.Contains(body, `name="cf_vendor_ticket"`) || !strings.Contains(body, `<option value="prod" selected>`) || !strings.Contains(body, "vault1") {
		t.Fatalf("new item form:\n%s", body)
	}
	if _, body = h.do(viewer, "GET", "/work/new?project=OPS&type="+typeID["task"], nil); strings.Contains(body, "cf_env") {
		t.Fatal("task form shows the incident's fields")
	}
	item := url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"Vault sealed"}, "priority": {"high"},
		"cf_vendor_ticket": {"V-77"}, "cf_server": {secret.HostID}}
	resp, body = h.do(viewer, "POST", "/work", item)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Environment is required") || !strings.Contains(body, `value="V-77"`) {
		t.Fatalf("required field: %d\n%s", resp.StatusCode, body)
	}
	item.Set("cf_env", "staging")
	if resp, body = h.do(viewer, "POST", "/work", item); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "pick one of the options") {
		t.Fatalf("bad option: %d", resp.StatusCode)
	}
	item.Set("cf_env", "prod")
	scopedItem := url.Values{}
	for k, v := range item {
		scopedItem[k] = v
	}
	if resp, body = h.do(scoped, "POST", "/work", scopedItem); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Server: pick a CI") {
		t.Fatalf("a CI the user can't see: %d", resp.StatusCode)
	}
	if resp, _ = h.do(viewer, "POST", "/work", item); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create: %d", resp.StatusCode)
	}

	// The page shows the values; the CI only to people who may see it.
	_, body = h.do(viewer, "GET", "/work/OPS-1", nil)
	if !strings.Contains(body, "V-77") || !strings.Contains(body, "Environment") || !strings.Contains(body, ">vault1</a>") {
		t.Fatalf("item page:\n%s", body)
	}
	_, body = h.do(scoped, "GET", "/work/OPS-1", nil)
	if strings.Contains(body, "vault1") || !strings.Contains(body, "a CI you can&#39;t see") {
		t.Fatalf("scoped item page:\n%s", body)
	}
	// Someone who can't see the CI can still edit the item and keep it.
	_, body = h.do(scoped, "GET", "/work/OPS-1/edit", nil)
	if strings.Contains(body, "vault1") || !strings.Contains(body, `value="`+secret.HostID+`" selected`) {
		t.Fatalf("scoped edit form:\n%s", body)
	}
	edit := url.Values{"title": {"Vault sealed"}, "priority": {"high"}, "cf_env": {"test"}, "cf_server": {secret.HostID}}
	if resp, body = h.do(scoped, "POST", "/work/OPS-1", edit); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("scoped edit: %d\n%s", resp.StatusCode, body)
	}
	it, _ := h.st.GetWorkItemByRef(ctx, "OPS-1")
	if it.Custom["env"] != "test" || it.Custom["server"] != secret.HostID || it.Custom["vendor_ticket"] != nil {
		t.Fatalf("after edit: %+v", it.Custom)
	}

	// Lists filter and show custom fields, and hide the CI's name too.
	_, body = h.list(viewer, "/work?cf=cf_env&co=eq&cv=test&cols=ref,cf_env,cf_server")
	if !strings.Contains(body, "OPS-1") || !strings.Contains(body, "vault1") {
		t.Fatalf("custom field list:\n%s", body)
	}
	_, body = h.list(scoped, "/work?cf=cf_env&co=eq&cv=test&cols=ref,cf_env,cf_server")
	if !strings.Contains(body, "OPS-1") || strings.Contains(body, "vault1") {
		t.Fatalf("scoped custom field list:\n%s", body)
	}
	if _, body = h.list(viewer, "/work?cf=cf_env&co=eq&cv=prod"); strings.Contains(body, "OPS-1") {
		t.Fatalf("filter by env=prod matched:\n%s", body)
	}

	// Layouts: the incident's default create screen puts env first and
	// serves view too; the project overrides the view screen.
	resp, _ = h.do(admin, "POST", "/settings/ticket-types/"+typeID["incident"]+"/layouts/create", url.Values{"sections": {"nope"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("bad layout JSON: %s", resp.Header.Get("Location"))
	}
	sections, _ := json.Marshal([]store.LayoutSection{{Title: "Triage", Columns: 2, Items: []store.LayoutItem{
		{Kind: "field", FieldID: fieldID["env"]}, {Kind: "core", Field: "title"}, {Kind: "core", Field: "priority"}}}})
	resp, _ = h.do(admin, "POST", "/settings/ticket-types/"+typeID["incident"]+"/layouts/create",
		url.Values{"sections": {string(sections)}, "view_uses_create": {"1"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("save default layout: %s", resp.Header.Get("Location"))
	}
	_, body = h.do(viewer, "GET", "/work/OPS-1/edit", nil)
	if i, j := strings.Index(body, "Triage"), strings.Index(body, `name="cf_vendor_ticket"`); i < 0 || j < i || !strings.Contains(body, "cols-2") ||
		!strings.Contains(body, "<legend>Other</legend>") {
		t.Fatalf("edit form with layout:\n%s", body)
	}
	if _, body = h.do(viewer, "GET", "/work/OPS-1", nil); !strings.Contains(body, "<h3>Triage</h3>") {
		t.Fatalf("view uses create:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/projects/OPS/types/incident/layouts/view", nil)
	if !strings.Contains(body, "default create layout") || !strings.Contains(body, "Triage") || !strings.Contains(body, "layout.js") {
		t.Fatalf("project view layout editor:\n%s", body)
	}
	sections, _ = json.Marshal([]store.LayoutSection{{Title: "Vendor", Collapsed: true, Items: []store.LayoutItem{{Kind: "group", GroupID: ops}}}})
	h.do(admin, "POST", "/projects/OPS/types/incident/layouts/view", url.Values{"sections": {string(sections)}})
	if _, body = h.do(viewer, "GET", "/work/OPS-1", nil); strings.Contains(body, "<h3>Triage</h3>") || !strings.Contains(body, "<summary>Vendor</summary>") {
		t.Fatalf("project view layout:\n%s", body)
	}
	h.do(admin, "POST", "/projects/OPS/types/incident/layouts/view/delete", nil)
	if _, body = h.do(viewer, "GET", "/work/OPS-1", nil); !strings.Contains(body, "<h3>Triage</h3>") {
		t.Fatalf("after reset:\n%s", body)
	}

	// Fields in a group can't be deleted; the history names them by label.
	if resp, _ := h.do(admin, "POST", "/settings/fields/"+fieldID["env"]+"/delete", nil); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("delete a field in use: %s", resp.Header.Get("Location"))
	}
	if _, body = h.do(viewer, "GET", "/work/OPS-1", nil); !strings.Contains(body, "changed Environment, Vendor ticket") {
		t.Fatalf("history:\n%s", body)
	}
}

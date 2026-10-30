package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestProjectCategoriesAndTags(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	types, _ := h.st.ListTicketTypes(ctx)
	typeID := map[string]string{}
	for _, tt := range types {
		typeID[tt.Key] = tt.ID
	}
	catID := func(path string) string {
		t.Helper()
		cats, err := h.st.ListProjectCategories(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cats {
			if c.Path == path {
				return c.ID
			}
		}
		t.Fatalf("no category %q in %+v", path, cats)
		return ""
	}

	// Only admins keep the lists.
	if resp, _ := h.do(viewer, "POST", "/settings/project-tags", url.Values{"name": {"x"}, "no_color": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer made a tag: %d", resp.StatusCode)
	}

	// Categories nest; a child without a color shows its parent's.
	resp, _ := h.do(admin, "POST", "/settings/project-categories", url.Values{"name": {"Infrastructure"}, "color": {"#2255AA"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("new category: %d", resp.StatusCode)
	}
	infra := catID("Infrastructure")
	h.do(admin, "POST", "/settings/project-categories", url.Values{"name": {"Network"}, "parent": {infra}, "no_color": {"1"}})
	network := catID("Infrastructure / Network")
	h.do(admin, "POST", "/settings/project-categories", url.Values{"name": {"Apps"}, "no_color": {"1"}})
	apps := catID("Apps")
	cats, _ := h.st.ListProjectCategories(ctx)
	if len(cats) != 3 || cats[0].Name != "Apps" || cats[2].Name != "Network" || cats[2].Depth != 1 || cats[2].ShownColor != "#2255aa" {
		t.Fatalf("tree: %+v", cats)
	}
	resp, body := h.do(admin, "POST", "/settings/project-categories", url.Values{"name": {"network"}, "parent": {infra}, "no_color": {"1"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already a category") {
		t.Fatalf("duplicate sibling: %d", resp.StatusCode)
	}
	resp, body = h.do(admin, "POST", "/settings/project-categories", url.Values{"name": {"a/b"}, "no_color": {"1"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "can&#39;t contain /") {
		t.Fatalf("slash in name: %d", resp.StatusCode)
	}
	resp, body = h.do(admin, "POST", "/settings/project-categories/"+infra, url.Values{"name": {"Infrastructure"}, "parent": {network}, "color": {"#2255aa"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "under itself") {
		t.Fatalf("cycle: %d", resp.StatusCode)
	}
	// The edit form doesn't offer the category or its subcategories as parents.
	_, body = h.do(admin, "GET", "/settings/project-categories?edit="+infra, nil)
	if strings.Contains(body, `<option value="`+network+`"`) || !strings.Contains(body, `<option value="`+apps+`"`) {
		t.Fatalf("parents offered:\n%s", body)
	}

	// Tags come from the list.
	h.do(admin, "POST", "/settings/project-tags", url.Values{"name": {"Customer facing"}, "color": {"#ffcc00"}})
	h.do(admin, "POST", "/settings/project-tags", url.Values{"name": {"Internal"}, "no_color": {"1"}})
	resp, body = h.do(admin, "POST", "/settings/project-tags", url.Values{"name": {"internal"}, "no_color": {"1"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "already a tag") {
		t.Fatalf("duplicate tag: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/settings/project-tags", url.Values{"name": {"bad"}, "color": {"red"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad color: %d", resp.StatusCode)
	}
	tags, _ := h.st.ListProjectTags(ctx)
	tagID := map[string]string{}
	for _, tg := range tags {
		tagID[tg.Name] = tg.ID
	}

	// Projects pick a category and tags.
	for _, p := range []url.Values{
		{"key": {"NET"}, "name": {"Network ops"}, "category": {network}, "tags": {tagID["Customer facing"], tagID["Internal"]}},
		{"key": {"WEB"}, "name": {"Website"}, "category": {apps}, "tags": {tagID["Customer facing"]}},
		{"key": {"MISC"}, "name": {"Odds and ends"}},
	} {
		p.Set("kind", "service_desk")
		p.Set("types", typeID["incident"])
		if resp, body := h.do(admin, "POST", "/projects", p); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("create %s: %d\n%s", p.Get("key"), resp.StatusCode, body)
		}
	}
	_, body = h.do(viewer, "GET", "/projects/NET", nil)
	if !strings.Contains(body, "Infrastructure / Network") || !strings.Contains(body, "background:#2255aa;color:#fff") ||
		!strings.Contains(body, "background:#ffcc00;color:#111") || !strings.Contains(body, "Internal") {
		t.Fatalf("project page:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/projects/NET/edit", nil)
	if !strings.Contains(body, `<option value="`+network+`" selected>`) || !strings.Contains(body, `value="`+tagID["Internal"]+`" checked`) {
		t.Fatalf("edit form:\n%s", body)
	}

	// The projects list filters a category with its subcategories.
	_, body = h.list(viewer, "/projects?cf=category&co=eq&cv="+infra)
	if !strings.Contains(body, "Network ops") || strings.Contains(body, "Website") || strings.Contains(body, "Odds and ends") {
		t.Fatalf("category filter:\n%s", body)
	}
	_, body = h.list(viewer, "/projects?cf=category&co=ne&cv="+infra)
	if strings.Contains(body, "Network ops") || !strings.Contains(body, "Website") || !strings.Contains(body, "Odds and ends") {
		t.Fatalf("category exclusion:\n%s", body)
	}
	_, body = h.list(viewer, "/projects?cf=tags&co=has&cv=Customer+facing&sort=category")
	if !strings.Contains(body, "Network ops") || !strings.Contains(body, "Website") || strings.Contains(body, "Odds and ends") ||
		strings.Index(body, "Website") > strings.Index(body, "Network ops") {
		t.Fatalf("tag filter, by category:\n%s", body)
	}
	_, body = h.list(viewer, "/projects?group=category")
	if !strings.Contains(body, "Category: <span class=\"tag\"") {
		t.Fatalf("group by category:\n%s", body)
	}

	// Work items filter by their project's category and tags.
	for _, p := range []string{"NET", "WEB", "MISC"} {
		if resp, body := h.do(viewer, "POST", "/work", url.Values{"project": {p}, "type": {typeID["incident"]},
			"title": {"Trouble in " + p}, "priority": {"medium"}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("file into %s: %d\n%s", p, resp.StatusCode, body)
		}
	}
	_, body = h.list(viewer, "/work?cf=project_category&co=eq&cv="+infra+"&cols=ref,title,project_category,project_tags")
	if !strings.Contains(body, "Trouble in NET") || strings.Contains(body, "Trouble in WEB") || !strings.Contains(body, "Infrastructure / Network") {
		t.Fatalf("work by category:\n%s", body)
	}
	_, body = h.list(viewer, "/work?cf=project_tags&co=has&cv=Customer+facing")
	if !strings.Contains(body, "Trouble in NET") || !strings.Contains(body, "Trouble in WEB") || strings.Contains(body, "Trouble in MISC") {
		t.Fatalf("work by tag:\n%s", body)
	}

	// Editing a project changes its labels, and the audit log says how.
	resp, _ = h.do(admin, "POST", "/projects/WEB", url.Values{"name": {"Website"}, "kind": {"service_desk"},
		"types": {typeID["incident"]}, "category": {infra}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit WEB: %d", resp.StatusCode)
	}
	p, _ := h.st.GetProject(ctx, "WEB")
	if p.CategoryID != infra || len(p.Tags) != 0 {
		t.Fatalf("WEB after edit: %+v", p)
	}
	var details string
	h.st.DB().QueryRowContext(ctx, `SELECT details::text FROM audit_log WHERE action = 'project.update' ORDER BY id DESC LIMIT 1`).Scan(&details)
	if !strings.Contains(details, `"Apps"`) || !strings.Contains(details, `"Infrastructure"`) || !strings.Contains(details, "Customer facing") {
		t.Fatalf("audit: %s", details)
	}

	// A category with subcategories stays; a leaf goes, leaving its
	// projects uncategorized. A deleted tag comes off its projects.
	resp, body = h.do(admin, "POST", "/settings/project-categories/"+infra+"/delete", nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "subcategories") {
		t.Fatalf("delete parent: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "POST", "/settings/project-categories/"+network+"/delete", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete leaf: %d", resp.StatusCode)
	}
	if resp, _ := h.do(admin, "POST", "/settings/project-tags/"+tagID["Internal"]+"/delete", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete tag: %d", resp.StatusCode)
	}
	p, _ = h.st.GetProject(ctx, "NET")
	if p.CategoryID != "" || len(p.Tags) != 1 || p.Tags[0].Name != "Customer facing" {
		t.Fatalf("NET after deletes: %+v", p)
	}

	// Old links to archived projects still open them.
	h.do(admin, "POST", "/projects/MISC", url.Values{"name": {"Odds and ends"}, "kind": {"service_desk"},
		"types": {typeID["incident"]}, "archived": {"1"}})
	if _, body = h.list(viewer, "/projects"); strings.Contains(body, "Odds and ends") {
		t.Fatalf("active projects show archived:\n%s", body)
	}
	if _, body = h.list(viewer, "/projects?archived=1"); !strings.Contains(body, "Odds and ends") {
		t.Fatalf("?archived=1:\n%s", body)
	}
}

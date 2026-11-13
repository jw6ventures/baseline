package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func (h *harness) search(c *http.Client, q string) searchView {
	h.t.Helper()
	resp, body := h.do(c, "GET", "/search.json?q="+url.QueryEscape(q), nil)
	if resp.StatusCode != 200 {
		h.t.Fatalf("search %q: %d %s", q, resp.StatusCode, body)
	}
	var v searchView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		h.t.Fatal(err)
	}
	return v
}

// titles lists the results as group/title.
func (v searchView) titles() []string {
	var out []string
	for _, g := range v.Groups {
		for _, r := range g.Results {
			out = append(out, g.Key+"/"+r.Ref+r.Title)
		}
	}
	return out
}

func TestSearchFindsRecordsInScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	h.addHost("plexbackup")
	h.ingest(plex, model.SectionContainers, containersFixture())
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})

	admin := h.signIn("ann", "lab-admins")
	if resp, _ := h.do(admin, "POST", "/cis", url.Values{"type": {"nas"}, "name": {"plex-nas"}, "status": {"active"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create CI: %d", resp.StatusCode)
	}

	got := strings.Join(h.search(admin, "plex").titles(), " ")
	for _, want := range []string{"host/plex", "host/plexbackup", "container/media-plex-1", "ci/plex-nas"} {
		if !strings.Contains(got, want) {
			t.Errorf("admin search lacks %s: %s", want, got)
		}
	}
	// The host is found under Hosts only, not again as a CI.
	if strings.Contains(got, "ci/plex ") || strings.HasSuffix(got, "ci/plex") {
		t.Errorf("host listed as a CI too: %s", got)
	}
	// The exact name ranks first.
	if v := h.search(admin, "plex"); v.Groups[0].Key != "host" || v.Groups[0].Results[0].Title != "plex" {
		t.Errorf("first result: %+v", v.Groups[0])
	}
	if v := h.search(admin, "media"); !strings.Contains(strings.Join(v.titles(), " "), "stack/media") {
		t.Errorf("stack missing: %v", v.titles())
	}

	// A scoped user finds only what their lists show.
	ops := h.signIn("carl", "media-ops")
	got = strings.Join(h.search(ops, "plex").titles(), " ")
	// Agentless CIs are everyone's, as on the CI list.
	if !strings.Contains(got, "host/plex") || strings.Contains(got, "plexbackup") || !strings.Contains(got, "ci/plex-nas") {
		t.Errorf("scoped search: %s", got)
	}
	if v := h.search(ops, ""); len(v.Groups) != 0 {
		t.Errorf("empty query: %+v", v)
	}
}

func TestSearchWorkItemsAndPage(t *testing.T) {
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
	if resp, body := h.do(admin, "POST", "/work", url.Values{"project": {"OPS"}, "type": {typeID["incident"]}, "title": {"NAS offline"}, "priority": {"high"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create item: %d %s", resp.StatusCode, body)
	}

	got := strings.Join(h.search(admin, "ops-1").titles(), " ")
	if !strings.Contains(got, "work/OPS-1NAS offline") {
		t.Errorf("by reference: %s", got)
	}
	if got := strings.Join(h.search(admin, "offline").titles(), " "); !strings.Contains(got, "work/OPS-1NAS offline") {
		t.Errorf("by title: %s", got)
	}
	if got := strings.Join(h.search(admin, "operations").titles(), " "); !strings.Contains(got, "project/OPSOperations") {
		t.Errorf("project: %s", got)
	}

	// The page works without JS, and escapes what was typed.
	resp, body := h.do(admin, "GET", "/search?q=offline", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `href="/work/OPS-1"`) || !strings.Contains(body, "NAS offline") {
		t.Fatalf("page: %d\n%s", resp.StatusCode, body)
	}
	_, body = h.do(admin, "GET", "/search?q="+url.QueryEscape("<b>nothing</b>"), nil)
	if strings.Contains(body, "<b>nothing</b>") || !strings.Contains(body, "Nothing you can see matches") {
		t.Errorf("no-match page:\n%s", body)
	}
	// Every page with the nav has the box.
	if _, body := h.do(admin, "GET", "/hosts", nil); !strings.Contains(body, `data-search=""`) || !strings.Contains(body, "/static/search.js") {
		t.Errorf("layout lacks the search box")
	}
}

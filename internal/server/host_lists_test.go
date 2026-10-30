package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestHostListPath(t *testing.T) {
	id := "9903ffbf-703c-4aef-b5dd-1c3ea49022ab"
	for path, want := range map[string]bool{
		"/hosts/" + id + "/containers":   true,
		"/hosts/" + id + "/stacks":       false, // not the container table
		"/hosts/" + id + "/containers/x": false,
		"/hosts/nope/containers":         false,
		"//evil.example/containers":      false,
		"/containers":                    false,
	} {
		if got := hostListPath("container", path); got != want {
			t.Errorf("%s: %v", path, got)
		}
	}
	if got := listBack("container", "/containers", "https://evil.example/"); got != "/containers" {
		t.Errorf("listBack let %q through", got)
	}
}

func TestHostRelatedLists(t *testing.T) {
	h := newHarness(t)
	a, b := h.addHost("a"), h.addHost("b")
	h.ingest(a, model.SectionContainers, appStacks(digestOld, time.Now(), "dwi-app", "pee-media", "metrics"))
	h.ingest(b, model.SectionContainers, appStacks(digestOld, time.Now(), "other"))
	admin := h.signIn("ann", "lab-admins")
	base := "/hosts/" + a.HostID

	// Old links open the list's own path, keeping their parameters.
	resp, _ := h.do(admin, "GET", base+"?tab=containers&notice=hi", nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != base+"/containers?notice=hi" {
		t.Fatalf("old containers tab: %d %s", resp.StatusCode, loc)
	}

	// Only this host's containers, without a Host column.
	_, body := h.list(admin, base+"/containers")
	for _, want := range []string{"dwi-app-app-1", "pee-media-app-1", "metrics-app-1", `data-path="` + base + `/containers"`, "Restart…"} {
		if !strings.Contains(body, want) {
			t.Fatalf("containers lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "other-app-1") || strings.Contains(body, ">Host</a></th>") {
		t.Fatalf("containers shows another host's rows or a Host column:\n%s", body)
	}
	// Filtering stays on the host's page.
	resp, _ = h.do(admin, "GET", base+"/containers?q=media", nil)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, base+"/containers?") {
		t.Fatalf("search went to %s", loc)
	}
	_, body = h.list(admin, base+"/containers?q=media")
	if !strings.Contains(body, "pee-media-app-1") || strings.Contains(body, "dwi-app-app-1") {
		t.Fatalf("search:\n%s", body)
	}

	// Stacks have their own tab, with what their names say in three columns.
	_, body = h.list(admin, base+"/stacks")
	for _, want := range []string{">Environment</a></th>", ">Category</a></th>", ">Visibility</a></th>", "dwi-app", "Pull images…"} {
		if !strings.Contains(body, want) {
			t.Fatalf("stacks lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Classification") || strings.Contains(body, ">other</a>") {
		t.Fatalf("stacks:\n%s", body)
	}
	if _, body = h.do(admin, "GET", base, nil); !strings.Contains(body, base+"/stacks") {
		t.Fatalf("no Stacks tab:\n%s", body)
	}
	resp, _ = h.do(admin, "GET", "/hosts/"+b.HostID+"/vms", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a host without guests has a VMs tab: %d", resp.StatusCode)
	}

	// Bulk restart opens the change form for the containers picked.
	rows, _ := h.st.ListContainers(t.Context(), []string{a.HostID, b.HostID})
	form := url.Values{"action": {"restart"}, "path": {base + "/containers"}, "back": {""}}
	for _, r := range rows {
		form.Add("id", r.CIID)
	}
	resp, _ = h.do(admin, "POST", "/lists/container/bulk", form)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Path != "/changes/new" || loc.Query().Get("action") != "container.restart" ||
		len(loc.Query()["container"]) != len(rows) {
		t.Fatalf("bulk restart: %d %s", resp.StatusCode, loc)
	}
	// An error returns to the host's list.
	resp, _ = h.do(admin, "POST", "/lists/container/bulk", url.Values{"action": {"restart"}, "path": {base + "/containers"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, base+"/containers?") || !strings.Contains(loc, "error=") {
		t.Fatalf("bulk with nothing picked went to %s", loc)
	}

	// Saving a list from the host's page returns there.
	resp, _ = h.do(admin, "POST", "/lists/container/saved", url.Values{"name": {"Mine"}, "query": {"q=media"}, "path": {base + "/containers"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, base+"/containers?") {
		t.Fatalf("save went to %s", loc)
	}
}

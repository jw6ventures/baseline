package server

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestWorkflowDiagram(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")
	viewer := h.signIn("vic", "viewers")
	all, _ := h.st.ListWorkflows(ctx)
	def := all[0]
	wfURL := "/settings/workflows/" + def.ID

	diagram := func() wfDiagram {
		t.Helper()
		_, body := h.do(admin, "GET", wfURL, nil)
		m := regexp.MustCompile(`(?s)<script type="application/json" id="wfmap-data">(.*?)</script>`).FindStringSubmatch(body)
		if m == nil || !strings.Contains(body, "/static/wfmap.js") {
			t.Fatalf("no diagram on the page:\n%s", body)
		}
		var d wfDiagram
		if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &d); err != nil {
			t.Fatalf("diagram JSON %q: %v", m[1], err)
		}
		return d
	}
	layout := func(c *http.Client, body string) int {
		t.Helper()
		req, _ := http.NewRequest("POST", h.ts.URL+wfURL+"/layout", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The published default: three statuses, nothing placed, Done from any
	// status asking for a resolution.
	d := diagram()
	if d.Draft || len(d.Statuses) != 3 || len(d.Transitions) != 4 || len(d.Categories) != 3 || d.Statuses[0].X != nil {
		t.Fatalf("published diagram: %+v", d)
	}
	ids := map[string]string{}
	for _, s := range d.Statuses {
		ids[s.Key] = s.ID
	}
	for _, tr := range d.Transitions {
		if tr.Name == "Done" && (tr.From != "" || tr.To != ids["done"] || !strings.Contains(tr.Requires, "a resolution")) {
			t.Fatalf("Done transition: %+v", tr)
		}
	}
	if code := layout(admin, `{"`+ids["todo"]+`": [1, 2]}`); code != http.StatusConflict {
		t.Fatalf("layout without a draft: %d", code)
	}

	// On a draft, statuses move; only admins move them.
	h.do(admin, "POST", wfURL+"/edit", nil)
	d = diagram()
	if !d.Draft {
		t.Fatal("not the draft")
	}
	for _, s := range d.Statuses {
		ids[s.Key] = s.ID
	}
	if code := layout(viewer, `{"`+ids["todo"]+`": [1, 2]}`); code != http.StatusForbidden {
		t.Fatalf("viewer moved a status: %d", code)
	}
	for _, bad := range []string{`nope`, `{"x": [1]}`, `{"x": "1,2"}`} {
		if code := layout(admin, bad); code != http.StatusBadRequest {
			t.Fatalf("layout %s: %d", bad, code)
		}
	}
	if code := layout(admin, `{"`+ids["todo"]+`": [120, -40.5], "`+ids["done"]+`": [460, 0]}`); code != http.StatusNoContent {
		t.Fatalf("layout: %d", code)
	}
	d = diagram()
	for _, s := range d.Statuses {
		if s.Key == "todo" && (s.X == nil || *s.X != 120 || *s.Y != -40.5) {
			t.Fatalf("placed status: %+v", s)
		}
	}

	// A status added on the diagram lands where it was asked for, and a
	// transition drawn on it; both come back to the diagram.
	resp, _ := h.do(admin, "POST", wfURL+"/statuses", url.Values{"key": {"review"}, "name": {"Review"}, "category": {"in_progress"},
		"x": {"300"}, "y": {"80"}, "back": {"diagram"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "#diagram") || !strings.Contains(loc, "notice=") {
		t.Fatalf("status from the diagram: %s", loc)
	}
	d = diagram()
	for _, s := range d.Statuses {
		if s.Key == "review" {
			ids["review"] = s.ID
			if s.X == nil || *s.X != 300 || *s.Y != 80 {
				t.Fatalf("new status: %+v", s)
			}
		}
	}
	resp, _ = h.do(admin, "POST", wfURL+"/transitions", url.Values{"name": {"Send to review"}, "from": {ids["todo"]}, "to": {ids["review"]},
		"back": {"diagram"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "#diagram") {
		t.Fatalf("transition from the diagram: %s", loc)
	}
	// A status added in the table form is left for the page to place.
	h.do(admin, "POST", wfURL+"/statuses", url.Values{"key": {"blocked"}, "name": {"Blocked"}, "category": {"todo"}, "x": {"NaN"}, "y": {"1"}})
	d = diagram()
	var drawn, blocked bool
	for _, tr := range d.Transitions {
		drawn = drawn || (tr.Name == "Send to review" && tr.From == ids["todo"] && tr.To == ids["review"])
	}
	for _, s := range d.Statuses {
		blocked = blocked || (s.Key == "blocked" && s.X == nil)
	}
	if !drawn || !blocked {
		t.Fatalf("diagram after edits: %+v", d)
	}
}

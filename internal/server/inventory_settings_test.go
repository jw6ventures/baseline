package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestRetireMissingStacksSetting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.signIn("ann", "lab-admins")
	r := h.addHost("nas")
	c := containersFixture()
	c.Stacks = append(c.Stacks, model.ComposeStack{Engine: "docker", Project: "oldapp", Services: []string{"app"}})
	h.ingest(r, model.SectionContainers, c)
	h.ingest(r, model.SectionContainers, containersFixture())
	h.st.MarkMissing(ctx, time.Now().Add(2*time.Hour))

	// Off by default.
	_, body := h.do(admin, "GET", "/settings/inventory", nil)
	if !strings.Contains(body, "Off: missing stacks are never retired") {
		t.Fatalf("settings page:\n%s", body)
	}
	resp, _ := h.do(admin, "POST", "/settings/inventory", url.Values{"retire_stacks": {"on"}, "retire_days": {"0"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "error=") {
		t.Fatalf("0 days: %d %s", resp.StatusCode, loc)
	}
	if resp, _ := h.do(admin, "POST", "/settings/inventory", url.Values{"retire_stacks": {"on"}, "retire_days": {"14"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	if d, _ := h.st.RetireMissingStacksDays(ctx); d != 14 {
		t.Fatalf("days = %d", d)
	}
	if _, body := h.do(admin, "GET", "/settings/inventory", nil); !strings.Contains(body, "more than 14 days are retired") {
		t.Fatalf("settings page after save:\n%s", body)
	}
	if n, err := h.st.RetireMissingStacks(ctx, time.Now().Add(15*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("retired %d %v", n, err)
	}

	// Gone lists skip it; Retired lists it.
	if _, body := h.list(admin, "/stacks?show=gone"); strings.Contains(body, "oldapp") {
		t.Fatalf("gone view lists a retired stack:\n%s", body)
	}
	if _, body := h.list(admin, "/stacks?show=retired"); !strings.Contains(body, "oldapp") {
		t.Fatalf("retired view:\n%s", body)
	}
	if _, body := h.list(admin, "/hosts/"+r.HostID+"/stacks?show=gone"); strings.Contains(body, "oldapp") {
		t.Fatalf("host gone view lists a retired stack:\n%s", body)
	}

	// Unchecking turns it off.
	h.do(admin, "POST", "/settings/inventory", url.Values{"retire_days": {"14"}})
	if d, _ := h.st.RetireMissingStacksDays(ctx); d != 0 {
		t.Fatalf("days after off = %d", d)
	}

	ops := h.signIn("olga", "ops-nobody")
	if resp, _ := h.do(ops, "POST", "/settings/inventory", url.Values{"retire_stacks": {"on"}, "retire_days": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: %d", resp.StatusCode)
	}
}

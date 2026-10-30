package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func (h *harness) ingest(r store.EnrollResult, section string, v any) {
	h.t.Helper()
	b, hash, _ := model.Encode(v)
	if _, err := h.st.IngestSection(context.Background(), r.HostID, r.AgentID, section, hash, b, ""); err != nil {
		h.t.Fatal(err)
	}
}

func TestUpdatesPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.ingest(plex, model.SectionUpdates, model.Updates{Managers: []string{"dnf"}, Warnings: []string{"dnf: couldn't refresh repository metadata: timeout"},
		Updates: []model.Update{
			{Manager: "dnf", Name: "openssl-libs", Arch: "x86_64", Installed: "1:3.2.2-6.el9", Candidate: "1:3.2.2-7.el9", Repo: "baseos", Security: true, Advisories: []string{"RLSA-2025:7895"}},
			{Manager: "dnf", Name: "tzdata", Arch: "noarch", Installed: "2025a-1.el9", Candidate: "2025b-1.el9", Repo: "baseos"},
		}})
	h.ingest(dns, model.SectionUpdates, model.Updates{Managers: []string{"dnf"}, Updates: []model.Update{
		{Manager: "dnf", Name: "openssl-libs", Arch: "x86_64", Installed: "1:3.2.2-6.el9", Candidate: "1:3.2.2-7.el9", Repo: "baseos", Security: true},
	}})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})

	admin := h.signIn("ann", "lab-admins")
	// The old by-package address opens the packages list.
	_, body := h.list(admin, "/updates?view=packages")
	if !strings.Contains(body, "openssl-libs") || !strings.Contains(body, `data-f="host_count" data-op="eq" data-nop="ne" data-v="2"`) ||
		!strings.Contains(body, `data-v="plex"`) || !strings.Contains(body, `data-v="dns1"`) || !strings.Contains(body, `data-v="1:3.2.2-7.el9"`) {
		t.Fatalf("by package:\n%s", body)
	}
	_, body = h.list(admin, "/updates/packages?q=tzdata")
	if !strings.Contains(body, "tzdata") || strings.Contains(body, "openssl-libs") {
		t.Fatalf("by package, searched:\n%s", body)
	}
	_, body = h.list(admin, "/updates?security=1")
	if !strings.Contains(body, ">plex<") || !strings.Contains(body, ">dns1<") || !strings.Contains(body, "Security &gt; 0") {
		t.Fatalf("by host, security only:\n%s", body)
	}
	_, body = h.list(admin, "/updates?cf=packages&co=has&cv=tzdata&sort=name")
	if !strings.Contains(body, ">plex<") || strings.Contains(body, ">dns1<") {
		t.Fatalf("by host, with a package:\n%s", body)
	}

	// A scoped operator sees only their hosts' updates.
	ops := h.signIn("carl", "media-ops")
	_, body = h.list(ops, "/updates/packages")
	if !strings.Contains(body, `data-v="plex"`) || strings.Contains(body, "dns1") || !strings.Contains(body, `data-f="host_count" data-op="eq" data-nop="ne" data-v="1"`) {
		t.Fatalf("scoped by package:\n%s", body)
	}
	resp, body := h.do(ops, "GET", "/hosts/"+plex.HostID+"?tab=updates", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "RLSA-2025:7895") || !strings.Contains(body, "couldn&#39;t refresh") ||
		!strings.Contains(body, "Check now") {
		t.Fatalf("host updates tab: %d\n%s", resp.StatusCode, body)
	}

	// "Check now" asks for the updates section only.
	h.hub.online[plex.AgentID] = true
	resp, _ = h.do(ops, "POST", "/hosts/"+plex.HostID+"/refresh", url.Values{"section": {"updates"}})
	if resp.StatusCode != http.StatusSeeOther || len(h.hub.sections) != 1 || strings.Join(h.hub.sections[0], ",") != "updates" ||
		!strings.Contains(resp.Header.Get("Location"), "tab=updates") {
		t.Fatalf("check now: %d %s %v", resp.StatusCode, resp.Header.Get("Location"), h.hub.sections)
	}

	_, body = h.do(admin, "GET", "/", nil)
	if !strings.Contains(body, "security updates") || !strings.Contains(body, "Needs attention") {
		t.Fatalf("dashboard:\n%s", body)
	}
}

func TestMetricsTabAndJSON(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.addHost("web1")
	if err := h.st.MaintainMetrics(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := range 10 {
		h.st.IngestMetrics(ctx, host.HostID, now.Add(-time.Duration(10-i)*time.Minute), []store.MetricSample{
			{Kind: "cpu", Name: "user", Value: float64(10 + i)},
			{Kind: "cpu", Name: "system", Value: 5},
			{Kind: "fs", Name: "used_pct", Instance: "/", Value: 42},
		})
	}
	admin := h.signIn("ann", "lab-admins")
	resp, body := h.do(admin, "GET", "/hosts/"+host.HostID+"?tab=metrics&range=1h", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `<svg class="chart-svg"`) || !strings.Contains(body, "Filesystem used") ||
		strings.Contains(body, "Drive temperature") || !strings.Contains(body, "/static/metrics.js") || !strings.Contains(body, "42%") {
		t.Fatalf("metrics tab: %d\n%s", resp.StatusCode, body)
	}
	// Other tabs don't load the chart scripts.
	if _, body := h.do(admin, "GET", "/hosts/"+host.HostID, nil); strings.Contains(body, "uPlot") {
		t.Fatal("chart scripts on the overview")
	}

	resp, body = h.do(admin, "GET", "/hosts/"+host.HostID+"/metrics/cpu.json?range=1h", nil)
	var d struct {
		Unit   string
		Max    float64
		Labels []string
		Times  []int64
		Values [][]*float64
	}
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &d) != nil {
		t.Fatalf("json: %d %s", resp.StatusCode, body)
	}
	if d.Unit != "%" || d.Max != 100 || strings.Join(d.Labels, ",") != "user,system" || len(d.Times) != 10 || *d.Values[0][9] != 19 {
		t.Fatalf("json = %+v", d)
	}
	if resp, _ := h.do(admin, "GET", "/hosts/"+host.HostID+"/metrics/nope.json", nil); resp.StatusCode != 404 {
		t.Fatalf("unknown panel: %d", resp.StatusCode)
	}

	// Out of scope: the host doesn't exist, as for its pages.
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "nobody", Role: rbac.Viewer, ScopeGroupID: mustGroup(t, h, "other")})
	if resp, _ := h.do(h.signIn("x", "nobody"), "GET", "/hosts/"+host.HostID+"/metrics/cpu.json", nil); resp.StatusCode != 404 {
		t.Fatalf("out of scope: %d", resp.StatusCode)
	}
}

func mustGroup(t *testing.T, h *harness, name string) string {
	g, err := h.st.CreateHostGroup(context.Background(), store.System, name, "")
	if err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func TestAgentUpdatesFromSettings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	web := h.addHost("web1")
	old := h.addHost("old1")
	h.st.AgentConnected(ctx, web.HostID, web.AgentID, store.Hello{AgentVersion: "1.0", Arch: "amd64", MachineID: "web1"})
	h.st.AgentConnected(ctx, old.HostID, old.AgentID, store.Hello{AgentVersion: "0.2.0", MachineID: "old1"}) // pre-M2: no arch
	h.st.PublishRelease(ctx, store.Release{Version: "2.0", Arch: "amd64", SHA256: "ab", Signature: []byte("s"), Size: 1, Path: "/x"})
	h.hub.online[web.AgentID] = true

	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	if resp, _ := h.do(h.signIn("o", "ops"), "POST", "/settings/agents/update", url.Values{"version": {"2.0"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator: %d", resp.StatusCode)
	}

	admin := h.signIn("ann", "lab-admins")
	_, body := h.do(admin, "GET", "/settings/agents", nil)
	if !strings.Contains(body, "2.0") || !strings.Contains(body, "re-run install.sh") || !strings.Contains(body, "2 not on 2.0") {
		t.Fatalf("agents page:\n%s", body)
	}
	resp, _ := h.do(admin, "POST", "/settings/agents/update", url.Values{"version": {"2.0"}})
	if resp.StatusCode != http.StatusSeeOther || len(h.hub.updated) != 1 || h.hub.updated[0] != web.AgentID {
		t.Fatalf("update all: %d %v", resp.StatusCode, h.hub.updated)
	}
	if got, _ := h.st.GetHost(ctx, web.HostID); got.AgentUpdateTarget != "2.0" {
		t.Fatalf("target = %q", got.AgentUpdateTarget)
	}
	if got, _ := h.st.GetHost(ctx, old.HostID); got.AgentUpdateTarget != "" {
		t.Fatal("a host without a matching build got a target")
	}
	if resp, _ := h.do(admin, "POST", "/settings/agents/update", url.Values{"version": {"9.9"}}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("unpublished version accepted")
	}
	_, body = h.do(admin, "GET", "/hosts/"+web.HostID, nil)
	if !strings.Contains(body, "updating to 2.0") {
		t.Fatalf("host overview:\n%s", body)
	}
	if !strings.Contains(h.auditActions(), "host.agent_update") {
		t.Fatal("not audited")
	}
}

func TestAgentUpdatesSkipSelfUpdateOff(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	web := h.addHost("web1")
	locked := h.addHost("locked1")
	h.st.AgentConnected(ctx, web.HostID, web.AgentID, store.Hello{AgentVersion: "1.0", Arch: "amd64", MachineID: "web1",
		Policy: &action.Policy{Jobs: true, AllowScripts: true}})
	h.st.AgentConnected(ctx, locked.HostID, locked.AgentID, store.Hello{AgentVersion: "1.0", Arch: "amd64", MachineID: "locked1",
		Policy: &action.Policy{Jobs: true, AllowScripts: true, SelfUpdateOff: true}})
	h.st.PublishRelease(ctx, store.Release{Version: "2.0", Arch: "amd64", SHA256: "ab", Signature: []byte("s"), Size: 1, Path: "/x"})
	h.hub.online[web.AgentID], h.hub.online[locked.AgentID] = true, true

	admin := h.signIn("ann", "lab-admins")
	_, body := h.do(admin, "GET", "/settings/agents", nil)
	if !strings.Contains(body, "1 with self-update off") || !strings.Contains(body, "off in agent.conf") {
		t.Fatalf("agents page:\n%s", body)
	}
	h.do(admin, "POST", "/settings/agents/update", url.Values{"version": {"2.0"}})
	if len(h.hub.updated) != 1 || h.hub.updated[0] != web.AgentID {
		t.Fatalf("updated %v", h.hub.updated)
	}
	if got, _ := h.st.GetHost(ctx, locked.HostID); got.AgentUpdateTarget != "" {
		t.Fatal("a host with self-update off got a target")
	}

	resp, _ := h.do(admin, "POST", "/hosts/"+locked.HostID+"/agent-update", url.Values{"version": {"2.0"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "self_update") {
		t.Fatalf("host update: %s", loc)
	}
	_, body = h.do(admin, "GET", "/hosts/"+locked.HostID, nil)
	if !strings.Contains(body, "self-update off") || strings.Contains(body, "Update to 2.0") {
		t.Fatalf("host overview:\n%s", body)
	}
}

func TestChartHelpers(t *testing.T) {
	for _, c := range []struct{ max, step, top float64 }{{100, 25, 100}, {7, 2, 8}, {0.3, 0.1, 0.30000000000000004}, {1234567, 500000, 1500000}, {0, 0.25, 1}} {
		step, top := niceScale(c.max)
		if step != c.step || math.Abs(top-c.top) > 1e-9 {
			t.Errorf("niceScale(%v) = %v, %v; want %v, %v", c.max, step, top, c.step, c.top)
		}
	}
	for v, want := range map[float64]string{1500: "1.5k", 2e6: "2M", 0.25: "0.25", 12.5: "12.5", 3: "3"} {
		if got := compact(v); got != want {
			t.Errorf("compact(%v) = %q, want %q", v, got, want)
		}
	}
	if got := formatValue(3<<30, "bytes/s"); got != "3.0 GiB/s" {
		t.Errorf("bytes/s = %q", got)
	}
	from := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	svg := string(svgChart(chartSpec{Title: `<script>`, Unit: "%", Max: 100, From: from, To: from.Add(time.Hour), Loc: time.UTC,
		Times: []time.Time{from, from.Add(time.Minute), from.Add(30 * time.Minute)},
		Lines: []chartLine{{Label: "a", Values: []float64{10, math.NaN(), 20}}}}))
	if strings.Contains(svg, "<script>") || !strings.Contains(svg, "&lt;script&gt;") {
		t.Fatal("title not escaped")
	}
	// The gap breaks the line: two moves, no line between them.
	if strings.Count(svg, "M") != 2 || strings.Contains(svg, "L") || !strings.Contains(svg, ">10:30<") {
		t.Fatalf("svg = %s", svg)
	}
}

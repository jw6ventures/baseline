package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/alert"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/notify"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func ruleOfKind(t *testing.T, st *store.Store, kind string) store.AlertRule {
	t.Helper()
	rules, _ := st.ListAlertRules(context.Background())
	for _, r := range rules {
		if r.Kind == kind {
			return r
		}
	}
	t.Fatalf("no %s rule", kind)
	return store.AlertRule{}
}

func TestAlertsUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	lab, _ := h.st.CreateHostGroup(ctx, store.System, "lab", "")
	plex := h.addHost("plex", media.ID)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "lab-ops", Role: rbac.Operator, ScopeGroupID: lab.ID})
	admin := h.signIn("ann", "lab-admins")
	mediaOps := h.signIn("mo", "media-ops")
	labOps := h.signIn("lo", "lab-ops")

	if _, body := h.do(admin, "GET", "/alerts", nil); !strings.Contains(body, "Nothing matches.") || !strings.Contains(body, "Resolved this week") {
		t.Fatalf("empty alerts:\n%s", body)
	}
	if _, body := h.do(admin, "GET", "/alerts?view=rules", nil); !strings.Contains(body, "Failed systemd units") ||
		!strings.Contains(body, "No notification channels yet") || !strings.Contains(body, "≥ 90%") {
		t.Fatalf("rules:\n%s", body)
	}

	// A channel: the token is sealed, never shown.
	resp, _ := h.do(admin, "POST", "/settings/notifications", url.Values{"kind": {"ntfy"}, "name": {"phone"},
		"server": {"https://ntfy.example"}, "topic": {"lab-alerts"}, "token": {"tk_secret"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("save channel: %s", resp.Header.Get("Location"))
	}
	chs, _ := h.st.ListChannels(ctx)
	if len(chs) != 1 || chs[0].Summary != "https://ntfy.example/lab-alerts" || strings.Contains(chs[0].ConfigEnc, "tk_secret") {
		t.Fatalf("channel: %+v", chs)
	}
	var cfg notify.Config
	if err := h.srv.secrets.Open(chs[0].ConfigEnc, &cfg); err != nil || cfg.Token != "tk_secret" {
		t.Fatalf("sealed config: %+v %v", cfg, err)
	}
	if resp, _ = h.do(admin, "POST", "/settings/notifications", url.Values{"kind": {"matrix"}, "name": {"x"},
		"homeserver": {"matrix.example"}, "room": {"ops"}, "token": {"t"}}); !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatal("bad Matrix settings accepted")
	}
	// Renaming keeps the settings; a test message is queued.
	h.do(admin, "POST", "/settings/notifications/"+chs[0].ID, url.Values{"name": {"my phone"}, "enabled": {"1"}})
	if c, _ := h.st.GetChannel(ctx, chs[0].ID); c.Name != "my phone" || c.ConfigEnc != chs[0].ConfigEnc || !c.Enabled {
		t.Fatalf("renamed: %+v", c)
	}
	h.do(admin, "POST", "/settings/notifications/"+chs[0].ID+"/test", nil)
	if _, body := h.do(admin, "GET", "/settings/notifications", nil); !strings.Contains(body, "Baseline test message") ||
		!strings.Contains(body, "queued") || strings.Contains(body, "tk_secret") {
		t.Fatalf("notifications page:\n%s", body)
	}
	if resp, _ := h.do(mediaOps, "GET", "/settings/notifications", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator saw channels: %d", resp.StatusCode)
	}

	// The units rule notifies the channel and fires at once.
	units := ruleOfKind(t, h.st, "failed_units")
	if _, body := h.do(admin, "GET", "/alert-rules/"+units.ID, nil); !strings.Contains(body, `name="exclude"`) ||
		!strings.Contains(body, "my phone") {
		t.Fatalf("rule form:\n%s", body)
	}
	resp, _ = h.do(admin, "POST", "/alert-rules/"+units.ID, url.Values{"name": {units.Name}, "severity": {"critical"},
		"channel": {chs[0].ID}, "exclude": {"fwupd*, snap.*"}, "notify_resolved": {"1"}, "enabled": {"1"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("save rule: %s", resp.Header.Get("Location"))
	}
	units, _ = h.st.GetAlertRule(ctx, units.ID)
	if units.Severity != "critical" || units.For != 0 || len(units.Channels) != 1 || len(units.Params.Exclude) != 2 {
		t.Fatalf("rule: %+v", units)
	}
	h.ingest(plex, model.SectionServices, model.Services{Units: []model.Service{{Name: "plexmediaserver.service", Active: "failed"}}})
	e := &alert.Evaluator{Store: h.st, PublicURL: h.cfg.PublicURL.String()}
	if err := e.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	open, _ := h.st.ListAlerts(ctx, store.AlertFilter{Open: true})
	if len(open) != 1 {
		t.Fatalf("open: %+v", open)
	}
	a := open[0]

	_, body := h.do(mediaOps, "GET", "/alerts", nil)
	if !strings.Contains(body, "plex: plexmediaserver.service failed") || !strings.Contains(body, `<option value="ack">Acknowledge</option>`) {
		t.Fatalf("media ops' alerts:\n%s", body)
	}
	if _, body = h.do(labOps, "GET", "/alerts", nil); strings.Contains(body, "plexmediaserver") {
		t.Fatal("lab ops see a media alert")
	}
	if resp, _ = h.do(labOps, "GET", "/alerts/"+a.ID, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("lab ops opened it: %d", resp.StatusCode)
	}
	if resp, _ = h.do(labOps, "POST", "/alerts/"+a.ID+"/ack", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("lab ops acked: %d", resp.StatusCode)
	}
	if _, body = h.do(admin, "GET", "/", nil); !strings.Contains(body, "alerts firing (1 critical)") {
		t.Fatalf("dashboard:\n%s", body)
	}
	if _, body = h.do(mediaOps, "GET", "/hosts/"+plex.HostID, nil); !strings.Contains(body, "plexmediaserver.service failed") {
		t.Fatalf("host overview lacks the alert:\n%s", body)
	}

	h.do(mediaOps, "POST", "/alerts/"+a.ID+"/ack", url.Values{"comment": {"restarting it"}})
	_, body = h.do(mediaOps, "GET", "/alerts/"+a.ID, nil)
	if !strings.Contains(body, "acknowledged by MO") || !strings.Contains(body, "restarting it") ||
		!strings.Contains(body, "my phone") || strings.Contains(body, ">Acknowledge</button>") {
		t.Fatalf("alert page:\n%s", body)
	}

	// Silences: one from the list, ended again; a global one needs a global
	// operator.
	resp, _ = h.do(mediaOps, "POST", "/alerts/"+a.ID+"/silence", url.Values{"for": {"4h"}, "from": {"list"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=Silenced") {
		t.Fatalf("silence: %s", resp.Header.Get("Location"))
	}
	sils, _ := h.st.ListSilences(ctx, time.Now())
	if len(sils) != 1 || sils[0].CIID != plex.HostID || sils[0].RuleID != units.ID || sils[0].Key != "plexmediaserver.service" {
		t.Fatalf("silences: %+v", sils)
	}
	if _, body = h.do(labOps, "GET", "/alerts?view=silences", nil); strings.Contains(body, "End now") {
		t.Fatal("lab ops can end a media silence")
	}
	if resp, _ = h.do(labOps, "POST", "/silences/"+sils[0].ID+"/end", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("lab ops ended it: %d", resp.StatusCode)
	}
	if _, body = h.do(mediaOps, "GET", "/alerts?view=silences", nil); !strings.Contains(body, "End now") || !strings.Contains(body, "on plex") {
		t.Fatalf("silences page:\n%s", body)
	}
	h.do(mediaOps, "POST", "/silences/"+sils[0].ID+"/end", nil)
	if sils, _ = h.st.ListSilences(ctx, time.Now()); len(sils) != 0 {
		t.Fatalf("not ended: %+v", sils)
	}
	// From the list: the alert's own operators silence it; others' picks
	// are skipped.
	resp, _ = h.do(labOps, "POST", "/lists/alert/bulk", url.Values{"action": {"silence"}, "value": {"1h"}, "id": {a.ID}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "Skipped+1") {
		t.Fatalf("lab ops' bulk silence: %s", loc)
	}
	resp, _ = h.do(mediaOps, "POST", "/lists/alert/bulk", url.Values{"action": {"silence"}, "value": {"1h"}, "id": {a.ID}})
	if sils, _ = h.st.ListSilences(ctx, time.Now()); len(sils) != 1 || sils[0].Key != "plexmediaserver.service" ||
		!strings.Contains(resp.Header.Get("Location"), "1+alert") {
		t.Fatalf("bulk silence: %s %+v", resp.Header.Get("Location"), sils)
	}
	h.do(mediaOps, "POST", "/silences/"+sils[0].ID+"/end", nil)
	if resp, _ = h.do(mediaOps, "POST", "/silences", url.Values{"for": {"1h"}, "comment": {"all of it"}}); !strings.Contains(resp.Header.Get("Location"), "global+operator") {
		t.Fatalf("scoped operator silenced everything: %s", resp.Header.Get("Location"))
	}
	if resp, _ = h.do(mediaOps, "POST", "/silences", url.Values{"for": {"1h"}, "comment": {"disk swap"}, "group": {media.ID}}); !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("group silence: %s", resp.Header.Get("Location"))
	}

	// Closing: the alert's own operators only, from its page or the list,
	// and it shows nowhere after.
	if _, body = h.do(mediaOps, "GET", "/alerts/"+a.ID, nil); !strings.Contains(body, ">Close</button>") {
		t.Fatalf("no close button:\n%s", body)
	}
	if resp, _ = h.do(labOps, "POST", "/lists/alert/bulk", url.Values{"action": {"close"}, "id": {a.ID}}); !strings.Contains(resp.Header.Get("Location"), "Skipped+1") {
		t.Fatalf("lab ops' bulk close: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(mediaOps, "POST", "/alerts/"+a.ID+"/close", url.Values{"comment": {"known"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=Closed") {
		t.Fatalf("close: %s", resp.Header.Get("Location"))
	}
	if got, _ := h.st.GetAlert(ctx, a.ID); got.State != store.AlertClosed || got.ClosedByName != "MO" {
		t.Fatalf("closed: %+v", got)
	}
	for _, path := range []string{"/alerts", "/alerts?view=history", "/hosts/" + plex.HostID, "/"} {
		if _, body = h.do(admin, "GET", path, nil); strings.Contains(body, "plexmediaserver.service failed") {
			t.Fatalf("%s shows the closed alert:\n%s", path, body)
		}
	}
	if _, body = h.do(mediaOps, "GET", "/alerts/"+a.ID, nil); !strings.Contains(body, "closed</span>") || strings.Contains(body, ">Close</button>") {
		t.Fatalf("closed alert's page:\n%s", body)
	}

	// New rules: the kind picker, then validation.
	if _, body = h.do(admin, "GET", "/alert-rules/new", nil); !strings.Contains(body, "Fixable CVEs") || !strings.Contains(body, "kind=disk_full") {
		t.Fatalf("kind picker:\n%s", body)
	}
	if resp, body = h.do(admin, "POST", "/alert-rules", url.Values{"kind": {"disk_full"}, "name": {"Media disks"},
		"percent": {"120"}, "severity": {"warning"}}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "between 1 and 100") {
		t.Fatalf("bad rule: %d", resp.StatusCode)
	}
	resp, _ = h.do(admin, "POST", "/alert-rules", url.Values{"kind": {"disk_full"}, "name": {"Media disks"}, "percent": {"80"},
		"severity": {"warning"}, "scope": {media.ID}, "for": {"10m"}, "repeat": {"1d"}, "enabled": {"1"}})
	if !strings.Contains(resp.Header.Get("Location"), "view=rules") {
		t.Fatalf("new rule: %s", resp.Header.Get("Location"))
	}
	if _, body = h.do(admin, "GET", "/alerts?view=rules", nil); !strings.Contains(body, "Media disks") ||
		!strings.Contains(body, "≥ 80%; for 10m; remind every 1d") {
		t.Fatalf("rules after create:\n%s", body)
	}
	if resp, _ = h.do(mediaOps, "GET", "/alert-rules/new", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator opened the rule form: %d", resp.StatusCode)
	}
	if got := h.auditActions(); !strings.Contains(got, "notify_channel.create") || !strings.Contains(got, "alert_rule.update") ||
		!strings.Contains(got, "alert.ack") || !strings.Contains(got, "alert.close") || !strings.Contains(got, "silence.create") || !strings.Contains(got, "silence.end") {
		t.Fatalf("audit: %s", got)
	}
}

func TestVulnerabilitiesUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	desk := h.addHost("desk")
	h.ingest(plex, model.SectionOS, model.OS{Hostname: "plex", ID: "rocky", VersionID: "9.6"})
	h.ingest(desk, model.SectionOS, model.OS{Hostname: "desk", ID: "fedora", VersionID: "42"})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	admin := h.signIn("ann", "lab-admins")
	mediaOps := h.signIn("mo", "media-ops")

	score := 7.0
	if err := h.st.ReplaceVulns(ctx, "Rocky Linux:9", []store.Vuln{
		{ID: "RLSA-2025:9978", Aliases: []string{"CVE-2025-32462"}, Summary: "Important: sudo security update", Severity: "high",
			CVSSScore: &score, Refs: []store.VulnRef{{Type: "ADVISORY", URL: "https://errata.rockylinux.org/RLSA-2025:9978"}}},
		{ID: "RLSA-2024:1", Summary: "Low: tzdata", Severity: "low"},
	}, []store.VulnAffected{
		{VulnID: "RLSA-2025:9978", Ecosystem: "Rocky Linux:9", Package: "sudo", Ranges: json.RawMessage(`[[{"introduced":"0"},{"fixed":"0:1.9.5p2-10.el9_6.1"}]]`)},
		{VulnID: "RLSA-2024:1", Ecosystem: "Rocky Linux:9", Package: "tzdata", Ranges: json.RawMessage(`[[{"introduced":"0"}]]`)},
	}); err != nil {
		t.Fatal(err)
	}
	h.st.SaveHostVulns(ctx, plex.HostID, "Rocky Linux:9", []store.HostVuln{
		{VulnID: "RLSA-2025:9978", Package: "sudo", Arch: "x86_64", Installed: "1.9.5p2-10.el9_6", Fixed: "0:1.9.5p2-10.el9_6.1",
			Candidate: "1.9.5p2-10.el9_6.1", FixAvailable: true, Severity: "high"},
		{VulnID: "RLSA-2024:1", Package: "tzdata", Installed: "2025a-1.el9", Severity: "low"},
	})
	h.st.SaveHostVulns(ctx, desk.HostID, "", nil)

	_, body := h.do(admin, "GET", "/vulnerabilities", nil)
	for _, want := range []string{"RLSA-2025:9978", "CVE-2025-32462", "Important: sudo security update", "7.0",
		"Not covered by OSV", ">desk</a>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("list lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "RLSA-2024:1") {
		t.Fatal("unfixable listed by default")
	}
	if _, body = h.do(admin, "GET", "/vulnerabilities?fixable=0&q=tzdata", nil); !strings.Contains(body, "RLSA-2024:1") || strings.Contains(body, "RLSA-2025:9978") {
		t.Fatalf("search:\n%s", body)
	}
	if _, body = h.do(admin, "GET", "/vulnerabilities?view=hosts", nil); !strings.Contains(body, "Rocky Linux:9") || !strings.Contains(body, "vsev-high") {
		t.Fatalf("by host:\n%s", body)
	}
	if _, body = h.do(admin, "GET", "/vulnerabilities/RLSA-2025:9978", nil); !strings.Contains(body, ">plex</a>") ||
		!strings.Contains(body, "fix available") || !strings.Contains(body, "errata.rockylinux.org") {
		t.Fatalf("vuln page:\n%s", body)
	}
	_, body = h.do(mediaOps, "GET", "/hosts/"+plex.HostID+"?tab=vulnerabilities", nil)
	if !strings.Contains(body, "Upgrade 1 fixing package…") || !strings.Contains(body, `name="pkg" value="sudo"`) ||
		!strings.Contains(body, `<span class="count warn" title="fixed by pending updates">1<span class="sr-only"> fixed by pending updates</span></span>`) {
		t.Fatalf("host tab:\n%s", body)
	}
	if _, body = h.do(admin, "GET", "/hosts/"+desk.HostID+"?tab=vulnerabilities", nil); !strings.Contains(body, "OSV publishes no vulnerability data") {
		t.Fatalf("uncovered host tab:\n%s", body)
	}
	if _, body = h.do(admin, "GET", "/", nil); !strings.Contains(body, "fixable CVEs (1 high or critical)") {
		t.Fatalf("dashboard:\n%s", body)
	}

	// Someone who can't see plex sees nothing of it.
	h.st.CreateHostGroup(ctx, store.System, "lab", "")
	lab, _ := h.st.ListHostGroups(ctx)
	for _, g := range lab {
		if g.Name == "lab" {
			h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "lab-view", Role: rbac.Viewer, ScopeGroupID: g.ID})
		}
	}
	other := h.signIn("lv", "lab-view")
	if _, body = h.do(other, "GET", "/vulnerabilities", nil); strings.Contains(body, "RLSA-2025:9978") {
		t.Fatal("another group's vulnerability listed")
	}
	if _, body = h.do(other, "GET", "/vulnerabilities/RLSA-2025:9978", nil); strings.Contains(body, ">plex</a>") {
		t.Fatal("another group's host listed")
	}

	if resp, _ := h.do(admin, "POST", "/vulnerabilities/sync", nil); !strings.Contains(resp.Header.Get("Location"), "turned+off") {
		t.Fatalf("sync without a syncer: %s", resp.Header.Get("Location"))
	}
	if resp, _ := h.do(mediaOps, "POST", "/vulnerabilities/sync", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator synced: %d", resp.StatusCode)
	}
}

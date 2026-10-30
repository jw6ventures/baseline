package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/notify"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

type host struct {
	id, agent string
}

func addHost(t *testing.T, st *store.Store, name string, groups ...string) host {
	t.Helper()
	ctx := context.Background()
	secret := pki.NewTokenSecret()
	if _, err := st.CreateEnrollmentToken(ctx, store.System, "", store.EnrollmentToken{
		Name: name, ExpiresAt: time.Now().Add(time.Hour), DefaultGroups: groups}, pki.HashTokenSecret(secret)); err != nil {
		t.Fatal(err)
	}
	res, err := st.Enroll(ctx, store.EnrollRequest{SecretHash: pki.HashTokenSecret(secret), MachineID: name, Hostname: name},
		func(string) (string, time.Time, error) { return "serial-" + name, time.Now().Add(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	h := host{res.HostID, res.AgentID}
	ingest(t, st, h, model.SectionOS, model.OS{Hostname: name, ID: "rocky", VersionID: "9.6"})
	return h
}

func ingest(t *testing.T, st *store.Store, h host, section string, v any) {
	t.Helper()
	b, hash, _ := model.Encode(v)
	if _, err := st.IngestSection(context.Background(), h.id, h.agent, section, hash, b, ""); err != nil {
		t.Fatal(err)
	}
}

func exec(t *testing.T, st *store.Store, q string, args ...any) {
	t.Helper()
	if _, err := st.DB().Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// ruleByKind returns the seeded rule of a kind.
func ruleByKind(t *testing.T, st *store.Store, kind string) store.AlertRule {
	t.Helper()
	rules, err := st.ListAlertRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Kind == kind {
			return r
		}
	}
	t.Fatalf("no %s rule", kind)
	return store.AlertRule{}
}

func openAlerts(t *testing.T, st *store.Store) map[string]store.Alert {
	t.Helper()
	as, err := st.ListAlerts(context.Background(), store.AlertFilter{Open: true})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.Alert{}
	for _, a := range as {
		out[a.RuleKind+"/"+a.Subject+"/"+a.Key] = a
	}
	return out
}

func keys(m map[string]store.Alert) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// sink is an ntfy server and a Matrix homeserver in one.
type sink struct {
	mu   sync.Mutex
	got  []string
	fail bool
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		http.Error(w, `{"error":"down"}`, http.StatusBadGateway)
		return
	}
	b, _ := io.ReadAll(r.Body)
	switch {
	case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/directory/room/"):
		if r.Header.Get("Authorization") != "Bearer mx-token" {
			http.Error(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"bad token"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"room_id":"!room:example.org"}`))
		return
	case strings.HasPrefix(r.URL.Path, "/_matrix/"):
		var m map[string]string
		json.Unmarshal(b, &m)
		s.got = append(s.got, "matrix "+r.Method+" "+r.URL.EscapedPath()+" "+m["body"])
		w.Write([]byte(`{"event_id":"$1"}`))
		return
	}
	s.got = append(s.got, "ntfy "+r.URL.Path+" "+r.Header.Get("Title")+" p"+r.Header.Get("Priority")+" "+r.Header.Get("Tags")+
		" "+r.Header.Get("Click")+" | "+string(b))
}

func (s *sink) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.got
	s.got = nil
	return g
}

func TestEvaluate(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	now := time.Now()
	sk := &sink{}
	srv := httptest.NewServer(sk)
	defer srv.Close()
	n := &notify.Notifier{Store: st, Open: func(sealed string, into any) error { return json.Unmarshal([]byte(sealed), into) },
		Now: func() time.Time { return now }}
	nudged := 0
	e := &Evaluator{Store: st, PublicURL: "https://baseline.example/", Now: func() time.Time { return now },
		Nudge: func() { nudged++ }}

	sealed := func(c notify.Config) string { b, _ := json.Marshal(c); return string(b) }
	ntfy, err := st.SaveChannel(ctx, store.System, store.NotifyChannel{Kind: notify.Ntfy, Name: "phone", Enabled: true,
		ConfigEnc: sealed(notify.Config{Server: srv.URL, Topic: "lab"})})
	if err != nil {
		t.Fatal(err)
	}
	mx, _ := st.SaveChannel(ctx, store.System, store.NotifyChannel{Kind: notify.Matrix, Name: "ops room", Enabled: true,
		ConfigEnc: sealed(notify.Config{Homeserver: srv.URL, Room: "#ops:example.org", Token: "mx-token"})})

	mediaG, _ := st.CreateHostGroup(ctx, store.System, "media", "")
	media := mediaG.ID
	plex := addHost(t, st, "plex", media)
	if err := st.MaintainMetrics(ctx, now); err != nil {
		t.Fatal(err)
	}
	db := addHost(t, st, "db")

	// Failed units notify both channels at once; other rules stay quiet
	// (no channels).
	units := ruleByKind(t, st, "failed_units")
	units.Channels, units.For, units.Params.Exclude = []string{ntfy, mx}, 0, []string{"fwupd*"}
	if _, err := st.SaveAlertRule(ctx, store.System, units); err != nil {
		t.Fatal(err)
	}
	ingest(t, st, plex, model.SectionServices, model.Services{Units: []model.Service{
		{Name: "nginx.service", Description: "web", Active: "failed"}, {Name: "fwupd-refresh.service", Active: "failed"},
		{Name: "sshd.service", Active: "active"}}})
	// A drive failing (critical whatever the rule says), a pending reboot
	// for long enough, an expiring certificate, a full disk.
	pass := false
	ingest(t, st, db, model.SectionSmart, model.Smart{Devices: []model.SmartDevice{
		{Name: "sda", Model: "WD Red", Passed: &pass}, {Name: "sdb", Passed: new(bool(true)), Reallocated: 8}}})
	ingest(t, st, db, model.SectionReboot, model.Reboot{Required: true, Reasons: []string{"kernel 5.14.0-570"}})
	exec(t, st, `UPDATE host SET reboot_required_since = now() - interval '8 days' WHERE ci_id = $1`, db.id)
	ingest(t, st, plex, model.SectionCerts, model.Certs{Certs: []model.Cert{{Location: "/etc/ssl/plex.pem", Subject: "CN=plex",
		NotAfter: now.Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339), NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339)}}})
	if err := st.IngestMetrics(ctx, plex.id, now.Add(-time.Minute), []store.MetricSample{
		{Kind: "fs", Name: "used_pct", Instance: "/", Value: 96}, {Kind: "fs", Name: "used_pct", Instance: "/boot", Value: 40},
		{Kind: "fs", Name: "inodes_used_pct", Instance: "/", Value: 12}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	got := openAlerts(t, st)
	want := []string{"cert_expiry/plex//etc/ssl/plex.pem", "disk_full/plex//", "failed_units/plex/nginx.service",
		"reboot_pending/db/", "smart/db/sda", "smart/db/sdb"}
	if !slices.Equal(keys(got), want) {
		t.Fatalf("open alerts %q", keys(got))
	}
	if a := got["smart/db/sda"]; a.Severity != "critical" || a.State != store.AlertFiring || !strings.Contains(a.Summary, "failing") {
		t.Fatalf("failing drive: %+v", a)
	}
	if a := got["smart/db/sdb"]; a.Severity != "warning" || !strings.Contains(a.Summary, "8 reallocated sectors") {
		t.Fatalf("degrading drive: %+v", a)
	}
	// The disk rule waits 5 minutes (seeded for_s) before firing.
	if a := got["disk_full/plex//"]; a.State != store.AlertPending || a.Summary != "plex: / is 96% full" {
		t.Fatalf("disk: %+v", a)
	}
	nginx := got["failed_units/plex/nginx.service"]
	if nginx.State != store.AlertFiring || nginx.NotifiedAt.IsZero() || nudged != 1 || !slices.Equal(nginx.GroupIDs, []string{media}) {
		t.Fatalf("nginx: %+v", nginx)
	}
	if err := n.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	sent := sk.take()
	if len(sent) != 2 ||
		sent[0] != "matrix PUT /_matrix/client/v3/rooms/%21room:example.org/send/m.room.message/baseline-1 [WARNING] Failed systemd units\nplex: nginx.service failed (web)\nhttps://baseline.example/alerts/"+nginx.ID ||
		sent[1] != "ntfy /lab [WARNING] Failed systemd units p4 warning https://baseline.example/alerts/"+nginx.ID+" | plex: nginx.service failed (web)" {
		t.Fatalf("sent %q", sent)
	}
	ch, _ := st.GetChannel(ctx, mx)
	if ch.LastSentAt.IsZero() || ch.LastError != "" {
		t.Fatalf("channel: %+v", ch)
	}

	// Five minutes on: the disk alert fires; nginx isn't notified again.
	now = now.Add(5 * time.Minute)
	if err := st.IngestMetrics(ctx, plex.id, now.Add(-time.Minute), []store.MetricSample{{Kind: "fs", Name: "used_pct", Instance: "/", Value: 97}}); err != nil {
		t.Fatal(err)
	}
	e.Pass(ctx)
	got = openAlerts(t, st)
	if a := got["disk_full/plex//"]; a.State != store.AlertFiring || a.Summary != "plex: / is 97% full" {
		t.Fatalf("disk after 5m: %+v", a)
	}
	if ns, _ := st.AlertNotifications(ctx, nginx.ID); len(ns) != 2 {
		t.Fatalf("nginx notified again: %d", len(ns))
	}

	// A silence on the units rule for plex mutes a new failure; ending it
	// lets the notification out.
	sil, err := st.CreateSilence(ctx, store.System, store.Silence{RuleID: units.ID, CIID: plex.id, Starts: now.Add(-time.Second),
		Ends: now.Add(time.Hour), Comment: "maintenance"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, st, plex, model.SectionServices, model.Services{Units: []model.Service{
		{Name: "nginx.service", Active: "failed"}, {Name: "plexmediaserver.service", Active: "failed"}}})
	e.Pass(ctx)
	got = openAlerts(t, st)
	pms := got["failed_units/plex/plexmediaserver.service"]
	if pms.SilenceID != sil || !pms.NotifiedAt.IsZero() || got["failed_units/plex/nginx.service"].SilenceID != sil {
		t.Fatalf("silenced: %+v", pms)
	}
	n.Deliver(ctx)
	if s := sk.take(); len(s) != 0 {
		t.Fatalf("silenced alert notified: %q", s)
	}
	if err := st.EndSilence(ctx, store.System, sil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	e.Pass(ctx)
	n.Deliver(ctx)
	if s := sk.take(); len(s) != 2 || !strings.Contains(s[1], "plexmediaserver.service failed") {
		t.Fatalf("after the silence: %q", s)
	}

	// Reminders every 30 minutes until someone acknowledges.
	units.Repeat = 30 * time.Minute
	st.SaveAlertRule(ctx, store.System, units)
	now = now.Add(31 * time.Minute)
	e.Pass(ctx)
	n.Deliver(ctx)
	if s := sk.take(); len(s) != 4 || !strings.Contains(s[0], "Still firing") {
		t.Fatalf("reminders: %q", s)
	}
	if err := st.AckAlert(ctx, store.System, pms.ID, "looking"); err != nil {
		t.Fatal(err)
	}
	if err := st.AckAlert(ctx, store.System, pms.ID, "again"); err != store.ErrNotFound {
		t.Fatalf("acked twice: %v", err)
	}
	now = now.Add(31 * time.Minute)
	e.Pass(ctx)
	n.Deliver(ctx)
	if s := sk.take(); len(s) != 2 || strings.Contains(strings.Join(s, ""), "plexmediaserver") {
		t.Fatalf("reminders after ack: %q", s)
	}

	// Units recover: resolved, with a message; the next failure is a new
	// alert.
	ingest(t, st, plex, model.SectionServices, model.Services{Units: []model.Service{{Name: "nginx.service", Active: "active"}}})
	e.Pass(ctx)
	n.Deliver(ctx)
	if s := sk.take(); len(s) != 4 || !strings.Contains(s[1], "[RESOLVED] Failed systemd units") ||
		!strings.Contains(s[1], "p2 white_check_mark") || !strings.Contains(s[1], "resolved after 1h") {
		t.Fatalf("resolved: %q", s)
	}
	if a, _ := st.GetAlert(ctx, nginx.ID); a.State != store.AlertResolved || a.ResolvedAt.IsZero() {
		t.Fatalf("nginx after recovery: %+v", a)
	}

	// Channels that are down are retried with backoff.
	ingest(t, st, plex, model.SectionServices, model.Services{Units: []model.Service{{Name: "nginx.service", Active: "failed"}}})
	e.Pass(ctx)
	sk.fail = true
	n.Deliver(ctx)
	ns, _ := st.DueNotifications(ctx, now.Add(time.Hour), 10)
	if len(ns) != 2 || ns[0].Attempts != 1 || ns[0].Error != "resolving #ops:example.org: HTTP 502 Bad Gateway" ||
		ns[1].Error != "HTTP 502: down" {
		t.Fatalf("after a failure: %+v", ns)
	}
	sk.fail = false
	if n.Deliver(ctx); len(sk.take()) != 0 {
		t.Fatal("retried before the backoff")
	}
	now = now.Add(time.Minute)
	if n.Deliver(ctx); len(sk.take()) != 2 {
		t.Fatal("not retried after the backoff")
	}

	// Scope: a rule for the media group ignores db; disabling a rule
	// resolves its alerts without a message.
	smart := ruleByKind(t, st, "smart")
	smart.ScopeGroups, smart.Channels = []string{media}, []string{ntfy}
	st.SaveAlertRule(ctx, store.System, smart)
	reboot := ruleByKind(t, st, "reboot_pending")
	reboot.Enabled = false
	st.SaveAlertRule(ctx, store.System, reboot)
	e.Pass(ctx)
	got = openAlerts(t, st)
	if _, ok := got["smart/db/sda"]; ok {
		t.Fatal("out-of-scope alert still open")
	}
	if _, ok := got["reboot_pending/db/"]; ok {
		t.Fatal("disabled rule's alert still open")
	}
	if n.Deliver(ctx); len(sk.take()) != 0 {
		t.Fatal("quiet resolutions notified")
	}
}

// Drives alert on a bad sector count that rises, or reaches the rule's
// threshold, not on a few that stay put; closing any alert puts it away
// until it gets worse.
func TestSmartAndClose(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	e := &Evaluator{Store: st}
	db := addHost(t, st, "db")
	drives := func(realloc, pending int64) {
		t.Helper()
		ingest(t, st, db, model.SectionSmart, model.Smart{Devices: []model.SmartDevice{
			{Name: "sda", Passed: new(bool(true)), Reallocated: realloc, Pending: pending},
			{Name: "nvme0", Passed: new(bool(true)), PercentUsed: 95}}})
	}
	pass := func() map[string]store.Alert {
		t.Helper()
		if err := e.Pass(ctx); err != nil {
			t.Fatal(err)
		}
		return openAlerts(t, st)
	}

	// A drive first seen with bad sectors has just gone from none to some.
	drives(1, 0)
	got := pass()
	sda := got["smart/db/sda"]
	if sda.State != store.AlertFiring || sda.Level != 1 || sda.Summary != "db: drive sda is degrading: 1 reallocated sectors (rising)" {
		t.Fatalf("new drive: %+v", sda)
	}
	if _, ok := got["smart/db/nvme0"]; !ok {
		t.Fatal("wear alerts whatever the count")
	}

	// Closed: gone from every listing, and staying put keeps it closed. A
	// pending sector reallocated isn't a rise.
	if err := st.CloseAlert(ctx, store.System, sda.ID, "one bad sector"); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseAlert(ctx, store.System, sda.ID, "again"); err != store.ErrNotFound {
		t.Fatalf("closed twice: %v", err)
	}
	drives(1, 0)
	if _, ok := pass()["smart/db/sda"]; ok {
		t.Fatal("closed alert open again")
	}
	if a, _ := st.GetAlert(ctx, sda.ID); a.State != store.AlertClosed || a.ClosedLevel != 1 || a.CloseComment != "one bad sector" {
		t.Fatalf("closed: %+v", a)
	}

	// One more: the closed one is done and a new one fires.
	drives(2, 0)
	got = pass()
	again := got["smart/db/sda"]
	if again.ID == sda.ID || again.State != store.AlertFiring || again.Level != 2 {
		t.Fatalf("worse after closing: %+v", again)
	}
	if a, _ := st.GetAlert(ctx, sda.ID); a.State != store.AlertResolved || !a.Closed() {
		t.Fatalf("the closed one: %+v", a)
	}
	if rs, _ := st.ListAlerts(ctx, store.AlertFilter{Resolved: time.Now().Add(-time.Hour)}); len(rs) != 0 {
		t.Fatalf("closed alerts listed as resolved: %+v", rs)
	}
	drives(1, 1) // a sector pending, another remapped: same count
	if a := pass()["smart/db/sda"]; a.ID != again.ID {
		t.Fatalf("a move between counters: %+v", a)
	}

	// The count stopped rising more than the window ago: quiet, unless it
	// reaches the threshold.
	exec(t, st, `UPDATE host_smart SET rose_at = now() - interval '8 days' WHERE host = $1`, db.id)
	if a, ok := pass()["smart/db/sda"]; ok {
		t.Fatalf("stable count still alerts: %+v", a)
	}
	smart := ruleByKind(t, st, "smart")
	if smart.Params.Days != 7 || smart.Params.Sectors != 100 {
		t.Fatalf("migrated params: %+v", smart.Params)
	}
	smart.Params.Sectors = 2
	st.SaveAlertRule(ctx, store.System, smart)
	if a := pass()["smart/db/sda"]; a.State != store.AlertFiring || strings.Contains(a.Summary, "rising") {
		t.Fatalf("at the threshold: %+v", a)
	}

	// Any kind closes. A closed alert whose condition ends resolves without
	// a message; the next occurrence is a new alert.
	ntfy, _ := st.SaveChannel(ctx, store.System, store.NotifyChannel{Kind: notify.Ntfy, Name: "phone", Enabled: true, ConfigEnc: "{}"})
	units := ruleByKind(t, st, "failed_units")
	units.Channels, units.For, units.NotifyResolved = []string{ntfy}, 0, true
	st.SaveAlertRule(ctx, store.System, units)
	ingest(t, st, db, model.SectionServices, model.Services{Units: []model.Service{{Name: "nginx.service", Active: "failed"}}})
	nginx := pass()["failed_units/db/nginx.service"]
	if err := st.CloseAlert(ctx, store.System, nginx.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := pass()["failed_units/db/nginx.service"]; ok {
		t.Fatal("closed unit alert open again")
	}
	ingest(t, st, db, model.SectionServices, model.Services{Units: []model.Service{{Name: "nginx.service", Active: "active"}}})
	pass()
	if a, _ := st.GetAlert(ctx, nginx.ID); a.State != store.AlertResolved {
		t.Fatalf("closed, then recovered: %+v", a)
	}
	if ns, _ := st.AlertNotifications(ctx, nginx.ID); len(ns) != 1 {
		t.Fatalf("notifications for a closed alert: %+v", ns)
	}
	ingest(t, st, db, model.SectionServices, model.Services{Units: []model.Service{{Name: "nginx.service", Active: "failed"}}})
	if a := pass()["failed_units/db/nginx.service"]; a.ID == nginx.ID || a.State != store.AlertFiring {
		t.Fatalf("failed again: %+v", a)
	}
}

// The kinds that don't come from inventory: CVEs, patch cycles, unplanned
// changes, changes waiting for approval, offline hosts.
func TestConditions(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	webG, _ := st.CreateHostGroup(ctx, store.System, "web", "")
	web := webG.ID
	h := addHost(t, st, "web1", web)
	exec(t, st, `UPDATE host SET connected = false, last_seen = now() - interval '1 hour' WHERE ci_id = $1`, h.id)

	if err := st.ReplaceVulns(ctx, "Rocky Linux:9", []store.Vuln{{ID: "RLSA-1", Severity: "critical"}, {ID: "RLSA-2", Severity: "low"}},
		[]store.VulnAffected{{VulnID: "RLSA-1", Ecosystem: "Rocky Linux:9", Package: "sudo", Ranges: json.RawMessage(`[]`)},
			{VulnID: "RLSA-2", Ecosystem: "Rocky Linux:9", Package: "sudo", Ranges: json.RawMessage(`[]`)}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveHostVulns(ctx, h.id, "Rocky Linux:9", []store.HostVuln{
		{VulnID: "RLSA-1", Package: "sudo", Installed: "1", Fixed: "2", Candidate: "2", FixAvailable: true, Severity: "critical"},
		{VulnID: "RLSA-2", Package: "sudo", Installed: "1", Fixed: "2", Candidate: "2", FixAvailable: true, Severity: "low"}}); err != nil {
		t.Fatal(err)
	}

	// A package change with no job behind it.
	ingest(t, st, h, model.SectionPackages, model.Packages{Packages: []model.Package{{Manager: "dnf", Name: "sudo", Version: "1"}}})
	ingest(t, st, h, model.SectionPackages, model.Packages{Packages: []model.Package{{Manager: "dnf", Name: "sudo", Version: "2"}}})

	// A patch group whose last cycle was blocked, and a change submitted
	// five hours ago.
	var mdl, group, chg string
	st.DB().QueryRow(`INSERT INTO change_model (name, action, risk, state) VALUES ('m', 'pkg.upgrade', 'low', 'approved') RETURNING id`).Scan(&mdl)
	st.DB().QueryRow(`INSERT INTO patch_group (name, host_group_id, schedule_cron, change_model_id) VALUES ('web', $1, '0 3 * * *', $2) RETURNING id`,
		web, mdl).Scan(&group)
	exec(t, st, `INSERT INTO patch_cycle (patch_group_id, scheduled_for, started_at, result, reason) VALUES
		($1, now() - interval '2 days', now() - interval '2 days', 'failed', ''),
		($1, now() - interval '1 day', now() - interval '1 day', 'blocked', 'canary failed'),
		($1, now(), now(), 'skipped', 'no hosts')`, group)
	st.DB().QueryRow(`INSERT INTO change (kind, title, risk, impact, state, required_approvals, submitted_at)
		VALUES ('normal', 'Upgrade web', 'low', 'low', 'submitted', 2, now() - interval '5 hours') RETURNING id`).Scan(&chg)
	exec(t, st, `INSERT INTO change_ci (change_id, ci_id) VALUES ($1, $2)`, chg, h.id)

	e := &Evaluator{Store: st}
	for _, kind := range []string{"cve_fixable", "unplanned_change", "host_offline", "patch_cycle", "change_approval"} {
		r := ruleByKind(t, st, kind)
		r.Enabled, r.For = true, 0
		if _, err := st.SaveAlertRule(ctx, store.System, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	got := openAlerts(t, st)
	for k, want := range map[string]string{
		"cve_fixable/web1/":                    "web1: 1 vulnerability rated high or worse is fixed by pending updates (1 critical)",
		"unplanned_change/web1/":               "web1: 1 unplanned change (packages)",
		"patch_cycle/Patch group web/" + group: "Patch group web is blocked: canary failed",
	} {
		if a, ok := got[k]; !ok || a.Summary != want {
			t.Errorf("%s: %q (open: %q)", k, a.Summary, keys(got))
		}
	}
	if a := got["host_offline/web1/"]; !strings.HasPrefix(a.Summary, "web1 is offline, last seen ") {
		t.Errorf("offline: %q", a.Summary)
	}
	a := got["change_approval/CHG-000001/CHG-000001"]
	if !strings.Contains(a.Summary, `"Upgrade web" has waited for approval`) || !strings.Contains(a.Summary, "(0 of 2 approvals)") ||
		!slices.Equal(a.GroupIDs, []string{web}) || a.Link != "/changes/"+chg {
		t.Errorf("approval: %+v", a)
	}
	if a := got["patch_cycle/Patch group web/"+group]; !slices.Equal(a.GroupIDs, []string{web}) || a.CIID != "" {
		t.Errorf("patch cycle: %+v", a)
	}
}

func TestCheck(t *testing.T) {
	r, err := Check(store.AlertRule{Name: "x", Kind: "disk_full", Severity: "warning",
		Params: store.AlertParams{Percent: 85, Days: 3, Exclude: []string{"a"}}})
	if err != nil || r.Params.Percent != 85 || r.Params.Days != 0 || r.Params.Exclude != nil {
		t.Fatalf("%+v %v", r.Params, err)
	}
	for _, bad := range []store.AlertRule{
		{Name: "x", Kind: "nope", Severity: "info"},
		{Name: "", Kind: "smart", Severity: "info"},
		{Name: "x", Kind: "smart", Severity: "loud"},
		{Name: "x", Kind: "disk_full", Severity: "info", Params: store.AlertParams{Percent: 120}},
		{Name: "x", Kind: "cve_fixable", Severity: "info", Params: store.AlertParams{MinSeverity: "negligible"}},
		{Name: "x", Kind: "smart", Severity: "info", Repeat: time.Minute},
	} {
		if _, err := Check(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	r, _ = Check(store.AlertRule{Name: "x", Kind: "failed_units", Severity: "info", Params: store.AlertParams{Exclude: []string{" a ", ""}}})
	if !slices.Equal(r.Params.Exclude, []string{"a"}) {
		t.Fatalf("exclude: %q", r.Params.Exclude)
	}
}

// A stack's Compose file changed on the host after Baseline wrote it.
func TestComposeDrift(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	e := &Evaluator{Store: st}
	h := addHost(t, st, "web1")
	stacks := func(sha string) {
		t.Helper()
		ingest(t, st, h, model.SectionContainers, model.Containers{Stacks: []model.ComposeStack{
			{Engine: "docker", Project: "web", Services: []string{"app"}, CLI: "docker compose",
				ConfigFiles: []model.ComposeFile{{Path: "/srv/web/compose.yaml", SHA256: sha}}},
			{Engine: "docker", Project: "other", Services: []string{"app"}, CLI: "docker compose",
				ConfigFiles: []model.ComposeFile{{Path: "/srv/other/compose.yaml", SHA256: "ffff"}}}}})
	}
	pass := func() map[string]store.Alert {
		t.Helper()
		if err := e.Pass(ctx); err != nil {
			t.Fatal(err)
		}
		return openAlerts(t, st)
	}
	stacks("aaaa")
	var stack, chg string
	st.DB().QueryRow(`SELECT ci_id FROM compose_stack WHERE project = 'web'`).Scan(&stack)
	if err := st.DB().QueryRow(`INSERT INTO change (kind, title, risk, impact, state, required_approvals)
		VALUES ('normal', 'Edit web', 'low', 'low', 'closed', 1) RETURNING id`).Scan(&chg); err != nil {
		t.Fatal(err)
	}
	write := func(sha, state string, finished time.Time) {
		t.Helper()
		var rev string
		if err := st.DB().QueryRow(`INSERT INTO compose_revision (host, engine, project, action, change_id, compose, compose_sha256, created_at)
			VALUES ($1, 'docker', 'web', 'compose.edit', $2, 'services: {}', $3, $4) RETURNING id`, h.id, chg, sha, finished).Scan(&rev); err != nil {
			t.Fatal(err)
		}
		exec(t, st, `INSERT INTO job (change_id, host, action, params, timeout_s, state, finished_at)
			VALUES ($1, $2, 'compose.edit', jsonb_build_object('revision', $3::text), 60, $4, $5)`, chg, h.id, rev, state, finished)
	}

	// Baseline wrote aaaa and the host reported it since: nothing. The other
	// stack Baseline never wrote.
	write("aaaa", "succeeded", time.Now().Add(-time.Hour))
	stacks("aaaa")
	if got := pass(); len(got) != 0 {
		t.Fatalf("no drift: %q", keys(got))
	}

	// Changed on the host.
	stacks("bbbb")
	got := pass()
	a, ok := got["compose_drift/web1/compose:docker/web@bbbb"]
	if !ok || a.State != store.AlertFiring || a.CIID != h.id || a.Link != "/stacks/"+stack || len(got) != 1 ||
		a.Summary != "web1: the Compose file of stack web (/srv/web/compose.yaml) was changed on the host since Baseline wrote it in CHG-000001" {
		t.Fatalf("drift: %+v (open: %q)", a, keys(got))
	}

	// A failed edit doesn't count, nor one the host hasn't reported since.
	write("bbbb", "failed", time.Now().Add(-time.Minute))
	write("cccc", "succeeded", time.Now().Add(time.Hour))
	if _, ok := pass()["compose_drift/web1/compose:docker/web@bbbb"]; !ok {
		t.Fatal("drift resolved before the host reported")
	}
	exec(t, st, `DELETE FROM compose_revision WHERE compose_sha256 = 'cccc'`)

	// Closed: stays away while the file stays; a further change fires again.
	if err := st.CloseAlert(ctx, store.System, a.ID, "known"); err != nil {
		t.Fatal(err)
	}
	stacks("bbbb")
	if got := pass(); len(got) != 0 {
		t.Fatalf("closed drift back: %q", keys(got))
	}
	stacks("dddd")
	if _, ok := pass()["compose_drift/web1/compose:docker/web@dddd"]; !ok {
		t.Fatal("a further change after closing")
	}

	// Baseline writes the file the host has: resolved.
	write("dddd", "succeeded", time.Now().Add(-time.Second))
	stacks("dddd")
	if got := pass(); len(got) != 0 {
		t.Fatalf("after an edit: %q", keys(got))
	}
}

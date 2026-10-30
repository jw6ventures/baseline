package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

var rePatchGroup = regexp.MustCompile(`/patch-groups/([0-9a-f-]{36})`)

// approvedModel creates an approved pkg.upgrade change model.
func (h *harness) approvedModel(name string) string {
	h.t.Helper()
	ctx := context.Background()
	params, err := change.ModelParams(action.PkgUpgrade, []byte(`{"mode":"all","reboot":"never"}`))
	if err != nil {
		h.t.Fatal(err)
	}
	u, err := h.st.UpsertUser(ctx, "model-approver", "approver@example.com", "Approver")
	if err != nil {
		h.t.Fatal(err)
	}
	actor := store.UserActor(u.ID, "10.0.0.1")
	id, err := h.st.SaveChangeModel(ctx, actor, store.ChangeModel{Name: name, Action: action.PkgUpgrade, Params: params, Risk: "medium"})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.st.ApproveChangeModel(ctx, actor, id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestWindowsUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	prod, _ := h.st.CreateHostGroup(ctx, store.System, "prod", "")
	h.addHost("web1", prod.ID)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	admin := h.signIn("ann", "lab-admins")

	resp, body := h.do(admin, "GET", "/windows/new", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Next openings") || !strings.Contains(body, `value="0 2 * * SUN"`) {
		t.Fatalf("new window form: %d\n%s", resp.StatusCode, body)
	}

	form := url.Values{"name": {"sunday nights"}, "kind": {"window"}, "cron": {"0 2 * * SUN"}, "duration": {"3h"},
		"tz": {"America/Chicago"}, "scope": {prod.ID}, "active": {"1"}}
	for field, bad := range map[string]string{"cron": "61 2 * * *", "tz": "Mars/Olympus", "duration": "3x"} {
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		f.Set(field, bad)
		resp, body := h.do(admin, "POST", "/windows", f)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, `class="notice bad"`) {
			t.Fatalf("bad %s accepted: %d", field, resp.StatusCode)
		}
	}
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	f.Set("duration", "40d")
	if resp, body := h.do(admin, "POST", "/windows", f); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "31 days") {
		t.Fatalf("40d window: %d", resp.StatusCode)
	}

	if resp, _ := h.do(admin, "POST", "/windows", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create window: %d", resp.StatusCode)
	}
	freeze := url.Values{"name": {"holidays"}, "kind": {"freeze"}, "cron": {"0 0 20 12 *"}, "duration": {"14d"}, "tz": {"UTC"}, "active": {"1"}}
	if resp, _ := h.do(admin, "POST", "/windows", freeze); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create freeze: %d", resp.StatusCode)
	}
	if resp, body := h.do(admin, "POST", "/windows", freeze); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate name: %d", resp.StatusCode)
	}

	ws, _ := h.st.ListWindows(ctx)
	if len(ws) != 2 || ws[0].Name != "sunday nights" || ws[0].Duration != 3*time.Hour || ws[0].TZ != "America/Chicago" ||
		len(ws[0].ScopeGroups) != 1 || ws[1].Kind != store.WindowKindFreeze || !ws[1].Global() {
		t.Fatalf("windows: %+v", ws)
	}
	cw, _ := change.Compile(ws[0])
	next := h.srv.openingText(cw.Sched.NextOpening(time.Now()))

	opening := cw.Sched.NextOpening(time.Now())
	start, end := opening.Start.In(h.srv.cfg.Location).Format("2006-01-02 15:04"), opening.End.In(h.srv.cfg.Location).Format("2006-01-02 15:04")
	viewer := h.signIn("vic", "viewers")
	_, body = h.list(viewer, "/windows")
	if !strings.Contains(body, "sunday nights") || !strings.Contains(body, "Sundays at 02:00, for 3h") ||
		!strings.Contains(body, start) || !strings.Contains(body, end) || !strings.Contains(body, "freeze</span>") ||
		!strings.Contains(body, "for 14d") || !strings.Contains(body, `data-v="prod"`) || strings.Contains(body, "/edit") {
		t.Fatalf("window list (want %q):\n%s", start, body)
	}
	// Admins get each window's edit form as its link.
	_, body = h.list(admin, "/windows?show=windows")
	if !strings.Contains(body, "/windows/"+ws[0].ID+"/edit") || strings.Contains(body, "holidays") {
		t.Fatalf("admin window list:\n%s", body)
	}
	if resp, _ := h.do(viewer, "POST", "/windows", freeze); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer created a window: %d", resp.StatusCode)
	}
	if resp, _ := h.do(viewer, "GET", "/windows/"+ws[0].ID+"/edit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer edit form: %d", resp.StatusCode)
	}

	// Edit shows a preview; saving changes it; delete removes it.
	_, body = h.do(admin, "GET", "/windows/"+ws[0].ID+"/edit", nil)
	if !strings.Contains(body, next) || !strings.Contains(body, `value="3h"`) {
		t.Fatalf("edit form:\n%s", body)
	}
	form.Set("duration", "90m")
	form.Del("active")
	if resp, _ := h.do(admin, "POST", "/windows/"+ws[0].ID, form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("update: %d", resp.StatusCode)
	}
	if w, _ := h.st.GetWindow(ctx, ws[0].ID); w.Duration != 90*time.Minute || w.Active {
		t.Fatalf("updated: %+v", w)
	}
	if resp, _ := h.do(admin, "POST", "/windows/"+ws[1].ID+"/delete", url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if _, err := h.st.GetWindow(ctx, ws[1].ID); err != store.ErrNotFound {
		t.Fatalf("deleted window: %v", err)
	}
	if got := h.auditActions(); !strings.Contains(got, "window.create window.create auth.login window.update window.delete") {
		t.Fatalf("audit: %s", got)
	}
}

func TestCalendarUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	prod, _ := h.st.CreateHostGroup(ctx, store.System, "prod", "")
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	web := h.addHost("web1", prod.ID)
	h.addHost("plex", media.ID)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-viewers", Role: rbac.Viewer, ScopeGroupID: media.ID})
	mid := h.approvedModel("all updates")

	if _, err := h.st.SaveWindow(ctx, store.System, store.MaintenanceWindow{Name: "nightly", Kind: store.WindowKindWindow,
		Cron: "0 2 * * *", Duration: 3 * time.Hour, TZ: "UTC", Active: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.SaveWindow(ctx, store.System, store.MaintenanceWindow{Name: "month-end freeze", Kind: store.WindowKindFreeze,
		Cron: "0 0 1 * *", Duration: 24 * time.Hour, TZ: "UTC", Active: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.SavePatchGroup(ctx, store.System, store.PatchGroup{Name: "prod-patching", HostGroupID: prod.ID,
		Cron: "30 3 * * *", TZ: "UTC", ModelID: mid, SuccessThreshold: 100, Concurrency: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// A Standard change planned for the 2nd of next month.
	now := time.Now().UTC()
	nextMonth := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	m, _ := h.st.GetChangeModel(ctx, mid)
	c, err := h.st.CreateChange(ctx, store.System, store.NewChange{Kind: store.KindStandard, ModelID: mid, Title: "Planned patching",
		Risk: action.Medium, PlannedStart: nextMonth.Add(24*time.Hour + 10*time.Hour), Steps: []store.PlanStep{{Action: action.PkgUpgrade,
			Params: m.Params, Summary: "upgrade", HostIDs: []string{web.HostID}}}})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != store.ChangeApproved {
		t.Fatalf("change state: %s", c.State)
	}

	admin := h.signIn("ann", "lab-admins")
	resp, body := h.do(admin, "GET", "/calendar?month="+nextMonth.Format("2006-01"), nil)
	if resp.StatusCode != 200 || !strings.Contains(body, nextMonth.Format("January 2006")) {
		t.Fatalf("calendar: %d\n%s", resp.StatusCode, body)
	}
	day2 := regexp.MustCompile(`(?s)id="d-` + nextMonth.AddDate(0, 0, 1).Format("2006-01-02") + `".*?</td>`).FindString(body)
	for _, want := range []string{"02:00–05:00</span> nightly", "03:30</span> prod-patching", "10:00</span> " + c.Ref() + " Planned patching",
		`class="cal-item window"`, `class="cal-item patch"`, `class="cal-item change"`, "/changes/" + c.ID} {
		if !strings.Contains(day2, want) {
			t.Fatalf("day 2 lacks %q:\n%s", want, day2)
		}
	}
	day1 := regexp.MustCompile(`(?s)id="d-` + nextMonth.Format("2006-01-02") + `".*?</td>`).FindString(body)
	if !strings.Contains(day1, `class="cal-item freeze"`) || !strings.Contains(day1, "all day</span> month-end freeze") {
		t.Fatalf("day 1:\n%s", day1)
	}

	// This month: today is marked, and the next fortnight is listed.
	_, body = h.do(admin, "GET", "/calendar", nil)
	if !strings.Contains(body, `aria-current="date"`) || !strings.Contains(body, now.Format("January 2006")) ||
		!strings.Contains(body, "Next 14 days") || !strings.Contains(body, "prod-patching") {
		t.Fatalf("this month:\n%s", body)
	}
	if resp, _ := h.do(admin, "GET", "/calendar?month=soon", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad month: %d", resp.StatusCode)
	}

	// Someone who can't see web1 doesn't see its change.
	mv := h.signIn("mo", "media-viewers")
	_, body = h.do(mv, "GET", "/calendar?month="+nextMonth.Format("2006-01"), nil)
	if strings.Contains(body, c.Ref()) || !strings.Contains(body, "nightly") {
		t.Fatalf("scoped viewer's calendar:\n%s", body)
	}
}

func TestPatchGroupsUI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	canaryHG, _ := h.st.CreateHostGroup(ctx, store.System, "canary", "")
	prodHG, _ := h.st.CreateHostGroup(ctx, store.System, "prod", "")
	policy := &action.Policy{Jobs: true}
	h.connect(h.addHost("canary1", canaryHG.ID), []string{"dnf", "systemd"}, policy)
	h.connect(h.addHost("prod1", prodHG.ID), []string{"dnf", "systemd"}, policy)
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "canary-ops", Role: rbac.Operator, ScopeGroupID: canaryHG.ID})
	mid := h.approvedModel("all updates")
	if _, err := h.st.SaveWindow(ctx, store.System, store.MaintenanceWindow{Name: "weekend", Kind: store.WindowKindWindow,
		Cron: "0 0 * * SAT", Duration: 48 * time.Hour, TZ: "UTC", Active: true}); err != nil {
		t.Fatal(err)
	}
	admin := h.signIn("ann", "lab-admins")

	_, body := h.do(admin, "GET", "/patch-groups/new", nil)
	if !strings.Contains(body, "canary (1 host)") || !strings.Contains(body, `selected>all updates (pkg.upgrade)`) ||
		!strings.Contains(body, ">weekend</option>") || !strings.Contains(body, "Next runs") {
		t.Fatalf("new form:\n%s", body)
	}

	form := url.Values{"name": {"canary"}, "host_group": {canaryHG.ID}, "cron": {"0 2 * * SAT"}, "tz": {"UTC"}, "model": {mid},
		"soak": {"0"}, "threshold": {"100"}, "concurrency": {"1"}, "promote": {"1"}, "stop_on_failure": {"1"}, "enabled": {"1"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("cron", "0 2 * *")
	if resp, body := h.do(admin, "POST", "/patch-groups", bad); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "five fields") {
		t.Fatalf("bad cron: %d", resp.StatusCode)
	}
	resp, _ := h.do(admin, "POST", "/patch-groups", form)
	m := rePatchGroup.FindStringSubmatch(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || m == nil {
		t.Fatalf("create canary: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	canary := m[1]

	prodForm := url.Values{"name": {"prod"}, "host_group": {prodHG.ID}, "cron": {"0 2 * * MON"}, "tz": {"UTC"}, "model": {mid},
		"blocked_by": {canary}, "soak": {"48h"}, "threshold": {"90"}, "concurrency": {"2"}, "promote": {"1"}, "enabled": {"1"}}
	resp, _ = h.do(admin, "POST", "/patch-groups", prodForm)
	m = rePatchGroup.FindStringSubmatch(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || m == nil {
		t.Fatalf("create prod: %d", resp.StatusCode)
	}
	prod := m[1]
	pg, _ := h.st.GetPatchGroup(ctx, prod)
	if pg.Soak != 48*time.Hour || pg.SuccessThreshold != 90 || pg.Concurrency != 2 || pg.StopOnFailure || len(pg.BlockedBy) != 1 {
		t.Fatalf("prod: %+v", pg)
	}

	// canary can't wait for prod: that's a loop.
	form.Set("blocked_by", prod)
	if resp, body := h.do(admin, "POST", "/patch-groups/"+canary, form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "loop") {
		t.Fatalf("loop: %d", resp.StatusCode)
	}
	form.Del("blocked_by")

	_, body = h.do(admin, "GET", "/patch-groups", nil)
	if !strings.Contains(body, "Saturdays at 02:00") || !strings.Contains(body, "soak 2d") || !strings.Contains(body, "≥90% of hosts") ||
		!strings.Contains(body, "never") {
		t.Fatalf("list:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/patch-groups/"+prod, nil)
	if !strings.Contains(body, "Run now") || !strings.Contains(body, "It hasn't run yet") || !strings.Contains(body, "installs only the package versions") ||
		!strings.Contains(body, ">canary</a>") {
		t.Fatalf("detail:\n%s", body)
	}

	// prod is blocked: canary never ran.
	resp, _ = h.do(admin, "POST", "/patch-groups/"+prod+"/run", url.Values{})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc.Query().Get("warn"), "blocked: canary hasn't run yet") {
		t.Fatalf("run prod: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	cs, _ := h.st.ListPatchCycles(ctx, prod, 5)
	if len(cs) != 1 || cs[0].Result != store.CycleBlocked {
		t.Fatalf("prod cycles: %+v", cs)
	}

	// A canary operator may run canary, not prod.
	ops := h.signIn("carl", "canary-ops")
	if resp, _ := h.do(ops, "POST", "/patch-groups/"+prod+"/run", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator ran prod: %d", resp.StatusCode)
	}
	if _, body := h.do(ops, "GET", "/patch-groups/"+prod, nil); strings.Contains(body, "Run now</button>") {
		t.Fatal("run button shown to an operator without prod")
	}
	resp, _ = h.do(ops, "POST", "/patch-groups/"+canary+"/run", url.Values{})
	loc, _ = url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc.Query().Get("notice"), "Started CHG-") {
		t.Fatalf("run canary: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	cs, _ = h.st.ListPatchCycles(ctx, canary, 5)
	if len(cs) != 1 || cs[0].Result != store.CycleRunning || cs[0].ChangeID == "" || len(cs[0].Planned) != 1 {
		t.Fatalf("canary cycles: %+v", cs)
	}
	_, body = h.do(ops, "GET", "/patch-groups/"+canary, nil)
	if !strings.Contains(body, cs[0].ChangeRef()) || !strings.Contains(body, "<summary>") || !strings.Contains(body, "canary1") {
		t.Fatalf("canary detail:\n%s", body)
	}
	if resp, _ := h.do(ops, "POST", "/patch-groups", prodForm); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator created a group: %d", resp.StatusCode)
	}
	if got := h.auditActions(); !strings.Contains(got, "patch_group.run patch_cycle.blocked") || !strings.Contains(got, "patch_group.run change.create change.state patch_cycle.running") {
		t.Fatalf("audit: %s", got)
	}

	// Deleting canary frees prod.
	if resp, _ := h.do(admin, "POST", "/patch-groups/"+canary+"/delete", url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if pg, _ := h.st.GetPatchGroup(ctx, prod); len(pg.BlockedBy) != 0 {
		t.Fatalf("prod still blocked by %v", pg.BlockedBy)
	}
}

func TestScheduleHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"0 2 * * SUN": "Sundays at 02:00", "30 22 * * 1-5": "weekdays at 22:30", "0 3 * * sat,sun": "weekends at 03:00",
		"0 2 * * MON,WED,FRI": "Mon, Wed, Fri at 02:00", "@daily": "daily at 00:00", "15 * * * *": "hourly at :15",
		"0 4 1 * *": "monthly on day 1 at 04:00", "0 0 20 12 *": "yearly on 20 Dec at 00:00", "*/5 * * * *": "",
		"0 2 * * 0-7": "daily at 02:00",
	} {
		if got := cronWords(in); got != want {
			t.Errorf("cronWords(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]time.Duration{"3h": 3 * time.Hour, "90m": 90 * time.Minute, "2d": 48 * time.Hour,
		"1d12h": 36 * time.Hour, "0": 0} {
		if got, err := parseSpan(in); err != nil || got != want {
			t.Errorf("parseSpan(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "3x", "-1h", "d"} {
		if _, err := parseSpan(in); err == nil {
			t.Errorf("parseSpan(%q) accepted", in)
		}
	}
	for d, want := range map[time.Duration]string{3 * time.Hour: "3h", 90 * time.Minute: "1h30m", 48 * time.Hour: "2d",
		36 * time.Hour: "36h", 0: "0"} {
		if got := spanText(d); got != want {
			t.Errorf("spanText(%v) = %q, want %q", d, got, want)
		}
	}
}

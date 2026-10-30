package change

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/store"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func window(t *testing.T, id, kind, cron string, d time.Duration, groups ...string) Window {
	t.Helper()
	w, err := Compile(store.MaintenanceWindow{ID: id, Name: id, Kind: kind, Cron: cron, Duration: d, TZ: "UTC",
		ScopeGroups: groups, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func calendar(ws ...Window) *Calendar {
	c := &Calendar{Windows: map[string]Window{}, Groups: map[string][]string{"h1": {"prod"}, "h2": {"lab"}},
		Hosts: map[string]store.Host{"h1": {ID: "h1", Hostname: "web1"}, "h2": {ID: "h2", Hostname: "lab1"}}}
	for _, w := range ws {
		c.Windows[w.ID] = w
		if w.Kind == store.WindowKindFreeze {
			c.Freezes = append(c.Freezes, w)
		}
	}
	return c
}

func TestPlan(t *testing.T) {
	sunday := window(t, "sunday", store.WindowKindWindow, "0 2 * * SUN", 3*time.Hour)
	// A freeze over the last week of the year, for prod only.
	freeze := window(t, "year-end", store.WindowKindFreeze, "0 0 24 12 *", 8*24*time.Hour, "prod")
	cal := calendar(sunday, freeze)
	now := at("2026-10-13T10:00:00Z") // a Tuesday

	for _, tc := range []struct {
		name       string
		ch         store.Change
		now        time.Time
		start, end string
		noteHas    string
		errHas     string
	}{
		{name: "no window starts now", ch: store.Change{HostIDs: []string{"h1"}}, now: now, start: "2026-10-13T10:00:00Z"},
		{name: "planned start", ch: store.Change{HostIDs: []string{"h1"}, PlannedStart: at("2026-10-14T09:00:00Z")}, now: now,
			start: "2026-10-14T09:00:00Z"},
		{name: "next opening", ch: store.Change{HostIDs: []string{"h1"}, WindowID: "sunday"}, now: now,
			start: "2026-10-18T02:00:00Z", end: "2026-10-18T05:00:00Z", noteHas: "waiting for maintenance window sunday"},
		{name: "inside the opening", ch: store.Change{HostIDs: []string{"h1"}, WindowID: "sunday"}, now: at("2026-10-18T03:00:00Z"),
			start: "2026-10-18T03:00:00Z", end: "2026-10-18T05:00:00Z"},
		{name: "planned inside the window", ch: store.Change{HostIDs: []string{"h1"}, WindowID: "sunday",
			PlannedStart: at("2026-10-25T04:00:00Z")}, now: now, start: "2026-10-25T04:00:00Z", end: "2026-10-25T05:00:00Z"},
		{name: "frozen", ch: store.Change{HostIDs: []string{"h1"}}, now: at("2026-12-25T00:00:00Z"),
			start: "2027-01-01T00:00:00Z", noteHas: "held by freeze year-end"},
		{name: "frozen, then the next opening", ch: store.Change{HostIDs: []string{"h1"}, WindowID: "sunday"},
			now: at("2026-12-25T00:00:00Z"), start: "2027-01-03T02:00:00Z", end: "2027-01-03T05:00:00Z"},
		{name: "freeze scoped to other hosts", ch: store.Change{HostIDs: []string{"h2"}}, now: at("2026-12-25T00:00:00Z"),
			start: "2026-12-25T00:00:00Z"},
		{name: "one frozen host holds the change", ch: store.Change{HostIDs: []string{"h2", "h1"}}, now: at("2026-12-25T00:00:00Z"),
			start: "2027-01-01T00:00:00Z"},
		{name: "emergency ignores freezes", ch: store.Change{Kind: store.KindEmergency, HostIDs: []string{"h1"}},
			now: at("2026-12-25T00:00:00Z"), start: "2026-12-25T00:00:00Z"},
		{name: "unknown window", ch: store.Change{HostIDs: []string{"h1"}, WindowID: "gone"}, now: now, errHas: "can't be read"},
	} {
		start, end, note, err := cal.Plan(tc.ch, tc.now)
		if tc.errHas != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("%s: err = %v", tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !start.Equal(at(tc.start)) {
			t.Errorf("%s: start = %v, want %s", tc.name, start.UTC(), tc.start)
		}
		if (tc.end == "") != end.IsZero() || (tc.end != "" && !end.Equal(at(tc.end))) {
			t.Errorf("%s: end = %v, want %q", tc.name, end.UTC(), tc.end)
		}
		if !strings.Contains(note, tc.noteHas) {
			t.Errorf("%s: note = %q", tc.name, note)
		}
	}

	if f := cal.FrozenHosts(at("2026-12-26T00:00:00Z")); f["h1"] != "year-end" || f["h2"] != "" {
		t.Errorf("FrozenHosts = %v", f)
	}
	if w, ok := cal.WindowFor("h2", now); !ok || w.ID != "sunday" {
		t.Errorf("WindowFor = %v %v", w.ID, ok)
	}
	off := sunday
	off.Active = false
	if _, _, _, err := calendar(off).Plan(store.Change{HostIDs: []string{"h1"}, WindowID: "sunday"}, now); err == nil ||
		!strings.Contains(err.Error(), "turned off") {
		t.Errorf("inactive window: %v", err)
	}
	// A freeze that never ends (every day, all day) can't be planned past.
	always := window(t, "always", store.WindowKindFreeze, "0 0 * * *", 24*time.Hour)
	if _, _, _, err := calendar(always).Plan(store.Change{HostIDs: []string{"h1"}}, now); err == nil {
		t.Error("planned through an endless freeze")
	}
}

func TestPromoted(t *testing.T) {
	model, _ := json.Marshal(action.UpgradeParams{Mode: action.ModeAll, Exclude: []string{"kernel*"}, Reboot: action.RebootIfRequired})
	validated := []store.ValidatedPackage{
		{OS: "rocky:9.6", Manager: "dnf", Name: "openssl", Arch: "x86_64", Version: "1:3.2.2-7.el9"},
		{OS: "rocky:9.6", Manager: "dnf", Name: "curl", Arch: "x86_64", Version: "7.76.1-30.el9"},
		{OS: "rocky:9.5", Manager: "dnf", Name: "bash", Arch: "x86_64", Version: "5.1.8-10.el9"},
		{OS: "rocky:9.6", Manager: "flatpak", Name: "org.gimp.GIMP", Version: "3.0.4"},
		{OS: "rocky:9.6", Manager: "dnf", Name: "kernel", Arch: "x86_64", Version: "5.14.0-600.el9"},
	}
	ups := []store.HostUpdate{
		modelUpdate("dnf", "openssl", "x86_64", "1:3.2.2-6.el9", "1:3.2.2-7.el9"),
		// Newer than what was validated: deferred.
		modelUpdate("dnf", "curl", "x86_64", "7.76.1-29.el9", "7.76.1-31.el9"),
		// Validated on another release only.
		modelUpdate("dnf", "bash", "x86_64", "5.1.8-9.el9", "5.1.8-10.el9"),
		modelUpdate("flatpak", "org.gimp.GIMP", "x86_64", "3.0.2", "3.0.4"),
		// Excluded by the model.
		modelUpdate("dnf", "kernel", "x86_64", "5.14.0-570.el9", "5.14.0-600.el9"),
	}
	host := store.Host{ID: "h1", Hostname: "web1", Capabilities: []string{"dnf", action.CapPkgPin}}
	p := store.PlannedHost{OS: "rocky:9.6"}
	raw, err := promoted(model, host, ups, validated, &p)
	if err != nil {
		t.Fatal(err)
	}
	var got action.UpgradeParams
	json.Unmarshal(raw, &got)
	if got.Mode != action.ModeSelected || strings.Join(got.Packages, ",") != "openssl,flatpak:org.gimp.GIMP" ||
		got.Versions["openssl"] != "1:3.2.2-7.el9" || len(got.Versions) != 1 || got.Reboot != action.RebootIfRequired {
		t.Fatalf("params = %s", raw)
	}
	if !p.Job || p.Deferred != 2 || p.Note != "" {
		t.Fatalf("planned = %+v", p)
	}

	// An agent that can't pin gets the names only, and a note says so.
	host.Capabilities = []string{"dnf"}
	p = store.PlannedHost{OS: "rocky:9.6"}
	raw, _ = promoted(model, host, ups, validated, &p)
	if strings.Contains(string(raw), "versions") || !strings.Contains(p.Note, "can't pin") {
		t.Fatalf("no pins: %s %+v", raw, p)
	}

	// Nothing validated: no job.
	p = store.PlannedHost{OS: "ubuntu:24.04"}
	if raw, _ = promoted(model, host, ups, validated, &p); raw != nil || p.Job || !strings.Contains(p.Note, "none of its 4") {
		t.Fatalf("nothing validated: %s %+v", raw, p)
	}
}

func modelUpdate(manager, name, arch, installed, candidate string) (u store.HostUpdate) {
	u.Manager, u.Name, u.Arch, u.Installed, u.Candidate = manager, name, arch, installed, candidate
	return u
}

func TestCycleResult(t *testing.T) {
	res, _ := json.Marshal(action.UpgradeResult{
		Changed: []action.PackageChange{{Manager: "dnf", Name: "openssl", Arch: "x86_64", From: "1", To: "2"},
			{Manager: "dnf", Name: "kernel", Arch: "x86_64", From: "a", To: "a, b"}},
		Added: []action.PackageChange{{Manager: "dnf", Name: "kernel-core", Arch: "x86_64", To: "b"}},
	})
	c := store.PatchCycle{ChangeState: store.ChangeFailed, Planned: []store.PlannedHost{
		{HostID: "h1", OS: "rocky:9.6"}, {HostID: "h2", OS: "rocky:9.6"},
		{HostID: "h3", OS: "bazzite:42", Image: "ghcr.io/ublue-os/bazzite:stable", ImageVersion: "42.20251010"}}}
	jobs := []store.Job{
		{HostID: "h1", Action: action.PkgUpgrade, State: store.JobSucceeded, Result: res},
		{HostID: "h2", Action: action.PkgUpgrade, State: store.JobFailed, Result: res},
		{HostID: "h3", Action: action.PkgUpgrade, State: store.JobSucceeded},
	}
	result, _, ok, validated := cycleResult(c, jobs)
	if result != store.CyclePartial || ok != 2 {
		t.Fatalf("result = %s, %d ok", result, ok)
	}
	var got []string
	for _, v := range validated {
		got = append(got, v.OS+" "+v.Manager+" "+v.Name+"="+v.Version)
	}
	want := "bazzite:42 rpm-ostree ghcr.io/ublue-os/bazzite:stable=42.20251010," +
		"rocky:9.6 dnf kernel-core=b,rocky:9.6 dnf openssl=2"
	if strings.Join(got, ",") != want {
		t.Fatalf("validated = %v", got)
	}
	if r, _, _, _ := cycleResult(store.PatchCycle{ChangeState: store.ChangeClosed}, jobs[:1]); r != store.CycleSuccess {
		t.Errorf("all ok = %s", r)
	}
	if r, _, _, _ := cycleResult(store.PatchCycle{ChangeState: store.ChangeFailed}, jobs[1:2]); r != store.CycleFailed {
		t.Errorf("none ok = %s", r)
	}
	if r, why, _, _ := cycleResult(store.PatchCycle{ChangeState: store.ChangeCancelled}, jobs[:1]); r != store.CycleCancelled || why == "" {
		t.Errorf("cancelled = %s %q", r, why)
	}
}

func TestModelParams(t *testing.T) {
	got, err := ModelParams(action.ComposeUpdate, []byte(`{"health_timeout":60}`))
	if err != nil || string(got) != `{"engine":"","project":"","health_timeout":60}` {
		t.Fatalf("compose model = %s %v", got, err)
	}
	if _, err := ModelParams(action.ComposeUpdate, []byte(`{"engine":"docker","project":"x"}`)); err == nil {
		t.Error("a compose model with a stack")
	}
	if _, err := ModelParams(action.ComposeUpdate, []byte(`{"health_timeout":1}`)); err == nil {
		t.Error("bad health timeout")
	}
	p, err := StackParams(action.ComposeUpdate, got, store.Stack{Engine: "docker", Project: "media"}, []string{"plex"})
	if err != nil || string(p) != `{"engine":"docker","project":"media","services":["plex"],"health_timeout":60}` {
		t.Fatalf("stack params = %s %v", p, err)
	}
	if got, err := ModelParams(action.PkgUpgrade, nil); err != nil || string(got) != `{"mode":"all","reboot":"never"}` {
		t.Fatalf("upgrade model = %s %v", got, err)
	}
}

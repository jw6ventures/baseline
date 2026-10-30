package change_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

var ctx = context.Background()

type env struct {
	t   *testing.T
	st  *store.Store
	m   *change.Manager
	now time.Time
	ann store.Actor
	n   int
}

func newEnv(t *testing.T) *env {
	st, _ := storetest.New(t)
	e := &env{t: t, st: st, now: time.Now().Truncate(time.Second)}
	e.m = change.New(st, &jw6_utils.Utils{LogLevel: jw6_utils.Fatal})
	e.m.Now = func() time.Time { return e.now }
	u, err := st.UpsertUser(ctx, "ann", "ann@example.com", "Ann")
	if err != nil {
		t.Fatal(err)
	}
	e.ann = store.UserActor(u.ID, "10.0.0.1")
	return e
}

// host enrolls a connected host running an OS release, in groups.
func (e *env) host(name, osID, version string, groups ...string) store.EnrollResult {
	e.t.Helper()
	e.n++
	hash := []byte(fmt.Sprintf("%-32s", fmt.Sprintf("%s-%d", e.t.Name(), e.n)))[:32]
	if _, err := e.st.CreateEnrollmentToken(ctx, store.System, "", store.EnrollmentToken{Name: "t",
		ExpiresAt: time.Now().Add(time.Hour), DefaultGroups: groups}, hash); err != nil {
		e.t.Fatal(err)
	}
	r, err := e.st.Enroll(ctx, store.EnrollRequest{SecretHash: hash, MachineID: name, Hostname: name},
		func(string) (string, time.Time, error) { return "serial-" + name, time.Now().Add(time.Hour), nil })
	if err != nil {
		e.t.Fatal(err)
	}
	e.ingest(r, model.SectionOS, model.OS{Hostname: name, ID: osID, VersionID: version, PrettyName: osID + " " + version})
	if _, err := e.st.AgentConnected(ctx, r.HostID, r.AgentID, store.Hello{AgentVersion: "test", BootID: "b1",
		Capabilities: []string{"dnf", "systemd", action.CapPkgPin}, Policy: &action.Policy{Jobs: true}}); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) ingest(r store.EnrollResult, section string, v any) {
	e.t.Helper()
	b, hash, _ := model.Encode(v)
	if _, err := e.st.IngestSection(ctx, r.HostID, r.AgentID, section, hash, b, ""); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) window(name, kind, cron string, d time.Duration, groups ...string) string {
	e.t.Helper()
	id, err := e.st.SaveWindow(ctx, e.ann, store.MaintenanceWindow{Name: name, Kind: kind, Cron: cron, Duration: d, TZ: "UTC",
		ScopeGroups: groups, Active: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) change(nc store.NewChange, hosts ...string) store.Change {
	e.t.Helper()
	params, _ := action.Validate(action.ServiceRestart, []byte(`{"unit":"nginx"}`))
	if nc.Steps == nil {
		nc.Steps = []store.PlanStep{{Action: action.ServiceRestart, Params: params, Summary: "Restart nginx", HostIDs: hosts}}
	}
	nc.Title, nc.Risk = "test", action.Low
	if nc.Kind != store.KindStandard {
		nc.SelfApprove = true
	}
	c, err := e.st.CreateChange(ctx, e.ann, nc)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) get(id string) store.Change {
	e.t.Helper()
	c, err := e.st.GetChange(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) advance() change.Gate {
	e.t.Helper()
	g, err := e.m.Advance(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

// finish ends every open job of a change.
func (e *env) finish(changeID, state string, result any) {
	e.t.Helper()
	js, _ := e.st.ListJobs(ctx, store.JobFilter{ChangeID: changeID})
	for _, j := range js {
		if j.Final() {
			continue
		}
		raw, _ := json.Marshal(result)
		if _, err := e.st.FinishJob(ctx, store.System, j.HostID, j.ID, store.JobResult{State: state, Result: raw}); err != nil {
			e.t.Fatal(err)
		}
	}
}

func TestAdvanceWindowsAndFreezes(t *testing.T) {
	e := newEnv(t)
	prod, _ := e.st.CreateHostGroup(ctx, store.System, "prod", "")
	web := e.host("web1", "rocky", "9.6", prod.ID)
	lab := e.host("lab1", "rocky", "9.6")

	// A window that opens tomorrow at 02:00 UTC for three hours.
	tomorrow := e.now.UTC().Add(24 * time.Hour)
	win := e.window("nightly", store.WindowKindWindow, fmt.Sprintf("0 2 %d %d *", tomorrow.Day(), tomorrow.Month()), 3*time.Hour)
	opens := time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 2, 0, 0, 0, time.UTC)

	inWindow := e.change(store.NewChange{WindowID: win, OnWindowEnd: store.WindowFail}, web.HostID)
	now := e.change(store.NewChange{}, lab.HostID)
	e.advance()
	if c := e.get(inWindow.ID); c.State != store.ChangeScheduled || !c.PlannedStart.Equal(opens) ||
		!c.PlannedEnd.Equal(opens.Add(3*time.Hour)) || !strings.Contains(c.ScheduleNote, "nightly") {
		t.Fatalf("windowed change: %s %v %v %q", c.State, c.PlannedStart, c.PlannedEnd, c.ScheduleNote)
	}
	if c := e.get(now.ID); c.State != store.ChangeInProgress || !c.WindowEndsAt.IsZero() {
		t.Fatalf("change without a window: %s", c.State)
	}

	// The window opens: in progress, until it closes.
	e.now = opens.Add(time.Minute)
	e.advance()
	c := e.get(inWindow.ID)
	if c.State != store.ChangeInProgress || !c.WindowEndsAt.Equal(opens.Add(3*time.Hour)) || c.ScheduleNote != "" {
		t.Fatalf("in the window: %s %v %q", c.State, c.WindowEndsAt, c.ScheduleNote)
	}
	// It closes before the job ran: the change says not to carry over, so
	// the job is skipped and the change fails.
	e.now = opens.Add(3*time.Hour + time.Minute)
	e.advance()
	if c = e.get(inWindow.ID); c.State != store.ChangeFailed || c.JobsQueued != 0 {
		t.Fatalf("window closed: %s, %d queued", c.State, c.JobsQueued)
	}

	// A weekly window carries the hosts left over to its next opening.
	weekly := e.window("weekly", store.WindowKindWindow, fmt.Sprintf("0 2 * * %d", int(tomorrow.Weekday())), 3*time.Hour)
	e.now = time.Now().Truncate(time.Second)
	carry := e.change(store.NewChange{WindowID: weekly}, web.HostID)
	e.now = opens.Add(time.Minute)
	e.advance()
	e.now = opens.Add(4 * time.Hour)
	e.advance()
	if c = e.get(carry.ID); c.State != store.ChangeScheduled || !c.PlannedStart.Equal(opens.Add(7*24*time.Hour)) ||
		!strings.Contains(c.ScheduleNote, "carried over") {
		t.Fatalf("carried over: %s %v %q", c.State, c.PlannedStart, c.ScheduleNote)
	}

	// A freeze on prod holds prod's changes until it ends, and tells the
	// dispatcher; Emergency changes go ahead.
	e.now = time.Now().Truncate(time.Second)
	e.window("change freeze", store.WindowKindFreeze, fmt.Sprintf("%d %d * * *", e.now.UTC().Minute(), e.now.UTC().Hour()),
		2*time.Hour, prod.ID)
	held := e.change(store.NewChange{}, web.HostID)
	urgent := e.change(store.NewChange{Kind: store.KindEmergency}, web.HostID)
	other := e.change(store.NewChange{}, lab.HostID)
	g := e.advance()
	if g.Frozen[web.HostID] != "change freeze" || g.Frozen[lab.HostID] != "" {
		t.Fatalf("gate: %v", g.Frozen)
	}
	if c = e.get(held.ID); c.State != store.ChangeScheduled || !strings.Contains(c.ScheduleNote, "freeze") ||
		c.PlannedStart.Before(e.now.Add(time.Hour)) {
		t.Fatalf("held by the freeze: %s %v %q", c.State, c.PlannedStart, c.ScheduleNote)
	}
	if c = e.get(urgent.ID); c.State != store.ChangeInProgress {
		t.Fatalf("emergency: %s", c.State)
	}
	if c = e.get(other.ID); c.State != store.ChangeInProgress {
		t.Fatalf("outside the freeze's scope: %s", c.State)
	}

	// Planned starts in a freeze are refused unless Emergency.
	if err := e.m.CheckStart(ctx, store.Change{HostIDs: []string{web.HostID}, PlannedStart: e.now.Add(time.Minute)}, e.now); err == nil ||
		!strings.Contains(err.Error(), "change freeze") {
		t.Fatalf("CheckStart in a freeze: %v", err)
	}
	if err := e.m.CheckStart(ctx, store.Change{Kind: store.KindEmergency, HostIDs: []string{web.HostID},
		PlannedStart: e.now.Add(time.Minute)}, e.now); err != nil {
		t.Fatal(err)
	}
	scoped := e.window("prod nights", store.WindowKindWindow, "0 3 * * *", time.Hour, prod.ID)
	if err := e.m.CheckStart(ctx, store.Change{HostIDs: []string{lab.HostID}, WindowID: scoped}, e.now); err == nil ||
		!strings.Contains(err.Error(), "doesn't cover lab1") {
		t.Fatalf("CheckStart outside the window's scope: %v", err)
	}
}

func TestEmergencyAndStandardLifecycle(t *testing.T) {
	e := newEnv(t)
	web := e.host("web1", "rocky", "9.6")

	// Emergency: done, then review before closing.
	c := e.change(store.NewChange{Kind: store.KindEmergency, RequiredApprovals: 3}, web.HostID)
	if c.State != store.ChangeApproved || c.RequiredApprovals != 1 {
		t.Fatalf("emergency: %s, %d approvals", c.State, c.RequiredApprovals)
	}
	e.advance()
	e.finish(c.ID, store.JobSucceeded, nil)
	if c = e.get(c.ID); c.State != store.ChangeReview || c.Outcome != "success" {
		t.Fatalf("emergency done: %s %s", c.State, c.Outcome)
	}
	if err := e.st.CloseChange(ctx, e.ann, c.ID, " "); err == nil {
		t.Fatal("closed without a review")
	}
	if err := e.st.CloseChange(ctx, e.ann, c.ID, "fixed the leak"); err != nil {
		t.Fatal(err)
	}
	if c = e.get(c.ID); c.State != store.ChangeClosed || c.ReviewNotes != "fixed the leak" || c.ReviewedBy != "Ann" {
		t.Fatalf("closed: %+v", c)
	}

	// Standard: needs an approved model; closes by itself.
	params, _ := action.Validate(action.ServiceRestart, []byte(`{"unit":"nginx"}`))
	mid, err := e.st.SaveChangeModel(ctx, e.ann, store.ChangeModel{Name: "restart nginx", Action: action.ServiceRestart,
		Params: params, Risk: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateChange(ctx, store.System, store.NewChange{Kind: store.KindStandard, ModelID: mid, Title: "x",
		Risk: action.Low, Steps: []store.PlanStep{{Action: action.ServiceRestart, Params: params, HostIDs: []string{web.HostID}}}}); err != store.ErrModel {
		t.Fatalf("pending model: %v", err)
	}
	if err := e.st.ApproveChangeModel(ctx, e.ann, mid); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.st.GetChangeModel(ctx, mid); !m.SelfApproved || !m.Approved() {
		t.Fatalf("model: %+v", m)
	}
	s := e.change(store.NewChange{Kind: store.KindStandard, ModelID: mid}, web.HostID)
	if s.State != store.ChangeApproved || s.ModelName != "restart nginx" {
		t.Fatalf("standard: %s %q", s.State, s.ModelName)
	}
	e.advance()
	e.finish(s.ID, store.JobSucceeded, nil)
	if s = e.get(s.ID); s.State != store.ChangeClosed || s.ClosedAt.IsZero() {
		t.Fatalf("standard done: %s", s.State)
	}
	// Editing the model needs approval again.
	if _, err := e.st.SaveChangeModel(ctx, e.ann, store.ChangeModel{ID: mid, Name: "restart nginx", Action: action.ServiceRestart,
		Params: params, Risk: "medium"}); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.st.GetChangeModel(ctx, mid); m.State != store.ModelPending || !m.ApprovedAt.IsZero() {
		t.Fatalf("edited model: %+v", m)
	}

	// Drafts are submitted by their requester; a rolled-back job rolls the
	// change back, which needs a review.
	d := e.change(store.NewChange{Draft: true}, web.HostID)
	if d.State != store.ChangeDraft {
		t.Fatalf("draft: %s", d.State)
	}
	if err := e.st.SubmitChange(ctx, store.System, d.ID); err != store.ErrState {
		t.Fatalf("submitted by someone else: %v", err)
	}
	if err := e.st.SubmitChange(ctx, e.ann, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ApproveChange(ctx, e.ann, d.ID, ""); err != nil {
		t.Fatal(err)
	}
	e.advance()
	e.finish(d.ID, store.JobRolledBack, action.ComposeResult{RolledBack: true})
	if d = e.get(d.ID); d.State != store.ChangeRolledBack || d.Outcome != "rolled_back" || !d.NeedsReview() {
		t.Fatalf("rolled back: %s %s", d.State, d.Outcome)
	}

	// A Normal change that needs two approvals waits for the second.
	two := e.change(store.NewChange{RequiredApprovals: 2}, web.HostID)
	if two.State != store.ChangeSubmitted || two.Approvals != 1 {
		t.Fatalf("two approvals: %s %d", two.State, two.Approvals)
	}
}

func upgradeResult(changed ...string) action.UpgradeResult {
	var r action.UpgradeResult
	for _, c := range changed {
		name, ver, _ := strings.Cut(c, "=")
		r.Changed = append(r.Changed, action.PackageChange{Manager: "dnf", Name: name, Arch: "x86_64", From: "old", To: ver})
	}
	return r
}

func TestPatchGroups(t *testing.T) {
	e := newEnv(t)
	canaryHG, _ := e.st.CreateHostGroup(ctx, store.System, "canary", "")
	prodHG, _ := e.st.CreateHostGroup(ctx, store.System, "prod", "")
	c1 := e.host("canary1", "rocky", "9.6", canaryHG.ID)
	p1 := e.host("prod1", "rocky", "9.6", prodHG.ID)

	params, _ := change.ModelParams(action.PkgUpgrade, []byte(`{"mode":"all","reboot":"if_required"}`))
	mid, _ := e.st.SaveChangeModel(ctx, e.ann, store.ChangeModel{Name: "all updates", Action: action.PkgUpgrade, Params: params, Risk: "medium"})
	canary, err := e.st.SavePatchGroup(ctx, e.ann, store.PatchGroup{Name: "canary", HostGroupID: canaryHG.ID, Cron: "0 2 * * SAT",
		TZ: "UTC", ModelID: mid, SuccessThreshold: 100, PromoteValidated: true, Concurrency: 1, StopOnFailure: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := e.st.SavePatchGroup(ctx, e.ann, store.PatchGroup{Name: "prod", HostGroupID: prodHG.ID, Cron: "0 2 * * MON",
		TZ: "UTC", ModelID: mid, BlockedBy: []string{canary}, Soak: 48 * time.Hour, SuccessThreshold: 100,
		PromoteValidated: true, Concurrency: 1, StopOnFailure: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	cg, _ := e.st.GetPatchGroup(ctx, canary)
	if _, err := e.st.SavePatchGroup(ctx, e.ann, store.PatchGroup{ID: canary, Name: "canary", HostGroupID: canaryHG.ID,
		Cron: cg.Cron, TZ: "UTC", ModelID: mid, BlockedBy: []string{prod}, SuccessThreshold: 100, Concurrency: 1, Enabled: true}); err != store.ErrCycle {
		t.Fatalf("loop: %v", err)
	}
	pg, _ := e.st.GetPatchGroup(ctx, prod)

	cycle := func(groupID string) store.PatchCycle {
		t.Helper()
		cs, err := e.st.ListPatchCycles(ctx, groupID, 1)
		if err != nil || len(cs) == 0 {
			t.Fatalf("cycles: %v", err)
		}
		return cs[0]
	}

	// Pending model: skipped. Then approved.
	e.m.RunCycle(ctx, cg, e.now, e.now)
	if c := cycle(canary); c.Result != store.CycleSkipped || !strings.Contains(c.Reason, "isn't approved") {
		t.Fatalf("pending model: %+v", c)
	}
	e.st.ApproveChangeModel(ctx, e.ann, mid)

	// prod is blocked until canary has run.
	e.m.RunCycle(ctx, pg, e.now, e.now)
	if c := cycle(prod); c.Result != store.CycleBlocked || !strings.Contains(c.Reason, "canary hasn't run yet") {
		t.Fatalf("blocked: %+v", c)
	}

	// canary runs everything and validates what it installed.
	upd := func(r store.EnrollResult, ups ...model.Update) {
		e.ingest(r, model.SectionUpdates, model.Updates{Managers: []string{"dnf"}, Updates: ups})
	}
	upd(c1, model.Update{Manager: "dnf", Name: "openssl", Arch: "x86_64", Installed: "1:3.2.2-6.el9", Candidate: "1:3.2.2-7.el9"})
	if created, err := e.m.RunCycle(ctx, cg, e.now, e.now); err != nil || !created {
		t.Fatalf("canary run: %v %v", created, err)
	}
	cc := cycle(canary)
	ch := e.get(cc.ChangeID)
	if cc.Result != store.CycleRunning || cc.Hosts != 1 || ch.Kind != store.KindStandard || ch.State != store.ChangeApproved {
		t.Fatalf("canary cycle: %+v, change %s %s", cc, ch.Kind, ch.State)
	}
	e.advance()
	e.finish(ch.ID, store.JobSucceeded, upgradeResult("openssl=1:3.2.2-7.el9"))
	if err := e.m.FinishCycles(ctx); err != nil {
		t.Fatal(err)
	}
	cc = cycle(canary)
	if cc.Result != store.CycleSuccess || cc.Succeeded != 1 || len(cc.Validated) != 1 ||
		cc.Validated[0] != (store.ValidatedPackage{OS: "rocky:9.6", Manager: "dnf", Name: "openssl", Arch: "x86_64", Version: "1:3.2.2-7.el9"}) {
		t.Fatalf("canary finished: %+v", cc)
	}
	if c := e.get(ch.ID); c.State != store.ChangeClosed {
		t.Fatalf("standard change: %s", c.State)
	}

	// prod soaks for 48 hours, then installs only what canary validated.
	e.m.RunCycle(ctx, pg, e.now, e.now)
	if c := cycle(prod); c.Result != store.CycleBlocked || !strings.Contains(c.Reason, "soaking") {
		t.Fatalf("soak: %+v", c)
	}
	upd(p1, model.Update{Manager: "dnf", Name: "openssl", Arch: "x86_64", Installed: "1:3.2.2-6.el9", Candidate: "1:3.2.2-7.el9"},
		model.Update{Manager: "dnf", Name: "curl", Arch: "x86_64", Installed: "7.76.1-29.el9", Candidate: "7.76.1-31.el9"})
	e.now = e.now.Add(49 * time.Hour)
	if created, err := e.m.RunCycle(ctx, pg, e.now, e.now); err != nil || !created {
		t.Fatalf("prod run: %v %v", created, err)
	}
	pc := cycle(prod)
	if pc.Result != store.CycleRunning || len(pc.Planned) != 1 || pc.Planned[0].Deferred != 1 ||
		strings.Join(pc.Planned[0].Packages, ",") != "openssl" {
		t.Fatalf("prod cycle: %+v", pc)
	}
	js, _ := e.st.ListJobs(ctx, store.JobFilter{ChangeID: pc.ChangeID})
	var p action.UpgradeParams
	json.Unmarshal(js[0].Params, &p)
	if len(js) != 1 || p.Mode != action.ModeSelected || p.Versions["openssl"] != "1:3.2.2-7.el9" {
		t.Fatalf("prod job: %s", js[0].Params)
	}

	// A second prod run before canary ran again is blocked.
	e.cancel(pc.ChangeID)
	e.m.FinishCycles(ctx)
	if c := cycle(prod); c.Result != store.CycleCancelled {
		t.Fatalf("cancelled cycle: %+v", c)
	}
	e.m.RunCycle(ctx, pg, e.now, e.now)
	if c := cycle(prod); c.Result != store.CycleBlocked || !strings.Contains(c.Reason, "since this group last ran") {
		t.Fatalf("stale blocker: %+v", c)
	}

	// A host group a patch group patches can't be deleted.
	if err := e.st.DeleteHostGroup(ctx, e.ann, prodHG.ID); !errors.Is(err, store.ErrInUse) || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("delete a patched host group: %v", err)
	}

	// The scheduler runs a group once per scheduled time.
	g, _ := e.st.GetPatchGroup(ctx, canary)
	g.Cron = "* * * * *"
	e.st.SavePatchGroup(ctx, e.ann, g)
	e.now = time.Now().Add(2 * time.Minute)
	if n, err := e.m.RunPatchGroups(ctx, e.now); err != nil || n != 1 {
		t.Fatalf("scheduled run: %d %v", n, err)
	}
	if n, _ := e.m.RunPatchGroups(ctx, e.now); n != 0 {
		t.Fatalf("ran twice: %d", n)
	}
}

func (e *env) cancel(id string) {
	e.t.Helper()
	if _, err := e.st.CancelChange(ctx, e.ann, id, ""); err != nil {
		e.t.Fatal(err)
	}
}

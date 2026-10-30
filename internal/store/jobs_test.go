package store_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

func user(t *testing.T, s *store.Store, sub string) store.Actor {
	t.Helper()
	u, err := s.UpsertUser(ctx, sub, sub+"@example.com", strings.ToUpper(sub))
	if err != nil {
		t.Fatal(err)
	}
	return store.UserActor(u.ID, "10.0.0.1")
}

// host enrolls host number n, with a token of its own.
func host(t *testing.T, s *store.Store, n int) store.EnrollResult {
	t.Helper()
	hash := []byte(fmt.Sprintf("%s-%d%s", t.Name(), n, strings.Repeat("x", 32)))[:32]
	if _, err := s.CreateEnrollmentToken(ctx, admin, "", store.EnrollmentToken{Name: "lab", ExpiresAt: time.Now().Add(time.Hour)}, hash); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(n)
	return enroll(t, s, hash, "m"+id, "d"+id, "s"+id)
}

func step(t *testing.T, name string, params any, hosts ...string) store.PlanStep {
	t.Helper()
	raw, _ := json.Marshal(params)
	norm, err := action.Validate(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return store.PlanStep{Action: name, Params: norm, Summary: action.Describe(name, norm), HostIDs: hosts}
}

func jobs(t *testing.T, s *store.Store, changeID string) []store.Job {
	t.Helper()
	js, err := s.ListJobs(ctx, store.JobFilter{ChangeID: changeID})
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func states(js []store.Job) string {
	var out []string
	for _, j := range js {
		out = append(out, j.State)
	}
	return strings.Join(out, ",")
}

func code(n int) *int { return &n }

func TestChangeLifecycle(t *testing.T) {
	s := newTestStore(t)
	h1 := host(t, s, 1)
	h2 := host(t, s, 2)
	ann := user(t, s, "ann")
	bob := user(t, s, "bob")

	c, err := s.CreateChange(ctx, ann, store.NewChange{
		Title: "Restart nginx", Risk: action.Low, Concurrency: 1, StopOnFailure: true,
		Steps: []store.PlanStep{step(t, action.ServiceRestart, action.UnitParams{Unit: "nginx"}, h1.HostID, h2.HostID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != store.ChangeSubmitted || c.Jobs != 2 || len(c.HostIDs) != 2 || !strings.HasPrefix(c.Ref(), "CHG-") {
		t.Fatalf("created: %+v", c)
	}
	// Nothing runs before approval.
	if n := startAll(t, s); n != 0 {
		t.Fatalf("started %d unapproved", n)
	}
	if q, _ := s.QueuedJobs(ctx); len(q) != 0 {
		t.Fatalf("queued before approval: %d", len(q))
	}

	// Another user's approval isn't self-approval.
	if err := s.ApproveChange(ctx, bob, c.ID, "go"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveChange(ctx, bob, c.ID, "again"); !errors.Is(err, store.ErrState) {
		t.Fatalf("second approval of an approved change: %v", err)
	}
	c, _ = s.GetChange(ctx, c.ID)
	if c.State != store.ChangeApproved || c.SelfApproved {
		t.Fatalf("approved: %+v", c)
	}
	if n := startAll(t, s); n != 1 {
		t.Fatalf("started %d", n)
	}
	q, err := s.QueuedJobs(ctx)
	if err != nil || len(q) != 2 || q[0].Concurrency != 1 || q[0].Open != 0 || q[0].Seq != 1 {
		t.Fatalf("queued: %+v %v", q, err)
	}
	if ok, err := s.MarkDispatched(ctx, q[0].Job); !ok || err != nil {
		t.Fatalf("dispatch: %v %v", ok, err)
	}
	if ok, _ := s.MarkDispatched(ctx, q[0].Job); ok {
		t.Fatal("dispatched twice")
	}
	q, _ = s.QueuedJobs(ctx)
	if len(q) != 1 || q[0].Open != 1 {
		t.Fatalf("after dispatch: %+v", q)
	}
	j1 := jobs(t, s, c.ID)[0]
	if open, _ := s.OpenJobs(ctx, h1.HostID); len(open) != 1 || open[0].ID != j1.ID {
		t.Fatalf("open jobs: %+v", open)
	}

	// Another host can't report on this job.
	if _, err := s.JobStarted(ctx, h2.HostID, j1.ID); err != nil {
		t.Fatal(err)
	}
	if j, _ := s.GetJob(ctx, j1.ID); j.State != store.JobDispatched {
		t.Fatalf("foreign start accepted: %s", j.State)
	}
	if ok, err := s.JobStarted(ctx, h1.HostID, j1.ID); !ok || err != nil {
		t.Fatalf("start: %v %v", ok, err)
	}

	// Output: duplicates dropped, text cleaned.
	for i, chunk := range []string{"one\n", "two\x00\n", "one\n"} {
		seq := int64(i + 1)
		if i == 2 {
			seq = 1
		}
		s.AppendJobOutput(ctx, h1.HostID, j1.ID, seq, "stdout", chunk)
	}
	out, _ := s.JobOutput(ctx, j1.ID, 0, 100)
	if len(out) != 2 || out[1].Chunk != "two\n" {
		t.Fatalf("output: %+v", out)
	}
	if _, err := s.AppendJobOutput(ctx, h2.HostID, j1.ID, 9, "stdout", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign output: %v", err)
	}

	// The first job fails: the change stops there.
	if ok, err := s.FinishJob(ctx, store.Actor{ID: "agent:" + h1.AgentID}, h1.HostID, j1.ID,
		store.JobResult{State: store.JobFailed, ExitCode: code(1), Error: "boom"}); !ok || err != nil {
		t.Fatalf("finish: %v %v", ok, err)
	}
	if ok, _ := s.FinishJob(ctx, store.System, h1.HostID, j1.ID, store.JobResult{State: store.JobSucceeded}); ok {
		t.Fatal("a resent result was applied again")
	}
	js := jobs(t, s, c.ID)
	if states(js) != "failed,cancelled" || !strings.Contains(js[1].Error, "earlier job") {
		t.Fatalf("after failure: %s %q", states(js), js[1].Error)
	}
	c, _ = s.GetChange(ctx, c.ID)
	if c.State != store.ChangeFailed || c.Outcome != "failed" || c.ActualEnd.IsZero() {
		t.Fatalf("change after failure: %+v", c)
	}

	audit, _ := s.ListAudit(ctx, 0, 100)
	var actions []string
	for _, e := range audit {
		actions = append([]string{e.Action}, actions...)
	}
	want := "change.create change.approve change.state change.state job.dispatch job.result change.state"
	if got := strings.Join(actions, " "); !strings.Contains(got, want) {
		t.Fatalf("audit: %s", got)
	}
	if v, _ := s.VerifyAudit(ctx); !v.OK() {
		t.Fatalf("audit chain: %+v", v)
	}
}

func TestSelfApprovalAndOutcomes(t *testing.T) {
	s := newTestStore(t)
	h1 := host(t, s, 1)
	h2 := host(t, s, 2)
	ann := user(t, s, "ann")

	c, err := s.CreateChange(ctx, ann, store.NewChange{
		Title: "Reboot", Risk: action.High, Concurrency: 2, StopOnFailure: false, SelfApprove: true,
		Steps: []store.PlanStep{step(t, action.HostReboot, nil, h1.HostID, h2.HostID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != store.ChangeApproved || !c.SelfApproved {
		t.Fatalf("self-approved: %+v", c)
	}
	appr, _ := s.ChangeApprovals(ctx, c.ID)
	if len(appr) != 1 || !appr[0].SelfApproved {
		t.Fatalf("approvals: %+v", appr)
	}
	startAll(t, s)
	q, _ := s.QueuedJobs(ctx)
	if len(q) != 2 {
		t.Fatalf("both hosts at once: %d", len(q))
	}
	for _, j := range q {
		s.MarkDispatched(ctx, j.Job)
	}
	js := jobs(t, s, c.ID)
	// A reboot: "rebooting" keeps the job running until the host is back.
	if ok, _ := s.FinishJob(ctx, store.System, h1.HostID, js[0].ID, store.JobResult{State: store.JobRebooting}); ok {
		t.Fatal("rebooting ended the job")
	}
	if j, _ := s.GetJob(ctx, js[0].ID); j.State != store.JobRunning || !j.AwaitingReboot {
		t.Fatalf("rebooting job: %+v", j)
	}
	s.FinishJob(ctx, store.System, h1.HostID, js[0].ID, store.JobResult{State: store.JobSucceeded, ExitCode: code(0)})
	s.FinishJob(ctx, store.System, h2.HostID, js[1].ID, store.JobResult{State: store.JobTimedOut, ExitCode: code(-1)})
	c, _ = s.GetChange(ctx, c.ID)
	if c.State != store.ChangeFailed || c.Outcome != "partial" || c.JobsOK != 1 || c.JobsFailed != 1 {
		t.Fatalf("partial: %+v", c)
	}

	// All succeed: implemented.
	c2, _ := s.CreateChange(ctx, ann, store.NewChange{Title: "x", Risk: action.Low, SelfApprove: true,
		Steps: []store.PlanStep{step(t, action.ServiceStart, action.UnitParams{Unit: "a"}, h1.HostID)}})
	startAll(t, s)
	j := jobs(t, s, c2.ID)[0]
	s.FinishJob(ctx, store.System, h1.HostID, j.ID, store.JobResult{State: store.JobSucceeded, ExitCode: code(0)})
	if c2, _ = s.GetChange(ctx, c2.ID); c2.State != store.ChangeImplemented || c2.Outcome != "success" {
		t.Fatalf("implemented: %+v", c2)
	}
	counts, _ := s.ChangeCounts(ctx, []string{h1.HostID, h2.HostID})
	if counts.AwaitingApproval != 0 || counts.InProgress != 0 {
		t.Fatalf("counts: %+v", counts)
	}
}

func TestRejectAndCancel(t *testing.T) {
	s := newTestStore(t)
	h := host(t, s, 1)
	ann, bob := user(t, s, "ann"), user(t, s, "bob")
	mk := func(approve bool) store.Change {
		c, err := s.CreateChange(ctx, ann, store.NewChange{Title: "x", Risk: action.Low, SelfApprove: approve,
			Steps: []store.PlanStep{step(t, action.ServiceStop, action.UnitParams{Unit: "a"}, h.HostID)}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := mk(false)
	if counts, _ := s.ChangeCounts(ctx, []string{h.HostID}); counts.AwaitingApproval != 1 {
		t.Fatalf("awaiting: %+v", counts)
	}
	// Counts only cover changes on hosts the caller can see.
	if counts, _ := s.ChangeCounts(ctx, nil); counts.AwaitingApproval != 0 {
		t.Fatalf("invisible change counted: %+v", counts)
	}
	if err := s.RejectChange(ctx, bob, c.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.GetChange(ctx, c.ID); c.State != store.ChangeRejected || states(jobs(t, s, c.ID)) != "cancelled" {
		t.Fatalf("rejected: %+v", c)
	}
	if _, err := s.CancelChange(ctx, ann, c.ID, ""); !errors.Is(err, store.ErrState) {
		t.Fatalf("cancel a rejected change: %v", err)
	}

	// Cancelling a change with a job on the agent hands that job back.
	c = mk(true)
	startAll(t, s)
	q, _ := s.QueuedJobs(ctx)
	s.MarkDispatched(ctx, q[0].Job)
	running, err := s.CancelChange(ctx, ann, c.ID, "wrong host")
	if err != nil || len(running) != 1 || running[0].AgentID != h.AgentID {
		t.Fatalf("cancel: %+v %v", running, err)
	}
	if c, _ = s.GetChange(ctx, c.ID); c.State != store.ChangeCancelled || c.Outcome != "cancelled" {
		t.Fatalf("cancelled: %+v", c)
	}
	// Its result still lands on the job; the change stays cancelled.
	s.FinishJob(ctx, store.System, h.HostID, running[0].ID, store.JobResult{State: store.JobCancelled, ExitCode: code(-1)})
	if c, _ = s.GetChange(ctx, c.ID); c.State != store.ChangeCancelled || states(jobs(t, s, c.ID)) != "cancelled" {
		t.Fatalf("after result: %+v %s", c, states(jobs(t, s, c.ID)))
	}
}

func TestExpireJobs(t *testing.T) {
	s := newTestStore(t)
	h1 := host(t, s, 1)
	h2 := host(t, s, 2)
	ann := user(t, s, "ann")
	c, _ := s.CreateChange(ctx, ann, store.NewChange{Title: "x", Risk: action.Low, Concurrency: 2, SelfApprove: true,
		Steps: []store.PlanStep{step(t, action.ServiceRestart, action.UnitParams{Unit: "a"}, h1.HostID, h2.HostID)}})
	startAll(t, s)
	q, _ := s.QueuedJobs(ctx)
	s.MarkDispatched(ctx, q[0].Job)
	if late, _ := s.ExpireJobs(ctx); len(late) != 0 {
		t.Fatalf("expired too early: %+v", late)
	}
	// h1's job is long past its timeout; h2 has been offline for hours.
	db := s.DB()
	if _, err := db.Exec(`UPDATE job SET dispatched_at = now() - interval '1 hour' WHERE id = $1`, q[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE change SET actual_start = now() - interval '2 hours' WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE host SET connected = false, last_seen = now() - interval '3 hours' WHERE ci_id = $1`, h2.HostID); err != nil {
		t.Fatal(err)
	}
	late, err := s.ExpireJobs(ctx)
	if err != nil || len(late) != 1 || late[0].ID != q[0].ID {
		t.Fatalf("late: %+v %v", late, err)
	}
	js := jobs(t, s, c.ID)
	if states(js) != "timed_out,failed" || !strings.Contains(js[1].Error, "offline") {
		t.Fatalf("expired: %s %q", states(js), js[1].Error)
	}
	if c, _ = s.GetChange(ctx, c.ID); c.State != store.ChangeFailed {
		t.Fatalf("change: %s", c.State)
	}
}

func TestOutputCap(t *testing.T) {
	s := newTestStore(t)
	h := host(t, s, 1)
	c, _ := s.CreateChange(ctx, user(t, s, "ann"), store.NewChange{Title: "x", Risk: action.Low,
		Steps: []store.PlanStep{step(t, action.ServiceRestart, action.UnitParams{Unit: "a"}, h.HostID)}})
	j := jobs(t, s, c.ID)[0]
	big := strings.Repeat("x", 1<<20)
	for i := range 7 {
		if _, err := s.AppendJobOutput(ctx, h.HostID, j.ID, int64(i+1), "stdout", big); err != nil {
			t.Fatal(err)
		}
	}
	out, _ := s.JobOutput(ctx, j.ID, 0, 100)
	if len(out) != 6 || !strings.Contains(out[5].Chunk, "truncated") || out[5].Stream != "info" {
		t.Fatalf("chunks: %d, last %q", len(out), out[len(out)-1].Chunk[:min(40, len(out[len(out)-1].Chunk))])
	}
}

func TestHistoryAttributedToChanges(t *testing.T) {
	s := newTestStore(t)
	h := host(t, s, 1)
	ann := user(t, s, "ann")
	pk := func(v string) model.Packages {
		return model.Packages{Managers: []string{"apt"}, Packages: []model.Package{{Manager: "apt", Name: "curl", Version: v}}}
	}
	ingestSection(t, s, h, model.SectionPackages, pk("1"))

	c, _ := s.CreateChange(ctx, ann, store.NewChange{Title: "patch", Risk: action.Medium, SelfApprove: true,
		Steps: []store.PlanStep{step(t, action.PkgUpgrade, action.UpgradeParams{}, h.HostID)}})
	startAll(t, s)
	j := jobs(t, s, c.ID)[0]
	s.MarkDispatched(ctx, j)
	s.JobStarted(ctx, h.HostID, j.ID)

	// While the job runs, a package change is attributed to it; a
	// container change isn't, since pkg.upgrade can't cause one.
	ingestSection(t, s, h, model.SectionPackages, pk("2"))
	ingestSection(t, s, h, model.SectionServices, model.Services{Units: []model.Service{{Name: "a.service", Active: "active"}}})
	ingestSection(t, s, h, model.SectionServices, model.Services{Units: []model.Service{{Name: "a.service", Active: "active", Enabled: "enabled"}}})
	s.FinishJob(ctx, store.System, h.HostID, j.ID, store.JobResult{State: store.JobSucceeded, ExitCode: code(0)})
	// After it ends, nothing is attributed without the job's ID...
	ingestSection(t, s, h, model.SectionPackages, pk("3"))
	// ...and with it, the job's change is named.
	p, hash := payload(t, pk("4"))
	if _, err := s.IngestSection(ctx, h.HostID, h.AgentID, model.SectionPackages, hash, p, j.ID); err != nil {
		t.Fatal(err)
	}
	// A job ID from another host is ignored.
	p, hash = payload(t, pk("5"))
	if _, err := s.IngestSection(ctx, h.HostID, h.AgentID, model.SectionPackages, hash, p, "00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}

	hist, _ := s.HostHistory(ctx, h.HostID, 20)
	var got []string
	for i := len(hist) - 1; i >= 0; i-- {
		e := hist[i]
		tag := "-"
		if e.ChangeID != "" {
			tag = e.ChangeRef()
			if e.ChangeID != c.ID {
				t.Fatalf("wrong change: %+v", e)
			}
		}
		got = append(got, e.Section+":"+tag)
	}
	ref := c.Ref()
	want := "packages:- packages:" + ref + " services:- services:" + ref + " packages:- packages:" + ref + " packages:-"
	if strings.Join(got, " ") != want {
		t.Fatalf("history:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestScriptLibrary(t *testing.T) {
	s := newTestStore(t)
	admin := user(t, s, "admin")
	id, err := s.CreateScript(ctx, admin, "clean-apt", "Clears the apt cache", store.NewScriptVersion{
		Interpreter: "/bin/sh", Risk: action.Low, Body: "apt-get clean\n",
		Params: []action.ScriptParam{{Name: "days", Type: "int"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateScript(ctx, admin, "clean-apt", "", store.NewScriptVersion{Interpreter: "/bin/sh", Risk: action.Low, Body: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	n, err := s.AddScriptVersion(ctx, admin, id, "Clears caches", store.NewScriptVersion{Interpreter: "/bin/bash", Risk: action.Medium, Body: "apt-get clean; apt-get autoclean\n"})
	if err != nil || n != 2 {
		t.Fatalf("version: %d %v", n, err)
	}
	sc, _ := s.GetScript(ctx, id)
	if sc.Latest != 2 || sc.Risk != "medium" || sc.Description != "Clears caches" {
		t.Fatalf("script: %+v", sc)
	}
	v1, err := s.GetScriptVersion(ctx, id, 1)
	if err != nil || v1.SHA256 != store.ScriptSHA256("apt-get clean\n") || len(v1.Params) != 1 || v1.CreatedBy != "ADMIN" {
		t.Fatalf("v1: %+v %v", v1, err)
	}
	// Versions are immutable, even to the database owner.
	if _, err := s.DB().Exec(`UPDATE script_version SET body = 'rm -rf /' WHERE script_id = $1`, id); err == nil {
		t.Fatal("a script version was edited")
	}
	vs, _ := s.ScriptVersions(ctx, id)
	if len(vs) != 2 || vs[0].Version != 2 {
		t.Fatalf("versions: %+v", vs)
	}
	if err := s.SetScriptArchived(ctx, admin, id, true); err != nil {
		t.Fatal(err)
	}
	if sc, _ = s.GetScript(ctx, id); !sc.Archived {
		t.Fatal("not archived")
	}

	// A job pins the version it ran.
	h := host(t, s, 1)
	st := step(t, action.ScriptRun, action.ScriptParams{ScriptID: id, Name: "clean-apt", Version: 1}, h.HostID)
	st.ScriptID, st.ScriptVersion = id, 1
	c, err := s.CreateChange(ctx, admin, store.NewChange{Title: "x", Risk: action.Low, Steps: []store.PlanStep{st}})
	if err != nil {
		t.Fatal(err)
	}
	if j := jobs(t, s, c.ID)[0]; j.ScriptID != id || j.ScriptVersion != 1 || j.TimeoutS != 600 {
		t.Fatalf("job: %+v", j)
	}
	if sc, _ = s.GetScript(ctx, id); sc.Runs != 1 {
		t.Fatalf("runs: %d", sc.Runs)
	}
}

// startAll starts every approved change, as internal/change does for
// changes without a window, and returns how many it started.
func startAll(t *testing.T, s *store.Store) int {
	t.Helper()
	cs, err := s.ListChanges(ctx, store.ChangeFilter{States: []string{store.ChangeApproved}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if err := s.StartChange(ctx, c.ID, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	return len(cs)
}

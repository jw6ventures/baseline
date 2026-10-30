package change

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/scheduler"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	// missedRun is how late a patch group's run may start, when the server
	// was down at its time; later runs are recorded as skipped.
	missedRun = 6 * time.Hour
	// lookBack bounds the search for runs the scheduler hasn't handled.
	lookBack = 7 * 24 * time.Hour
)

// NextRun is the patch group's next scheduled run after t; zero if its
// schedule can't be read or never fires.
func NextRun(g store.PatchGroup, t time.Time) time.Time {
	s, err := scheduler.Parse(g.Cron)
	if err != nil {
		return time.Time{}
	}
	loc, err := time.LoadLocation(g.TZ)
	if err != nil {
		return time.Time{}
	}
	return s.Next(t, loc)
}

// RunPatchGroups starts the runs that are due, one cycle per group and
// scheduled time. It returns how many changes it created.
func (m *Manager) RunPatchGroups(ctx context.Context, now time.Time) (int, error) {
	groups, err := m.St.ListPatchGroups(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, g := range groups {
		if !g.Enabled {
			continue
		}
		since := g.LastRunAt
		if since.IsZero() {
			since = g.CreatedAt
		}
		since = maxTime(since, now.Add(-lookBack))
		var due time.Time
		for t := NextRun(g, since); !t.IsZero() && !t.After(now); t = NextRun(g, t) {
			due = t
		}
		if due.IsZero() {
			continue
		}
		if ok, err := m.St.ClaimPatchRun(ctx, g.ID, due); err != nil || !ok {
			if err != nil {
				m.errorf(ctx, "patch group %s: %v", g.Name, err)
			}
			continue
		}
		created, err := m.RunCycle(ctx, g, due, now)
		if err != nil {
			m.errorf(ctx, "patch group %s: %v", g.Name, err)
		}
		if created {
			n++
		}
	}
	return n, nil
}

// RunCycle runs one cycle of a patch group scheduled at due: it checks the
// groups that block it, works out what each host installs and creates the
// Standard change. A blocked or skipped run is recorded as a cycle too.
func (m *Manager) RunCycle(ctx context.Context, g store.PatchGroup, due, now time.Time) (bool, error) {
	cycle := store.PatchCycle{GroupID: g.ID, GroupName: g.Name, ScheduledFor: due}
	record := func(result, reason string) (bool, error) {
		cycle.Result, cycle.Reason = result, reason
		m.logf(jw6_utils.Info, "Patch group %s, run of %s: %s (%s)", g.Name, due.UTC().Format(time.RFC3339), result, reason)
		_, err := m.St.RecordCycle(ctx, cycle)
		return false, err
	}
	if now.Sub(due) > missedRun {
		return record(store.CycleSkipped, "the server wasn't running at the scheduled time")
	}
	model, err := m.St.GetChangeModel(ctx, g.ModelID)
	if err != nil {
		return false, err
	}
	if !model.Approved() {
		return record(store.CycleSkipped, "change model "+model.Name+" isn't approved")
	}

	var validated []store.ValidatedPackage
	reason, err := m.blocked(ctx, g, now, &validated)
	if err != nil {
		return false, err
	}
	if reason != "" {
		return record(store.CycleBlocked, reason)
	}

	if strings.HasPrefix(model.Action, "compose.") {
		return m.runStacks(ctx, g, model, due, now, cycle, record)
	}
	hosts, err := m.St.HostGroupMembers(ctx, g.HostGroupID)
	if err != nil {
		return false, err
	}
	if len(hosts) == 0 {
		return record(store.CycleSkipped, "the host group "+g.HostGroupName+" has no hosts")
	}
	promote := g.PromoteValidated && len(g.BlockedBy) > 0 && model.Action == action.PkgUpgrade
	var steps []store.PlanStep
	for _, h := range hosts {
		p := store.PlannedHost{HostID: h.ID, Hostname: h.DisplayName(), OS: osKey(h)}
		params := model.Params
		if ok, why := h.Policy.Allows(model.Action); !ok {
			p.Note = why
		} else if ok, why := action.MustGet(model.Action).Supported(h.Capabilities); !ok {
			p.Note = "it " + why
		} else if model.Action == action.PkgUpgrade {
			ups, err := m.St.HostUpdates(ctx, h.ID)
			if err != nil {
				return false, err
			}
			if promote {
				params, err = promoted(model.Params, h, ups, validated, &p)
				if err != nil {
					return false, err
				}
			} else {
				p.Job = true
			}
			// What an image-based host is about to deploy, for the groups
			// this one blocks: the job's result can't say (it's staged).
			for _, u := range ups {
				if u.Image && p.Job {
					p.Image, p.ImageVersion = u.Name, u.Candidate
				}
			}
		} else {
			p.Job = true
		}
		cycle.Planned = append(cycle.Planned, p)
		if p.Job {
			step := store.PlanStep{Action: model.Action, Params: params, Summary: action.Describe(model.Action, params),
				HostIDs: []string{h.ID}, ScriptID: model.ScriptID, ScriptVersion: model.ScriptVersion}
			steps = append(steps, step)
			cycle.Hosts++
		}
	}
	if len(steps) == 0 {
		why := "no host has anything to do"
		if promote {
			why = "nothing validated is pending on these hosts"
		}
		return record(store.CycleSuccess, why)
	}
	title := fmt.Sprintf("Patch group %s: %s", g.Name, model.Summary())
	if promote {
		title = fmt.Sprintf("Patch group %s: validated updates", g.Name)
	}
	c, err := m.St.CreateChange(ctx, store.System, store.NewChange{
		Kind: store.KindStandard, ModelID: model.ID, Title: title,
		Justification: "Scheduled run of patch group " + g.Name + " (" + g.Cron + " " + g.TZ + ")",
		Risk:          action.Risk(model.Risk), Concurrency: g.Concurrency, StopOnFailure: g.StopOnFailure,
		WindowID: g.WindowID, PlannedStart: due, Steps: steps,
	})
	if err != nil {
		return false, err
	}
	cycle.ChangeID, cycle.Result = c.ID, store.CycleRunning
	if _, err := m.St.RecordCycle(ctx, cycle); err != nil {
		return true, err
	}
	m.logf(jw6_utils.Info, "Patch group %s: %s on %d hosts", g.Name, c.Ref(), cycle.Hosts)
	return true, nil
}

// runStacks runs the rest of a Compose group's cycle: a Standard change
// updating each of its stacks that has newer images (planStacks).
func (m *Manager) runStacks(ctx context.Context, g store.PatchGroup, model store.ChangeModel, due, now time.Time,
	cycle store.PatchCycle, record func(result, reason string) (bool, error)) (bool, error) {
	if len(g.Stacks) == 0 {
		return record(store.CycleSkipped, "it has no stacks; they were deleted")
	}
	steps, cis, err := m.planStacks(ctx, g, model, now, &cycle)
	if err != nil {
		return false, err
	}
	if len(steps) == 0 {
		cycle.Result, cycle.Reason = store.CycleSuccess, "no stack has anything to update"
		if g.PromoteValidated && slices.ContainsFunc(cycle.Planned, func(p store.PlannedHost) bool { return p.Deferred > 0 }) {
			cycle.Reason = "nothing newer is validated yet"
		}
		m.logf(jw6_utils.Info, "Patch group %s, run of %s: %s (%s)", g.Name, due.UTC().Format(time.RFC3339), cycle.Result, cycle.Reason)
		_, err := m.St.RecordCycle(ctx, cycle)
		return false, err
	}
	c, err := m.St.CreateChange(ctx, store.System, store.NewChange{
		Kind: store.KindStandard, ModelID: model.ID,
		Title:         fmt.Sprintf("Patch group %s: update %s", g.Name, plural(len(steps), "Compose stack")),
		Justification: "Scheduled run of patch group " + g.Name + " (" + g.Cron + " " + g.TZ + ")",
		Risk:          action.Risk(model.Risk), Concurrency: g.Concurrency, StopOnFailure: g.StopOnFailure,
		WindowID: g.WindowID, PlannedStart: due, Steps: steps, CIs: cis,
	})
	if err != nil {
		return false, err
	}
	cycle.ChangeID, cycle.Result = c.ID, store.CycleRunning
	if _, err := m.St.RecordCycle(ctx, cycle); err != nil {
		return true, err
	}
	m.logf(jw6_utils.Info, "Patch group %s: %s on %s", g.Name, c.Ref(), plural(cycle.Hosts, "stack"))
	return true, nil
}

// blocked checks the groups that block g (docs/change-management.md §4):
// each one's latest cycle must have succeeded on enough hosts, at least the
// soak time ago, and since g last ran. It returns why g is blocked, or "",
// adding what the blocking cycles validated.
func (m *Manager) blocked(ctx context.Context, g store.PatchGroup, now time.Time, validated *[]store.ValidatedPackage) (string, error) {
	if len(g.BlockedBy) == 0 {
		return "", nil
	}
	mine, err := m.St.LastRanCycle(ctx, g.ID)
	if err != nil {
		return "", err
	}
	var reasons []string
	for i, id := range g.BlockedBy {
		name := g.BlockedByNames[i]
		last, err := m.St.LastRanCycle(ctx, id)
		if err != nil {
			return "", err
		}
		switch {
		case last == nil:
			reasons = append(reasons, name+" hasn't run yet")
		case last.Result == store.CycleRunning:
			reasons = append(reasons, name+" is still running")
		case (last.Result != store.CycleSuccess && last.Result != store.CyclePartial) || last.Rate() < g.SuccessThreshold:
			reasons = append(reasons, fmt.Sprintf("%s's last run %s (%d of %d hosts succeeded; %d%% needed)",
				name, last.Result, last.Succeeded, last.Hosts, g.SuccessThreshold))
		case last.FinishedAt.Add(g.Soak).After(now):
			reasons = append(reasons, fmt.Sprintf("%s finished %s ago, soaking for %s", name,
				now.Sub(last.FinishedAt).Round(time.Minute), g.Soak))
		case mine != nil && !last.FinishedAt.After(mine.StartedAt):
			reasons = append(reasons, name+" hasn't succeeded again since this group last ran")
		default:
			*validated = append(*validated, last.Validated...)
		}
	}
	return joinNames(reasons), nil
}

func osKey(h store.Host) string { return h.OSID + ":" + h.OSVersion }

// promoted narrows an upgrade to what the blocking groups validated: the
// host's pending updates whose candidate is exactly a version validated on
// the same OS release. Those are pinned on agents that take pins; the rest
// wait for a later cycle.
func promoted(modelParams []byte, h store.Host, ups []store.HostUpdate, validated []store.ValidatedPackage,
	p *store.PlannedHost) ([]byte, error) {
	var mp action.UpgradeParams
	if err := json.Unmarshal(modelParams, &mp); err != nil {
		return nil, err
	}
	// By manager and name; the arch must match when both sides know it.
	ok := map[[2]string][]store.ValidatedPackage{}
	for _, v := range validated {
		if v.OS == p.OS {
			k := [2]string{v.Manager, v.Name}
			ok[k] = append(ok[k], v)
		}
	}
	validVersion := func(u store.HostUpdate) string {
		for _, v := range ok[[2]string{u.Manager, u.Name}] {
			if v.Arch == "" || u.Arch == "" || v.Arch == u.Arch {
				return v.Version
			}
		}
		return ""
	}
	pin := slices.Contains(h.Capabilities, action.CapPkgPin)
	out := action.UpgradeParams{Mode: action.ModeSelected, Reboot: mp.Reboot, Versions: map[string]string{}}
	for _, u := range ups {
		if excluded(mp.Exclude, u.Name) || (mp.Mode == action.ModeSecurity && !u.Security) {
			continue
		}
		entry := u.Name
		if u.Manager == "flatpak" || u.Manager == "snap" || u.Manager == "rpm-ostree" {
			entry = u.Manager + ":" + u.Name
		}
		if mp.Mode == action.ModeSelected && !slices.Contains(mp.Packages, entry) {
			continue
		}
		// A package the upgrade newly pulls in (a new kernel) comes along
		// with the one that needs it.
		if u.Installed == "" && !u.Image {
			continue
		}
		if validVersion(u) != u.Candidate {
			p.Deferred++
			continue
		}
		if slices.Contains(out.Packages, entry) {
			continue
		}
		out.Packages = append(out.Packages, entry)
		if pin && u.Manager != "flatpak" && u.Manager != "snap" {
			out.Versions[entry] = u.Candidate
		}
	}
	switch {
	case len(out.Packages) == 0 && p.Deferred > 0:
		p.Note = fmt.Sprintf("none of its %d pending updates is validated yet", p.Deferred)
		return nil, nil
	case len(out.Packages) == 0:
		p.Note = "nothing validated is pending"
		return nil, nil
	case !pin:
		p.Note = "its agent can't pin versions; the validated packages are named, at their current candidates"
	}
	if len(out.Versions) == 0 {
		out.Versions = nil
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	norm, err := action.Validate(action.PkgUpgrade, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.DisplayName(), err)
	}
	p.Packages, p.Versions, p.Job = out.Packages, out.Versions, true
	return norm, nil
}

func excluded(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// FinishCycles records how cycles ended once their change has: success when
// every host succeeded, partial or failed otherwise, and the
// package@version pairs that succeeded, for the groups they block.
func (m *Manager) FinishCycles(ctx context.Context) error {
	cycles, err := m.St.EndedCycles(ctx)
	if err != nil {
		return err
	}
	for _, c := range cycles {
		if c.ChangeID == "" {
			if err := m.St.FinishCycle(ctx, c.ID, store.CycleCancelled, "its change was deleted", c.Hosts, 0, nil); err != nil {
				return err
			}
			continue
		}
		jobs, err := m.St.ListJobs(ctx, store.JobFilter{ChangeID: c.ChangeID, Limit: 10000})
		if err != nil {
			return err
		}
		result, reason, ok, validated := cycleResult(c, jobs)
		if err := m.St.FinishCycle(ctx, c.ID, result, reason, len(jobs), ok, validated); err != nil {
			return err
		}
		m.logf(jw6_utils.Info, "Patch group %s: cycle %s, %d of %d hosts succeeded", c.GroupName, result, ok, len(jobs))
	}
	return nil
}

func cycleResult(c store.PatchCycle, jobs []store.Job) (result, reason string, ok int, validated []store.ValidatedPackage) {
	planned := map[string]store.PlannedHost{}
	for _, p := range c.Planned {
		planned[p.HostID] = p
	}
	seen := map[store.ValidatedPackage]bool{}
	add := func(v store.ValidatedPackage) {
		if !seen[v] {
			seen[v] = true
			validated = append(validated, v)
		}
	}
	for _, j := range jobs {
		if j.State != store.JobSucceeded {
			continue
		}
		ok++
		p := planned[j.HostID]
		if p.Image != "" {
			add(store.ValidatedPackage{OS: p.OS, Manager: "rpm-ostree", Name: p.Image, Version: p.ImageVersion})
		}
		if j.Action != action.PkgUpgrade {
			continue
		}
		var r action.UpgradeResult
		if json.Unmarshal(j.Result, &r) != nil {
			continue
		}
		for _, pc := range append(slices.Clone(r.Changed), r.Added...) {
			// Several installed versions (kernels) don't make one version.
			if pc.To == "" || strings.Contains(pc.To, ", ") {
				continue
			}
			add(store.ValidatedPackage{OS: p.OS, Manager: pc.Manager, Name: pc.Name, Arch: pc.Arch, Version: pc.To})
		}
	}
	slices.SortFunc(validated, func(a, b store.ValidatedPackage) int {
		return strings.Compare(a.OS+"\x00"+a.Manager+"\x00"+a.Name+"\x00"+a.Arch, b.OS+"\x00"+b.Manager+"\x00"+b.Name+"\x00"+b.Arch)
	})
	switch {
	case c.ChangeState == store.ChangeCancelled || c.ChangeState == store.ChangeRejected:
		return store.CycleCancelled, "its change was " + c.ChangeState, ok, validated
	case ok == len(jobs):
		return store.CycleSuccess, "", ok, validated
	case ok == 0:
		return store.CycleFailed, "", ok, validated
	}
	return store.CyclePartial, "", ok, validated
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

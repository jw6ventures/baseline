package change

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/stackname"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// planStacks plans a Compose group's cycle (docs/change-management.md §4):
// a step for each of its stacks that has newer images behind its tags,
// adding what it set out to do on every stack to the cycle. It returns the
// steps and the stacks they update.
func (m *Manager) planStacks(ctx context.Context, g store.PatchGroup, model store.ChangeModel, now time.Time,
	cycle *store.PatchCycle) ([]store.PlanStep, []string, error) {
	hosts, err := m.St.ListHosts(ctx)
	if err != nil {
		return nil, nil, err
	}
	byHost := map[string]store.Host{}
	ids := make([]string, len(hosts))
	for i, h := range hosts {
		byHost[h.ID], ids[i] = h, h.ID
	}
	all, err := m.St.ListStacks(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	rows, err := m.St.ListContainers(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	ctrs := map[string][]store.ContainerRow{} // by stack CI
	for _, c := range rows {
		if c.StackCI != "" {
			ctrs[c.StackCI] = append(ctrs[c.StackCI], c)
		}
	}
	spec := action.MustGet(model.Action)
	var targets []updategroup.Target
	for _, id := range g.Stacks {
		i := slices.IndexFunc(all, func(st store.Stack) bool { return st.CIID == id })
		if i < 0 {
			continue
		}
		st, h := all[i], byHost[all[i].HostID]
		p := store.PlannedHost{HostID: st.HostID, Hostname: h.DisplayName(), StackID: st.CIID, Project: st.Project}
		ok, why := st.Updatable()
		switch {
		case h.Revoked:
			p.Note = "its host is revoked"
		case !ok:
			p.Note = "Baseline can't update it: " + why
		case st.Pinned:
			p.Note = "it's pinned"
		}
		if p.Note == "" {
			if ok, why := h.Policy.Allows(model.Action); !ok {
				p.Note = why
			} else if ok, why := spec.Supported(h.Capabilities); !ok {
				p.Note = "its host " + why
			} else if st.Drift == 0 {
				p.Note = "no newer images behind its tags"
			}
		}
		if p.Note == "" {
			open, err := m.St.ListChanges(ctx, store.ChangeFilter{CIID: st.CIID, Limit: 10})
			if err != nil {
				return nil, nil, err
			}
			if slices.ContainsFunc(open, func(c store.Change) bool { return c.Open() }) {
				p.Note = "another change on it is still open"
			}
		}
		if p.Note == "" {
			p.Job = true
			if g.PromoteValidated {
				promote(&p, st, all, ctrs, g.Soak, now)
			}
		}
		cycle.Planned = append(cycle.Planned, p)
		if p.Job {
			targets = append(targets, updategroup.Target{Stack: st, Services: p.Services})
		}
	}
	if len(targets) == 0 {
		return nil, nil, nil
	}
	// Services in update groups update with their groups, in order
	// (docs/change-management.md §5.4).
	ix := updategroup.New(all, rows)
	check := m.scheduledCheck(ctx, ix, byHost, targets, model.Action,
		"it isn't in patch group "+g.Name+", and this group's stacks don't update ahead of it", now)
	steps, cis, held, err := m.GroupedSteps(ctx, ix, model.Action, model.Params, targets, check)
	if err != nil {
		return nil, nil, err
	}
	for _, h := range held {
		i := slices.IndexFunc(cycle.Planned, func(p store.PlannedHost) bool { return p.StackID == h.Member.Stack.CIID })
		if i < 0 {
			continue
		}
		note := h.Member.Service + " waits: " + h.Why
		if cycle.Planned[i].Note != "" {
			note = cycle.Planned[i].Note + "; " + note
		}
		cycle.Planned[i].Note = note
	}
	// Members of other stacks that come along.
	for _, s := range steps {
		var p action.ComposeParams
		json.Unmarshal(s.Params, &p)
		host := s.HostIDs[0]
		i := slices.IndexFunc(all, func(st store.Stack) bool {
			return st.HostID == host && st.Project == p.Project && st.Engine == p.Engine
		})
		if i < 0 || slices.ContainsFunc(cycle.Planned, func(x store.PlannedHost) bool { return x.StackID == all[i].CIID }) {
			continue
		}
		cycle.Planned = append(cycle.Planned, store.PlannedHost{HostID: host, Hostname: byHost[host].DisplayName(),
			StackID: all[i].CIID, Project: p.Project, Services: p.Services, Job: true,
			Note: "with update group " + s.UpdateGroup})
	}
	cycle.Hosts = len(steps)
	if len(steps) == 0 {
		return nil, nil, nil
	}
	return steps, cis, nil
}

// promote narrows a stack's update to the images its earlier environment
// validated. A stack whose name puts it in Test, Staging or Prod
// (internal/stackname) is checked against the copies of the same app at the
// nearest earlier stage (Dev for Test and Staging; Test or Staging, else
// Dev, for Prod), preferring copies of the same visibility: each service
// with a newer image updates only if one of those copies runs exactly that
// image, running and not unhealthy, since at least soak ago. The rest wait
// for a later cycle. A stack with no earlier copy updates everything.
func promote(p *store.PlannedHost, st store.Stack, all []store.Stack, ctrs map[string][]store.ContainerRow,
	soak time.Duration, now time.Time) {
	validators := earlier(st, all)
	if len(validators) == 0 {
		if meta, ok := stackname.Parse(st.Project); ok && stackname.Stage(meta.Environment) > 0 {
			p.Note = "no earlier copy of " + meta.App + " to promote from: updates everything newer"
		}
		return
	}
	var names []string
	var running []store.ContainerRow
	for _, v := range validators {
		names = append(names, v.Project+" on "+v.Hostname)
		running = append(running, ctrs[v.CIID]...)
	}
	p.Validator = strings.Join(names, ", ")
	validated := func(digest string) (ok, young bool) {
		for _, c := range running {
			if c.State != "running" || c.Health == "unhealthy" || !slices.Contains(c.ImageDigests, digest) {
				continue
			}
			started, err := time.Parse(time.RFC3339, c.StartedAt)
			if soak == 0 || (err == nil && !started.After(now.Add(-soak))) {
				return true, false
			}
			young = true
		}
		return false, young
	}
	verdict := map[string]bool{} // by service: validated
	young := map[string]bool{}   // by service: runs there, not soaked yet
	for _, c := range ctrs[st.CIID] {
		if !c.Drift || c.LatestDigest == "" || c.ComposeService == "" {
			continue
		}
		ok, y := validated(c.LatestDigest)
		if prev, seen := verdict[c.ComposeService]; seen {
			ok = ok && prev // replicas: every one's image must be validated
		}
		verdict[c.ComposeService], young[c.ComposeService] = ok, young[c.ComposeService] || y
	}
	soaking := 0
	for svc, ok := range verdict {
		if ok {
			p.Services = append(p.Services, svc)
			continue
		}
		p.Deferred++
		if young[svc] {
			soaking++
		}
	}
	slices.Sort(p.Services)
	switch {
	case len(p.Services) == 0 && soaking > 0:
		p.Job, p.Note = false, fmt.Sprintf("its newer images run on %s but haven't soaked for %s yet", p.Validator, soak)
	case len(p.Services) == 0:
		p.Job, p.Note = false, "none of its newer images runs on "+p.Validator+" yet"
	case p.Deferred > 0:
		p.Note = fmt.Sprintf("validated on %s; %s wait for a later cycle", p.Validator, plural(p.Deferred, "service"))
	default:
		p.Note = "validated on " + p.Validator
	}
}

// earlier lists the present copies of a stack's app at the nearest stage
// before it, those of the same visibility when there are any.
func earlier(st store.Stack, all []store.Stack) []store.Stack {
	meta, ok := stackname.Parse(st.Project)
	stage := stackname.Stage(meta.Environment)
	if !ok || stage <= 0 {
		return nil
	}
	var out []store.Stack
	best := -1
	for _, o := range all {
		om, ok := stackname.Parse(o.Project)
		at := stackname.Stage(om.Environment)
		if !ok || o.CIID == st.CIID || !o.Present || !stackname.SameApp(meta, om) || at < 0 || at >= stage || at < best {
			continue
		}
		if at > best {
			best, out = at, nil
		}
		out = append(out, o)
	}
	if slices.ContainsFunc(out, func(o store.Stack) bool { return o.Visibility == st.Visibility }) {
		out = slices.DeleteFunc(out, func(o store.Stack) bool { return o.Visibility != st.Visibility })
	}
	return out
}

package change

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// GroupIndex reads every stack's update groups (internal/updategroup), with
// the hosts by ID.
func (m *Manager) GroupIndex(ctx context.Context) (*updategroup.Index, map[string]store.Host, error) {
	hosts, err := m.St.ListHosts(ctx)
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]store.Host{}
	ids := make([]string, len(hosts))
	for i, h := range hosts {
		byID[h.ID], ids[i] = h, h.ID
	}
	stacks, err := m.St.ListStacks(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	rows, err := m.St.ListContainers(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	return updategroup.New(stacks, rows), byID, nil
}

// MemberBlock says why Baseline can't run act on a member's stack, or "":
// the checks every compose.update path makes of a stack.
func MemberBlock(act string, st store.Stack, h store.Host) string {
	if ok, why := st.Updatable(); !ok {
		return "Baseline can't update it: " + why
	}
	switch {
	case h.ID == "":
		return "its host is gone"
	case h.Revoked:
		return "its host is revoked"
	case st.Pinned:
		return "its stack is pinned"
	}
	if ok, why := h.Policy.Allows(act); !ok {
		return why
	}
	if ok, why := action.MustGet(act).Supported(h.Capabilities); !ok {
		return "its host " + why
	}
	return ""
}

// OpenChange reports whether a change on the stack is still open.
func (m *Manager) OpenChange(ctx context.Context, stackCI string) (bool, error) {
	open, err := m.St.ListChanges(ctx, store.ChangeFilter{CIID: stackCI, Limit: 10})
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(open, func(c store.Change) bool { return c.Open() }), nil
}

// GroupedSteps are the plan steps of an update of targets with their update
// groups (updategroup.Index.Plan): act on each step's stack, with params
// from the model the stack's updates run under, or modelParams. It returns
// the affected stacks too.
func (m *Manager) GroupedSteps(ctx context.Context, ix *updategroup.Index, act string, modelParams []byte,
	targets []updategroup.Target, check updategroup.Check) ([]store.PlanStep, []string, []updategroup.Held, error) {
	planned, held := ix.Plan(targets, check)
	models := map[string][]byte{}
	var steps []store.PlanStep
	var cis []string
	for _, p := range planned {
		params := modelParams
		if p.Group != "" && p.Stack.ModelID != "" && modelParams != nil {
			// A member pulled in from another stack updates as its own
			// stack's model says (its health timeout).
			if _, ok := models[p.Stack.ModelID]; !ok {
				mod, err := m.St.GetChangeModel(ctx, p.Stack.ModelID)
				if err != nil {
					return nil, nil, nil, err
				}
				models[p.Stack.ModelID] = mod.Params
			}
			params = models[p.Stack.ModelID]
		}
		raw, err := StackParams(act, params, p.Stack, p.Services)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s on %s: %w", p.Stack.Project, p.Stack.Hostname, err)
		}
		steps = append(steps, store.PlanStep{Action: act, Params: raw, Summary: action.Describe(act, raw),
			HostIDs: []string{p.Stack.HostID}, UpdateGroup: p.Group, UpdateOrder: p.Order})
		if !slices.Contains(cis, p.Stack.CIID) {
			cis = append(cis, p.Stack.CIID)
		}
	}
	return steps, cis, held, nil
}

// lowestAsked is the lowest order of the members among the targets' own
// services; -1 when none is a member.
func lowestAsked(ix *updategroup.Index, targets []updategroup.Target) map[string]int {
	out := map[string]int{}
	for _, t := range targets {
		svcs := t.Services
		if len(svcs) == 0 {
			svcs = ix.Services(t.Stack.CIID)
		}
		for _, s := range svcs {
			if mem, ok := ix.Of(t.Stack.CIID, s); ok {
				if o, seen := out[mem.Group]; !seen || mem.Order < o {
					out[mem.Group] = mem.Order
				}
			}
		}
	}
	return out
}

// scheduledCheck is the check of members for the scheduler's Standard
// changes (auto-update, patch groups). A member of a stack that isn't a
// target (others) may come along only after what was asked for, never
// ahead of it, and only when its stack's updates run under an approved
// change model, so that nothing is pre-approved that an approver didn't
// set up. why says what keeps such a member from leading.
func (m *Manager) scheduledCheck(ctx context.Context, ix *updategroup.Index, hosts map[string]store.Host,
	targets []updategroup.Target, act, notTarget string, now time.Time) updategroup.Check {
	isTarget := map[string]bool{}
	for _, t := range targets {
		isTarget[t.Stack.CIID] = true
	}
	lowest := lowestAsked(ix, targets)
	return func(mem updategroup.Member, wanted bool) string {
		open, err := m.OpenChange(ctx, mem.Stack.CIID)
		switch {
		case err != nil:
			return "its changes can't be read: " + err.Error()
		case open && !isTarget[mem.Stack.CIID]:
			return "another change on it is still open"
		case !wanted:
			return ""
		}
		if why := MemberBlock(act, mem.Stack, hosts[mem.Stack.HostID]); why != "" {
			return why
		}
		if isTarget[mem.Stack.CIID] {
			return ""
		}
		if o, ok := lowest[mem.Group]; !ok || mem.Order <= o {
			return notTarget
		}
		if mem.Stack.ModelState != store.ModelApproved {
			return "its stack's updates don't run under an approved change model; an approver sets one on its page"
		}
		return ""
	}
}

// groupNote sums up a plan's update groups for a change's description.
func groupNote(steps []store.PlanStep, held []updategroup.Held) string {
	var groups []string
	for _, s := range steps {
		if s.UpdateGroup != "" && !slices.Contains(groups, s.UpdateGroup) {
			groups = append(groups, s.UpdateGroup)
		}
	}
	var b strings.Builder
	if len(groups) > 0 {
		fmt.Fprintf(&b, "Update groups %s: their members update in order, each after the ones before it succeeded.",
			joinNames(groups))
	}
	if len(held) > 0 {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString("Left out: " + updategroup.Describe(held) + ".")
	}
	return b.String()
}

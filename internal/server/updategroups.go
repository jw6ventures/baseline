package server

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// withGroups turns the compose.update steps of a change made by hand, one
// per stack, into steps that update the stacks' update groups with them
// (docs/change-management.md §5.4): their members, in order, each after
// the ones before it succeeded. Members of other stacks come along, ahead
// of what was asked for when they come first in the group; the requester
// must be able to change them. With a model (a Standard change), they also
// need their own stack's updates to run under an approved model. It
// returns the steps, the affected stacks and their names.
func (s *Server) withGroups(ctx context.Context, g rbac.Grants, hosts map[string]store.Host, model *store.ChangeModel,
	stacks []store.Stack, steps []store.PlanStep) ([]store.PlanStep, []string, []string, error) {
	ix, all, err := s.changes.GroupIndex(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	var targets []updategroup.Target
	base := map[string]action.ComposeParams{} // by stack CI
	for i, st := range stacks {
		var p action.ComposeParams
		if err := json.Unmarshal(steps[i].Params, &p); err != nil {
			return nil, nil, nil, err
		}
		base[st.CIID] = p
		targets = append(targets, updategroup.Target{Stack: st, Services: p.Services})
	}
	isTarget := func(ci string) bool { _, ok := base[ci]; return ok }
	check := func(m updategroup.Member, wanted bool) string {
		if isTarget(m.Stack.CIID) {
			return ""
		}
		open, err := s.changes.OpenChange(ctx, m.Stack.CIID)
		switch {
		case err != nil:
			return "its changes can't be read"
		case open:
			return "another change on it is still open"
		case !wanted:
			return ""
		}
		h, ok := hosts[m.Stack.HostID]
		if !ok || !g.HasOn(rbac.Operator, h.GroupIDs) {
			return "changing it needs the operator role on its host"
		}
		if why := change.MemberBlock(action.ComposeUpdate, m.Stack, all[m.Stack.HostID]); why != "" {
			return why
		}
		if model != nil && m.Stack.ModelState != store.ModelApproved {
			return "its stack's updates don't run under an approved change model, so it can't be in a Standard change"
		}
		return ""
	}
	planned, held := ix.Plan(targets, check)
	if len(held) > 0 {
		return nil, nil, nil, errors.New("update groups hold back part of this update: " + updategroup.Describe(held) +
			". Pick the stack's other services to update just those")
	}
	var out []store.PlanStep
	var cis, objects []string
	template := base[stacks[0].CIID]
	for _, p := range planned {
		params, ok := base[p.Stack.CIID]
		if !ok {
			params = template
			if model != nil {
				if params, err = stackModelParams(ctx, s.store, p.Stack); err != nil {
					return nil, nil, nil, err
				}
			}
		}
		params.Engine, params.Project, params.Services = p.Stack.Engine, p.Stack.Project, p.Services
		raw, _ := json.Marshal(params)
		norm, err := action.Validate(action.ComposeUpdate, raw)
		if err != nil {
			return nil, nil, nil, errors.New(p.Stack.Project + ": " + err.Error())
		}
		out = append(out, store.PlanStep{Action: action.ComposeUpdate, Params: norm,
			Summary: action.Describe(action.ComposeUpdate, norm), HostIDs: []string{p.Stack.HostID},
			UpdateGroup: p.Group, UpdateOrder: p.Order})
		if !slices.Contains(cis, p.Stack.CIID) {
			cis, objects = append(cis, p.Stack.CIID), append(objects, p.Stack.Project)
		}
	}
	return out, cis, objects, nil
}

// stackModelParams are the compose.update parameters of the model a
// stack's updates run under.
func stackModelParams(ctx context.Context, st *store.Store, stack store.Stack) (action.ComposeParams, error) {
	var p action.ComposeParams
	m, err := st.GetChangeModel(ctx, stack.ModelID)
	if err != nil {
		return p, err
	}
	if len(m.Params) > 0 {
		err = json.Unmarshal(m.Params, &p)
	}
	return p, err
}

// stepHosts are the hosts of steps, sorted and without repeats.
func stepHosts(steps []store.PlanStep) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.HostIDs...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// withGroups turns the compose.update steps of a change made by hand, one
// per stack, into steps that update the stacks' update groups with them
// (docs/change-management.md §5.3): their members, in order, each after
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
	// A new tag asked for by hand applies to what was named, nothing more;
	// the update group's own page moves a whole group.
	for _, st := range stacks {
		if base[st.CIID].Tag == "" {
			continue
		}
		if !slices.Contains(all[st.HostID].Capabilities, action.CapComposeRetag) {
			return nil, nil, nil, errors.New(st.Hostname + "'s agent can't change tags in Compose files; update it")
		}
	}
	if slices.ContainsFunc(stacks, func(st store.Stack) bool { return base[st.CIID].Tag != "" }) {
		var cis, objects []string
		for _, st := range stacks {
			cis, objects = append(cis, st.CIID), append(objects, st.Project)
		}
		return steps, cis, objects, nil
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

// Pages ---------------------------------------------------------------------

// groupView is an update group as the user may see it.
type groupView struct {
	*updategroup.Group
	Members []updategroup.Member // on hosts the user can see
	Hidden  int                  // members on hosts the user can't see
	Tag     string               // the leaders' tag
	Advice  string               // the newer tag the leaders' semver rule allows
	// Retag: whether the user may ask to move the group to a tag, or why not.
	CanRetag   bool
	RetagBlock string
	CanApprove bool // approver on every member's host
	Changes    []store.Change
}

// Mixed reports whether members run tags other than the leaders'.
func (g groupView) Mixed() bool {
	return slices.ContainsFunc(g.Members, func(m updategroup.Member) bool { return m.Tag() != g.Tag })
}

type groupsView struct {
	Groups []groupView
	Notice string
	Error  string
}

// groupViews are the update groups with members on hosts the user can see.
func (s *Server) groupViews(r *http.Request) ([]groupView, *updategroup.Index, map[string]store.Host, error) {
	ctx := r.Context()
	ix, all, err := s.changes.GroupIndex(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	visible, err := s.visibleHostIDs(r)
	if err != nil {
		return nil, nil, nil, err
	}
	g := principal(r).Grants
	var out []groupView
	for _, grp := range ix.Groups {
		v := groupView{Group: grp, CanRetag: true, CanApprove: true}
		if l := grp.Leaders(); len(l) > 0 {
			v.Tag = l[0].Tag()
		}
		for _, m := range grp.Members {
			if !slices.Contains(visible, m.Stack.HostID) {
				v.Hidden++
				continue
			}
			v.Members = append(v.Members, m)
			h := all[m.Stack.HostID]
			v.CanRetag = v.CanRetag && g.HasOn(rbac.Operator, h.GroupIDs)
			v.CanApprove = v.CanApprove && g.HasOn(rbac.Approver, h.GroupIDs)
		}
		if len(v.Members) == 0 {
			continue
		}
		if v.Hidden > 0 {
			v.CanRetag, v.CanApprove = false, false
			v.RetagBlock = "some of its members are on hosts you can't see"
		} else if !v.CanRetag {
			v.RetagBlock = "moving it to a tag needs the operator role on every member's host"
		}
		if v.Advice, err = s.changes.Advice(ctx, ix, grp); err != nil {
			return nil, nil, nil, err
		}
		out = append(out, v)
	}
	return out, ix, all, nil
}

// updateGroups lists the update groups.
func (s *Server) updateGroups(w http.ResponseWriter, r *http.Request) {
	groups, _, _, err := s.groupViews(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "update_groups", s.data(r, "Update groups", groupsView{Groups: groups}))
}

// updateGroupPage is one update group: its members, and moving it to a tag.
func (s *Server) updateGroupPage(w http.ResponseWriter, r *http.Request) {
	groups, _, _, err := s.groupViews(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	i := slices.IndexFunc(groups, func(g groupView) bool { return g.Key == r.PathValue("key") })
	if i < 0 {
		s.errorPage(w, r, http.StatusNotFound, "No such update group.")
		return
	}
	v := groups[i]
	cis := map[string]bool{}
	for _, m := range v.Members {
		if cis[m.Stack.CIID] {
			continue
		}
		cis[m.Stack.CIID] = true
		cs, err := s.store.ListChanges(r.Context(), store.ChangeFilter{CIID: m.Stack.CIID, Limit: 20})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, c := range cs {
			if strings.HasPrefix(c.Title, "Move update group "+v.Key+" to tag ") &&
				!slices.ContainsFunc(v.Changes, func(x store.Change) bool { return x.ID == c.ID }) {
				v.Changes = append(v.Changes, c)
			}
		}
	}
	q := r.URL.Query()
	s.pages.render(w, http.StatusOK, "update_group", s.data(r, "Update group "+v.Key,
		struct {
			groupView
			Notice, Error, TagInput string
		}{v, q.Get("notice"), q.Get("error"), cmp.Or(q.Get("tag"), v.Advice)}))
}

// updateGroupRetag asks to move every member of an update group to a tag:
// a Normal change, submitted for approval or approved at once by an
// approver of every member's host.
func (s *Server) updateGroupRetag(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := r.PathValue("key")
	back := func(kind, msg, tag string) {
		http.Redirect(w, r, s.url("/update-groups/"+url.PathEscape(key)+"?tag="+urlQueryEscape(tag)+"&"+kind+"="+
			urlQueryEscape(msg)), http.StatusSeeOther)
	}
	groups, ix, all, err := s.groupViews(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	i := slices.IndexFunc(groups, func(g groupView) bool { return g.Key == key })
	if i < 0 {
		s.errorPage(w, r, http.StatusNotFound, "No such update group.")
		return
	}
	v := groups[i]
	tag := strings.TrimSpace(r.FormValue("tag"))
	if !v.CanRetag {
		back("error", "You can't move this group: "+v.RetagBlock+".", tag)
		return
	}
	approve := r.FormValue("submit") == "approve"
	if approve && !v.CanApprove {
		back("error", "Approving needs the approver role on every member's host; submit it for approval instead.", tag)
		return
	}
	grp, _ := ix.Group(key)
	steps, cis, err := s.changes.RetagSteps(ctx, grp, all, tag)
	if err != nil {
		back("error", sentence(err), tag)
		return
	}
	justification := strings.TrimSpace(r.FormValue("justification"))
	if justification == "" {
		justification = "Move every member of update group " + key + " to tag " + tag + ", the leaders first."
	}
	c, err := s.store.CreateChange(ctx, s.actor(r), store.NewChange{
		Kind: store.KindNormal, Title: change.RetagTitle(grp, tag), Justification: justification,
		Description: "Every member moves to tag " + tag + ", lowest order first, each after the ones before it succeeded. " +
			"A member whose update fails is rolled back, with its Compose file.",
		Risk: action.Medium, Concurrency: 1, StopOnFailure: true, Steps: steps, CIs: cis, SelfApprove: approve,
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := c.Ref() + " submitted. It runs once an approver approves it."
	if approve {
		s.nudgeJobs()
		msg = c.Ref() + " approved by you (self-approval, recorded as such). Its jobs are starting."
	}
	s.backToChange(w, r, c.ID, "notice", msg)
}

// stackUpdateGroup puts a service of a stack in an update group, or takes
// it out. Since update groups bring services into Standard changes, it is
// an approver's call on the host, like the stack's change model.
func (s *Server) stackUpdateGroup(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such stack.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, ok := s.hostAccess(w, r, st.HostID, rbac.Approver, "No such stack."); !ok {
		return
	}
	back := func(kind, msg string) {
		http.Redirect(w, r, s.url("/stacks/"+st.CIID+"?"+kind+"="+urlQueryEscape(msg)+"#update-groups"), http.StatusSeeOther)
	}
	service := r.FormValue("service")
	ix, _, err := s.changes.GroupIndex(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !slices.Contains(ix.Services(st.CIID), service) {
		back("error", "The stack has no service "+service+".")
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("group")))
	if name == "" {
		if err := s.store.SetStackUpdateGroup(r.Context(), s.actor(r), st.CIID, service, nil); err != nil {
			s.serverError(w, r, err)
			return
		}
		back("notice", service+" is in no update group now.")
		return
	}
	order, err := strconv.Atoi(cmp.Or(strings.TrimSpace(r.FormValue("order")), strconv.Itoa(updategroup.DefaultOrder)))
	if err == nil {
		err = updategroup.CheckOrder(order)
	}
	if err == nil {
		err = updategroup.CheckName(name)
	}
	if err != nil {
		back("error", sentence(err))
		return
	}
	if err := s.store.SetStackUpdateGroup(r.Context(), s.actor(r), st.CIID, service,
		&store.UpdateGroup{Group: name, Order: order}); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := fmt.Sprintf("%s is in update group %s, order %d.", service, name, order)
	if m, ok := ix.Of(st.CIID, service); ok && m.Label {
		msg += " Its containers' labels put it in " + m.Name + ", and labels win."
	}
	back("notice", msg)
}

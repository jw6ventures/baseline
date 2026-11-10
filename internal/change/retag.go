package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/updategroup"
)

// RetagSteps move every member of an update group to tag, in order: the
// leaders first, each member after the ones before it succeeded
// (docs/change-management.md §5.3). The members' images differ, but they
// share their tag. Every member must be able to take it now; otherwise
// it says which can't, and why.
func (m *Manager) RetagSteps(ctx context.Context, g *updategroup.Group, hosts map[string]store.Host,
	tag string) ([]store.PlanStep, []string, error) {
	if err := action.CheckTag(tag); err != nil {
		return nil, nil, err
	}
	var problems []string
	for _, mem := range g.Members {
		why := MemberBlock(action.ComposeUpdate, mem.Stack, hosts[mem.Stack.HostID])
		if why == "" {
			if ok, w := action.MustGet(action.ComposeUpdate).Supported(hosts[mem.Stack.HostID].Capabilities); ok &&
				!slices.Contains(hosts[mem.Stack.HostID].Capabilities, action.CapComposeRetag) {
				why = "its agent can't change tags in Compose files; update it"
			} else if !ok {
				why = "its host " + w
			}
		}
		if why == "" {
			open, err := m.OpenChange(ctx, mem.Stack.CIID)
			if err != nil {
				return nil, nil, err
			}
			if open {
				why = "another change on its stack is still open"
			}
		}
		if why != "" {
			problems = append(problems, mem.Where()+": "+why)
		}
	}
	if len(problems) > 0 {
		return nil, nil, errors.New("every member moves to the new tag, but " + strings.Join(problems, "; "))
	}
	type key struct {
		stack string
		order int
	}
	var keys []key
	services := map[key][]string{}
	stacks := map[string]store.Stack{}
	for _, mem := range g.Members {
		k := key{mem.Stack.CIID, mem.Order}
		if _, ok := services[k]; !ok {
			keys = append(keys, k)
		}
		services[k] = append(services[k], mem.Service)
		stacks[mem.Stack.CIID] = mem.Stack
	}
	var steps []store.PlanStep
	var cis []string
	for _, k := range keys {
		st := stacks[k.stack]
		p := action.ComposeParams{Engine: st.Engine, Project: st.Project, Services: services[k], Tag: tag}
		if st.ModelID != "" {
			// Its health timeout, as its updates have it.
			if mod, err := m.St.GetChangeModel(ctx, st.ModelID); err == nil && len(mod.Params) > 0 {
				var mp action.ComposeParams
				if json.Unmarshal(mod.Params, &mp) == nil {
					p.HealthTimeout = mp.HealthTimeout
				}
			}
		}
		raw, _ := json.Marshal(p)
		norm, err := action.Validate(action.ComposeUpdate, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", st.Project, err)
		}
		steps = append(steps, store.PlanStep{Action: action.ComposeUpdate, Params: norm,
			Summary: action.Describe(action.ComposeUpdate, norm), HostIDs: []string{st.HostID},
			UpdateGroup: g.Key, UpdateOrder: k.order})
		if !slices.Contains(cis, st.CIID) {
			cis = append(cis, st.CIID)
		}
	}
	return steps, cis, nil
}

// RetagTitle is the title of a change moving a group to a tag; proposals
// are told apart by it.
func RetagTitle(g *updategroup.Group, tag string) string {
	return fmt.Sprintf("Move update group %s to tag %s", g.Key, tag)
}

// Advice is the newest tag the semver rule of a group's leaders allows them,
// if it is newer than the one they run: the tag the group can move to.
func (m *Manager) Advice(ctx context.Context, ix *updategroup.Index, g *updategroup.Group) (string, error) {
	leaders := g.Leaders()
	rows := make([]store.ContainerRow, len(leaders))
	var stacks []store.Stack
	var repos []string
	for i, l := range leaders {
		rows[i] = l.Row
		stacks = append(stacks, l.Stack)
		if ref, err := registry.ParseRef(l.Row.CheckRef); err == nil {
			repos = append(repos, ref.Repo())
		}
	}
	rules := store.SemverRules(rows, stacks)
	if !slices.ContainsFunc(rules, func(r *registry.Rule) bool { return r != nil }) || len(repos) == 0 {
		return "", nil
	}
	tags, err := m.St.RepositoryTags(ctx, repos)
	if err != nil {
		return "", err
	}
	checks, err := m.St.RepositoryImageChecks(ctx, repos)
	if err != nil {
		return "", err
	}
	for i, row := range rows {
		if rules[i] == nil {
			continue
		}
		ref, err := registry.ParseRef(row.CheckRef)
		if err != nil {
			continue
		}
		if tag, ok := row.Advise(*rules[i], tags[ref.Repo()], checks); ok {
			return tag, nil
		}
	}
	return "", nil
}

// ProposeRetags asks, as Normal changes an approver must approve, to move
// update groups to the newer tag their leaders' semver rules allow, for
// groups whose leaders' stacks update themselves or are in an enabled
// Compose patch group. Each group and tag is proposed once: a rejected or
// cancelled proposal isn't made again. It returns how many it made.
func (m *Manager) ProposeRetags(ctx context.Context, now time.Time) (int, error) {
	ix, hosts, err := m.GroupIndex(ctx)
	if err != nil || len(ix.Groups) == 0 {
		return 0, err
	}
	inGroups := map[string]bool{}
	pgs, err := m.St.ListPatchGroups(ctx)
	if err != nil {
		return 0, err
	}
	for _, pg := range pgs {
		if pg.Enabled {
			for _, id := range pg.Stacks {
				inGroups[id] = true
			}
		}
	}
	n := 0
	for _, g := range ix.Groups {
		leaders := g.Leaders()
		if !slices.ContainsFunc(leaders, func(l updategroup.Member) bool {
			return l.Stack.AutoUpdate || inGroups[l.Stack.CIID]
		}) {
			continue
		}
		tag, err := m.Advice(ctx, ix, g)
		if err != nil {
			return n, err
		}
		if tag == "" {
			continue
		}
		title := RetagTitle(g, tag)
		known, err := m.St.ListChanges(ctx, store.ChangeFilter{CIID: leaders[0].Stack.CIID, Limit: 200})
		if err != nil {
			return n, err
		}
		if slices.ContainsFunc(known, func(c store.Change) bool {
			return c.Title == title || (c.Open() && strings.HasPrefix(c.Title, RetagTitle(g, "")))
		}) {
			continue
		}
		steps, cis, err := m.RetagSteps(ctx, g, hosts, tag)
		if err != nil {
			m.logf(jw6_utils.Debug, "Update group %s can't move to %s yet: %v", g.Key, tag, err)
			continue
		}
		c, err := m.St.CreateChange(ctx, store.System, store.NewChange{
			Kind: store.KindNormal, Title: title,
			Justification: fmt.Sprintf("The semver rule of %s allows tag %s, and its stack updates itself or is in a patch group. "+
				"Moving a tag edits the Compose files, so it waits for an approver.", leaders[0].Where(), tag),
			Description: fmt.Sprintf("Every member of update group %s moves to tag %s, lowest order first, "+
				"each after the ones before it succeeded. A member whose update fails is rolled back, with its Compose file.", g.Key, tag),
			Risk: action.Medium, Concurrency: 1, StopOnFailure: true, Steps: steps, CIs: cis,
		})
		if err != nil {
			m.errorf(ctx, "update group %s: %v", g.Key, err)
			continue
		}
		m.logf(jw6_utils.Info, "Update group %s: %s proposes tag %s", g.Key, c.Ref(), tag)
		n++
	}
	return n, nil
}

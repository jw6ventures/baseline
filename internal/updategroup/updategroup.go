// Package updategroup works out update groups (docs/change-management.md
// §5.4): Compose services, possibly in different stacks and on different
// hosts, that update together and in order, such as an identity server and
// the proxy outposts that must never run ahead of it. A container joins a
// group with the labels baseline.update.group and baseline.update.order, or
// its service is put in one on its stack's page; the labels win. Groups are
// scoped by the environment a stack's name carries, so a Dev and a Prod copy
// of the same group never mix.
package updategroup

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/store"
)

const (
	LabelGroup = "baseline.update.group"
	LabelOrder = "baseline.update.order"
	// DefaultOrder is a member's order when nothing sets one.
	DefaultOrder = 1
	MaxOrder     = 1000
)

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// CheckName says what is wrong with a group's name, or nil.
func CheckName(name string) error {
	if !reName.MatchString(name) {
		return fmt.Errorf("%q isn't a group name: lowercase letters, digits, '.', '_' and '-', up to 63", name)
	}
	return nil
}

// CheckOrder says what is wrong with a member's order, or nil.
func CheckOrder(order int) error {
	if order < 0 || order > MaxOrder {
		return fmt.Errorf("the order must be between 0 and %d", MaxOrder)
	}
	return nil
}

// Member is one Compose service in a group.
type Member struct {
	Group   string // the group's key: its name, with the environment when the stack's name has one
	Name    string // the group's name as set
	Order   int
	Label   bool // set by the containers' labels, not on the stack's page
	Stack   store.Stack
	Service string
	Image   string // the reference its containers run
	Drift   bool   // the registry has a newer image behind its tag
	// Problem says what was wrong with its labels, if anything; the member
	// still counts, with what could be read.
	Problem string
}

func (m Member) key() string { return m.Stack.CIID + "/" + m.Service }

// Where names the member for messages: "server in authentik on host1".
func (m Member) Where() string {
	return m.Service + " in " + m.Stack.Project + " on " + m.Stack.Hostname
}

// Group is an update group and its members, in update order.
type Group struct {
	Key, Name, Environment string
	Members                []Member
}

// Leaders are the members with the lowest order.
func (g Group) Leaders() []Member {
	var out []Member
	for _, m := range g.Members {
		if len(out) > 0 && m.Order != out[0].Order {
			break
		}
		out = append(out, m)
	}
	return out
}

// Index is every group, and what it needs to split stacks around them.
type Index struct {
	Groups    []*Group
	byKey     map[string]*Group
	byService map[string]*Member // stack CI/service
	services  map[string][]string
	stacks    map[string]store.Stack
}

// Key is a group's key: its name, scoped by the environment.
func Key(env, name string) string {
	if env == "" {
		return name
	}
	return strings.ToLower(env) + ":" + name
}

// New reads the groups from the stacks' settings and their containers'
// labels. Stacks that aren't present are left out.
func New(stacks []store.Stack, rows []store.ContainerRow) *Index {
	ix := &Index{byKey: map[string]*Group{}, byService: map[string]*Member{}, services: map[string][]string{},
		stacks: map[string]store.Stack{}}
	for _, st := range stacks {
		if st.Present {
			ix.stacks[st.CIID] = st
		}
	}
	add := func(m Member) {
		ix.byService[m.key()] = &m
	}
	for _, c := range rows {
		st, ok := ix.stacks[c.StackCI]
		if !ok || c.ComposeService == "" {
			continue
		}
		if !slices.Contains(ix.services[st.CIID], c.ComposeService) {
			ix.services[st.CIID] = append(ix.services[st.CIID], c.ComposeService)
		}
		k := st.CIID + "/" + c.ComposeService
		if m, ok := ix.byService[k]; ok {
			m.Drift = m.Drift || (c.Drift && !c.Pinned)
			continue
		}
		m := Member{Stack: st, Service: c.ComposeService, Image: c.Image, Drift: c.Drift && !c.Pinned, Order: DefaultOrder}
		if name := strings.TrimSpace(c.Labels[LabelGroup]); name != "" {
			m.Name, m.Label = name, true
			if err := CheckName(name); err != nil {
				m.Problem, m.Name = err.Error(), strings.ToLower(name)
			}
			if v, ok := c.Labels[LabelOrder]; ok {
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err == nil {
					err = CheckOrder(n)
				}
				if err != nil {
					m.Problem = fmt.Sprintf("%s=%q: %v", LabelOrder, v, err)
				} else {
					m.Order = n
				}
			}
		} else if g, ok := st.UpdateGroups[c.ComposeService]; ok && g.Group != "" {
			m.Name, m.Order = g.Group, g.Order
		} else {
			// Not a member, but known: it may join later in this pass.
			m.Name = ""
		}
		add(m)
	}
	for k, m := range ix.byService {
		if m.Name == "" {
			delete(ix.byService, k)
			continue
		}
		m.Group = Key(m.Stack.Environment, m.Name)
		g, ok := ix.byKey[m.Group]
		if !ok {
			g = &Group{Key: m.Group, Name: m.Name, Environment: m.Stack.Environment}
			ix.byKey[m.Group] = g
			ix.Groups = append(ix.Groups, g)
		}
		g.Members = append(g.Members, *m)
	}
	for _, g := range ix.Groups {
		slices.SortFunc(g.Members, memberOrder)
	}
	slices.SortFunc(ix.Groups, func(a, b *Group) int { return cmp.Compare(a.Key, b.Key) })
	for _, s := range ix.services {
		slices.Sort(s)
	}
	return ix
}

func memberOrder(a, b Member) int {
	return cmp.Or(cmp.Compare(a.Order, b.Order), cmp.Compare(strings.ToLower(a.Stack.Hostname), strings.ToLower(b.Stack.Hostname)),
		cmp.Compare(a.Stack.Project, b.Stack.Project), cmp.Compare(a.Service, b.Service))
}

// Group returns a group by key.
func (ix *Index) Group(key string) (*Group, bool) {
	g, ok := ix.byKey[key]
	return g, ok
}

// Of returns the member a stack's service is, if it is one.
func (ix *Index) Of(stackCI, service string) (Member, bool) {
	m, ok := ix.byService[stackCI+"/"+service]
	if !ok {
		return Member{}, false
	}
	return *m, true
}

// Services are the services of a stack that have containers.
func (ix *Index) Services(stackCI string) []string { return ix.services[stackCI] }

// Target is what an update asks for: a stack, and its services (none: all
// of them).
type Target struct {
	Stack    store.Stack
	Services []string
}

// Step is one update in a plan: services of a stack, part of an update
// group when Group is set.
type Step struct {
	Stack    store.Stack
	Services []string // none: the whole stack
	Group    string
	Order    int
}

// Held is a member that a plan leaves out, and why.
type Held struct {
	Member Member
	Why    string
}

// Check says why a member can't be updated now, or "". wanted is false
// for a member the plan wouldn't update (current, and not asked for): it
// still holds back the members after it while, say, another change is
// updating it.
type Check func(m Member, wanted bool) string

// Plan turns targets into steps. Services that belong to an update group
// come out of their stack's step and update with their group: every member
// asked for, or with a newer image, in order, lowest first. A member that
// can't be updated (check) holds back the members after it; members of the
// same order don't hold each other back. Steps not in a group come first,
// in the targets' order; then each group's, by order.
func (ix *Index) Plan(targets []Target, check Check) ([]Step, []Held) {
	var steps []Step
	var touched []string
	asked := map[string]bool{}
	for _, t := range targets {
		svcs := t.Services
		if len(svcs) == 0 {
			svcs = ix.services[t.Stack.CIID]
		}
		var rest []string
		grouped := false
		for _, s := range svcs {
			if m, ok := ix.byService[t.Stack.CIID+"/"+s]; ok {
				grouped = true
				asked[m.key()] = true
				if !slices.Contains(touched, m.Group) {
					touched = append(touched, m.Group)
				}
				continue
			}
			rest = append(rest, s)
		}
		switch {
		case !grouped:
			steps = append(steps, Step{Stack: t.Stack, Services: t.Services})
		case len(rest) > 0:
			steps = append(steps, Step{Stack: t.Stack, Services: rest})
		}
	}
	var held []Held
	for _, key := range touched {
		g := ix.byKey[key]
		var blocker *Member
		var blockedBy string
		var groupSteps []Step
		for i, m := range g.Members {
			if !asked[m.key()] && !m.Drift {
				// Current, and nobody asked for it.
				if why := check(m, false); blocker == nil && why != "" {
					blocker, blockedBy = &g.Members[i], why
				}
				continue
			}
			if blocker != nil && blocker.Order < m.Order {
				held = append(held, Held{Member: m, Why: "it waits for " + blocker.Where() + " (" + blockedBy + ")"})
				continue
			}
			if why := check(m, true); why != "" {
				held = append(held, Held{Member: m, Why: why})
				if blocker == nil {
					blocker, blockedBy = &g.Members[i], why
				}
				continue
			}
			j := slices.IndexFunc(groupSteps, func(s Step) bool { return s.Stack.CIID == m.Stack.CIID && s.Order == m.Order })
			if j < 0 {
				groupSteps = append(groupSteps, Step{Stack: m.Stack, Group: key, Order: m.Order})
				j = len(groupSteps) - 1
			}
			groupSteps[j].Services = append(groupSteps[j].Services, m.Service)
		}
		steps = append(steps, groupSteps...)
	}
	return steps, held
}

// Grouped reports whether any step is part of an update group.
func Grouped(steps []Step) bool {
	return slices.ContainsFunc(steps, func(s Step) bool { return s.Group != "" })
}

// Describe lists held members for a message.
func Describe(held []Held) string {
	var out []string
	for _, h := range held {
		out = append(out, h.Member.Where()+": "+h.Why)
	}
	return strings.Join(out, "; ")
}

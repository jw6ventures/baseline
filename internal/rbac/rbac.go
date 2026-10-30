// Package rbac turns a user's IdP groups and the configured role bindings into
// what that user may do. See docs/change-management.md §7.
package rbac

import (
	"fmt"
	"slices"
)

type Role string

const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Approver Role = "approver"
	Admin    Role = "admin"
)

// Roles lists every role, lowest first.
var Roles = []Role{Viewer, Operator, Approver, Admin}

func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !slices.Contains(Roles, r) {
		return "", fmt.Errorf("unknown role %q", s)
	}
	return r, nil
}

// implies reports whether holding role have also grants role want. Operator
// and approver each include viewer; admin includes everything.
func implies(have, want Role) bool {
	switch {
	case have == want, have == Admin:
		return true
	case want == Viewer:
		return have == Operator || have == Approver
	}
	return false
}

// Binding maps an IdP group to a role, globally (ScopeGroupID empty) or on one
// host group. Admin bindings are always global.
type Binding struct {
	IdPGroup     string
	Role         Role
	ScopeGroupID string
}

// Grants is the effective permission set of one user.
type Grants struct {
	global map[Role]bool
	scoped map[string]map[Role]bool // host group ID -> roles
}

// Resolve computes the grants for a user in the given IdP groups.
// bootstrapAdminGroup, when non-empty, is an IdP group that is always admin.
func Resolve(groups []string, bindings []Binding, bootstrapAdminGroup string) Grants {
	g := Grants{global: map[Role]bool{}, scoped: map[string]map[Role]bool{}}
	if bootstrapAdminGroup != "" && slices.Contains(groups, bootstrapAdminGroup) {
		g.global[Admin] = true
	}
	for _, b := range bindings {
		if !slices.Contains(groups, b.IdPGroup) {
			continue
		}
		if b.ScopeGroupID == "" || b.Role == Admin {
			g.global[b.Role] = true
			continue
		}
		if g.scoped[b.ScopeGroupID] == nil {
			g.scoped[b.ScopeGroupID] = map[Role]bool{}
		}
		g.scoped[b.ScopeGroupID][b.Role] = true
	}
	return g
}

// Has reports whether the user holds want globally.
func (g Grants) Has(want Role) bool {
	for have := range g.global {
		if implies(have, want) {
			return true
		}
	}
	return false
}

// HasOn reports whether the user holds want on a host that belongs to the
// given host groups: a global grant, or a grant scoped to any of them.
func (g Grants) HasOn(want Role, hostGroupIDs []string) bool {
	if g.Has(want) {
		return true
	}
	for _, id := range hostGroupIDs {
		for have := range g.scoped[id] {
			if implies(have, want) {
				return true
			}
		}
	}
	return false
}

// HasAnywhere reports whether the user holds want globally or on at least one
// host group. It decides whether to show a page at all; per-object checks
// still use HasOn.
func (g Grants) HasAnywhere(want Role) bool {
	if g.Has(want) {
		return true
	}
	for _, roles := range g.scoped {
		for have := range roles {
			if implies(have, want) {
				return true
			}
		}
	}
	return false
}

// Empty reports whether the user has no access at all.
func (g Grants) Empty() bool { return len(g.global) == 0 && len(g.scoped) == 0 }

// Global returns the user's global roles, lowest first, for display.
func (g Grants) Global() []Role {
	var out []Role
	for _, r := range Roles {
		if g.global[r] {
			out = append(out, r)
		}
	}
	return out
}

// Scoped returns the user's host-group-scoped roles, for display.
func (g Grants) Scoped() map[string][]Role {
	out := map[string][]Role{}
	for id, roles := range g.scoped {
		for _, r := range Roles {
			if roles[r] {
				out[id] = append(out[id], r)
			}
		}
	}
	return out
}

// Restrict returns the grants limited to the given roles, for an API token
// that may use a subset of its user's roles. A role the user holds only by
// implication is kept when it is allowed: an admin's token restricted to
// viewer is a global viewer.
func (g Grants) Restrict(allowed []Role) Grants {
	out := Grants{global: map[Role]bool{}, scoped: map[string]map[Role]bool{}}
	keep := func(dst map[Role]bool, have Role) {
		for _, want := range allowed {
			if implies(have, want) {
				dst[want] = true
			}
		}
	}
	for have := range g.global {
		keep(out.global, have)
	}
	for id, roles := range g.scoped {
		dst := map[Role]bool{}
		for have := range roles {
			keep(dst, have)
		}
		if len(dst) > 0 {
			out.scoped[id] = dst
		}
	}
	return out
}

// Roles lists every role the user holds anywhere, lowest first, implied
// ones included: what a token of theirs may be restricted to.
func (g Grants) Roles() []Role {
	var out []Role
	for _, r := range Roles {
		if g.HasAnywhere(r) {
			out = append(out, r)
		}
	}
	return out
}

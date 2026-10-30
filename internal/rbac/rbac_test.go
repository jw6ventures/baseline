package rbac

import (
	"slices"
	"testing"
)

func TestRoleImplication(t *testing.T) {
	cases := []struct {
		have, want Role
		ok         bool
	}{
		{Viewer, Viewer, true},
		{Viewer, Operator, false},
		{Operator, Viewer, true},
		{Operator, Approver, false},
		{Approver, Viewer, true},
		{Approver, Operator, false},
		{Admin, Viewer, true},
		{Admin, Operator, true},
		{Admin, Approver, true},
	}
	for _, c := range cases {
		g := Resolve([]string{"g"}, []Binding{{IdPGroup: "g", Role: c.have}}, "")
		if got := g.Has(c.want); got != c.ok {
			t.Errorf("%s has %s = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

func TestScopedBinding(t *testing.T) {
	bindings := []Binding{
		{IdPGroup: "lab-users", Role: Viewer},
		{IdPGroup: "lab-media-ops", Role: Operator, ScopeGroupID: "media"},
	}
	g := Resolve([]string{"lab-users", "lab-media-ops"}, bindings, "")

	if g.Has(Operator) {
		t.Error("scoped operator must not be global operator")
	}
	if !g.HasOn(Operator, []string{"web", "media"}) {
		t.Error("operator on a media host")
	}
	if g.HasOn(Operator, []string{"web"}) {
		t.Error("operator on a non-media host")
	}
	if !g.HasOn(Viewer, []string{"web"}) {
		t.Error("global viewer applies everywhere")
	}
	if !g.HasAnywhere(Operator) || g.HasAnywhere(Approver) {
		t.Error("HasAnywhere")
	}
}

func TestAdminIsAlwaysGlobal(t *testing.T) {
	g := Resolve([]string{"x"}, []Binding{{IdPGroup: "x", Role: Admin, ScopeGroupID: "media"}}, "")
	if !g.Has(Admin) || !g.HasOn(Operator, nil) {
		t.Error("an admin binding with a scope must still be global")
	}
}

func TestUnrelatedGroupsGrantNothing(t *testing.T) {
	g := Resolve([]string{"other"}, []Binding{{IdPGroup: "admins", Role: Admin}}, "")
	if !g.Empty() || g.Has(Viewer) {
		t.Error("expected no access")
	}
}

func TestBootstrapAdmin(t *testing.T) {
	g := Resolve([]string{"authentik Admins"}, nil, "authentik Admins")
	if !g.Has(Admin) {
		t.Error("bootstrap group should be admin")
	}
	if g := Resolve([]string{"authentik Admins"}, nil, ""); !g.Empty() {
		t.Error("no bootstrap group configured, no access")
	}
}

func TestGlobalListing(t *testing.T) {
	g := Resolve([]string{"a", "b"}, []Binding{{IdPGroup: "b", Role: Approver}, {IdPGroup: "a", Role: Viewer}}, "")
	if got := g.Global(); !slices.Equal(got, []Role{Viewer, Approver}) {
		t.Errorf("Global() = %v", got)
	}
}

func TestParseRole(t *testing.T) {
	if r, err := ParseRole("operator"); err != nil || r != Operator {
		t.Error(r, err)
	}
	if _, err := ParseRole("root"); err == nil {
		t.Error("want error")
	}
}

func TestRestrict(t *testing.T) {
	g := Resolve([]string{"admins", "media-ops"}, []Binding{
		{IdPGroup: "admins", Role: Admin},
		{IdPGroup: "media-ops", Role: Operator, ScopeGroupID: "media"},
	}, "")
	// An admin's token limited to viewer is a global viewer and nothing more.
	v := g.Restrict([]Role{Viewer})
	if !v.Has(Viewer) || v.Has(Operator) || v.Has(Admin) || v.HasAnywhere(Operator) {
		t.Errorf("viewer-only: %v %v", v.Global(), v.Scoped())
	}
	// Operator keeps viewer by implication; the scoped grant stays scoped.
	o := Resolve([]string{"media-ops"}, []Binding{{IdPGroup: "media-ops", Role: Operator, ScopeGroupID: "media"}}, "").
		Restrict([]Role{Operator})
	if o.Has(Viewer) || !o.HasOn(Operator, []string{"media"}) || !o.HasOn(Viewer, []string{"media"}) {
		t.Errorf("scoped operator: %v %v", o.Global(), o.Scoped())
	}
	// A role the user doesn't hold grants nothing.
	if a := o.Restrict([]Role{Approver}); !a.Empty() {
		t.Errorf("approver from an operator: %v", a.Scoped())
	}
	if got := g.Roles(); !slices.Equal(got, []Role{Viewer, Operator, Approver, Admin}) {
		t.Errorf("Roles() = %v", got)
	}
	if got := o.Roles(); !slices.Equal(got, []Role{Viewer, Operator}) {
		t.Errorf("Roles() = %v", got)
	}
}

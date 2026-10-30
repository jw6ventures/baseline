package server

import (
	"testing"

	"github.com/jw6ventures/baseline/internal/rbac"
)

func navFor(t *testing.T, role rbac.Role, path string) []navGroup {
	t.Helper()
	g := rbac.Resolve([]string{"g"}, []rbac.Binding{{IdPGroup: "g", Role: role}}, "")
	return buildNav(&Principal{Grants: g}, path)
}

func navGroupKeys(groups []navGroup) []string {
	var keys []string
	for _, g := range groups {
		keys = append(keys, g.Key)
	}
	return keys
}

func TestNavGroupsByRole(t *testing.T) {
	admin := navGroupKeys(navFor(t, rbac.Admin, "/"))
	if len(admin) == 0 || admin[len(admin)-1] != "admin" {
		t.Errorf("admin nav groups = %v, want Administration last", admin)
	}
	for _, k := range navGroupKeys(navFor(t, rbac.Operator, "/")) {
		if k == "admin" {
			t.Errorf("operator sees Administration")
		}
	}
}

func TestNavCurrentItem(t *testing.T) {
	cases := []struct{ path, group, label string }{
		{"/", "home", "Dashboard"},
		{"/work", "work", "Work items"},
		{"/hosts/abc", "inventory", "Hosts"},
		{"/change-models", "change", "Change models"},
		{"/settings/enrollment/tokens", "admin", "Enrollment"},
		{"/settings/ticket-types/x/layouts/view", "admin", "Ticket types"},
		{"/settings/field-groups/new", "admin", "Field groups"},
	}
	for _, c := range cases {
		var got []string
		for _, g := range navFor(t, rbac.Admin, c.path) {
			for _, it := range g.Items {
				if it.Current {
					got = append(got, g.Key+"/"+it.Label)
					if !g.Open {
						t.Errorf("%s: group %s holds the current item but is closed", c.path, g.Key)
					}
				}
			}
			if g.Open && g.Key != c.group {
				t.Errorf("%s: group %s is open", c.path, g.Key)
			}
		}
		if want := c.group + "/" + c.label; len(got) != 1 || got[0] != want {
			t.Errorf("%s: current = %v, want [%s]", c.path, got, want)
		}
	}
}

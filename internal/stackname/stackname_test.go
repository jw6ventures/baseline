package stackname

import "testing"

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		want Meta
		ok   bool
	}{
		{"pii-backup", Meta{"Prod", "Infrastructure", "Internal", "backup"}, true},
		{"pie-authentik", Meta{"Prod", "Infrastructure", "External", "authentik"}, true},
		{"pee-jellyfin", Meta{"Prod", "Entertainment", "External", "jellyfin"}, true},
		{"phi-healthrecords", Meta{"Prod", "Health", "Internal", "healthrecords"}, true},
		{"pwe-proxy", Meta{"Prod", "Web", "External", "proxy"}, true},
		{"die-jellyfin", Meta{"Dev", "Infrastructure", "External", "jellyfin"}, true},
		{"sii-app", Meta{"Staging", "Infrastructure", "Internal", "app"}, true},
		{"tee-jellyfin", Meta{"Test", "Entertainment", "External", "jellyfin"}, true},
		{"PWE-Proxy", Meta{"Prod", "Web", "External", "proxy"}, true},
		{"pii-my-app", Meta{"Prod", "Infrastructure", "Internal", "my-app"}, true},

		{"baseline", Meta{}, false},    // no prefix
		{"data-hub", Meta{}, false},    // four letters
		{"pi-rustdesk", Meta{}, false}, // two letters
		{"pii-", Meta{}, false},        // no app
		{"xie-thing", Meta{}, false},   // unknown environment
		{"pxe-thing", Meta{}, false},   // unknown category
		{"piw-thing", Meta{}, false},   // unknown visibility
		{"", Meta{}, false},
	} {
		got, ok := Parse(tc.name)
		if ok != tc.ok || got != tc.want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAttrs(t *testing.T) {
	if a := Attrs("jane"); a != nil {
		t.Errorf("Attrs(jane) = %v, want nil", a)
	}
	a := Attrs("pwe-webhosting")
	if a["environment"] != "Prod" || a["category"] != "Web" || a["visibility"] != "External" || len(a) != 3 {
		t.Errorf("Attrs(pwe-webhosting) = %v", a)
	}
}

func TestStage(t *testing.T) {
	for env, want := range map[string]int{"Dev": 0, "Test": 1, "Staging": 1, "Prod": 2, "": -1, "QA": -1} {
		if got := Stage(env); got != want {
			t.Errorf("Stage(%q) = %d, want %d", env, got, want)
		}
	}
	dev, _ := Parse("dei-jellyfin")
	prod, _ := Parse("pee-jellyfin")
	web, _ := Parse("pwe-jellyfin")
	if !SameApp(dev, prod) || SameApp(prod, web) {
		t.Error("SameApp")
	}
}

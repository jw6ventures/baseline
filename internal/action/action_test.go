package action

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestValidateDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{PkgUpgrade, ``, `{"mode":"all","reboot":"never"}`},
		{PkgUpgrade, `{}`, `{"mode":"all","reboot":"never"}`},
		{PkgUpgrade, `{"mode":"security","reboot":"if_required"}`, `{"mode":"security","reboot":"if_required"}`},
		{PkgUpgrade, `{"mode":"selected","packages":["openssl","flatpak:org.gimp.GIMP"]}`,
			`{"mode":"selected","packages":["openssl","flatpak:org.gimp.GIMP"],"reboot":"never"}`},
		{PkgUpgrade, `{"exclude":["kernel*","linux-image-[0-9]*","?zdata"],"reboot":"always"}`,
			`{"mode":"all","exclude":["kernel*","linux-image-[0-9]*","?zdata"],"reboot":"always"}`},
		{ServiceRestart, `{"unit":"nginx"}`, `{"unit":"nginx.service"}`},
		{ServiceStart, `{"unit":"postgresql@16-main"}`, `{"unit":"postgresql@16-main.service"}`},
		{ServiceStop, `{"unit":"ssh.service"}`, `{"unit":"ssh.service"}`},
		{ServiceRestart, `{"unit":"systemd-fsck@dev-disk-by\\x2duuid.service"}`, `{"unit":"systemd-fsck@dev-disk-by\\x2duuid.service"}`},
		{ContainerRestart, `{"engine":"docker","name":"web-1"}`, `{"engine":"docker","name":"web-1"}`},
		{ContainerRestart, `{"engine":"podman:alice","name":"db"}`, `{"engine":"podman:alice","name":"db"}`},
		{HostReboot, ``, `{"delay_s":10}`},
		{HostReboot, `{"delay_s":5}`, `{"delay_s":5}`},
		{HostReboot, `{"delay_s":3600}`, `{"delay_s":3600}`},
		{ScriptRun, `{"script_id":"s1","name":"cleanup","version":2,"args":{"days":"7"}}`,
			`{"script_id":"s1","name":"cleanup","version":2,"args":{"days":"7"}}`},
		{ScriptRun, `{"script_id":"s1","name":"x","version":1,"timeout_s":14400}`,
			`{"script_id":"s1","name":"x","version":1,"timeout_s":14400}`},
		{PkgUpgrade, `{"mode":"selected","packages":["openssl","rpm-ostree:ghcr.io/ublue-os/bazzite:stable"],` +
			`"versions":{"openssl":"1:3.0.7-28.el9_4","rpm-ostree:ghcr.io/ublue-os/bazzite:stable":"42.20251010"}}`,
			`{"mode":"selected","packages":["openssl","rpm-ostree:ghcr.io/ublue-os/bazzite:stable"],"reboot":"never",` +
				`"versions":{"openssl":"1:3.0.7-28.el9_4","rpm-ostree:ghcr.io/ublue-os/bazzite:stable":"42.20251010"}}`},
		{ComposeUpdate, `{"engine":"docker","project":"media"}`, `{"engine":"docker","project":"media","health_timeout":120}`},
		{ComposeUpdate, `{"engine":"podman:alice","project":"web_1","services":["b","a","b"],"health_timeout":10}`,
			`{"engine":"podman:alice","project":"web_1","services":["a","b"],"health_timeout":10}`},
		{ComposePull, `{"engine":"docker","project":"media","services":[]}`, `{"engine":"docker","project":"media"}`},
	} {
		got, err := Validate(tc.name, []byte(tc.in))
		if err != nil {
			t.Errorf("%s %s: %v", tc.name, tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s %s = %s, want %s", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name, in, err string
	}{
		{PkgUpgrade, `{"mode":"all","force":true}`, "unknown field"},
		{PkgUpgrade, `{"mode":"everything"}`, "mode must be"},
		{PkgUpgrade, `{"reboot":"sometimes"}`, "reboot must be"},
		{PkgUpgrade, `{"mode":"selected"}`, "at least one package"},
		{PkgUpgrade, `{"mode":"all","packages":["openssl"]}`, "only listed in selected mode"},
		{PkgUpgrade, `{"mode":"security","packages":["openssl"]}`, "only listed in selected mode"},
		{PkgUpgrade, `{"mode":"selected","packages":["-oAPT::Get::AllowUnauthenticated=1"]}`, "isn't a package name"},
		{PkgUpgrade, `{"mode":"selected","packages":["--reinstall"]}`, "isn't a package name"},
		{PkgUpgrade, `{"mode":"selected","packages":["open ssl"]}`, "isn't a package name"},
		{PkgUpgrade, `{"mode":"selected","packages":["openssl;reboot"]}`, "isn't a package name"},
		{PkgUpgrade, `{"mode":"selected","packages":[""]}`, "isn't a package name"},
		{PkgUpgrade, `{"exclude":["-x"]}`, "isn't a package name or pattern"},
		{PkgUpgrade, `{"exclude":["kernel["]}`, "isn't a package name or pattern"}, // bad glob
		{PkgUpgrade, `{"exclude":["a b"]}`, "isn't a package name or pattern"},
		{PkgUpgrade, `{"exclude":[""]}`, "isn't a package name or pattern"},
		{PkgUpgrade, `[]`, "parameters"},
		{PkgUpgrade, `{"mode":`, "parameters"},
		{ServiceRestart, `{}`, "isn't a unit name"},
		{ServiceRestart, `{"unit":"-H"}`, "isn't a unit name"},
		{ServiceRestart, `{"unit":"--now"}`, "isn't a unit name"},
		{ServiceRestart, `{"unit":"a b"}`, "isn't a unit name"},
		{ServiceRestart, `{"unit":"x/y"}`, "isn't a unit name"},
		{ServiceRestart, `{"unit":"nginx","now":true}`, "unknown field"},
		{ServiceStop, `{"unit":"docker.socket"}`, "only .service units"},
		{ServiceStart, `{"unit":"multi-user.target"}`, "only .service units"},
		{ServiceStart, `{"unit":"nginx.service.d"}`, "only .service units"},
		{ContainerRestart, `{"engine":"docker"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"lxc","name":"web"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"docker:Bad","name":"web"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"docker","name":"-web"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"docker","name":"_web"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"docker","name":"a/b"}`, "engine and a name"},
		{ContainerRestart, `{"engine":"docker","name":"web","id":"x"}`, "unknown field"},
		{HostReboot, `{"delay_s":4}`, "between 5 seconds and an hour"},
		{HostReboot, `{"delay_s":0}`, "between 5 seconds and an hour"},
		{HostReboot, `{"delay_s":3601}`, "between 5 seconds and an hour"},
		{HostReboot, `{"delay_s":-10}`, "between 5 seconds and an hour"},
		{HostReboot, `{"delay":30}`, "unknown field"},
		{ScriptRun, `{"name":"x","version":1}`, "pick a script version"},
		{ScriptRun, `{"script_id":"s1","version":0}`, "pick a script version"},
		{ScriptRun, `{"script_id":"s1","version":1,"timeout_s":14401}`, "at most 4h0m0s"},
		{ScriptRun, `{"script_id":"s1","version":1,"timeout_s":-1}`, "at most"},
		{ScriptRun, `{"script_id":"s1","version":1,"body":"rm -rf /"}`, "unknown field"},
		{PkgUpgrade, `{"mode":"all","versions":{"openssl":"1"}}`, "only pinned in selected mode"},
		{PkgUpgrade, `{"mode":"selected","packages":["a"],"versions":{"b":"1"}}`, "isn't listed"},
		{PkgUpgrade, `{"mode":"selected","packages":["a"],"versions":{"a":"-1"}}`, "isn't a version"},
		{PkgUpgrade, `{"mode":"selected","packages":["a"],"versions":{"a":"1 2"}}`, "isn't a version"},
		{PkgUpgrade, `{"mode":"selected","packages":["snap:lxd"],"versions":{"snap:lxd":"5"}}`, "can't be pinned"},
		{ComposeUpdate, `{}`, "engine and a project"},
		{ComposeUpdate, `{"engine":"docker","project":"Media"}`, "engine and a project"},
		{ComposeUpdate, `{"engine":"docker","project":"-p"}`, "engine and a project"},
		{ComposeUpdate, `{"engine":"docker","project":"m","services":["-x"]}`, "isn't a service name"},
		{ComposeUpdate, `{"engine":"docker","project":"m","health_timeout":5}`, "health timeout"},
		{ComposeUpdate, `{"engine":"docker","project":"m","file":"/etc/x.yml"}`, "unknown field"},
		{ComposePull, `{"engine":"docker","project":"m","health_timeout":60}`, "compose.update's"},
		{"compose.down", `{}`, "unknown action"},
		{"", `{}`, "unknown action"},
	} {
		_, err := Validate(tc.name, []byte(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s %s: err = %v, want %q", tc.name, tc.in, err, tc.err)
		}
	}
}

// A name that reaches a command line must never start with "-". The regexp
// accepts "manager:" as an optional prefix, but also lets the whole string
// match without it, so "flatpak:--help" validates and the agent splits it
// into manager "flatpak" and name "--help".
func TestValidatePackageNameOptionAfterManager(t *testing.T) {
	for _, pk := range []string{"flatpak:--help", "snap:-x", "apt:--reinstall"} {
		if _, err := Validate(PkgUpgrade, []byte(`{"mode":"selected","packages":["`+pk+`"]}`)); err == nil {
			t.Errorf("%q validated", pk)
		}
	}
}

// Overflowing timeout_s wraps time.Duration into range and validates:
// (60 + 2^55) * 1e9 = 60e9 + 1953125 * 2^64.
func TestValidateScriptTimeoutOverflow(t *testing.T) {
	n := 60 + 1<<55
	if d := time.Duration(n) * time.Second; d != time.Minute {
		t.Fatalf("setup: %d s wraps to %v", n, d)
	}
	raw, _ := json.Marshal(ScriptParams{ScriptID: "s1", Version: 1, Timeout: n})
	if _, err := Validate(ScriptRun, raw); err == nil {
		t.Errorf("timeout_s %d validated", n)
	}
}

func TestValidateTooMany(t *testing.T) {
	var pk []string
	for range 1001 {
		pk = append(pk, "p")
	}
	raw, _ := json.Marshal(UpgradeParams{Mode: ModeSelected, Packages: pk})
	if _, err := Validate(PkgUpgrade, raw); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("1001 packages: %v", err)
	}
	ex := make([]string, 101)
	for i := range ex {
		ex[i] = "k*"
	}
	raw, _ = json.Marshal(UpgradeParams{Exclude: ex})
	if _, err := Validate(PkgUpgrade, raw); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("101 excludes: %v", err)
	}
}

func TestValidateUnitLength(t *testing.T) {
	long := strings.Repeat("a", 255)
	if _, err := Validate(ServiceRestart, []byte(`{"unit":"`+long+`"}`)); err != nil {
		t.Errorf("255 chars: %v", err)
	}
	if _, err := Validate(ServiceRestart, []byte(`{"unit":"`+long+`a"}`)); err == nil {
		t.Error("256 chars validated")
	}
}

func TestTimeout(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		want         time.Duration
	}{
		{PkgUpgrade, `{"mode":"all","reboot":"never"}`, 2 * time.Hour},
		{PkgUpgrade, `{"mode":"all","reboot":"if_required"}`, 2*time.Hour + 20*time.Minute},
		{PkgUpgrade, `{"mode":"all","reboot":"always"}`, 2*time.Hour + 20*time.Minute},
		{PkgUpgrade, `not json`, 2 * time.Hour},
		{ServiceRestart, `{"unit":"nginx.service"}`, 5 * time.Minute},
		{ContainerRestart, `{}`, 5 * time.Minute},
		{HostReboot, `{"delay_s":10}`, 20 * time.Minute},
		{ScriptRun, `{"script_id":"s","version":1}`, DefaultScriptTimeout},
		{ScriptRun, `{"script_id":"s","version":1,"timeout_s":90}`, 90 * time.Second},
		{"nope", `{}`, DefaultScriptTimeout},
	} {
		if got := Timeout(tc.name, []byte(tc.params)); got != tc.want {
			t.Errorf("Timeout(%s, %s) = %v, want %v", tc.name, tc.params, got, tc.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	for _, tc := range []struct {
		name, params, want string
	}{
		{PkgUpgrade, `{"mode":"all","reboot":"never"}`, "Install all updates"},
		{PkgUpgrade, `{"mode":"security","reboot":"if_required"}`, "Install security updates, reboot if required"},
		{PkgUpgrade, `{"mode":"all","exclude":["kernel*","docker-ce"],"reboot":"always"}`,
			"Install all updates except kernel*, docker-ce, then reboot"},
		{PkgUpgrade, `{"mode":"selected","packages":["openssl","curl"],"reboot":"never"}`, "Upgrade openssl, curl"},
		{PkgUpgrade, `{"mode":"selected","packages":["a","b","c"]}`, "Upgrade a, b, c"},
		{PkgUpgrade, `{"mode":"selected","packages":["a","b","c","d"]}`, "Upgrade 4 packages"},
		{ServiceRestart, `{"unit":"nginx.service"}`, "Restart nginx.service"},
		{ServiceStart, `{"unit":"nginx.service"}`, "Start nginx.service"},
		{ServiceStop, `{"unit":"nginx.service"}`, "Stop nginx.service"},
		{ContainerRestart, `{"engine":"docker","name":"web"}`, "Restart container web"},
		{HostReboot, `{"delay_s":10}`, "Reboot"},
		{ScriptRun, `{"script_id":"s","name":"cleanup","version":3}`, "Run script cleanup v3"},
		{ComposeUpdate, `{"engine":"docker","project":"media","services":["plex","sonarr"]}`, "Update stack media (plex, sonarr)"},
		{ComposePull, `{"engine":"docker","project":"media"}`, "Pull images of stack media"},
		{PkgUpgrade, `{"mode":"selected","packages":["openssl"],"versions":{"openssl":"3.0.15-1"}}`, "Upgrade openssl to validated versions"},
		{"nope.action", `{}`, "nope.action"},
	} {
		if got := Describe(tc.name, []byte(tc.params)); got != tc.want {
			t.Errorf("Describe(%s, %s) = %q, want %q", tc.name, tc.params, got, tc.want)
		}
	}
}

func TestSuggestRisk(t *testing.T) {
	for _, tc := range []struct {
		risks   []Risk
		targets int
		want    Risk
	}{
		{nil, 1, Low},
		{nil, 6, Medium},
		{[]Risk{Low}, 5, Low},
		{[]Risk{Low}, 6, Medium},
		{[]Risk{Low, Medium}, 1, Medium},
		{[]Risk{Medium, Low}, 6, High},
		{[]Risk{High}, 1, High},
		{[]Risk{High, Low}, 100, High}, // never past high
		{[]Risk{Medium}, 0, Medium},
	} {
		if got := SuggestRisk(tc.risks, tc.targets); got != tc.want {
			t.Errorf("SuggestRisk(%v, %d) = %s, want %s", tc.risks, tc.targets, got, tc.want)
		}
	}
}

func TestParseRisk(t *testing.T) {
	for _, s := range []string{"low", "medium", "high"} {
		if r, err := ParseRisk(s); err != nil || string(r) != s {
			t.Errorf("ParseRisk(%q) = %q %v", s, r, err)
		}
	}
	for _, s := range []string{"", "High", "critical"} {
		if _, err := ParseRisk(s); err == nil {
			t.Errorf("ParseRisk(%q) accepted", s)
		}
	}
}

func TestAffecting(t *testing.T) {
	for _, tc := range []struct {
		section string
		want    []string
	}{
		{model.SectionPackages, []string{PkgUpgrade, ScriptRun}},
		{model.SectionContainers, []string{ContainerRestart, ComposePull, ComposeUpdate, ComposeStart, ComposeArchive, ComposeMove, ComposeDeploy, ComposeEdit, HostReboot, ScriptRun}},
		{model.SectionPorts, []string{ServiceRestart, ServiceStart, ServiceStop, ContainerRestart, ComposeUpdate, ComposeStart, ComposeArchive, ComposeMove, ComposeDeploy,
			ComposeEdit, HostReboot, ScriptRun}},
		{model.SectionHardware, []string{ScriptRun}},
		{"nope", nil},
	} {
		if got := Affecting(tc.section); !slices.Equal(got, tc.want) {
			t.Errorf("Affecting(%s) = %v, want %v", tc.section, got, tc.want)
		}
	}
}

func TestSpecs(t *testing.T) {
	if !slices.Equal(Names, []string{PkgUpgrade, ServiceRestart, ServiceStart, ServiceStop, ContainerRestart, ComposePull,
		ComposeUpdate, ComposeStart, ComposeArchive, ComposeMove, ComposeDeploy, ComposeEdit, HostReboot, ScriptRun,
		K8sRestart, K8sScale, K8sSetImage, K8sDeletePod, K8sSuspend, K8sResume, K8sTrigger, K8sDeploy, K8sEdit}) {
		t.Errorf("Names = %v", Names)
	}
	for _, n := range Names {
		s, ok := Get(n)
		if !ok || s.Name != n || s.Label == "" || s.Timeout <= 0 || s.Typical <= 0 || s.Typical > s.Timeout ||
			len(s.Sections) == 0 || s.Risk.rank() < 0 {
			t.Errorf("spec %s = %+v", n, s)
		}
		if s.Category != CategoryScript && !slices.Contains(Categories, s.Category) {
			t.Errorf("%s: category %q isn't in Categories", n, s.Category)
		}
	}
	if _, ok := Get("nope"); ok {
		t.Error("Get(nope) found something")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustGet(nope) didn't panic")
		}
	}()
	MustGet("nope")
}

func TestSupported(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []string
		ok   bool
		why  string
	}{
		{PkgUpgrade, []string{"systemd", "dnf"}, true, ""},
		{PkgUpgrade, []string{"flatpak"}, true, ""},
		{PkgUpgrade, []string{"systemd"}, false, "needs apt or dnf or rpm-ostree or flatpak or snap"},
		{PkgUpgrade, nil, false, "needs apt or dnf or rpm-ostree or flatpak or snap"},
		{ServiceRestart, []string{"systemd"}, true, ""},
		{ServiceRestart, []string{"docker"}, false, "needs systemd"},
		{ContainerRestart, []string{"podman"}, true, ""},
		{ContainerRestart, []string{"systemd"}, false, "needs docker or podman"},
		{HostReboot, nil, true, ""},
		{ScriptRun, nil, true, ""},
	} {
		ok, why := MustGet(tc.name).Supported(tc.caps)
		if ok != tc.ok || why != tc.why {
			t.Errorf("%s.Supported(%v) = %v %q, want %v %q", tc.name, tc.caps, ok, why, tc.ok, tc.why)
		}
	}
}

func TestPolicyAllows(t *testing.T) {
	all := Policy{Jobs: true, AllowScripts: true}
	for _, tc := range []struct {
		p    Policy
		name string
		ok   bool
		why  string
	}{
		{Policy{AllowScripts: true}, ServiceRestart, false, "runs no jobs"},
		{Policy{}, "nope", false, "runs no jobs"},
		{all, "nope", false, "unknown action"},
		{all, PkgUpgrade, true, ""},
		{all, HostReboot, true, ""},
		{all, ScriptRun, true, ""},
		{Policy{Jobs: true}, ScriptRun, false, "allow_scripts"},
		{Policy{Jobs: true}, ServiceRestart, true, ""},
		// Scripts aren't an allow_actions category.
		{Policy{Jobs: true, AllowScripts: true, AllowActions: []string{}}, ScriptRun, true, ""},
		{Policy{Jobs: true, AllowScripts: true, AllowActions: []string{}}, ServiceRestart, false, `"service" actions are turned off`},
		{Policy{Jobs: true, AllowActions: []string{CategoryPatch, CategoryService}}, ServiceStop, true, ""},
		{Policy{Jobs: true, AllowActions: []string{CategoryPatch, CategoryService}}, PkgUpgrade, true, ""},
		{Policy{Jobs: true, AllowActions: []string{CategoryPatch, CategoryService}}, HostReboot, false, `"reboot" actions`},
		{Policy{Jobs: true, AllowActions: []string{CategoryPatch}}, ContainerRestart, false, `"container" actions`},
	} {
		ok, why := tc.p.Allows(tc.name)
		if ok != tc.ok || (tc.why == "" && why != "") || !strings.Contains(why, tc.why) {
			t.Errorf("%+v.Allows(%s) = %v %q, want %v %q", tc.p, tc.name, ok, why, tc.ok, tc.why)
		}
	}
	if !all.AllActions() || (Policy{AllowActions: []string{}}).AllActions() {
		t.Error("AllActions")
	}
}

func TestParseAllowActions(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string // nil: all
	}{
		{"all", nil},
		{" * ", nil},
		{"", []string{}},
		{"none", []string{}},
		{"  none  ", []string{}},
		{"patch", []string{"patch"}},
		{"patch, service ,reboot", []string{"patch", "service", "reboot"}},
		{"service,patch,service", []string{"service", "patch"}},
		{"container", []string{"container"}},
		{"patch,compose", []string{"patch", "compose"}},
	} {
		got, err := ParseAllowActions(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if (got == nil) != (tc.want == nil) || !slices.Equal(got, tc.want) {
			t.Errorf("%q = %#v, want %#v", tc.in, got, tc.want)
		}
	}
	for _, in := range []string{"script", "patch,docker", "patch,,service", "ALL", "patch;service"} {
		if _, err := ParseAllowActions(in); err == nil || !strings.Contains(err.Error(), "unknown action category") {
			t.Errorf("%q: err = %v", in, err)
		}
	}
}

// Scripts ---------------------------------------------------------------------

func TestParseScriptParams(t *testing.T) {
	text := `
days int required # keep this many days of logs
  dir string /\/var\/log\/.*/ # e.g. /var/log/nginx

dry_run bool
mode string required /fast|slow/
`
	ps, err := ParseScriptParams(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []ScriptParam{
		{Name: "days", Type: "int", Required: true, Help: "keep this many days of logs"},
		{Name: "dir", Type: "string", Pattern: `\/var\/log\/.*`, Help: "e.g. /var/log/nginx"},
		{Name: "dry_run", Type: "bool"},
		{Name: "mode", Type: "string", Required: true, Pattern: "fast|slow"},
	}
	if !reflect.DeepEqual(ps, want) {
		t.Fatalf("got %+v\nwant %+v", ps, want)
	}
	// Round trip.
	f := FormatScriptParams(ps)
	if f != "days int required # keep this many days of logs\ndir string /\\/var\\/log\\/.*/ # e.g. /var/log/nginx\ndry_run bool\nmode string required /fast|slow/\n" {
		t.Errorf("format = %q", f)
	}
	again, err := ParseScriptParams(f)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Errorf("round trip = %+v %v", again, err)
	}
	if ps, err := ParseScriptParams(" \n\n"); err != nil || len(ps) != 0 {
		t.Errorf("empty = %+v %v", ps, err)
	}
	// The pattern may come after "required" or before it.
	ps, err = ParseScriptParams("x string /a+/ required")
	if err != nil || len(ps) != 1 || !ps[0].Required || ps[0].Pattern != "a+" {
		t.Errorf("pattern before required = %+v %v", ps, err)
	}
}

func TestParseScriptParamsErrors(t *testing.T) {
	for _, tc := range []struct {
		in, err string
	}{
		{"days", "line 1: expected"},
		{"a int\nb", "line 2: expected"},
		{"days int optional", "expected"},
		{"days int required extra", "expected"},
		{"x string /abc", "line 1: a pattern is written /like this/"},
		{"Days int", "names are lowercase"},
		{"1days int", "names are lowercase"},
		{"my-days int", "names are lowercase"},
		{strings.Repeat("a", 33) + " int", "names are lowercase"},
		{"a int\na string", `"a" is declared twice`},
		{"a float", "type must be string, int or bool"},
		{"a string /(/", "bad pattern"},
	} {
		if _, err := ParseScriptParams(tc.in); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%q: err = %v, want %q", tc.in, err, tc.err)
		}
	}
	var many []string
	for i := range 33 {
		many = append(many, fmt.Sprintf("p%d int", i))
	}
	if _, err := ParseScriptParams(strings.Join(many, "\n")); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Errorf("33 params: %v", err)
	}
}

// FormatScriptParams is meant to be ParseScriptParams' inverse, but a "#"
// inside a pattern is taken for the start of the help text.
func TestFormatScriptParamsPatternWithHash(t *testing.T) {
	ps := []ScriptParam{{Name: "color", Type: "string", Pattern: "#[0-9a-f]{6}"}}
	if err := ValidateScriptParams(ps); err != nil {
		t.Fatal(err)
	}
	got, err := ParseScriptParams(FormatScriptParams(ps))
	if err != nil || !reflect.DeepEqual(got, ps) {
		t.Errorf("round trip = %+v %v", got, err)
	}
}

func TestScriptArgs(t *testing.T) {
	ps := []ScriptParam{
		{Name: "days", Type: "int", Required: true},
		{Name: "dir", Type: "string", Pattern: `/var/log/[a-z]+`},
		{Name: "dry_run", Type: "bool"},
		{Name: "level", Type: "string", Pattern: "a|b"},
	}
	for _, tc := range []struct {
		values map[string]string
		args   []string
		err    string
	}{
		{map[string]string{"days": "7"}, []string{"7", "", "", ""}, ""},
		{map[string]string{"days": "-3", "dir": "/var/log/nginx", "dry_run": "1", "level": "b"},
			[]string{"-3", "/var/log/nginx", "true", "b"}, ""},
		{map[string]string{"days": "0", "dry_run": "F"}, []string{"0", "", "false", ""}, ""},
		{map[string]string{"days": "1", "dry_run": "TRUE"}, []string{"1", "", "true", ""}, ""},
		{map[string]string{"days": "1", "dry_run": ""}, []string{"1", "", "", ""}, ""},
		{map[string]string{}, nil, "days is required"},
		{map[string]string{"days": ""}, nil, "days is required"},
		{map[string]string{"days": "7.5"}, nil, "days must be a whole number"},
		{map[string]string{"days": "seven"}, nil, "days must be a whole number"},
		{map[string]string{"days": "99999999999999999999"}, nil, "days must be a whole number"},
		{map[string]string{"days": "1", "dry_run": "yes"}, nil, "dry_run must be true or false"},
		// The pattern is anchored to the whole value.
		{map[string]string{"days": "1", "dir": "/var/log/nginx/../../etc"}, nil, "dir doesn't match"},
		{map[string]string{"days": "1", "dir": "x/var/log/nginx"}, nil, "dir doesn't match"},
		{map[string]string{"days": "1", "level": "ab"}, nil, "level doesn't match /a|b/"},
		{map[string]string{"days": "1", "level": "xa"}, nil, "level doesn't match"},
		{map[string]string{"days": "1", "host": "x"}, nil, `no parameter "host"`},
		{map[string]string{"days": "1", "dir": "/var/log/a\x00b"}, nil, "NUL byte"},
		{map[string]string{"days": "1", "dir": strings.Repeat("a", 4097)}, nil, "too long"},
	} {
		args, env, err := ScriptArgs(ps, tc.values)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: err = %v, want %q", tc.values, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.values, err)
			continue
		}
		if !slices.Equal(args, tc.args) {
			t.Errorf("%q: args = %q, want %q", tc.values, args, tc.args)
		}
		wantEnv := map[string]string{"BASELINE_PARAM_DAYS": tc.args[0], "BASELINE_PARAM_DIR": tc.args[1],
			"BASELINE_PARAM_DRY_RUN": tc.args[2], "BASELINE_PARAM_LEVEL": tc.args[3]}
		for _, k := range slices.Collect(maps.Keys(wantEnv)) { // and the names from before the rename
			wantEnv["JCMDB_"+strings.TrimPrefix(k, "BASELINE_")] = wantEnv[k]
		}
		if !reflect.DeepEqual(env, wantEnv) {
			t.Errorf("%q: env = %q, want %q", tc.values, env, wantEnv)
		}
	}
	// No parameters, no values.
	if args, env, err := ScriptArgs(nil, nil); err != nil || len(args) != 0 || len(env) != 0 {
		t.Errorf("none = %q %q %v", args, env, err)
	}
	// A bool's pattern sees the normalized value.
	bp := []ScriptParam{{Name: "b", Type: "bool", Pattern: "true"}}
	if args, _, err := ScriptArgs(bp, map[string]string{"b": "1"}); err != nil || args[0] != "true" {
		t.Errorf("bool pattern = %q %v", args, err)
	}
}

// `\Q` quotes to the end of the regexp, so wrapped in ^(?:...)$ it would
// swallow the anchors. It is refused when the parameters are saved, and a
// pattern stored before that makes ScriptArgs fail rather than panic (the
// job dispatcher calls it, internal/jobs).
func TestScriptArgsQuotedPattern(t *testing.T) {
	ps := []ScriptParam{{Name: "x", Type: "string", Pattern: `\Qa.b`}}
	if err := ValidateScriptParams(ps); err == nil {
		t.Fatal(`\Q pattern accepted`)
	}
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("ScriptArgs panicked: %v", p)
		}
	}()
	if _, _, err := ScriptArgs(ps, map[string]string{"x": "a.b"}); err == nil {
		t.Error("ScriptArgs accepted a bad pattern")
	}
}

func TestCheckComposeRoot(t *testing.T) {
	for dir, ok := range map[string]bool{
		"/srv/stacks": true, "/opt/compose": true, "/var/lib/baseline/stacks": true, "/home/me/stacks": true, "/usr2": true,
		"": false, "/": false, "srv": false, "/srv/": false, "/srv/../etc": false, "/srv//x": false, "/srv/a\nb": false,
		"/etc": false, "/etc/stacks": false, "/usr/local/stacks": false, "/proc/1": false, "/var/run/x": false, "/boot": false,
	} {
		if err := CheckComposeRoot(dir); (err == nil) != ok {
			t.Errorf("CheckComposeRoot(%q) = %v", dir, err)
		}
	}
	// An edit doesn't move a stack.
	raw := `{"engine":"docker","project":"app","revision":"11111111-2222-4333-8444-555555555555","env":true,"root":"/srv"}`
	if _, err := Validate(ComposeEdit, []byte(raw)); err == nil {
		t.Error("an edit took a root")
	}
}

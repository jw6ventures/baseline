package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
)

// aptSim is `apt-get -s dist-upgrade` on the fake host: docker-ce is held
// (listed anyway, to check the agent leaves it out), the kernel is newly
// pulled in, tzdata and curl aren't security updates.
const aptSim = `Reading package lists...
Building dependency tree...
Calculating upgrade...
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all]) []
Inst curl [8.5.0-2ubuntu10.4] (8.5.0-2ubuntu10.5 Ubuntu:24.04/noble-updates [amd64])
Inst linux-image-6.8.0-86-generic (6.8.0-86.87 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst docker-ce [5:27.0.1-1~ubuntu.24.04~noble] (5:27.3.1-1~ubuntu.24.04~noble Docker:noble-security [amd64])
Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`

// aptHost is a fake Debian host whose package database an apt-get run
// (through the fake Exec) changes.
type aptHost struct {
	mu        sync.Mutex
	env       *collect.Env
	installed map[string]string   // name → version
	cands     map[string]string   // what an upgrade installs
	older     map[string][]string // other versions the repository has
	held      string
	code      int  // apt-get's exit status
	noSim     bool // the simulation fails
	noDpkg    bool // dpkg-query fails
	runs      []string
	cmds      []Cmd
}

func newAptHost(t *testing.T) *aptHost {
	h := &aptHost{
		installed: map[string]string{
			"libssl3t64": "3.0.13-0ubuntu3.4", "openssl": "3.0.13-0ubuntu3.4", "tzdata": "2024a-3ubuntu1.1",
			"curl": "8.5.0-2ubuntu10.4", "docker-ce": "5:27.0.1-1~ubuntu.24.04~noble", "bash": "5.2.21-2ubuntu4",
		},
		cands: map[string]string{
			"libssl3t64": "3.0.13-0ubuntu3.5", "openssl": "3.0.13-0ubuntu3.5", "tzdata": "2025b-0ubuntu0.24.04",
			"curl": "8.5.0-2ubuntu10.5", "linux-image-6.8.0-86-generic": "6.8.0-86.87",
			"docker-ce": "5:27.3.1-1~ubuntu.24.04~noble",
		},
		held: "docker-ce",
	}
	h.env = &collect.Env{
		Root: t.TempDir(),
		Run:  h.run,
		Has: func(name string) bool {
			return name == "dpkg-query" || name == "apt-get" || name == "apt-mark"
		},
	}
	return h
}

func (h *aptHost) file(t *testing.T, path, content string) {
	p := filepath.Join(h.env.Root, path)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *aptHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := strings.Join(append([]string{name}, args...), " ")
	h.runs = append(h.runs, key)
	switch {
	case name == "dpkg-query" && !h.noDpkg:
		var names []string
		for n := range h.installed {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			arch := "amd64"
			if n == "tzdata" {
				arch = "all"
			}
			fmt.Fprintf(&b, "ii \t%s\t%s\t%s\t%s\n", n, h.installed[n], arch, n)
		}
		return []byte(b.String()), nil
	case key == "apt-get update -q -o DPkg::Lock::Timeout=120":
		return nil, nil
	case key == "apt-get -s -q -o Debug::NoLocking=1 dist-upgrade" && !h.noSim:
		return []byte(aptSim), nil
	case key == "apt-mark showhold":
		return []byte(h.held + "\n"), nil
	}
	return nil, errors.New("not stubbed: " + key)
}

// exec is the job's Exec: apt-get upgrades what it names, or everything
// not held for dist-upgrade.
func (h *aptHost) exec(_ context.Context, c Cmd, stdout, _ io.Writer) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cmds = append(h.cmds, c)
	if c.Name != "apt-get" {
		return 127, nil
	}
	fmt.Fprintln(stdout, "Reading package lists...")
	if h.code != 0 {
		return h.code, nil
	}
	var names []string
	if c.Args[len(c.Args)-1] == "dist-upgrade" {
		for n := range h.cands {
			if n != h.held {
				names = append(names, n)
			}
		}
	} else if i := slices.Index(c.Args, "--only-upgrade"); i >= 0 {
		names = c.Args[i+1:]
	}
	for _, n := range names {
		// name=version installs exactly that version, which must be the
		// candidate or another one the repository has.
		if n, v, ok := strings.Cut(n, "="); ok && h.cands[n] != v && !slices.Contains(h.older[n], v) {
			fmt.Fprintf(stdout, "E: Version '%s' for '%s' was not found\n", v, n)
			return 100, nil
		}
	}
	for _, n := range names {
		if n, v, ok := strings.Cut(n, "="); ok {
			h.installed[n] = v
		} else if v, ok := h.cands[n]; ok {
			h.installed[n] = v
		}
	}
	return 0, nil
}

func (h *aptHost) runner(t *testing.T) *Runner {
	r := newRunner(t, nil)
	r.Env, r.Exec = h.env, h.exec
	return r
}

func upgradeResult(t *testing.T, b []byte) action.UpgradeResult {
	t.Helper()
	var res action.UpgradeResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("result %q: %v", b, err)
	}
	return res
}

func names(cs []action.PackageChange) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func TestUpgradeAll(t *testing.T) {
	h := newAptHost(t)
	r := h.runner(t)
	var col collected
	r.Collect = col.collect
	id := jobID(30)
	start(r, id, action.PkgUpgrade, `{}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")

	if len(h.cmds) != 1 {
		t.Fatalf("commands = %v", h.cmds)
	}
	c := h.cmds[0]
	if c.Name != "apt-get" || !slices.Equal(c.Args, []string{"-y", "-q", "-o", "DPkg::Lock::Timeout=600",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "dist-upgrade"}) {
		t.Errorf("command = %v", c)
	}
	if !slices.Contains(c.Env, "DEBIAN_FRONTEND=noninteractive") || !slices.Contains(c.Env, "NEEDRESTART_MODE=l") {
		t.Errorf("env = %q", c.Env)
	}
	u := upgradeResult(t, res.GetResultJson())
	want := []action.PackageChange{
		{Manager: "apt", Name: "curl", Arch: "amd64", From: "8.5.0-2ubuntu10.4", To: "8.5.0-2ubuntu10.5"},
		{Manager: "apt", Name: "libssl3t64", Arch: "amd64", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5"},
		{Manager: "apt", Name: "openssl", Arch: "amd64", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5"},
		{Manager: "apt", Name: "tzdata", Arch: "all", From: "2024a-3ubuntu1.1", To: "2025b-0ubuntu0.24.04"},
	}
	if !reflect.DeepEqual(u.Changed, want) {
		t.Errorf("changed = %+v", u.Changed)
	}
	if len(u.Added) != 1 || u.Added[0].Name != "linux-image-6.8.0-86-generic" || u.Added[0].To != "6.8.0-86.87" ||
		len(u.Removed) != 0 {
		t.Errorf("added %+v removed %+v", u.Added, u.Removed)
	}
	if !slices.Equal(u.Managers, []string{"apt"}) || u.RebootRequired || u.Rebooting || len(u.Warnings) != 0 {
		t.Errorf("result = %+v", u)
	}
	info := outputOf(evs, "info")
	for _, s := range []string{"Refreshing package metadata…\n",
		"$ DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l apt-get -y -q",
		"Packages: 4 upgraded, 1 installed.\n"} {
		if !strings.Contains(info, s) {
			t.Errorf("info lacks %q:\n%s", s, info)
		}
	}
	if outputOf(evs, "stdout") != "Reading package lists...\n" {
		t.Errorf("stdout = %q", outputOf(evs, "stdout"))
	}
	if got := col.get(); len(got) != 1 || got[0] != id+": packages,updates,reboot,os,services" {
		t.Errorf("collect = %q", got)
	}
}

func TestUpgradeModes(t *testing.T) {
	for _, tc := range []struct {
		params  string
		args    []string // after "install --only-upgrade"; nil: nothing runs
		changed []string
		info    string
	}{
		{`{"mode":"security"}`, []string{"libssl3t64", "openssl"}, []string{"libssl3t64", "openssl"}, ""},
		{`{"exclude":["tz*"]}`, []string{"curl", "libssl3t64", "openssl"}, []string{"curl", "libssl3t64", "openssl"}, ""},
		{`{"mode":"security","exclude":["libssl*"]}`, []string{"openssl"}, []string{"openssl"}, ""},
		{`{"mode":"selected","packages":["openssl","apt:tzdata","docker-ce"]}`, []string{"openssl", "tzdata"},
			[]string{"openssl", "tzdata"}, ""},
		{`{"mode":"selected","packages":["curl"],"exclude":["curl"]}`, nil, nil, "apt: nothing to upgrade\n"},
		{`{"exclude":["*"]}`, nil, nil, "apt: nothing to upgrade\n"},
		{`{"mode":"selected","packages":["bash"]}`, nil, nil, "No packages changed.\n"},
		{`{"mode":"selected","packages":["flatpak:org.gimp.GIMP"]}`, nil, nil, "No packages changed.\n"},
	} {
		h := newAptHost(t)
		r := h.runner(t)
		start(r, jobID(31), action.PkgUpgrade, tc.params)
		evs, res := untilResult(t, r, jobID(31))
		checkResult(t, res, "succeeded", 0, "")
		switch {
		case tc.args == nil && len(h.cmds) != 0:
			t.Errorf("%s: ran %v", tc.params, h.cmds)
		case tc.args != nil:
			if len(h.cmds) != 1 {
				t.Errorf("%s: commands %v", tc.params, h.cmds)
				continue
			}
			i := slices.Index(h.cmds[0].Args, "install")
			if i < 0 || h.cmds[0].Args[i+1] != "--only-upgrade" || !slices.Equal(h.cmds[0].Args[i+2:], tc.args) {
				t.Errorf("%s: args %q", tc.params, h.cmds[0].Args)
			}
		}
		u := upgradeResult(t, res.GetResultJson())
		if !slices.Equal(names(u.Changed), tc.changed) || len(u.Added) != 0 {
			t.Errorf("%s: changed %v added %v", tc.params, names(u.Changed), names(u.Added))
		}
		if wantManagers := tc.args != nil; (len(u.Managers) == 1) != wantManagers {
			t.Errorf("%s: managers %v", tc.params, u.Managers)
		}
		if !strings.Contains(outputOf(evs, "info"), tc.info) {
			t.Errorf("%s: info = %q", tc.params, outputOf(evs, "info"))
		}
	}
}

func TestUpgradeRebootIfRequired(t *testing.T) {
	h := newAptHost(t)
	h.file(t, "/var/run/reboot-required", "*** System restart required ***\n")
	r := h.runner(t)
	id := jobID(32)
	start(r, id, action.PkgUpgrade, `{"mode":"security","reboot":"if_required"}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "rebooting", 0, "")
	u := upgradeResult(t, res.GetResultJson())
	if !u.Rebooting || !u.RebootRequired || len(u.RebootReasons) != 1 ||
		!strings.Contains(u.RebootReasons[0], "/var/run/reboot-required") || len(u.Changed) != 2 {
		t.Errorf("result = %+v", u)
	}
	if !strings.Contains(outputOf(evs, "info"), "Rebooting in 10 seconds.\n") {
		t.Errorf("info = %q", outputOf(evs, "info"))
	}
	if rec, _ := r.load(id); rec.State != stateRebooting || string(rec.Result) != string(res.GetResultJson()) {
		t.Errorf("journal = %+v", rec)
	}
	// Don't wait for the reboot (newRunner's Reboot would fail the test).
	r.Cancel(id)
	_, res = untilResult(t, r, id)
	checkResult(t, res, "cancelled", 0, "cancelled before the reboot")
	waitIdle(t, r)
}

func TestUpgradeRebootPolicies(t *testing.T) {
	for _, tc := range []struct {
		params   string
		required bool
		state    string
		info     string
	}{
		{`{"reboot":"if_required"}`, false, "succeeded", ""},
		{`{"reboot":"never"}`, true, "succeeded", "A reboot is required to finish: the system asks for a reboot (/run/reboot-required).\n"},
		{`{"reboot":"always"}`, false, "rebooting", "Rebooting in 10 seconds.\n"},
	} {
		h := newAptHost(t)
		if tc.required {
			h.file(t, "/run/reboot-required", "")
		}
		r := h.runner(t)
		id := jobID(33)
		start(r, id, action.PkgUpgrade, tc.params)
		evs, res := untilResult(t, r, id)
		checkResult(t, res, tc.state, 0, "")
		u := upgradeResult(t, res.GetResultJson())
		if u.RebootRequired != tc.required || u.Rebooting != (tc.state == "rebooting") {
			t.Errorf("%s: result = %+v", tc.params, u)
		}
		if !strings.Contains(outputOf(evs, "info"), tc.info) {
			t.Errorf("%s: info = %q", tc.params, outputOf(evs, "info"))
		}
		r.Cancel(id)
		if tc.state == "rebooting" {
			untilResult(t, r, id)
		}
		waitIdle(t, r)
	}
}

func TestUpgradeFails(t *testing.T) {
	h := newAptHost(t)
	h.code = 100
	r := h.runner(t)
	start(r, jobID(34), action.PkgUpgrade, `{"reboot":"always"}`)
	_, res := untilResult(t, r, jobID(34))
	checkResult(t, res, "failed", 100, "apt exited with status 100")
	u := upgradeResult(t, res.GetResultJson())
	if !slices.Equal(u.Managers, []string{"apt"}) || len(u.Changed) != 0 || u.Rebooting {
		t.Errorf("result = %+v", u)
	}
}

func TestUpgradeCollectFailures(t *testing.T) {
	h := newAptHost(t)
	h.noSim = true
	r := h.runner(t)
	start(r, jobID(35), action.PkgUpgrade, `{}`)
	_, res := untilResult(t, r, jobID(35))
	checkResult(t, res, "failed", -1, "checking for updates: apt:")
	if len(h.cmds) != 0 {
		t.Errorf("ran %v", h.cmds)
	}

	h = newAptHost(t)
	h.noDpkg = true
	r = h.runner(t)
	start(r, jobID(36), action.PkgUpgrade, `{}`)
	_, res = untilResult(t, r, jobID(36))
	checkResult(t, res, "failed", -1, "reading installed packages: apt:")
	if len(h.cmds) != 0 {
		t.Errorf("ran %v", h.cmds)
	}
}

func TestUpgradeCmd(t *testing.T) {
	aptOpts := []string{"-y", "-q", "-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold"}
	ups := func(manager string, nameInstalled ...string) []model.Update {
		var out []model.Update
		for i := 0; i < len(nameInstalled); i += 2 {
			out = append(out, model.Update{Manager: manager, Name: nameInstalled[i], Installed: nameInstalled[i+1]})
		}
		return out
	}
	for _, tc := range []struct {
		m     string
		p     action.UpgradeParams
		cands []model.Update
		name  string
		args  []string
		ok    bool
	}{
		{"apt", action.UpgradeParams{Mode: action.ModeAll}, ups("apt", "openssl", "1"), "apt-get",
			append(slices.Clone(aptOpts), "dist-upgrade"), true},
		{"apt", action.UpgradeParams{Mode: action.ModeSecurity}, ups("apt", "openssl", "1", "linux-image-x", "", "openssl", "1"),
			"apt-get", append(slices.Clone(aptOpts), "install", "--only-upgrade", "openssl"), true},
		{"apt", action.UpgradeParams{Mode: action.ModeSecurity}, ups("apt", "linux-image-x", ""), "", nil, false},
		{"apt", action.UpgradeParams{Mode: action.ModeAll, Exclude: []string{"x"}}, ups("apt", "linux-image-x", ""), "", nil, false},
		{"dnf", action.UpgradeParams{Mode: action.ModeAll}, ups("dnf", "openssl", "1"), "dnf", []string{"-y", "upgrade"}, true},
		{"dnf", action.UpgradeParams{Mode: action.ModeSecurity, Exclude: []string{"kernel*", "podman"}}, ups("dnf", "openssl", "1"),
			"dnf", []string{"-y", "upgrade", "--security", "--exclude=kernel*", "--exclude=podman"}, true},
		{"dnf", action.UpgradeParams{Mode: action.ModeAll, Exclude: []string{"kernel*"}}, ups("dnf", "openssl", "1"),
			"dnf", []string{"-y", "upgrade", "--exclude=kernel*"}, true},
		// dnf names packages it doesn't have yet.
		{"dnf", action.UpgradeParams{Mode: action.ModeSelected}, ups("dnf", "openssl", "1", "kernel-core", ""),
			"dnf", []string{"-y", "upgrade", "openssl", "kernel-core"}, true},
		{"rpm-ostree", action.UpgradeParams{Mode: action.ModeAll}, ups("rpm-ostree", "image", "1"), "rpm-ostree", []string{"upgrade"}, true},
		{"flatpak", action.UpgradeParams{Mode: action.ModeAll}, ups("flatpak", "org.gimp.GIMP", "2.10"),
			"flatpak", []string{"update", "-y", "--noninteractive"}, true},
		{"flatpak", action.UpgradeParams{Mode: action.ModeSelected}, ups("flatpak", "org.gimp.GIMP", "2.10"),
			"flatpak", []string{"update", "-y", "--noninteractive", "org.gimp.GIMP"}, true},
		{"flatpak", action.UpgradeParams{Mode: action.ModeAll, Exclude: []string{"org.kde.*"}}, ups("flatpak", "org.gimp.GIMP", "2.10"),
			"flatpak", []string{"update", "-y", "--noninteractive", "org.gimp.GIMP"}, true},
		{"snap", action.UpgradeParams{Mode: action.ModeAll}, ups("snap", "lxd", "5.21"), "snap", []string{"refresh"}, true},
		{"snap", action.UpgradeParams{Mode: action.ModeSelected}, ups("snap", "lxd", "5.21", "core22", "1"),
			"snap", []string{"refresh", "lxd", "core22"}, true},
		{"pacman", action.UpgradeParams{Mode: action.ModeAll}, ups("pacman", "x", "1"), "", nil, false},
	} {
		c, ok := upgradeCmd(tc.m, tc.p, tc.cands, nil)
		if ok != tc.ok || c.Name != tc.name || !slices.Equal(c.Args, tc.args) {
			t.Errorf("%s %+v = %v %v, want %s %q %v", tc.m, tc.p, c, ok, tc.name, tc.args, tc.ok)
		}
		if tc.m != "apt" && len(c.Env) != 0 {
			t.Errorf("%s: env %q", tc.m, c.Env)
		}
	}
}

func TestDiffPackages(t *testing.T) {
	pk := func(m, name, arch, version string) model.Package {
		return model.Package{Manager: m, Name: name, Arch: arch, Version: version}
	}
	before := []model.Package{
		pk("apt", "openssl", "amd64", "3.0.13-0ubuntu3.4"),
		pk("apt", "libc6", "amd64", "2.39-0ubuntu8.5"),
		pk("apt", "libc6", "i386", "2.39-0ubuntu8.5"),
		pk("apt", "bash", "amd64", "5.2"),
		pk("dnf", "kernel-core", "x86_64", "5.14.0-570.17.1"),
		pk("dnf", "kernel-core", "x86_64", "5.14.0-570.12.1"),
		pk("dnf", "kernel-modules", "x86_64", "5.14.0-570.17.1"),
		{Manager: "dnf", Name: "openssl", Arch: "x86_64", Epoch: "1", Version: "3.2.2", Release: "6"},
		pk("flatpak", "org.gimp.GIMP", "x86_64", "2.10.38"),
	}
	after := []model.Package{
		pk("apt", "openssl", "amd64", "3.0.13-0ubuntu3.5"),
		pk("apt", "libc6", "amd64", "2.39-0ubuntu8.5"),
		pk("apt", "libc6", "i386", "2.39-0ubuntu8.6"),
		pk("apt", "zsh", "amd64", "5.9"),
		// The order of a multi-version package doesn't matter.
		pk("dnf", "kernel-modules", "x86_64", "5.14.0-570.17.1"),
		pk("dnf", "kernel-core", "x86_64", "5.14.0-570.22.1"),
		pk("dnf", "kernel-core", "x86_64", "5.14.0-570.17.1"),
		{Manager: "dnf", Name: "openssl", Arch: "x86_64", Epoch: "1", Version: "3.2.2", Release: "7"},
		pk("flatpak", "org.gimp.GIMP", "x86_64", "2.10.38"),
		pk("flatpak", "org.gimp.GIMP", "aarch64", "2.10.38"),
	}
	changed, added, removed := diffPackages(before, after)
	wantChanged := []action.PackageChange{
		{Manager: "apt", Name: "libc6", Arch: "i386", From: "2.39-0ubuntu8.5", To: "2.39-0ubuntu8.6"},
		{Manager: "apt", Name: "openssl", Arch: "amd64", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5"},
		{Manager: "dnf", Name: "kernel-core", Arch: "x86_64", From: "5.14.0-570.12.1, 5.14.0-570.17.1",
			To: "5.14.0-570.17.1, 5.14.0-570.22.1"},
		{Manager: "dnf", Name: "openssl", Arch: "x86_64", From: "1:3.2.2-6", To: "1:3.2.2-7"},
	}
	wantAdded := []action.PackageChange{
		{Manager: "apt", Name: "zsh", Arch: "amd64", To: "5.9"},
		{Manager: "flatpak", Name: "org.gimp.GIMP", Arch: "aarch64", To: "2.10.38"},
	}
	wantRemoved := []action.PackageChange{{Manager: "apt", Name: "bash", Arch: "amd64", From: "5.2"}}
	if !reflect.DeepEqual(changed, wantChanged) {
		t.Errorf("changed = %+v", changed)
	}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Errorf("added = %+v", added)
	}
	if !reflect.DeepEqual(removed, wantRemoved) {
		t.Errorf("removed = %+v", removed)
	}
	if c, a, r := diffPackages(before, before); c != nil || a != nil || r != nil {
		t.Errorf("no change = %v %v %v", c, a, r)
	}
}

func TestUpgradeSummary(t *testing.T) {
	for _, tc := range []struct {
		r    action.UpgradeResult
		want string
	}{
		{action.UpgradeResult{}, "No packages changed."},
		{action.UpgradeResult{Changed: make([]action.PackageChange, 3)}, "Packages: 3 upgraded."},
		{action.UpgradeResult{Changed: make([]action.PackageChange, 1), Added: make([]action.PackageChange, 2),
			Removed: make([]action.PackageChange, 1)}, "Packages: 1 upgraded, 2 installed, 1 removed."},
		{action.UpgradeResult{Removed: make([]action.PackageChange, 1)}, "Packages: 1 removed."},
	} {
		if got := upgradeSummary(tc.r); got != tc.want {
			t.Errorf("%q, want %q", got, tc.want)
		}
	}
}

// A second package job waits for the first; cancelling it should end it
// without waiting, but r.pkg.Lock() ignores the job's context.
func TestUpgradeWaitingForLockCancels(t *testing.T) {
	h := newAptHost(t)
	r := h.runner(t)
	busy, release := make(chan struct{}), make(chan struct{})
	var once, unblock sync.Once
	r.Exec = func(ctx context.Context, c Cmd, stdout, stderr io.Writer) (int, error) {
		once.Do(func() {
			close(busy)
			<-release
		})
		return h.exec(ctx, c, stdout, stderr)
	}
	defer func() {
		unblock.Do(func() { close(release) })
		waitIdle(t, r)
	}()
	first, second := jobID(40), jobID(41)
	start(r, first, action.PkgUpgrade, `{}`)
	<-busy
	start(r, second, action.PkgUpgrade, `{}`)
	for {
		ev := next(t, r)
		if ev.GetJobId() == second && strings.Contains(string(ev.GetData()), "Waiting for another package job") {
			break
		}
	}
	r.Cancel(second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if ev := r.Next(); ev != nil {
				r.Sent(ev)
				if ev.GetJobId() == second && ev.GetType() == agentv1.JobEvent_RESULT {
					checkResult(t, ev, "cancelled", -1, "cancelled")
					return
				}
				continue
			}
			select {
			case <-r.Ready():
			case <-release:
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("the queued job didn't end when cancelled")
		unblock.Do(func() { close(release) })
		<-done
	}
}

func TestUpgradePinnedApt(t *testing.T) {
	h := newAptHost(t)
	h.older = map[string][]string{"curl": {"8.5.0-2ubuntu10.4"}, "bash": {"5.2.21-2ubuntu5"}}
	r := h.runner(t)
	id := jobID(37)
	// openssl's pin is its candidate; bash has no update but the pinned
	// version exists; docker-ce is held; tzdata isn't pinned.
	start(r, id, action.PkgUpgrade, `{"mode":"selected","packages":["openssl","apt:bash","tzdata","docker-ce"],
		"versions":{"openssl":"3.0.13-0ubuntu3.5","apt:bash":"5.2.21-2ubuntu5","docker-ce":"5:27.3.1-1~ubuntu.24.04~noble"}}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if len(h.cmds) != 1 {
		t.Fatalf("commands = %v", h.cmds)
	}
	i := slices.Index(h.cmds[0].Args, "--only-upgrade")
	if got := h.cmds[0].Args[i+1:]; !slices.Equal(got, []string{"openssl=3.0.13-0ubuntu3.5", "tzdata", "bash=5.2.21-2ubuntu5"}) {
		t.Errorf("args = %q", got)
	}
	u := upgradeResult(t, res.GetResultJson())
	if !slices.Equal(names(u.Changed), []string{"bash", "openssl", "tzdata"}) {
		t.Errorf("changed = %+v", u.Changed)
	}
	held := "apt: docker-ce is held, so it stays at 5:27.0.1-1~ubuntu.24.04~noble rather than 5:27.3.1-1~ubuntu.24.04~noble"
	if !slices.Contains(u.Warnings, held) || !strings.Contains(outputOf(evs, "info"), held+"\n") {
		t.Errorf("warnings = %q", u.Warnings)
	}

	// A pin the repository can't provide fails the job; nothing else is
	// installed instead.
	h = newAptHost(t)
	r = h.runner(t)
	id = jobID(38)
	start(r, id, action.PkgUpgrade, `{"mode":"selected","packages":["curl","openssl"],"versions":{"curl":"8.5.0-2ubuntu10.9"}}`)
	evs, res = untilResult(t, r, id)
	checkResult(t, res, "failed", 100, "apt exited with status 100")
	if !strings.Contains(outputOf(evs, "stdout"), "E: Version '8.5.0-2ubuntu10.9' for 'curl' was not found") ||
		len(upgradeResult(t, res.GetResultJson()).Changed) != 0 {
		t.Errorf("stdout = %q", outputOf(evs, "stdout"))
	}
}

func TestUpgradeCands(t *testing.T) {
	ups := model.Updates{
		Managers: []string{"dnf"},
		Updates: []model.Update{
			{Manager: "dnf", Name: "openssl", Installed: "1:3.2.2-6.el9", Candidate: "1:3.2.2-7.el9"},
			{Manager: "dnf", Name: "kernel-core", Candidate: "5.14.0-570.22.1.el9"},
			{Manager: "dnf", Name: "podman", Installed: "5.2.2-1.el9", Candidate: "5.4.0-1.el9"},
			{Manager: "flatpak", Name: "org.gimp.GIMP", Installed: "2.10", Candidate: "2.10.38"},
		},
		Held: []string{"podman"},
	}
	installed := []model.Package{
		{Manager: "dnf", Name: "openssl", Epoch: "1", Version: "3.2.2", Release: "6.el9"},
		{Manager: "dnf", Name: "bash", Version: "5.1.8", Release: "9.el9"},
		{Manager: "dnf", Name: "podman", Version: "5.2.2", Release: "1.el9"},
	}
	p := action.UpgradeParams{Mode: action.ModeSelected, Exclude: []string{"kernel*"}}
	want := []string{"openssl", "kernel-core", "bash", "podman", "zsh", "kernel-modules"}
	pins := map[string]string{"openssl": "1:3.2.2-6.el9_5", "bash": "5.1.8-10.el9", "podman": "5.3.0-1.el9",
		"zsh": "5.8-9.el9", "kernel-modules": "5.14.0-570.22.1.el9"}
	cands, warns := upgradeCands("dnf", p, want, pins, ups, installed)
	var got []string
	for _, u := range cands {
		got = append(got, u.Name+" "+u.Installed+" → "+u.Candidate)
	}
	if !slices.Equal(got, []string{"openssl 1:3.2.2-6.el9 → 1:3.2.2-6.el9_5", "bash 5.1.8-9.el9 → 5.1.8-10.el9"}) {
		t.Errorf("cands = %q", got)
	}
	if !slices.Equal(warns, []string{"dnf: podman is held, so it stays at 5.2.2-1.el9 rather than 5.3.0-1.el9",
		"dnf: zsh isn't installed, so it can't be upgraded to 5.8-9.el9"}) {
		t.Errorf("warns = %q", warns)
	}
	c, ok := upgradeCmd("dnf", p, cands, pins)
	if !ok || c.String() != "dnf -y upgrade --exclude=kernel* openssl-1:3.2.2-6.el9_5 bash-5.1.8-10.el9" {
		t.Errorf("command = %s", c)
	}

	// Unpinned, as before.
	cands, warns = upgradeCands("dnf", p, want, nil, ups, installed)
	if len(cands) != 1 || cands[0].Name != "openssl" || cands[0].Candidate != "1:3.2.2-7.el9" || warns != nil {
		t.Errorf("unpinned = %+v %q", cands, warns)
	}

	// An image-based host deploys a pinned image version even when its check
	// found nothing, or found another version.
	img := "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable"
	p = action.UpgradeParams{Mode: action.ModeSelected}
	for _, listed := range [][]model.Update{nil, {{Manager: "rpm-ostree", Name: "bazzite:stable", Installed: "41.20250101",
		Candidate: "41.20250301", Image: true}}} {
		ups := model.Updates{Managers: []string{"rpm-ostree"}, Updates: listed}
		pins := map[string]string{img: "41.20250215"}
		cands, _ := upgradeCands("rpm-ostree", p, []string{img}, pins, ups, nil)
		c, ok := upgradeCmd("rpm-ostree", p, cands, pins)
		if !ok || c.String() != "rpm-ostree deploy 41.20250215" {
			t.Errorf("%d listed: %s %v", len(listed), c, ok)
		}
		cands, _ = upgradeCands("rpm-ostree", p, []string{img}, nil, ups, nil)
		if c, _ := upgradeCmd("rpm-ostree", p, cands, nil); len(listed) > 0 && c.String() != "rpm-ostree upgrade" {
			t.Errorf("unpinned: %s", c)
		}
	}
}

func TestUpgradeCmdPinned(t *testing.T) {
	sel := action.UpgradeParams{Mode: action.ModeSelected}
	cands := []model.Update{{Manager: "apt", Name: "openssl", Installed: "3.0.13-0ubuntu3.4"},
		{Manager: "apt", Name: "linux-image-x", Installed: ""}, {Manager: "apt", Name: "curl", Installed: "8.5.0"}}
	c, ok := upgradeCmd("apt", sel, cands, map[string]string{"openssl": "3.0.13-0ubuntu3.5", "linux-image-x": "1"})
	i := slices.Index(c.Args, "--only-upgrade")
	if !ok || i < 0 || !slices.Equal(c.Args[i+1:], []string{"openssl=3.0.13-0ubuntu3.5", "curl"}) {
		t.Errorf("apt = %v", c)
	}
	c, _ = upgradeCmd("dnf", sel, []model.Update{{Manager: "dnf", Name: "openssl"}, {Manager: "dnf", Name: "curl"}},
		map[string]string{"openssl": "3.2.2-7.el9", "curl": "7.76.1-31.el9"})
	if c.String() != "dnf -y upgrade openssl-3.2.2-7.el9 curl-7.76.1-31.el9" {
		t.Errorf("dnf = %s", c)
	}
}

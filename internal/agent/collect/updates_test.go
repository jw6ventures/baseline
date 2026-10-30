package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

const rpmQuery = "rpm -qa --queryformat %{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"

func byName(ups []model.Update) map[string]model.Update {
	m := map[string]model.Update{}
	for _, u := range ups {
		m[u.Name] = u
	}
	return m
}

const aptSimulate = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Calculating upgrade...
The following NEW packages will be installed:
  linux-image-6.8.0-86-generic
The following packages will be upgraded:
  libssl3t64 openssl tzdata
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all]) []
Inst linux-image-6.8.0-86-generic (6.8.0-86.87 Ubuntu:24.04/noble-updates [amd64])
Inst libc6:i386 [2.39-0ubuntu8.5] (2.39-0ubuntu8.6 Ubuntu:24.04/noble-updates [i386])
Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`

func TestUpdatesApt(t *testing.T) {
	f := newFixture(t)
	f.cmds["dpkg-query"] = ""
	f.cmds["apt-get update -q -o DPkg::Lock::Timeout=120"] = ""
	f.exits["apt-get update -q -o DPkg::Lock::Timeout=120"] = 100
	f.cmds["apt-get -s -q -o Debug::NoLocking=1 dist-upgrade"] = aptSimulate
	f.cmds["apt-mark showhold"] = "docker-ce\n"

	u, err := f.env.Updates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(u.Managers, ",") != "apt" || len(u.Updates) != 5 || strings.Join(u.Held, ",") != "docker-ce" {
		t.Fatalf("%+v", u)
	}
	// A failed refresh is a warning, not a failure.
	if len(u.Warnings) != 1 || !strings.Contains(u.Warnings[0], "apt: couldn't refresh") {
		t.Errorf("warnings = %q", u.Warnings)
	}
	m := byName(u.Updates)
	if o := m["openssl"]; o.Installed != "3.0.13-0ubuntu3.4" || o.Candidate != "3.0.13-0ubuntu3.5" || !o.Security ||
		o.Repo != "Ubuntu:24.04/noble-updates" || o.Arch != "amd64" {
		t.Errorf("openssl = %+v", o)
	}
	if tz := m["tzdata"]; tz.Security || tz.Arch != "all" || tz.Candidate != "2025b-0ubuntu0.24.04" {
		t.Errorf("tzdata = %+v", tz)
	}
	if k := m["linux-image-6.8.0-86-generic"]; k.Installed != "" || k.Candidate != "6.8.0-86.87" {
		t.Errorf("new kernel = %+v", k)
	}
	if c := m["libc6"]; c.Arch != "i386" || c.Installed != "2.39-0ubuntu8.5" {
		t.Errorf("multiarch = %+v", c)
	}
}

func TestUpdatesAptListFailureFailsSection(t *testing.T) {
	f := newFixture(t)
	f.cmds["dpkg-query"] = ""
	f.cmds["apt-get update -q -o DPkg::Lock::Timeout=120"] = ""
	// The simulation isn't stubbed, so it fails.
	if _, err := f.env.Updates(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// dnf4 output: one name wrapped onto its own line, then the obsoletes list.
const dnfCheckUpdate = `
kernel-core.x86_64                   5.14.0-570.25.1.el9_6           baseos
openssl-libs.x86_64                  1:3.2.2-6.el9_5.2               baseos
python3-some-really-long-package-name-here.noarch
                                     2.1.0-3.el9                     appstream
tzdata.noarch                        2025b-1.el9                     baseos
Obsoleting Packages
grub2-tools.x86_64                   1:2.06-104.el9_6                baseos
    grub2-tools.x86_64               1:2.06-94.el9                   @baseos
`

const dnf4Advisories = `RLSA-2025:7895 Important/Sec. openssl-libs-1:3.2.2-6.el9_5.2.x86_64
RLSA-2025:8001 Moderate/Sec.  kernel-core-5.14.0-570.25.1.el9_6.x86_64
RLSA-2025:8002 Important/Sec. kernel-core-5.14.0-570.25.1.el9_6.x86_64
`

func TestUpdatesDnf(t *testing.T) {
	f := newFixture(t)
	f.cmds["rpm"] = ""
	f.cmds["dnf -q makecache"] = ""
	f.cmds["dnf -q -C check-update"] = dnfCheckUpdate
	f.exits["dnf -q -C check-update"] = 100
	f.cmds[rpmQuery] = "kernel-core\t0\t5.14.0\t570.9.1.el9_6\tx86_64\tkernel-5.14.0-570.9.1.el9_6.src.rpm\n" +
		"kernel-core\t0\t5.14.0\t570.22.1.el9_6\tx86_64\tkernel-5.14.0-570.22.1.el9_6.src.rpm\n" +
		"openssl-libs\t1\t3.2.2\t6.el9_5.1\tx86_64\topenssl-3.2.2-6.el9_5.1.src.rpm\n" +
		"tzdata\t0\t2025a\t1.el9\tnoarch\ttzdata-2025a-1.el9.src.rpm\n"
	f.cmds["dnf -q -C updateinfo list --security"] = dnf4Advisories

	u, err := f.env.Updates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(u.Managers, ",") != "dnf" || len(u.Updates) != 4 || len(u.Warnings) != 0 {
		t.Fatalf("%+v", u)
	}
	m := byName(u.Updates)
	if k := m["kernel-core"]; k.Installed != "5.14.0-570.22.1.el9_6" || k.Candidate != "5.14.0-570.25.1.el9_6" ||
		!k.Security || strings.Join(k.Advisories, ",") != "RLSA-2025:8001,RLSA-2025:8002" {
		t.Errorf("kernel = %+v", k)
	}
	if o := m["openssl-libs"]; o.Installed != "1:3.2.2-6.el9_5.1" || o.Candidate != "1:3.2.2-6.el9_5.2" || o.Arch != "x86_64" || !o.Security {
		t.Errorf("openssl = %+v", o)
	}
	if p := m["python3-some-really-long-package-name-here"]; p.Candidate != "2.1.0-3.el9" || p.Repo != "appstream" || p.Installed != "" {
		t.Errorf("wrapped = %+v", p)
	}
	if tz := m["tzdata"]; tz.Security || tz.Installed != "2025a-1.el9" {
		t.Errorf("tzdata = %+v", tz)
	}
	if _, ok := m["grub2-tools"]; ok {
		t.Error("obsoletes listed as updates")
	}
}

func TestUpdatesDnfNoneAndDnf5Advisories(t *testing.T) {
	f := newFixture(t)
	f.cmds["rpm"] = ""
	f.cmds["dnf -q makecache"] = ""
	f.cmds["dnf -q -C check-update"] = ""
	u, err := f.env.Updates(context.Background())
	if err != nil || len(u.Updates) != 0 {
		t.Fatalf("%+v %v", u, err)
	}

	adv := parseDnfAdvisories(`Name                 Type     Severity  Package                              Issued
FEDORA-2025-1a2b3c4d security Moderate  openssl-libs-1:3.2.4-3.fc42.x86_64   2025-09-30 01:02:03
`)
	if got := adv["openssl-libs.x86_64"]; len(got) != 1 || got[0] != "FEDORA-2025-1a2b3c4d" {
		t.Fatalf("dnf5 = %v", adv)
	}
}

func TestUpdatesImageBased(t *testing.T) {
	f := newFixture(t)
	f.file("/run/ostree-booted", "")
	f.cmds["rpm-ostree status --json"] = bazziteStatus
	f.cmds["rpm-ostree upgrade --check"] = `Note: --check and --preview may be unreliable.  See https://github.com/coreos/rpm-ostree/issues/1579
AvailableUpdate:
        Version: 42.20261010.0 (2026-10-10T04:32:11Z)
         Digest: sha256:4f1c2d3e
`
	f.cmds["dnf"] = ""
	f.cmds["flatpak list --columns=application,branch,arch,version,active"] =
		"org.mozilla.firefox\tstable\tx86_64\t131.0\taaaaaaaaaaaaaaaa\norg.freedesktop.Platform\t24.08\tx86_64\t\tbbbbbbbbbbbbbbbb\n"
	f.cmds["flatpak remote-ls --updates --columns=application,branch,arch,version,origin,commit"] =
		"org.mozilla.firefox\tstable\tx86_64\t132.0\tflathub\tcccccccccccccccc\norg.freedesktop.Platform\t24.08\tx86_64\t\tflathub\tdddddddddddddddd\n"

	u, err := f.env.Updates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(u.Managers, ",") != "rpm-ostree,flatpak" || len(u.Updates) != 3 {
		t.Fatalf("%+v", u)
	}
	m := byName(u.Updates)
	img := m["ghcr.io/ublue-os/bazzite:stable"]
	if !img.Image || img.Installed != "42.20261001" || img.Candidate != "42.20261010.0" || img.Digest != "sha256:4f1c2d3e" {
		t.Errorf("image = %+v", img)
	}
	if ff := m["org.mozilla.firefox"]; ff.Installed != "131.0" || ff.Candidate != "132.0" || ff.Repo != "flathub" {
		t.Errorf("firefox = %+v", ff)
	}
	if rt := m["org.freedesktop.Platform//24.08"]; rt.Installed != "bbbbbbbbbbbb" || rt.Candidate != "dddddddddddd" {
		t.Errorf("runtime = %+v", rt)
	}

	// No update: rpm-ostree exits 77.
	f.cmds["rpm-ostree upgrade --check"] = "No updates available.\n"
	f.exits["rpm-ostree upgrade --check"] = 77
	if u, err = f.env.Updates(context.Background()); err != nil || len(u.Updates) != 2 {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestUpdatesNetworkFailuresWarn(t *testing.T) {
	f := newFixture(t)
	f.cmds["snap list --unicode=never --color=never"] = "Name    Version   Rev    Tracking       Publisher   Notes\nlxd     5.21.3    35624  5.21/stable    canonical✓  -\n"
	f.file("/run/snapd.socket", "")
	f.cmds["flatpak list --columns=application,branch,arch,version,active"] = ""
	f.cmds["snap refresh --list"] = "Name  Version  Rev    Size   Publisher   Notes\nlxd   5.21.4   36500  98MB   canonical✓  -\n"

	u, err := f.env.Updates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// flatpak remote-ls isn't stubbed: its failure is a warning.
	if len(u.Warnings) != 1 || !strings.HasPrefix(u.Warnings[0], "flatpak: update check failed") {
		t.Errorf("warnings = %q", u.Warnings)
	}
	if len(u.Updates) != 1 || u.Updates[0].Installed != "5.21.3 (35624)" || u.Updates[0].Candidate != "5.21.4 (36500)" {
		t.Errorf("snap = %+v", u.Updates)
	}
}

func TestFirstLine(t *testing.T) {
	err := &CmdError{Err: errors.New("exit status 100"), Stderr: "W: Some index files failed to download.\nE: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease"}
	if got := firstLine(err); !strings.HasPrefix(got, "E: Failed to fetch") {
		t.Fatalf("%q", got)
	}
}

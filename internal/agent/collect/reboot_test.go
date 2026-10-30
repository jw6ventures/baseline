package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func rebootProc(f *fixture, pid int, cgroup, maps string) {
	f.file(fmt.Sprintf("/proc/%d/cgroup", pid), "0::"+cgroup+"\n")
	f.file(fmt.Sprintf("/proc/%d/maps", pid), maps)
}

const rebootMapsHeader = "55d0c8a00000-55d0c8a2a000 r--p 00000000 103:02 1574    /usr/sbin/nginx\n"

func TestRebootUbuntu(t *testing.T) {
	f := newFixture(t)
	f.file("/var/run/reboot-required", "*** System restart required ***\n")
	f.file("/var/run/reboot-required.pkgs", "linux-image-6.8.0-87-generic\nlinux-base\nlinux-image-6.8.0-87-generic\n")
	f.file("/proc/sys/kernel/osrelease", "6.8.0-85-generic\n")
	f.file("/lib/modules/6.8.0-85-generic/modules.dep", "")
	f.file("/usr/lib/modules/6.8.0-87-generic/modules.dep", "")
	f.file("/lib/modules/6.8.0-90-generic/extra/leftover.ko", "") // removed kernel
	f.file("/lib/modules/6.8.0-99-lowlatency/modules.dep", "")    // another flavor

	deleted := "7f1c2a400000-7f1c2a4a0000 r-xp 00000000 103:02 2231 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"
	rebootProc(f, 1, "/init.scope", rebootMapsHeader+deleted)
	rebootProc(f, 10, "/system.slice/nginx.service", rebootMapsHeader+deleted)
	rebootProc(f, 11, "/system.slice/nginx.service", rebootMapsHeader+deleted)
	rebootProc(f, 12, "/system.slice/docker-0123abcd.scope", deleted)
	rebootProc(f, 13, "/kubepods.slice/kubepods-pod1.slice/cri-containerd-4567.scope", deleted)
	rebootProc(f, 14, "/system.slice/postgresql@16-main.service",
		"7f00 rw-s 00000000 00:01 9 /dev/shm/PostgreSQL.1234 (deleted)\n"+
			"7f01 r-xp 00000000 103:02 77 /usr/lib/x86_64-linux-gnu/libc.so.6\n")
	rebootProc(f, 15, "/system.slice/ssh.service", rebootMapsHeader)
	rebootProc(f, 16, "/system.slice/kthreadd.service", "") // a kernel thread's empty maps
	rebootProc(f, 17, "/user.slice/user-1000.slice/session-3.scope", deleted)
	rebootProc(f, 18, "/system.slice/cron.service",
		"7f02 r-xp 00000000 103:02 78 /usr/lib/x86_64-linux-gnu/libcrypto.so.3;6710aa3e (deleted)\n")

	r, err := f.env.Reboot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Required || len(r.Reasons) != 2 ||
		r.Reasons[0] != "the system asks for a reboot (/var/run/reboot-required)" ||
		r.Reasons[1] != "running kernel 6.8.0-85-generic is older than the installed 6.8.0-87-generic" {
		t.Errorf("reasons = %q", r.Reasons)
	}
	if strings.Join(r.Packages, ",") != "linux-base,linux-image-6.8.0-87-generic" {
		t.Errorf("packages = %q", r.Packages)
	}
	if strings.Join(r.Services, ",") != "cron.service,nginx.service" {
		t.Errorf("services = %q", r.Services)
	}
}

func TestRebootRHEL(t *testing.T) {
	f := newFixture(t)
	f.cmds["needs-restarting -r"] = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	f.exits["needs-restarting -r"] = 1
	f.file("/proc/sys/kernel/osrelease", "4.18.0-553.el8_10.x86_64\n")
	f.file("/lib/modules/4.18.0-553.el8_10.x86_64/vmlinuz", "")
	f.file("/lib/modules/4.18.0-553.16.1.el8_10.x86_64/vmlinuz", "")

	r, err := f.env.Reboot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"needs-restarting: core libraries or services were updated",
		"running kernel 4.18.0-553.el8_10.x86_64 is older than the installed 4.18.0-553.16.1.el8_10.x86_64"}
	if !r.Required || strings.Join(r.Reasons, "|") != strings.Join(want, "|") || r.Packages != nil || r.Services != nil {
		t.Errorf("%+v", r)
	}
}

func TestRebootNotNeeded(t *testing.T) {
	f := newFixture(t)
	f.cmds["needs-restarting -r"] = "No core libraries or services have been updated since boot-up.\n"
	f.file("/proc/sys/kernel/osrelease", "6.11.5-200.fc40.x86_64\n")
	f.file("/lib/modules/6.11.4-201.fc40.x86_64/vmlinuz", "")
	f.file("/lib/modules/6.11.5-200.fc40.x86_64/vmlinuz", "")
	r, err := f.env.Reboot(context.Background())
	if err != nil || r.Required || r.Reasons != nil {
		t.Fatalf("%+v %v", r, err)
	}

	// needs-restarting failing for another reason is no answer.
	f.exits["needs-restarting -r"] = 2
	if r, _ := f.env.Reboot(context.Background()); r.Required {
		t.Fatalf("exit 2: %+v", r)
	}
}

func TestRebootImageBased(t *testing.T) {
	f := newFixture(t)
	f.file("/run/ostree-booted", "")
	f.cmds["rpm-ostree status --json"] = bazziteStatus
	// The kernel is part of the image and not compared.
	f.file("/proc/sys/kernel/osrelease", "6.16.4-116.bazzite.fc42.x86_64\n")
	f.file("/usr/lib/modules/6.17.1-100.bazzite.fc42.x86_64/vmlinuz", "")
	r, err := f.env.Reboot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Required || len(r.Reasons) != 1 || r.Reasons[0] != "deployment 42.20261008 is staged and waits for a reboot" {
		t.Errorf("reasons = %q", r.Reasons)
	}

	f.cmds["rpm-ostree status --json"] = strings.Replace(bazziteStatus, `"staged": true`, `"staged": false`, 1)
	if r, _ := f.env.Reboot(context.Background()); r.Required {
		t.Errorf("nothing staged: %+v", r)
	}
}

func TestKernelFlavor(t *testing.T) {
	for in, want := range map[string]string{
		"6.8.0-85-generic":                   "generic",
		"6.8.12-4-pve":                       "pve",
		"6.1.0-26-amd64":                     "amd64",
		"6.11.4-201.fc40.x86_64":             "",
		"4.18.0-553.el8_10.x86_64":           "",
		"6.1.0-26-cloud-amd64":               "cloud-amd64",
		"6.6.51+rpt-rpi-v8":                  "rpi-v8",
		"6.10.14-linuxkit":                   "linuxkit",
		"5.15.167.4-microsoft-standard-WSL2": "microsoft-standard-WSL2",
	} {
		if got := kernelFlavor(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

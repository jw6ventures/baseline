package collect

import (
	"context"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

const (
	svcUnitsJSONCmd = "systemctl list-units --type=service --all --output=json --no-pager"
	svcFilesJSONCmd = "systemctl list-unit-files --type=service --output=json --no-pager"
	svcUnitsTextCmd = "systemctl list-units --type=service --all --plain --no-legend --no-pager"
	svcFilesTextCmd = "systemctl list-unit-files --type=service --plain --no-legend --no-pager"
)

// From systemd 255 (Ubuntu 24.04).
const svcUnitsJSON = `[
{"unit":"getty@tty1.service","load":"loaded","active":"active","sub":"running","job":"","description":"Getty on tty1"},
{"unit":"nginx.service","load":"loaded","active":"failed","sub":"failed","job":"","description":"A high performance web server and a reverse proxy server"},
{"unit":"plymouth-quit-wait.service","load":"not-found","active":"inactive","sub":"dead","job":"","description":"plymouth-quit-wait.service"},
{"unit":"ssh.service","load":"loaded","active":"active","sub":"running","job":"","description":"OpenBSD Secure Shell server"},
{"unit":"systemd-fsck@dev-disk-by\\x2duuid-0B5A\\x2d1C2D.service","load":"loaded","active":"active","sub":"exited","job":"","description":"File System Check on /dev/disk/by-uuid/0B5A-1C2D"},
{"unit":"systemd-resolved.service","load":"loaded","active":"active","sub":"running","job":"","description":"Network Name Resolution"},
{"unit":"user@1000.service","load":"loaded","active":"active","sub":"running","job":"","description":"User Manager for UID 1000"},
{"unit":"wpa_supplicant.service","load":"masked","active":"inactive","sub":"dead","job":"","description":"wpa_supplicant.service"}
]`

const svcFilesJSON = `[
{"unit_file":"getty@.service","state":"enabled","preset":"enabled"},
{"unit_file":"nginx.service","state":"enabled","preset":"enabled"},
{"unit_file":"rsync.service","state":"disabled","preset":"enabled"},
{"unit_file":"serial-getty@.service","state":"disabled","preset":"enabled"},
{"unit_file":"ssh.service","state":"enabled","preset":"enabled"},
{"unit_file":"sshd.service","state":"alias","preset":null},
{"unit_file":"systemd-fsck@.service","state":"static","preset":null},
{"unit_file":"systemd-resolved.service","state":"enabled","preset":"enabled"},
{"unit_file":"dbus-org.freedesktop.resolve1.service","state":"alias","preset":null},
{"unit_file":"user@.service","state":"static","preset":null},
{"unit_file":"wpa_supplicant.service","state":"masked","preset":"enabled"},
{"unit_file":"apache2.service","state":"masked","preset":"enabled"}
]`

func svcByName(units []model.Service) map[string]model.Service {
	m := map[string]model.Service{}
	for _, u := range units {
		m[u.Name] = u
	}
	return m
}

func checkUbuntuServices(t *testing.T, s model.Services) {
	t.Helper()
	var names []string
	for _, u := range s.Units {
		names = append(names, u.Name)
	}
	want := []string{"apache2.service", "getty@tty1.service", "nginx.service", "rsync.service", "ssh.service",
		`systemd-fsck@dev-disk-by\x2duuid-0B5A\x2d1C2D.service`, "systemd-resolved.service", "user@1000.service",
		"wpa_supplicant.service"}
	if len(names) != len(want) {
		t.Fatalf("units = %q\nwant    %q", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("units = %q\nwant    %q", names, want)
		}
	}
	m := svcByName(s.Units)
	if n := m["nginx.service"]; !n.Failed() || n.Sub != "failed" || n.Enabled != "enabled" || n.Load != "loaded" ||
		n.Description != "A high performance web server and a reverse proxy server" {
		t.Errorf("nginx = %+v", n)
	}
	if g := m["getty@tty1.service"]; g.Enabled != "enabled" || g.Active != "active" || g.Sub != "running" {
		t.Errorf("instance = %+v", g)
	}
	if f := m[`systemd-fsck@dev-disk-by\x2duuid-0B5A\x2d1C2D.service`]; f.Enabled != "static" {
		t.Errorf("escaped instance = %+v", f)
	}
	if w := m["wpa_supplicant.service"]; w.Load != "masked" || w.Enabled != "masked" || w.Active != "inactive" {
		t.Errorf("masked = %+v", w)
	}
	if r := (model.Service{Name: "rsync.service", Active: "inactive", Enabled: "disabled"}); m["rsync.service"] != r {
		t.Errorf("unloaded = %+v", m["rsync.service"])
	}
	if a := m["apache2.service"]; a.Load != "" || a.Enabled != "masked" {
		t.Errorf("masked, not loaded = %+v", a)
	}
}

func TestServicesJSON(t *testing.T) {
	f := newFixture(t)
	f.file("/run/systemd/system/.keep", "")
	f.cmds[svcUnitsJSONCmd] = svcUnitsJSON
	f.cmds[svcFilesJSONCmd] = svcFilesJSON

	s, err := f.env.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkUbuntuServices(t, s)
}

// systemd 239 (Rocky 8) prints its table whatever --output says.
const svcUnitsText239 = `getty@tty1.service                                                      loaded    active   running Getty on tty1
● nginx.service                                                         loaded    failed   failed  A high performance web server and a reverse proxy server
● plymouth-quit-wait.service                                            not-found inactive dead    plymouth-quit-wait.service
ssh.service                                                             loaded    active   running OpenBSD Secure Shell server
systemd-fsck@dev-disk-by\x2duuid-0B5A\x2d1C2D.service                   loaded    active   exited  File System Check on /dev/disk/by-uuid/0B5A-1C2D
systemd-resolved.service                                                loaded    active   running Network Name Resolution
user@1000.service                                                       loaded    active   running User Manager for UID 1000
wpa_supplicant.service                                                  masked    inactive dead    wpa_supplicant.service
`

const svcFilesText239 = `apache2.service                              masked
dbus-org.freedesktop.resolve1.service        enabled
getty@.service                               enabled
nginx.service                                enabled
rsync.service                                disabled
serial-getty@.service                        disabled
ssh.service                                  enabled
systemd-fsck@.service                        static
systemd-resolved.service                     enabled
user@.service                                static
wpa_supplicant.service                       masked
`

func TestServicesTextFallback(t *testing.T) {
	f := newFixture(t)
	f.file("/run/systemd/system/.keep", "")
	f.cmds[svcUnitsJSONCmd] = svcUnitsText239
	f.cmds[svcFilesJSONCmd] = svcFilesText239
	f.cmds[svcUnitsTextCmd] = svcUnitsText239
	f.cmds[svcFilesTextCmd] = svcFilesText239

	s, err := f.env.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Without the "alias" state an alias reads as a unit file of its own;
	// it's harmless, and drop it so the rest compares with the JSON case.
	m := svcByName(s.Units)
	if a := m["dbus-org.freedesktop.resolve1.service"]; a.Enabled != "enabled" {
		t.Errorf("alias = %+v", a)
	}
	var rest []model.Service
	for _, u := range s.Units {
		if u.Name != "dbus-org.freedesktop.resolve1.service" {
			rest = append(rest, u)
		}
	}
	checkUbuntuServices(t, model.Services{Units: rest})

	// Unicode-less terminals print "*" instead of "●".
	units, err := parseListUnits("* nginx.service loaded failed failed nginx\n")
	if err != nil || len(units) != 1 || units[0].Unit != "nginx.service" || units[0].Description != "nginx" {
		t.Errorf("star marker: %+v %v", units, err)
	}
}

func TestServicesAbsentOrFailing(t *testing.T) {
	// systemctl installed, but systemd isn't the running init (a container).
	f := newFixture(t)
	f.cmds[svcUnitsJSONCmd] = svcUnitsJSON
	s, err := f.env.Services(context.Background())
	if err != nil || s.Units == nil || len(s.Units) != 0 {
		t.Fatalf("not systemd: %+v %v", s, err)
	}

	// systemd runs but can't be asked: fail rather than report nothing.
	f = newFixture(t)
	f.file("/run/systemd/system/.keep", "")
	f.cmds["systemctl --version"] = "systemd 255"
	if _, err := f.env.Services(context.Background()); err == nil {
		t.Fatal("expected an error")
	}

	// A table we can't read is an error too, not a short list.
	f = newFixture(t)
	f.file("/run/systemd/system/.keep", "")
	f.cmds[svcUnitsJSONCmd] = ""
	f.cmds[svcUnitsTextCmd] = "Failed to connect to bus: No such file or directory\n"
	f.cmds[svcFilesJSONCmd] = svcFilesJSON
	if _, err := f.env.Services(context.Background()); err == nil {
		t.Fatal("expected an error for an unreadable table")
	}
}

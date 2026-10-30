// Package collect gathers the agent's inventory sections. A missing tool or
// file means "capability absent", never an error (docs/agent.md).
package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
)

// Env is how collectors see the host. Tests point Root at a fixture tree and
// replace Run.
type Env struct {
	Root string // prefix for /etc, /proc, /sys, /run; "" on a real host
	Run  func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Has reports whether a command is installed.
	Has func(name string) bool
	// Statfs reads filesystem usage; nil means the real syscall on a real
	// host (Root == "") and nothing in tests.
	Statfs func(path string, st *syscall.Statfs_t) error
	// HighSecurity adds peripherals and NIC link state to the hardware
	// section; the server turns it on for high security hosts.
	HighSecurity atomic.Bool
}

// SetHighSecurity turns high security collection on or off and reports
// whether that changed it.
func (e *Env) SetHighSecurity(on bool) bool { return e.HighSecurity.Swap(on) != on }

// Host is the Env of the machine the agent runs on.
func Host() *Env {
	return &Env{
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			// Callers that expect a slow command (a repository refresh)
			// set their own deadline.
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
			}
			cmd := exec.CommandContext(ctx, name, args...)
			// Stable, parseable output regardless of the host's locale.
			cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil && stderr.Len() > 0 {
				return out, &CmdError{Err: err, Stderr: strings.TrimSpace(stderr.String())}
			}
			return out, err
		},
		Has: func(name string) bool {
			_, err := exec.LookPath(name)
			return err == nil
		},
	}
}

// ErrAbsent is returned by a collector whose subject isn't on this host (no
// hypervisor, no Kubernetes runtime). Nothing is sent for the section.
var ErrAbsent = errors.New("not present on this host")

type CmdError struct {
	Err    error
	Stderr string
}

func (e *CmdError) Error() string { return e.Err.Error() + ": " + e.Stderr }
func (e *CmdError) Unwrap() error { return e.Err }

// exitCode is a failed command's exit status, 0 for success and -1 when it
// didn't run at all. Some tools signal results this way (dnf check-update
// exits 100 when there are updates).
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	var ce interface{ ExitCode() int }
	if errors.As(err, &ce) {
		return ce.ExitCode()
	}
	return -1
}

// firstLine shortens a command error to something fit for the UI.
func firstLine(err error) string {
	msg := err.Error()
	var ce *CmdError
	if errors.As(err, &ce) {
		// The last line of stderr is usually the actual complaint.
		lines := strings.Split(strings.TrimSpace(ce.Stderr), "\n")
		msg = strings.TrimSpace(lines[len(lines)-1])
	} else if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

func (e *Env) statfs(path string, st *syscall.Statfs_t) error {
	switch {
	case e.Statfs != nil:
		return e.Statfs(path, st)
	case e.Root == "":
		return syscall.Statfs(path, st)
	}
	return errors.New("no statfs in a fixture")
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

// Read returns a file's contents trimmed of surrounding whitespace, or "".
func (e *Env) Read(p string) string {
	b, err := os.ReadFile(e.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (e *Env) ReadBytes(p string) ([]byte, error) { return os.ReadFile(e.path(p)) }

func (e *Env) Exists(p string) bool {
	_, err := os.Stat(e.path(p))
	return err == nil
}

// Glob matches under Root and returns host paths.
func (e *Env) Glob(pattern string) []string {
	m, _ := filepath.Glob(e.path(pattern))
	for i := range m {
		m[i] = strings.TrimPrefix(m[i], e.Root)
	}
	return m
}

// Link returns the base name of a symlink's target, or "".
func (e *Env) Link(p string) string {
	t, err := os.Readlink(e.path(p))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

func (e *Env) ReadDir(p string) []string {
	ents, err := os.ReadDir(e.path(p))
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range ents {
		out = append(out, d.Name())
	}
	return out
}

// parseKV parses KEY=value lines (os-release, udev data), unquoting values.
func parseKV(s string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
			v = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(v)
		}
		m[strings.TrimSpace(k)] = v
	}
	return m
}

// Capabilities lists the tools and features this host has, for Hello.
func (e *Env) Capabilities() []string {
	var caps []string
	for _, c := range []struct{ name, bin string }{
		{"apt", "dpkg-query"}, {"dnf", "dnf"}, {"rpm", "rpm"}, {"rpm-ostree", "rpm-ostree"}, {"bootc", "bootc"},
		{"flatpak", "flatpak"}, {"snap", "snap"}, {"dmidecode", "dmidecode"}, {"lsblk", "lsblk"},
		{"lspci", "lspci"}, {"smartctl", "smartctl"}, {"systemd", "systemctl"},
		{"needs-restarting", "needs-restarting"}, {"zpool", "zpool"}, {"pvesh", "pvesh"},
		{"virsh", "virsh"}, {"crictl", "crictl"}, {"docker", "docker"}, {"podman", "podman"},
	} {
		if e.Has(c.bin) {
			caps = append(caps, c.name)
		}
	}
	if e.Exists("/run/ostree-booted") {
		caps = append(caps, "image-based")
	}
	if e.Exists("/var/run/docker.sock") && !contains(caps, "docker") {
		caps = append(caps, "docker")
	}
	if e.Exists("/run/podman/podman.sock") && !contains(caps, "podman") {
		caps = append(caps, "podman")
	}
	// What the agent itself can do: drive Compose stacks and write their
	// files when a Compose CLI for an engine it has is installed (a file
	// lookup), and install exact package versions.
	if (contains(caps, "docker") && e.composeCLI("docker") != "") || (contains(caps, "podman") && e.composeCLI("podman") != "") {
		caps = append(caps, action.CapCompose, action.CapComposeFiles, action.CapComposeRoots, action.CapComposeStart,
			action.CapComposeArchive, action.CapComposeRootless)
	}
	caps = append(caps, action.CapPkgPin)
	return caps
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// procCgroup is a process's cgroup v2 path ("/system.slice/sshd.service"),
// or "" when it isn't readable or the host only has cgroup v1.
func (e *Env) procCgroup(pid int) string {
	for _, line := range strings.Split(e.Read("/proc/"+strconv.Itoa(pid)+"/cgroup"), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	return ""
}

// procUnit is the systemd unit a process runs in. It reads the cgroup v2
// path, or on cgroup v1 hosts (Rocky 8) systemd's own name=systemd
// hierarchy, which has the same layout.
func (e *Env) procUnit(pid int) string {
	var v1 string
	for _, line := range strings.Split(e.Read("/proc/"+strconv.Itoa(pid)+"/cgroup"), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok && p != "/" {
			return cgroupUnit(p)
		}
		if _, p, ok := strings.Cut(line, ":name=systemd:"); ok {
			v1 = p
		}
	}
	return cgroupUnit(v1)
}

// cgroupUnit is the systemd unit a cgroup path belongs to: the last
// .service or .scope segment ("docker-<id>.scope" for a container).
func cgroupUnit(path string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if strings.HasSuffix(segs[i], ".service") || strings.HasSuffix(segs[i], ".scope") {
			return segs[i]
		}
	}
	return ""
}

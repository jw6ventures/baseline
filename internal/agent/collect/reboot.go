package collect

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/vercmp"
)

// Reboot reports whether the host needs a reboot, and why, plus the
// services still running code from deleted libraries (docs/agent.md §1.4).
func (e *Env) Reboot(ctx context.Context) (model.Reboot, error) {
	var r model.Reboot
	for _, p := range []string{"/var/run/reboot-required", "/run/reboot-required"} {
		if e.Exists(p) {
			r.Reasons = append(r.Reasons, "the system asks for a reboot ("+p+")")
			r.Packages = sortedUniq(strings.Fields(e.Read(p + ".pkgs")))
			break
		}
	}
	if e.Has("needs-restarting") {
		// Exit 1 means a reboot is needed; anything else is no answer.
		if _, err := e.Run(ctx, "needs-restarting", "-r"); exitCode(err) == 1 {
			r.Reasons = append(r.Reasons, "needs-restarting: core libraries or services were updated")
		}
	}
	if e.Exists("/run/ostree-booted") && e.Has("rpm-ostree") {
		// The kernel comes with the image; /usr/lib/modules holds only the
		// booted one, so the staged deployment is what tells.
		if img, err := e.rpmOstreeImage(ctx); err == nil && img.Staged != nil {
			r.Reasons = append(r.Reasons, "deployment "+img.Staged.Version+" is staged and waits for a reboot")
		}
	} else if reason := e.kernelReason(); reason != "" {
		r.Reasons = append(r.Reasons, reason)
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	r.Services = e.deletedLibServices()
	r.Required = len(r.Reasons) > 0
	return r, nil
}

// kernelReason compares the running kernel with the newest installed one.
func (e *Env) kernelReason() string {
	running := e.Read("/proc/sys/kernel/osrelease")
	if running == "" {
		return ""
	}
	newest := ""
	for _, k := range e.installedKernels() {
		// Flavors (generic, lowlatency, pve) are separate lines that sort by
		// name, not age; compare like with like.
		if kernelFlavor(k) != kernelFlavor(running) {
			continue
		}
		if newest == "" || vercmp.RPM(k, newest) > 0 {
			newest = k
		}
	}
	if newest != "" && vercmp.RPM(newest, running) > 0 {
		return "running kernel " + running + " is older than the installed " + newest
	}
	return ""
}

// installedKernels lists module directories that still hold a kernel; a
// removed kernel can leave an empty directory behind.
func (e *Env) installedKernels() []string {
	seen := map[string]bool{}
	var out []string
	for _, dir := range []string{"/lib/modules", "/usr/lib/modules"} {
		for _, name := range e.ReadDir(dir) {
			if seen[name] {
				continue
			}
			p := dir + "/" + name + "/"
			if e.Exists(p+"modules.dep") || e.Exists(p+"vmlinuz") {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// kernelFlavor is what follows the last numeric segment of a kernel
// release: "generic" in 6.8.0-85-generic, "cloud-amd64" in
// 6.1.0-26-cloud-amd64, "pve" in 6.8.12-4-pve; "" for Fedora and RHEL.
func kernelFlavor(release string) string {
	segs := strings.Split(release, "-")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" && segs[i][0] >= '0' && segs[i][0] <= '9' {
			return strings.Join(segs[i+1:], "-")
		}
	}
	return ""
}

// deletedLibServices lists the .service units whose processes map a
// deleted shared library: they run old code until restarted.
func (e *Env) deletedLibServices() []string {
	units := map[string]bool{}
	for _, name := range e.ReadDir("/proc") {
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		// Only services are reported, which also leaves out containers
		// (their own scopes), sessions and init.scope. Reading the cgroup
		// first saves scanning maps we'd ignore.
		unit := e.procUnit(pid)
		if !strings.HasSuffix(unit, ".service") || units[unit] {
			continue
		}
		if e.mapsDeletedLib(name) {
			units[unit] = true
		}
	}
	out := make([]string, 0, len(units))
	for u := range units {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// mapsDeletedLib reports whether a process maps a shared library that has
// been deleted (replaced by an upgrade). Kernel threads have empty maps.
func (e *Env) mapsDeletedLib(pid string) bool {
	f, err := os.Open(e.path("/proc/" + pid + "/maps"))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		p, ok := strings.CutSuffix(line, " (deleted)")
		if !ok {
			continue
		}
		if i := strings.LastIndexByte(p, '/'); i >= 0 && strings.Contains(p[i:], ".so") {
			return true
		}
	}
	return false
}

func sortedUniq(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	sort.Strings(s)
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

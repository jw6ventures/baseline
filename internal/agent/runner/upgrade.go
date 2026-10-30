package runner

import (
	"context"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
)

// upgrade is pkg.upgrade (docs/agent.md §2): refresh metadata, upgrade with
// each package manager the request covers, read the versions back from the
// package database, and reboot if the policy says so. Holds are respected,
// and excludes are glob patterns on package names.
func (r *Runner) upgrade(ctx context.Context, p action.UpgradeParams, out *output) outcome {
	// Package managers take locks; one such job at a time is enough.
	select {
	case r.pkg <- struct{}{}:
	default:
		out.info("Waiting for another package job on this host to finish…\n")
		select {
		case r.pkg <- struct{}{}:
		case <-ctx.Done():
			return failed("stopped while waiting for another package job")
		}
	}
	defer func() { <-r.pkg }()
	env := r.Env

	before, err := env.Packages(ctx)
	if err != nil {
		return failed("reading installed packages: %v", err)
	}
	out.info("Refreshing package metadata…\n")
	ups, err := env.Updates(ctx)
	if err != nil {
		return failed("checking for updates: %v", err)
	}
	res := action.UpgradeResult{Warnings: ups.Warnings}
	for _, w := range ups.Warnings {
		out.info("warning: %s\n", w)
	}

	system := ""
	for _, m := range ups.Managers {
		if m == "apt" || m == "dnf" || m == "rpm-ostree" {
			system = m
		}
	}
	// Selected packages per manager: "name" means the system manager. Pins
	// are their exact versions (Versions), by manager and name.
	want := map[string][]string{}
	pins := map[string]map[string]string{}
	for _, pk := range p.Packages {
		m, name, ok := strings.Cut(pk, ":")
		if !ok || !slices.Contains([]string{"apt", "dnf", "rpm-ostree", "flatpak", "snap"}, m) {
			m, name = system, pk
		}
		if m == "apt" || m == "dnf" || m == "rpm-ostree" {
			m = system
		}
		want[m] = append(want[m], name)
		if v, ok := p.Versions[pk]; ok {
			if pins[m] == nil {
				pins[m] = map[string]string{}
			}
			pins[m][name] = v
		}
	}

	var runErr *outcome
	for _, m := range []string{system, "flatpak", "snap"} {
		if m == "" || !slices.Contains(ups.Managers, m) {
			continue
		}
		switch {
		case p.Mode == action.ModeSelected && len(want[m]) == 0:
			continue
		case p.Mode == action.ModeSecurity && (m == "flatpak" || m == "snap"):
			continue // no security information to go by
		case p.Mode == action.ModeSecurity && m == "rpm-ostree":
			w := "rpm-ostree: image-based hosts take whole-image updates only, so security mode skips them"
			out.info("%s\n", w)
			res.Warnings = append(res.Warnings, w)
			continue
		}
		cands, warns := upgradeCands(m, p, want[m], pins[m], ups, before.Packages)
		for _, w := range warns {
			out.info("%s\n", w)
			res.Warnings = append(res.Warnings, w)
		}
		if len(cands) == 0 {
			out.info("%s: nothing to upgrade\n", m)
			continue
		}
		cmd, ok := upgradeCmd(m, p, cands, pins[m])
		if !ok {
			out.info("%s: nothing to upgrade\n", m)
			continue
		}
		res.Managers = append(res.Managers, m)
		code, err := r.exec(ctx, cmd, out)
		if err != nil || code != 0 {
			o := outcome{failed: true, exitCode: code, err: fmt.Sprintf("%s exited with status %d", m, code)}
			if err != nil {
				o.err = fmt.Sprintf("%s: %v", m, err)
			}
			runErr = &o
			break
		}
	}

	// Read back what changed, even after a failure: a half-done upgrade
	// should still say what it did. The job's context may be gone.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if after, err := env.Packages(rctx); err == nil {
		res.Changed, res.Added, res.Removed = diffPackages(before.Packages, after.Packages)
	} else {
		res.Warnings = append(res.Warnings, "reading installed packages afterwards: "+err.Error())
	}
	rb, err := env.Reboot(rctx)
	if err == nil {
		res.RebootRequired, res.RebootReasons = rb.Required, rb.Reasons
	}
	out.info("\n%s\n", upgradeSummary(res))

	if runErr != nil {
		runErr.result = res
		return *runErr
	}
	o := outcome{result: &res}
	if p.Reboot == action.RebootAlways || (p.Reboot == action.RebootIfRequired && res.RebootRequired) {
		res.Rebooting = true
		o.reboot, o.delay = true, action.DefaultRebootDelay*time.Second
		out.info("Rebooting in %d seconds.\n", action.DefaultRebootDelay)
	} else if res.RebootRequired {
		out.info("A reboot is required to finish: %s.\n", strings.Join(res.RebootReasons, "; "))
	}
	return o
}

// upgradeCands are the updates manager m applies for a request: want are
// the names a selected upgrade lists, pins their exact versions. Held and
// excluded packages are left out. A pinned package is named even when the
// host has no update for it, or one to another version: the manager then
// installs exactly the pinned version or fails. warns says what was left
// out that a pin asked for.
func upgradeCands(m string, p action.UpgradeParams, want []string, pins map[string]string, ups model.Updates,
	installed []model.Package) (cands []model.Update, warns []string) {
	excluded := func(name string) bool {
		for _, g := range p.Exclude {
			if ok, _ := path.Match(g, name); ok {
				return true
			}
		}
		return false
	}
	for _, u := range ups.Updates {
		switch {
		case u.Manager != m, excluded(u.Name), slices.Contains(ups.Held, u.Name):
		case p.Mode == action.ModeSecurity && !u.Security:
		case p.Mode == action.ModeSelected && m != "rpm-ostree" && !slices.Contains(want, u.Name):
		default:
			if v, ok := pins[u.Name]; ok {
				u.Candidate = v
			}
			cands = append(cands, u)
		}
	}
	if len(pins) == 0 {
		return cands, nil
	}
	if m == "rpm-ostree" {
		// The host has one image: a pinned version of it is deployed
		// whatever the update check found.
		for _, name := range want {
			if v, ok := pins[name]; ok {
				u := model.Update{Manager: m, Name: name, Candidate: v, Image: true}
				if len(cands) > 0 {
					u.Installed = cands[0].Installed
				}
				return []model.Update{u}, nil
			}
		}
		return cands, nil
	}
	for _, name := range want {
		v, ok := pins[name]
		if !ok || slices.ContainsFunc(cands, func(u model.Update) bool { return u.Name == name }) {
			continue
		}
		var from string
		for _, pk := range installed {
			if pk.Manager == m && pk.Name == name {
				from = pk.FullVersion()
			}
		}
		switch {
		case excluded(name):
		case slices.Contains(ups.Held, name):
			warns = append(warns, fmt.Sprintf("%s: %s is held, so it stays at %s rather than %s", m, name, from, v))
		case from == "":
			warns = append(warns, fmt.Sprintf("%s: %s isn't installed, so it can't be upgraded to %s", m, name, v))
		default:
			cands = append(cands, model.Update{Manager: m, Name: name, Installed: from, Candidate: v})
		}
	}
	return cands, warns
}

// upgradeCmd is the command that upgrades cands with manager m, naming the
// pinned ones with their versions. It is false when there is nothing to
// name (apt with only newly pulled-in packages).
func upgradeCmd(m string, p action.UpgradeParams, cands []model.Update, pins map[string]string) (Cmd, bool) {
	var names []string
	for _, u := range cands {
		// A package an upgrade would newly pull in (a new kernel) isn't
		// installed, so it can't be named; it comes along as a dependency.
		if u.Installed == "" && m == "apt" {
			continue
		}
		name := u.Name
		if v, ok := pins[u.Name]; ok {
			switch m {
			case "apt":
				name += "=" + v
			case "dnf":
				name += "-" + v // name-[epoch:]version-release
			}
		}
		names = append(names, name)
	}
	names = uniq(names)
	// Name packages unless everything goes: then the manager's own full
	// upgrade also handles new dependencies and obsoletes.
	everything := p.Mode == action.ModeAll && len(p.Exclude) == 0
	switch m {
	case "apt":
		args := []string{"-y", "-q", "-o", "DPkg::Lock::Timeout=600",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
		if everything {
			args = append(args, "dist-upgrade")
		} else {
			if len(names) == 0 {
				return Cmd{}, false
			}
			args = append(append(args, "install", "--only-upgrade"), names...)
		}
		// needrestart lists services to restart rather than restarting them
		// in the middle of the job; the reboot section reports them.
		return Cmd{Name: "apt-get", Args: args, Env: []string{"DEBIAN_FRONTEND=noninteractive",
			"APT_LISTCHANGES_FRONTEND=none", "NEEDRESTART_MODE=l"}}, true
	case "dnf":
		args := []string{"-y", "upgrade"}
		if p.Mode == action.ModeSecurity {
			args = append(args, "--security")
		}
		for _, g := range p.Exclude {
			args = append(args, "--exclude="+g)
		}
		if p.Mode == action.ModeSelected {
			args = append(args, names...)
		}
		return Cmd{Name: "dnf", Args: args}, true
	case "rpm-ostree":
		// A pinned image version is deployed as such (docs/agent.md §2,
		// image-based hosts).
		for _, u := range cands {
			if v, ok := pins[u.Name]; ok {
				return Cmd{Name: "rpm-ostree", Args: []string{"deploy", v}}, true
			}
		}
		return Cmd{Name: "rpm-ostree", Args: []string{"upgrade"}}, true
	case "flatpak":
		args := []string{"update", "-y", "--noninteractive"}
		if !everything {
			args = append(args, names...)
		}
		return Cmd{Name: "flatpak", Args: args}, true
	case "snap":
		args := []string{"refresh"}
		if !everything {
			args = append(args, names...)
		}
		return Cmd{Name: "snap", Args: args}, true
	}
	return Cmd{}, false
}

// diffPackages compares package lists by manager, name and arch. A package
// installed in several versions (kernels) compares as its set of versions.
func diffPackages(before, after []model.Package) (changed, added, removed []action.PackageChange) {
	type key struct{ manager, name, arch string }
	versions := func(ps []model.Package) map[key][]string {
		m := map[key][]string{}
		for _, p := range ps {
			k := key{p.Manager, p.Name, p.Arch}
			m[k] = append(m[k], p.FullVersion())
		}
		for k := range m {
			sort.Strings(m[k])
		}
		return m
	}
	b, a := versions(before), versions(after)
	for k, av := range a {
		bv, ok := b[k]
		switch {
		case !ok:
			added = append(added, action.PackageChange{Manager: k.manager, Name: k.name, Arch: k.arch, To: strings.Join(av, ", ")})
		case !slices.Equal(av, bv):
			changed = append(changed, action.PackageChange{Manager: k.manager, Name: k.name, Arch: k.arch,
				From: strings.Join(bv, ", "), To: strings.Join(av, ", ")})
		}
	}
	for k, bv := range b {
		if _, ok := a[k]; !ok {
			removed = append(removed, action.PackageChange{Manager: k.manager, Name: k.name, Arch: k.arch, From: strings.Join(bv, ", ")})
		}
	}
	for _, l := range [][]action.PackageChange{changed, added, removed} {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Manager != l[j].Manager {
				return l[i].Manager < l[j].Manager
			}
			if l[i].Name != l[j].Name {
				return l[i].Name < l[j].Name
			}
			return l[i].Arch < l[j].Arch
		})
	}
	return changed, added, removed
}

func upgradeSummary(r action.UpgradeResult) string {
	if len(r.Changed)+len(r.Added)+len(r.Removed) == 0 {
		return "No packages changed."
	}
	var parts []string
	if n := len(r.Changed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d upgraded", n))
	}
	if n := len(r.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d installed", n))
	}
	if n := len(r.Removed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", n))
	}
	return "Packages: " + strings.Join(parts, ", ") + "."
}

func uniq(s []string) []string {
	var out []string
	for _, v := range s {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

package collect

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/vercmp"
)

// refreshTimeout bounds a repository refresh, which downloads metadata and
// can be slow on a cold cache.
const refreshTimeout = 15 * time.Minute

// Updates collects the "updates" section: what upgrading would install now
// (docs/agent.md §2). Refreshing repository metadata is read-only on the
// system's packages.
//
// A network problem (a repository that can't be refreshed, a flatpak remote
// that is down) becomes a warning and the rest of the check goes on. A local
// failure (the package database can't be read) fails the section, and the
// server keeps the last good copy.
func (e *Env) Updates(ctx context.Context) (model.Updates, error) {
	u := model.Updates{Managers: []string{}, Updates: []model.Update{}}
	warn := func(manager, what string, err error) {
		u.Warnings = append(u.Warnings, fmt.Sprintf("%s: %s: %s", manager, what, firstLine(err)))
	}

	imageBased := e.Exists("/run/ostree-booted") && e.Has("rpm-ostree")
	switch {
	case imageBased:
		up, err := e.imageUpdate(ctx)
		if err != nil {
			warn("rpm-ostree", "update check failed", err)
		} else if up != nil {
			u.Updates = append(u.Updates, *up)
		}
		u.Managers = append(u.Managers, "rpm-ostree")
	case e.Has("dpkg-query") && e.Has("apt-get"):
		ups, held, err := e.aptUpdates(ctx, warn)
		if err != nil {
			return u, fmt.Errorf("apt: %w", err)
		}
		u.Managers = append(u.Managers, "apt")
		u.Updates = append(u.Updates, ups...)
		u.Held = append(u.Held, held...)
	case e.Has("rpm") && e.Has("dnf"):
		ups, err := e.dnfUpdates(ctx, warn)
		if err != nil {
			return u, fmt.Errorf("dnf: %w", err)
		}
		u.Managers = append(u.Managers, "dnf")
		u.Updates = append(u.Updates, ups...)
	}
	if e.Has("flatpak") {
		ups, err := e.flatpakUpdates(ctx)
		if err != nil {
			warn("flatpak", "update check failed", err)
		}
		u.Managers = append(u.Managers, "flatpak")
		u.Updates = append(u.Updates, ups...)
	}
	if e.Has("snap") && e.Exists("/run/snapd.socket") {
		ups, err := e.snapUpdates(ctx)
		if err != nil {
			warn("snap", "update check failed", err)
		}
		u.Managers = append(u.Managers, "snap")
		u.Updates = append(u.Updates, ups...)
	}

	sort.Slice(u.Updates, func(i, j int) bool {
		a, b := u.Updates[i], u.Updates[j]
		if a.Manager != b.Manager {
			return a.Manager < b.Manager
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Arch < b.Arch
	})
	sort.Strings(u.Held)
	return u, nil
}

// apt -------------------------------------------------------------------------

func (e *Env) aptUpdates(ctx context.Context, warn func(string, string, error)) ([]model.Update, []string, error) {
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	_, err := e.Run(rctx, "apt-get", "update", "-q", "-o", "DPkg::Lock::Timeout=120")
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		warn("apt", "couldn't refresh package lists", err)
	}
	// A simulation needs no lock, so it works while unattended-upgrades runs.
	out, err := e.Run(ctx, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil {
		return nil, nil, err
	}
	var held []string
	if out, err := e.Run(ctx, "apt-mark", "showhold"); err == nil {
		held = strings.Fields(string(out))
	}
	return parseAptSimulate(string(out)), held, nil
}

// parseAptSimulate reads the "Inst" lines of `apt-get -s dist-upgrade`:
//
//	Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//	Inst linux-image-6.8.0-86-generic (6.8.0-86.87 Ubuntu:24.04/noble-updates [amd64])
//
// The second form has no installed version: a package the upgrade pulls in.
func parseAptSimulate(out string) []model.Update {
	var ups []model.Update
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "Inst ")
		if !ok {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		u := model.Update{Manager: "apt", Name: name}
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				continue
			}
			u.Installed, rest = rest[1:end], strings.TrimSpace(rest[end+1:])
		}
		open, end := strings.IndexByte(rest, '('), strings.LastIndexByte(rest, ')')
		if open != 0 || end < 0 {
			continue
		}
		body := rest[1:end]
		if i := strings.LastIndex(body, " ["); i >= 0 && strings.HasSuffix(body, "]") {
			u.Arch, body = body[i+2:len(body)-1], body[:i]
		}
		u.Candidate, body, _ = strings.Cut(body, " ")
		for _, origin := range strings.Split(body, ",") {
			origin = strings.TrimSpace(origin)
			if origin == "" {
				continue
			}
			if u.Repo == "" {
				u.Repo = origin
			}
			if strings.Contains(origin, "-security") {
				u.Security = true
			}
		}
		if n, arch, ok := strings.Cut(u.Name, ":"); ok { // multiarch: libc6:i386
			u.Name, u.Arch = n, arch
		}
		ups = append(ups, u)
	}
	return ups
}

// dnf -------------------------------------------------------------------------

func (e *Env) dnfUpdates(ctx context.Context, warn func(string, string, error)) ([]model.Update, error) {
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	_, err := e.Run(rctx, "dnf", "-q", "makecache")
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		warn("dnf", "couldn't refresh repository metadata", err)
	}
	// From the cache only: the refresh above already went to the network.
	out, err := e.Run(ctx, "dnf", "-q", "-C", "check-update")
	if code := exitCode(err); code != 0 && code != 100 {
		return nil, err
	}
	ups := parseDnfCheckUpdate(string(out))
	if len(ups) == 0 {
		return ups, nil
	}

	// check-update doesn't print installed versions.
	pkgs, err := e.rpmPackages(ctx, "dnf")
	if err != nil {
		return nil, err
	}
	installed := map[string]string{}
	for _, p := range pkgs {
		k := p.Name + "." + p.Arch
		// Kernels are installed in several versions; show the newest.
		if v, ok := installed[k]; !ok || vercmp.RPM(p.FullVersion(), v) > 0 {
			installed[k] = p.FullVersion()
		}
	}
	for i := range ups {
		ups[i].Installed = installed[ups[i].Name+"."+ups[i].Arch]
	}

	if out, err := e.Run(ctx, "dnf", "-q", "-C", "updateinfo", "list", "--security"); err != nil {
		warn("dnf", "couldn't read security advisories", err)
	} else {
		markSecurity(ups, parseDnfAdvisories(string(out)))
	}
	return ups, nil
}

// parseDnfCheckUpdate reads `dnf check-update`: "name.arch  [epoch:]version-release  repo".
// dnf4 wraps a long name onto a line of its own, so a one-field line joins
// the next. The obsoletes list at the end is not upgrades and is skipped.
func parseDnfCheckUpdate(out string) []model.Update {
	var ups []model.Update
	var carry string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		f := strings.Fields(line)
		if carry != "" {
			if len(f) == 2 {
				f = append([]string{carry}, f...)
			}
			carry = ""
		}
		switch {
		case len(f) == 1 && strings.Contains(f[0], ".") && !strings.HasSuffix(f[0], ":"):
			carry = f[0]
			continue
		case len(f) != 3:
			continue
		}
		dot := strings.LastIndexByte(f[0], '.')
		if dot <= 0 || !strings.Contains(f[1], "-") || !strings.ContainsAny(f[1], "0123456789") {
			continue
		}
		ups = append(ups, model.Update{Manager: "dnf", Name: f[0][:dot], Arch: f[0][dot+1:], Candidate: f[1], Repo: f[2]})
	}
	return ups
}

// parseDnfAdvisories reads `dnf updateinfo list --security`. dnf4 prints
// "ID  severity/Sec.  nevra" and dnf5 "ID  type  severity  nevra  issued";
// either way the first field is the advisory and one field is a NEVRA.
// It returns advisory IDs by name.arch.
func parseDnfAdvisories(out string) map[string][]string {
	adv := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		for _, field := range f[1:] {
			if name, arch, ok := parseNEVRA(field); ok {
				k := name + "." + arch
				if !slices.Contains(adv[k], f[0]) {
					adv[k] = append(adv[k], f[0])
				}
				break
			}
		}
	}
	return adv
}

var rpmArches = []string{"x86_64", "noarch", "aarch64", "i686", "ppc64le", "s390x", "armv7hl"}

// parseNEVRA splits name-[epoch:]version-release.arch, keeping name and arch.
func parseNEVRA(s string) (name, arch string, ok bool) {
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 || !slices.Contains(rpmArches, s[dot+1:]) {
		return "", "", false
	}
	arch, s = s[dot+1:], s[:dot]
	for range 2 { // release, then version
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return "", "", false
		}
		s = s[:i]
	}
	return s, arch, true
}

func markSecurity(ups []model.Update, adv map[string][]string) {
	for i := range ups {
		if ids := adv[ups[i].Name+"."+ups[i].Arch]; len(ids) > 0 {
			ups[i].Security = true
			ups[i].Advisories = slices.Sorted(slices.Values(ids))
		}
	}
}

// rpm-ostree ------------------------------------------------------------------

// imageUpdate checks for a newer OS image. Image-based hosts upgrade as a
// whole, so this is one update for the image rather than per package.
func (e *Env) imageUpdate(ctx context.Context) (*model.Update, error) {
	img, err := e.rpmOstreeImage(ctx)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	out, err := e.Run(rctx, "rpm-ostree", "upgrade", "--check")
	switch exitCode(err) {
	case 0:
	case 77: // no update available
		return nil, nil
	default:
		return nil, err
	}
	version, digest := parseUpgradeCheck(string(out))
	if version == "" && digest == "" {
		return nil, nil
	}
	return &model.Update{
		Manager: "rpm-ostree", Name: imageName(img.Origin), Installed: img.Version,
		Candidate: firstNonEmpty(version, short(digest, 19)), Digest: digest, Image: true,
	}, nil
}

// parseUpgradeCheck reads `rpm-ostree upgrade --check`:
//
//	AvailableUpdate:
//	        Version: 42.20261008.0 (2026-10-08T04:32:11Z)
//	         Digest: sha256:4f1c...
func parseUpgradeCheck(out string) (version, digest string) {
	in := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "AvailableUpdate:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Version":
			version = strings.Fields(v + " ")[0]
		case "Digest", "Commit":
			if digest == "" {
				digest = v
			}
		}
	}
	return version, digest
}

// imageName drops the transport from an ostree container origin:
// "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable".
func imageName(origin string) string {
	if i := strings.Index(origin, "://"); i >= 0 {
		return origin[i+3:]
	}
	return origin
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// flatpak ---------------------------------------------------------------------

func (e *Env) flatpakUpdates(ctx context.Context) ([]model.Update, error) {
	out, err := e.Run(ctx, "flatpak", "list", "--columns=application,branch,arch,version,active")
	if err != nil {
		return nil, err
	}
	type inst struct{ version, commit string }
	installed := map[string]inst{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 5 && f[0] != "" {
			installed[f[0]+"/"+f[2]+"/"+f[1]] = inst{f[3], f[4]}
		}
	}
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	out, err = e.Run(rctx, "flatpak", "remote-ls", "--updates", "--columns=application,branch,arch,version,origin,commit")
	if err != nil {
		return nil, err
	}
	var ups []model.Update
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 6 || f[0] == "" {
			continue
		}
		have := installed[f[0]+"/"+f[2]+"/"+f[1]]
		u := model.Update{Manager: "flatpak", Name: f[0], Arch: f[2], Installed: have.version, Candidate: f[3], Repo: f[4]}
		// Runtimes have no version, and a rebuild keeps it: show commits.
		if u.Candidate == "" || u.Candidate == u.Installed {
			u.Installed, u.Candidate = short(have.commit, 12), short(f[5], 12)
		}
		if f[1] != "stable" && f[1] != "" {
			u.Name += "//" + f[1]
		}
		ups = append(ups, u)
	}
	return ups, nil
}

// snap ------------------------------------------------------------------------

func (e *Env) snapUpdates(ctx context.Context) ([]model.Update, error) {
	out, err := e.Run(ctx, "snap", "list", "--unicode=never", "--color=never")
	if err != nil {
		return nil, err
	}
	installed := map[string]string{}
	for _, p := range parseSnap(string(out)) {
		installed[p.Name] = p.Version + " (" + p.Release + ")"
	}
	rctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	out, err = e.Run(rctx, "snap", "refresh", "--list")
	if err != nil {
		return nil, err
	}
	var ups []model.Update
	for i, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || f[0] == "Name" {
			continue
		}
		ups = append(ups, model.Update{Manager: "snap", Name: f[0], Installed: installed[f[0]], Candidate: f[1] + " (" + f[2] + ")"})
	}
	return ups, nil
}

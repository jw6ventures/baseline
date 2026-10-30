package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
)

// Packages collects the "packages" section. If any manager fails the whole
// section fails: a partial list would read as mass removals in the history.
func (e *Env) Packages(ctx context.Context) (model.Packages, error) {
	p := model.Packages{Managers: []string{}, Packages: []model.Package{}}
	add := func(name string, pkgs []model.Package, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		p.Managers = append(p.Managers, name)
		p.Packages = append(p.Packages, pkgs...)
		return nil
	}

	imageBased := e.Exists("/run/ostree-booted") && e.Has("rpm-ostree")
	switch {
	case imageBased:
		pkgs, err := e.rpmPackages(ctx, "rpm-ostree")
		if err == nil {
			if out, err := e.Run(ctx, "rpm-ostree", "status", "--json"); err == nil {
				layered := parseLayered(out)
				for i := range pkgs {
					pkgs[i].Layered = layered[pkgs[i].Name]
				}
			}
		}
		if err := add("rpm-ostree", pkgs, err); err != nil {
			return p, err
		}
	case e.Has("dpkg-query"):
		out, err := e.Run(ctx, "dpkg-query", "-W", "-f",
			`${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\n`)
		if err := add("apt", parseDpkg(string(out)), err); err != nil {
			return p, err
		}
	case e.Has("rpm"):
		name := "rpm"
		if e.Has("dnf") || e.Has("yum") {
			name = "dnf"
		}
		pkgs, err := e.rpmPackages(ctx, name)
		if err := add(name, pkgs, err); err != nil {
			return p, err
		}
	}
	if e.Has("flatpak") {
		out, err := e.Run(ctx, "flatpak", "list", "--columns=application,version,branch,arch,origin")
		if err := add("flatpak", parseFlatpak(string(out)), err); err != nil {
			return p, err
		}
	}
	if e.Has("snap") && e.Exists("/run/snapd.socket") {
		out, err := e.Run(ctx, "snap", "list", "--unicode=never", "--color=never")
		if err := add("snap", parseSnap(string(out)), err); err != nil {
			return p, err
		}
	}

	sort.Slice(p.Packages, func(i, j int) bool {
		a, b := p.Packages[i], p.Packages[j]
		if a.Manager != b.Manager {
			return a.Manager < b.Manager
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Arch != b.Arch {
			return a.Arch < b.Arch
		}
		return a.FullVersion() < b.FullVersion()
	})
	return p, nil
}

// parseDpkg reads dpkg-query output, keeping fully installed packages only.
func parseDpkg(out string) []model.Package {
	var pkgs []model.Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || !strings.HasPrefix(f[0], "ii") {
			continue
		}
		p := model.Package{Manager: "apt", Name: f[1], Arch: f[3], Source: f[4]}
		p.Epoch, p.Version = splitEpoch(f[2])
		if p.Source == p.Name {
			p.Source = ""
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func splitEpoch(v string) (epoch, rest string) {
	if e, r, ok := strings.Cut(v, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		return e, r
	}
	return "", v
}

func (e *Env) rpmPackages(ctx context.Context, manager string) ([]model.Package, error) {
	out, err := e.Run(ctx, "rpm", "-qa", "--queryformat",
		`%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`)
	if err != nil {
		return nil, err
	}
	return parseRpm(string(out), manager), nil
}

func parseRpm(out, manager string) []model.Package {
	var pkgs []model.Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 6 || f[0] == "gpg-pubkey" || f[0] == "" {
			continue
		}
		p := model.Package{Manager: manager, Name: f[0], Version: f[2], Release: f[3], Arch: f[4]}
		if f[1] != "0" && f[1] != "(none)" {
			p.Epoch = f[1]
		}
		if p.Arch == "(none)" {
			p.Arch = ""
		}
		if src := sourceRPMName(f[5]); src != p.Name {
			p.Source = src
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// sourceRPMName turns "openssl-3.2.2-6.el10.src.rpm" into "openssl".
func sourceRPMName(s string) string {
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".rpm"), ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	for range 2 {
		if i := strings.LastIndexByte(s, '-'); i > 0 {
			s = s[:i]
		}
	}
	if s == "(none)" {
		return ""
	}
	return s
}

// parseFlatpak reads `flatpak list --columns=application,version,branch,arch,origin`.
func parseFlatpak(out string) []model.Package {
	var pkgs []model.Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || f[0] == "" {
			continue
		}
		p := model.Package{Manager: "flatpak", Name: f[0], Version: f[1], Arch: f[3], Repo: f[4]}
		// Runtimes have no version, only a branch; apps can be installed
		// from several branches at once.
		switch {
		case p.Version == "":
			p.Version = f[2]
		case f[2] != "stable" && f[2] != "":
			p.Release = f[2]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// parseSnap reads `snap list`: Name Version Rev Tracking Publisher Notes.
func parseSnap(out string) []model.Package {
	var pkgs []model.Package
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 {
			continue
		}
		p := model.Package{Manager: "snap", Name: f[0], Version: f[1], Release: f[2]}
		if len(f) >= 4 {
			p.Repo = f[3] // tracking channel
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

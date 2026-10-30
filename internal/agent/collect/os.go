package collect

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// Identity is what the agent reports in Hello and at enrollment.
type Identity struct {
	MachineID string
	DMIUUID   string
	Hostname  string
	BootID    string
	BootTime  time.Time
}

func (e *Env) Identity() Identity {
	id := Identity{
		MachineID: e.Read("/etc/machine-id"),
		DMIUUID:   strings.ToLower(e.Read("/sys/class/dmi/id/product_uuid")),
		Hostname:  e.hostname(),
		BootID:    e.Read("/proc/sys/kernel/random/boot_id"),
	}
	for _, line := range strings.Split(e.Read("/proc/stat"), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				id.BootTime = time.Unix(n, 0)
			}
		}
	}
	return id
}

func (e *Env) hostname() string {
	if h := e.Read("/proc/sys/kernel/hostname"); h != "" {
		return h
	}
	if e.Root == "" {
		h, _ := os.Hostname()
		return h
	}
	return e.Read("/etc/hostname")
}

// OS collects the "os" section.
func (e *Env) OS(ctx context.Context) (model.OS, error) {
	rel := parseKV(e.Read("/etc/os-release"))
	if len(rel) == 0 {
		rel = parseKV(e.Read("/usr/lib/os-release"))
	}
	o := model.OS{
		Hostname:   e.hostname(),
		ID:         rel["ID"],
		IDLike:     rel["ID_LIKE"],
		Name:       rel["NAME"],
		Version:    rel["VERSION"],
		VersionID:  rel["VERSION_ID"],
		VariantID:  rel["VARIANT_ID"],
		PrettyName: rel["PRETTY_NAME"],
		Kernel:     e.Read("/proc/sys/kernel/osrelease"),
		MachineID:  e.Read("/etc/machine-id"),
		Timezone:   e.timezone(),
	}
	if o.PrettyName == "" {
		o.PrettyName = strings.TrimSpace(o.Name + " " + o.Version)
	}
	o.Arch = e.arch()
	o.FQDN = e.fqdn(o.Hostname)
	if e.Exists("/run/ostree-booted") && e.Has("rpm-ostree") {
		img, err := e.rpmOstreeImage(ctx)
		if err == nil {
			o.Image = img
		}
	}
	return o, nil
}

func (e *Env) arch() string {
	if e.Root != "" {
		return e.Read("/proc/sys/kernel/arch")
	}
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range u.Machine {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

func (e *Env) timezone() string {
	if tz := e.Read("/etc/timezone"); tz != "" {
		return tz
	}
	t, err := os.Readlink(e.path("/etc/localtime"))
	if err != nil {
		return ""
	}
	if _, after, ok := strings.Cut(t, "zoneinfo/"); ok {
		return after
	}
	return ""
}

// fqdn resolves the hostname's canonical name. It only reports names with a
// dot, and nothing when DNS doesn't know the host.
func (e *Env) fqdn(hostname string) string {
	if e.Root != "" || hostname == "" {
		return ""
	}
	if strings.Contains(hostname, ".") {
		return hostname
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cname, err := net.DefaultResolver.LookupCNAME(ctx, hostname)
	cname = strings.TrimSuffix(cname, ".")
	if err != nil || !strings.Contains(cname, ".") {
		return ""
	}
	return cname
}

// rpmOstreeImage describes the booted and staged deployments.
func (e *Env) rpmOstreeImage(ctx context.Context) (*model.OSImage, error) {
	out, err := e.Run(ctx, "rpm-ostree", "status", "--json")
	if err != nil {
		return nil, err
	}
	return parseRpmOstreeStatus(out)
}

type rpmOstreeStatus struct {
	Deployments []struct {
		Booted                bool     `json:"booted"`
		Staged                bool     `json:"staged"`
		Version               string   `json:"version"`
		Checksum              string   `json:"checksum"`
		Origin                string   `json:"origin"`
		ContainerImageRef     string   `json:"container-image-reference"`
		ContainerImageDigest  string   `json:"container-image-reference-digest"`
		RequestedPackages     []string `json:"requested-packages"`
		Packages              []string `json:"packages"`
		RequestedLocalPkgs    []string `json:"requested-local-packages"`
		BaseRemovals          []any    `json:"base-removals"`
		RequestedBaseRemovals []string `json:"requested-base-removals"`
	} `json:"deployments"`
}

func parseRpmOstreeStatus(out []byte) (*model.OSImage, error) {
	var st rpmOstreeStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, err
	}
	img := &model.OSImage{}
	for _, d := range st.Deployments {
		switch {
		case d.Booted:
			img.Origin = d.ContainerImageRef
			if img.Origin == "" {
				img.Origin = d.Origin
			}
			img.Version, img.Checksum, img.Digest = d.Version, d.Checksum, d.ContainerImageDigest
		case d.Staged:
			img.Staged = &model.OSImageStaged{Version: d.Version, Checksum: d.Checksum}
		}
	}
	return img, nil
}

// layeredPackages are the names rpm-ostree reports as layered on the booted
// deployment.
func parseLayered(out []byte) map[string]bool {
	var st rpmOstreeStatus
	layered := map[string]bool{}
	if json.Unmarshal(out, &st) != nil {
		return layered
	}
	for _, d := range st.Deployments {
		if !d.Booted {
			continue
		}
		for _, list := range [][]string{d.Packages, d.RequestedPackages, d.RequestedLocalPkgs} {
			for _, p := range list {
				layered[p] = true
			}
		}
	}
	return layered
}

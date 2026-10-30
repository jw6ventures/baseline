package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/jw6ventures/baseline/internal/model"
)

// pveValue is a pvesh JSON scalar. pvesh prints numbers as numbers or as
// strings depending on the API schema and version, so both are accepted and
// kept as text.
type pveValue string

func (v *pveValue) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = pveValue(s)
		return nil
	}
	if string(b) == "null" {
		*v = ""
		return nil
	}
	// A number or a bool; objects and arrays are never read.
	*v = pveValue(b)
	return nil
}

func (v pveValue) String() string { return strings.TrimSpace(string(v)) }

// Int is the value as an integer, 0 when it isn't one.
func (v pveValue) Int() int64 {
	s := v.String()
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f)
	}
	return 0
}

func (v pveValue) Bool() bool {
	s := v.String()
	return s == "true" || v.Int() != 0
}

// pveConfig is a guest's config: flat keys to scalar values.
type pveConfig map[string]pveValue

type pveResource struct {
	VMID     pveValue `json:"vmid"`
	Name     string   `json:"name"`
	Node     string   `json:"node"`
	Type     string   `json:"type"`
	Status   string   `json:"status"`
	Template pveValue `json:"template"`
	Tags     string   `json:"tags"`
	HAState  string   `json:"hastate"`
	MaxCPU   pveValue `json:"maxcpu"`
}

// pvesh runs `pvesh get <path> [args] --output-format json` and decodes it.
func (e *Env) pvesh(ctx context.Context, v any, path string, args ...string) error {
	argv := append([]string{"get", path}, args...)
	argv = append(argv, "--output-format", "json")
	out, err := e.Run(ctx, "pvesh", argv...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("pvesh get %s: unreadable output", path)
	}
	return nil
}

// proxmoxVMs reads this node's guests and the cluster's storage
// definitions. Each node's agent reports only the guests the node runs.
func (e *Env) proxmoxVMs(ctx context.Context) (model.Hypervisor, []model.Guest, []model.VMStorage) {
	h := model.Hypervisor{Platform: "proxmox"}
	var status []struct {
		Type  string   `json:"type"`
		Name  string   `json:"name"`
		Local pveValue `json:"local"`
	}
	if err := e.pvesh(ctx, &status, "/cluster/status"); err != nil {
		h.Error = firstLine(err)
		return h, nil, nil
	}
	for _, s := range status {
		switch {
		case s.Type == "node" && s.Local.Bool():
			h.Node = s.Name
		case s.Type == "cluster":
			h.Cluster = s.Name
		}
	}
	var version struct {
		Version string `json:"version"`
	}
	if e.pvesh(ctx, &version, "/version") == nil {
		h.Version = version.Version
	}
	if h.Node == "" {
		h.Error = "local node not found in /cluster/status"
		return h, nil, nil
	}
	storage := e.proxmoxStorage(ctx, h.Node)

	var resources []pveResource
	if err := e.pvesh(ctx, &resources, "/cluster/resources", "--type", "vm"); err != nil {
		h.Error = firstLine(err)
		return h, nil, storage
	}
	var local []pveResource
	for _, r := range resources {
		if r.Node == h.Node && (r.Type == "qemu" || r.Type == "lxc") {
			local = append(local, r)
		}
	}

	// pvesh starts a Perl interpreter per call, so configs are read a few
	// at a time. The first failure in list order is reported, so the
	// message doesn't depend on scheduling.
	guests := make([]model.Guest, len(local))
	errs := make([]error, len(local))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, r := range local {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var cfg pveConfig
			path := "/nodes/" + h.Node + "/" + r.Type + "/" + r.VMID.String() + "/config"
			if err := e.pvesh(ctx, &cfg, path); err != nil {
				errs[i] = fmt.Errorf("%s %s: %s", r.Type, r.VMID.String(), firstLine(err))
				return
			}
			guests[i] = proxmoxGuest(r, cfg)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			h.Error = firstLine(err)
			return h, nil, storage
		}
	}
	return h, guests, storage
}

// proxmoxStorage lists the storage definitions usable on node. A failure
// leaves storage out rather than failing the platform: guests don't depend
// on it.
func (e *Env) proxmoxStorage(ctx context.Context, node string) []model.VMStorage {
	var list []struct {
		Storage string   `json:"storage"`
		Type    string   `json:"type"`
		Content string   `json:"content"`
		Shared  pveValue `json:"shared"`
		Path    string   `json:"path"`
		Nodes   string   `json:"nodes"` // restricted to these nodes; "" for all
	}
	if e.pvesh(ctx, &list, "/storage") != nil {
		return nil
	}
	var out []model.VMStorage
	for _, s := range list {
		if s.Nodes != "" && !contains(pveList(s.Nodes), node) {
			continue
		}
		out = append(out, model.VMStorage{Name: s.Storage, Type: s.Type, Content: pveList(s.Content),
			Shared: s.Shared.Bool(), Path: s.Path})
	}
	return out
}

// pveList splits a Proxmox list ("images,rootdir", tags "a;b" or "a b")
// into sorted, unique, non-empty items.
func pveList(s string) []string {
	return sortedUniq(strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}))
}

func proxmoxGuest(r pveResource, cfg pveConfig) model.Guest {
	g := model.Guest{
		Platform:  "proxmox",
		Kind:      r.Type,
		ID:        r.VMID.String(),
		Name:      r.Name,
		State:     r.Status,
		Template:  r.Template.Bool() || cfg["template"].Bool(),
		Autostart: cfg["onboot"].Bool(),
		OSType:    cfg["ostype"].String(),
		Tags:      pveList(r.Tags),
		HAState:   r.HAState,
	}
	g.MemoryBytes = uint64(pveMemoryMiB(cfg["memory"])) << 20
	if r.Type == "qemu" {
		proxmoxQemu(&g, cfg)
	} else {
		proxmoxLXC(&g, cfg, r.MaxCPU.Int())
	}
	return g
}

// pveMemoryMiB reads `memory`: MiB, as a number, a string, or (PVE 8.1+)
// the property string "current=4096". 512 when unset, Proxmox's default.
func pveMemoryMiB(v pveValue) int64 {
	s := v.String()
	if s == "" {
		return 512
	}
	first, _, _ := strings.Cut(s, ",")
	first = strings.TrimPrefix(first, "current=")
	n, _ := strconv.ParseInt(first, 10, 64)
	return n
}

var (
	pveQemuDiskKey = regexp.MustCompile(`^(scsi|sata|ide|virtio|efidisk|tpmstate)\d+$`)
	pveLXCDiskKey  = regexp.MustCompile(`^(rootfs|mp\d+)$`)
	pveNICKey      = regexp.MustCompile(`^net\d+$`)
)

func proxmoxQemu(g *model.Guest, cfg pveConfig) {
	sockets, cores := cfg["sockets"].Int(), cfg["cores"].Int()
	if sockets <= 0 {
		sockets = 1
	}
	if cores <= 0 {
		cores = 1
	}
	g.CPUs = int(sockets * cores)
	// vcpus is how many of those are plugged in at boot.
	if n := cfg["vcpus"].Int(); n > 0 {
		g.CPUs = int(n)
	}
	opts := pveOptions(cfg["smbios1"].String())
	g.UUID = strings.ToLower(opts["uuid"])
	// machine is "q35", "pc-q35-8.1", or "type=q35,viommu=virtio".
	machine := pveOptions(cfg["machine"].String())
	g.Machine = firstNonEmpty(machine["type"], machine[""])

	for key, v := range cfg {
		switch {
		case pveQemuDiskKey.MatchString(key):
			d := pveDisk(key, v.String())
			d.Device = "disk"
			if pveOptions(v.String())["media"] == "cdrom" {
				d.Device = "cdrom"
			}
			g.Disks = append(g.Disks, d)
		case pveNICKey.MatchString(key):
			g.NICs = append(g.NICs, pveQemuNIC(key, v.String()))
		}
	}
}

func proxmoxLXC(g *model.Guest, cfg pveConfig, maxCPU int64) {
	// No cores limit means the container may use every host CPU, which
	// /cluster/resources reports as maxcpu.
	g.CPUs = int(cfg["cores"].Int())
	if g.CPUs <= 0 {
		g.CPUs = int(maxCPU)
	}
	for key, v := range cfg {
		switch {
		case pveLXCDiskKey.MatchString(key):
			g.Disks = append(g.Disks, pveDisk(key, v.String()))
		case pveNICKey.MatchString(key):
			o := pveOptions(v.String())
			g.NICs = append(g.NICs, model.GuestNIC{Name: key, MAC: strings.ToLower(o["hwaddr"]),
				Bridge: o["bridge"], Model: o["type"], VLAN: pveAtoi(o["tag"])})
		}
	}
}

// pveDisk reads a drive or mount point: "local-lvm:vm-100-disk-0,size=32G",
// "none,media=cdrom", or a bind mount "/srv/data,mp=/data". The volume is
// the first field (or volume=/file=); an empty CD drive has none.
func pveDisk(key, v string) model.GuestDisk {
	o := pveOptions(v)
	src := firstNonEmpty(o[""], o["volume"], o["file"])
	if src == "none" {
		src = ""
	}
	return model.GuestDisk{Name: key, Source: src, SizeBytes: pveSize(o["size"])}
}

// pveQemuNIC reads "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=10": the
// first pair is the model and its MAC. "model=virtio,macaddr=..." and a bare
// "e1000,macaddr=..." are the long forms of the same.
func pveQemuNIC(key, v string) model.GuestNIC {
	n := model.GuestNIC{Name: key}
	first, _, _ := strings.Cut(v, ",")
	if m, mac, ok := strings.Cut(first, "="); ok && m != "model" && strings.Count(mac, ":") == 5 {
		n.Model, n.MAC = m, mac
	}
	o := pveOptions(v)
	n.Model = firstNonEmpty(n.Model, o["model"], o[""])
	n.MAC = strings.ToLower(firstNonEmpty(o["macaddr"], n.MAC))
	n.Bridge = o["bridge"]
	n.VLAN = pveAtoi(o["tag"])
	return n
}

// pveOptions splits a property string "a,k=v,k2=v2" into its pairs; a
// field without "=" (the default key) is stored under "".
func pveOptions(s string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			k, v = "", f
		}
		if _, dup := m[k]; !dup {
			m[k] = v
		}
	}
	return m
}

// pveSize reads a disk size: bytes, or with a K/M/G/T suffix (base 1024).
func pveSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := 1.0
	switch strings.ToUpper(s[len(s)-1:]) {
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0
	}
	return uint64(f * mult)
}

func pveAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

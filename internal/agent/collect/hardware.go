package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/jw6ventures/baseline/internal/model"
)

// Hardware collects the "hardware" section (docs/agent.md §1.1).
func (e *Env) Hardware(ctx context.Context) (model.Hardware, error) {
	hw := model.Hardware{
		System:         e.system(),
		Virtualization: e.virtualization(ctx),
		CPU:            e.cpu(),
		Memory:         e.memory(ctx),
		Disks:          e.disks(ctx),
		Filesystems:    e.filesystems(),
		NICs:           e.nics(),
		PCI:            e.pci(ctx),
	}
	if e.HighSecurity.Load() {
		hw.Peripherals = &model.Peripherals{USB: e.usb(), Displays: e.displays()}
		for i, n := range hw.NICs {
			if n.Kind == "physical" {
				hw.NICs[i].Link = e.link(n.Name)
			}
		}
	}
	return hw, nil
}

func (e *Env) system() model.System {
	d := func(f string) string { return clean(e.Read("/sys/class/dmi/id/" + f)) }
	return model.System{
		Vendor: d("sys_vendor"), Product: d("product_name"), Version: d("product_version"),
		Serial: d("product_serial"), UUID: strings.ToLower(d("product_uuid")), Chassis: chassisType(d("chassis_type")),
		BIOSVendor: d("bios_vendor"), BIOSVersion: d("bios_version"), BIOSDate: d("bios_date"),
		BoardVendor: d("board_vendor"), BoardName: d("board_name"), BoardSerial: d("board_serial"),
	}
}

// clean drops the placeholder strings firmware vendors leave in DMI fields.
func clean(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "to be filled by o.e.m.", "default string", "system product name", "system serial number",
		"not specified", "none", "0123456789", "system version", "o.e.m.", "unknown":
		return ""
	}
	return strings.TrimSpace(s)
}

// chassisType maps the SMBIOS chassis code to a name.
func chassisType(code string) string {
	names := map[string]string{
		"1": "", "2": "", "3": "desktop", // 1 and 2 are "other" and "unknown" "4": "low-profile desktop", "6": "mini tower",
		"7": "tower", "8": "portable", "9": "laptop", "10": "notebook", "13": "all-in-one",
		"17": "main server chassis", "23": "rack mount", "24": "sealed-case pc", "28": "blade",
		"30": "tablet", "31": "convertible", "32": "detachable", "35": "mini pc", "36": "stick pc",
	}
	if n, ok := names[code]; ok {
		return n
	}
	return code
}

func (e *Env) virtualization(ctx context.Context) string {
	if e.Has("systemd-detect-virt") {
		out, _ := e.Run(ctx, "systemd-detect-virt")
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	vendor := strings.ToLower(e.Read("/sys/class/dmi/id/sys_vendor") + " " + e.Read("/sys/class/dmi/id/product_name"))
	for key, name := range map[string]string{"qemu": "kvm", "kvm": "kvm", "vmware": "vmware",
		"virtualbox": "oracle", "microsoft corporation virtual": "microsoft", "xen": "xen"} {
		if strings.Contains(vendor, key) {
			return name
		}
	}
	return "none"
}

// interestingFlags are the CPU flags worth tracking in a CMDB.
var interestingFlags = []string{"aes", "avx", "avx2", "avx512f", "hypervisor", "lm", "sha_ni", "svm", "vmx"}

func (e *Env) cpu() model.CPU {
	var c model.CPU
	sockets := map[string]bool{}
	cores := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(e.Read("/proc/cpuinfo")))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var physID string
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			c.Threads++
		case "model name", "Model": // x86; arm64 has "Model" on some kernels
			if c.Model == "" {
				c.Model = v
			}
		case "vendor_id", "CPU implementer":
			if c.Vendor == "" {
				c.Vendor = v
			}
		case "physical id":
			physID = v
			sockets[v] = true
		case "core id":
			cores[physID+"/"+v] = true
		case "microcode":
			c.Microcode = v
		case "flags", "Features":
			if c.Flags == nil {
				have := strings.Fields(v)
				c.Flags = []string{}
				for _, f := range interestingFlags {
					if slices.Contains(have, f) {
						c.Flags = append(c.Flags, f)
					}
				}
			}
		}
	}
	c.Sockets = max(len(sockets), 1)
	c.Cores = len(cores)
	if c.Cores == 0 {
		c.Cores = c.Threads
	}
	if c.Model == "" {
		c.Model = e.Read("/sys/firmware/devicetree/base/model") // e.g. Raspberry Pi
	}
	return c
}

func (e *Env) memory(ctx context.Context) model.Memory {
	var m model.Memory
	for _, line := range strings.Split(e.Read("/proc/meminfo"), "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				kb, _ := strconv.ParseUint(f[0], 10, 64)
				m.TotalBytes = kb * 1024
			}
		}
	}
	if e.Has("dmidecode") {
		if out, err := e.Run(ctx, "dmidecode", "-t", "16,17"); err == nil {
			m.ECC, m.DIMMs = parseDmidecodeMemory(string(out))
		}
	}
	return m
}

// parseDmidecodeMemory reads "Physical Memory Array" (ECC) and "Memory
// Device" records, skipping empty slots.
func parseDmidecodeMemory(out string) (ecc string, dimms []model.DIMM) {
	for _, rec := range strings.Split(out, "\n\n") {
		fields := map[string]string{}
		var kind string
		for _, line := range strings.Split(rec, "\n") {
			t := strings.TrimSpace(line)
			if t == "Physical Memory Array" || t == "Memory Device" {
				kind = t
				continue
			}
			if k, v, ok := strings.Cut(t, ":"); ok {
				fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		switch kind {
		case "Physical Memory Array":
			if v := fields["Error Correction Type"]; v != "" && ecc == "" {
				ecc = v
			}
		case "Memory Device":
			size := parseDMISize(fields["Size"])
			if size == 0 {
				continue
			}
			d := model.DIMM{
				Locator:      fields["Locator"],
				SizeBytes:    size,
				Type:         clean(fields["Type"]),
				Manufacturer: clean(fields["Manufacturer"]),
				PartNumber:   clean(fields["Part Number"]),
				Serial:       clean(fields["Serial Number"]),
			}
			speed := fields["Configured Memory Speed"]
			if speed == "" || speed == "Unknown" {
				speed = fields["Speed"]
			}
			if f := strings.Fields(speed); len(f) > 0 {
				d.SpeedMTs, _ = strconv.Atoi(f[0])
			}
			if bank := fields["Bank Locator"]; bank != "" && !strings.Contains(d.Locator, bank) {
				d.Locator = strings.TrimSpace(bank + " " + d.Locator)
			}
			dimms = append(dimms, d)
		}
	}
	sort.Slice(dimms, func(i, j int) bool { return dimms[i].Locator < dimms[j].Locator })
	return ecc, dimms
}

func parseDMISize(s string) uint64 {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0
	}
	n, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0
	}
	switch f[1] {
	case "kB", "KB":
		return n << 10
	case "MB":
		return n << 20
	case "GB":
		return n << 30
	case "TB":
		return n << 40
	}
	return 0
}

// disks prefers lsblk (it reads udev for serials); /sys/block is the
// fallback.
func (e *Env) disks(ctx context.Context) []model.Disk {
	if e.Has("lsblk") {
		out, err := e.Run(ctx, "lsblk", "-J", "-b", "-d", "-o", "NAME,TYPE,MODEL,SERIAL,WWN,SIZE,ROTA,TRAN,REV")
		if err == nil {
			if d, err := parseLsblk(out); err == nil {
				return d
			}
		}
	}
	var out []model.Disk
	for _, name := range e.ReadDir("/sys/block") {
		if skipBlock(name) {
			continue
		}
		base := "/sys/block/" + name
		size, _ := strconv.ParseUint(e.Read(base+"/size"), 10, 64)
		if size == 0 {
			continue
		}
		out = append(out, model.Disk{
			Name:       name,
			Model:      e.Read(base + "/device/model"),
			Serial:     e.Read(base + "/device/serial"),
			WWN:        e.Read(base + "/device/wwid"),
			SizeBytes:  size * 512,
			Rotational: e.Read(base+"/queue/rotational") == "1",
			Firmware:   firstNonEmpty(e.Read(base+"/device/firmware_rev"), e.Read(base+"/device/rev")),
		})
	}
	return out
}

func skipBlock(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd", "zd"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func parseLsblk(out []byte) ([]model.Disk, error) {
	var doc struct {
		Blockdevices []struct {
			Name   string          `json:"name"`
			Type   string          `json:"type"`
			Model  *string         `json:"model"`
			Serial *string         `json:"serial"`
			WWN    *string         `json:"wwn"`
			Size   json.Number     `json:"size"`
			Rota   json.RawMessage `json:"rota"`
			Tran   *string         `json:"tran"`
			Rev    *string         `json:"rev"`
		} `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	disks := []model.Disk{}
	for _, b := range doc.Blockdevices {
		if b.Type != "disk" || skipBlock(b.Name) {
			continue
		}
		size, _ := strconv.ParseUint(b.Size.String(), 10, 64)
		if size == 0 {
			continue
		}
		wwn := s(b.WWN)
		if strings.Trim(strings.TrimPrefix(wwn, "0x"), "0") == "" {
			wwn = "" // placeholder on cheap SSDs
		}
		rota := string(b.Rota) // true/false in newer lsblk, "1"/"0" in older
		disks = append(disks, model.Disk{
			Name: b.Name, Model: s(b.Model), Serial: s(b.Serial), WWN: wwn, SizeBytes: size,
			Rotational: rota == "true" || rota == `"1"` || rota == "1",
			Transport:  s(b.Tran), Firmware: s(b.Rev),
		})
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Name < disks[j].Name })
	return disks, nil
}

// realFS are filesystem types worth inventorying. Pseudo filesystems,
// overlay (one per container) and tmpfs are left out.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true,
	"exfat": true, "ntfs": true, "ntfs3": true, "f2fs": true, "bcachefs": true, "jfs": true, "reiserfs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "fuse.sshfs": true, "ceph": true, "glusterfs": true,
}

func (e *Env) filesystems() []model.Filesystem {
	seen := map[string]bool{}
	out := []model.Filesystem{}
	for _, line := range strings.Split(e.Read("/proc/self/mountinfo"), "\n") {
		// id parent major:minor root mountpoint opts [optional...] - fstype source superopts
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 2 {
			continue
		}
		mount, fstype, dev := unescapeMount(pf[4]), qf[0], qf[1]
		if !realFS[fstype] || seen[mount] {
			continue
		}
		// Bind mounts and container mounts of the host's own filesystems
		// show up under /var/lib/{docker,containers,kubelet}.
		if isContainerPath(mount) {
			continue
		}
		seen[mount] = true
		fs := model.Filesystem{Mountpoint: mount, Device: dev, FSType: fstype}
		// A ZFS dataset's statfs size is its used space plus the pool's
		// free space, so it moves with every write; pool capacity comes
		// from zpool instead.
		if fstype != "zfs" {
			var st syscall.Statfs_t
			if e.statfs(mount, &st) == nil {
				fs.SizeBytes = st.Blocks * uint64(st.Bsize)
			}
		}
		out = append(out, fs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

func isContainerPath(p string) bool {
	for _, pre := range []string{"/var/lib/docker/", "/var/lib/containers/", "/var/lib/kubelet/", "/run/containerd/", "/var/lib/containerd/", "/run/k3s/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes mountinfo uses for spaces etc.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (e *Env) nics() []model.NIC {
	addrs := map[string][]string{}
	if e.Root == "" {
		ifs, _ := net.Interfaces()
		for _, i := range ifs {
			as, _ := i.Addrs()
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
					addrs[i.Name] = append(addrs[i.Name], a.String())
				}
			}
		}
	}
	out := []model.NIC{}
	for _, name := range e.ReadDir("/sys/class/net") {
		base := "/sys/class/net/" + name
		if name == "lo" || isEphemeralNIC(name) {
			continue
		}
		n := model.NIC{Name: name, MAC: e.Read(base + "/address"), Driver: e.Link(base + "/device/driver")}
		switch {
		case e.Exists(base + "/bonding"):
			n.Kind = "bond"
		case e.Exists(base + "/bridge"):
			n.Kind = "bridge"
		case strings.Contains(e.Read(base+"/uevent"), "DEVTYPE=vlan"):
			n.Kind = "vlan"
		case e.Exists(base + "/device"):
			n.Kind = "physical"
		default:
			n.Kind = "virtual"
		}
		if n.Kind == "physical" {
			// Speed reads -1 or fails while the link is down; keep the last
			// known value out of the section rather than flapping.
			if sp, err := strconv.Atoi(e.Read(base + "/speed")); err == nil && sp > 0 {
				n.SpeedMbps = sp
			}
		}
		n.Master = e.Link(base + "/master")
		sort.Strings(addrs[name])
		n.Addresses = addrs[name]
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// isEphemeralNIC skips per-container veths and tunnels that come and go.
func isEphemeralNIC(name string) bool {
	for _, p := range []string{"veth", "docker", "br-", "cni", "flannel", "cali", "vxlan", "tap", "fwpr", "fwln", "fwbr", "virbr", "vnet", "macvtap", "podman", "lxc"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var lspciLine = regexp.MustCompile(`"([^"]*)"`)

func (e *Env) pci(ctx context.Context) []model.PCIDevice {
	if !e.Has("lspci") {
		return nil
	}
	out, err := e.Run(ctx, "lspci", "-mm", "-nn")
	if err != nil {
		return nil
	}
	return parseLspci(string(out))
}

// parseLspci reads `lspci -mm -nn`: slot "class [code]" "vendor [id]" "device [id]" ...
func parseLspci(out string) []model.PCIDevice {
	var devs []model.PCIDevice
	for _, line := range strings.Split(out, "\n") {
		slot, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		q := lspciLine.FindAllStringSubmatch(rest, -1)
		if len(q) < 3 {
			continue
		}
		devs = append(devs, model.PCIDevice{Address: slot, Class: q[0][1], Vendor: q[1][1], Device: q[2][1]})
	}
	return devs
}

// usb lists devices plugged into USB ports from sysfs. Entries are named by
// port path (1-1.2); root hubs (usb1) and interfaces (1-1.2:1.0) are skipped.
func (e *Env) usb() []model.USBDevice {
	devs := []model.USBDevice{}
	const dir = "/sys/bus/usb/devices/"
	for _, name := range e.ReadDir(dir) {
		if strings.HasPrefix(name, "usb") || strings.Contains(name, ":") {
			continue
		}
		base := dir + name + "/"
		d := model.USBDevice{Name: name, VendorID: e.Read(base + "idVendor"), ProductID: e.Read(base + "idProduct"),
			Manufacturer: e.Read(base + "manufacturer"), Product: e.Read(base + "product"), Serial: e.Read(base + "serial")}
		if d.VendorID == "" && d.ProductID == "" {
			continue // gone while we looked
		}
		// Class 00 means each interface says; the first one's is the device's.
		class := e.Read(base + "bDeviceClass")
		if class == "00" || class == "" {
			class = e.Read(base + name + ":1.0/bInterfaceClass")
		}
		d.Class = usbClass(class)
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })
	return devs
}

// link is a NIC's link: "up" or "down" by carrier, "off" when the
// interface is disabled (reading carrier then fails).
func (e *Env) link(name string) string {
	switch e.Read("/sys/class/net/" + name + "/carrier") {
	case "1":
		return "up"
	case "0":
		return "down"
	}
	return "off"
}

// displays lists DRM connectors (card0-HDMI-A-1) with their status and the
// monitor on each, from its EDID.
func (e *Env) displays() []model.Display {
	out := []model.Display{}
	const dir = "/sys/class/drm/"
	for _, name := range e.ReadDir(dir) {
		// Connectors are card<N>-<type>-<n>; card<N> and renderD<N> are the GPUs.
		if !strings.HasPrefix(name, "card") || !strings.Contains(name, "-") {
			continue
		}
		d := model.Display{Name: name, Status: e.Read(dir + name + "/status")}
		if d.Status == "" {
			continue
		}
		if d.Status == "connected" {
			if b, err := e.ReadBytes(dir + name + "/edid"); err == nil {
				d.Monitor, d.Serial = parseEDID(b)
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseEDID reads a monitor's name and serial from its EDID: the name and
// serial descriptors, else the manufacturer's PNP ID, product code and
// numeric serial.
func parseEDID(b []byte) (monitor, serial string) {
	if len(b) < 128 || string(b[:8]) != "\x00\xff\xff\xff\xff\xff\xff\x00" {
		return "", ""
	}
	mfg := uint16(b[8])<<8 | uint16(b[9])
	pnp := string([]byte{byte(mfg>>10&0x1f) + '@', byte(mfg>>5&0x1f) + '@', byte(mfg&0x1f) + '@'})
	var name string
	for off := 54; off+18 <= 126; off += 18 {
		d := b[off : off+18]
		if d[0] != 0 || d[1] != 0 {
			continue // a timing, not a descriptor
		}
		text := strings.TrimSpace(strings.SplitN(string(d[5:]), "\n", 2)[0])
		switch d[3] {
		case 0xfc:
			name = text
		case 0xff:
			serial = text
		}
	}
	if name == "" {
		name = fmt.Sprintf("%04x", uint16(b[11])<<8|uint16(b[10]))
	}
	if serial == "" {
		if n := uint32(b[15])<<24 | uint32(b[14])<<16 | uint32(b[13])<<8 | uint32(b[12]); n != 0 {
			serial = strconv.FormatUint(uint64(n), 10)
		}
	}
	return pnp + " " + name, serial
}

// usbClass names a USB class code the way lspci names PCI classes.
func usbClass(code string) string {
	names := map[string]string{"01": "Audio", "02": "Communications", "03": "Human Interface Device", "06": "Imaging",
		"07": "Printer", "08": "Mass Storage", "09": "Hub", "0a": "CDC Data", "0b": "Smart Card",
		"0d": "Content Security", "0e": "Video", "0f": "Personal Healthcare", "10": "Audio/Video",
		"dc": "Diagnostic", "e0": "Wireless", "ef": "Miscellaneous", "fe": "Application Specific", "ff": "Vendor Specific"}
	code = strings.ToLower(code)
	if n, ok := names[code]; ok {
		return n + " [" + code + "]"
	}
	if code == "" || code == "00" {
		return ""
	}
	return "[" + code + "]"
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

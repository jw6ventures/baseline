package collect

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

// fixture builds a fake host: files under a temp root, and canned command
// output keyed by "name arg1 arg2...".
type fixture struct {
	t     *testing.T
	env   *Env
	cmds  map[string]string
	exits map[string]int // non-zero exit status for a stubbed command
}

// exitError is a stubbed command's non-zero exit.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitError) ExitCode() int { return int(e) }

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, cmds: map[string]string{}, exits: map[string]int{}}
	f.env = &Env{
		Root: t.TempDir(),
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			key := strings.Join(append([]string{name}, args...), " ")
			if out, ok := f.cmds[key]; ok {
				if code := f.exits[key]; code != 0 {
					return []byte(out), exitError(code)
				}
				return []byte(out), nil
			}
			return nil, errors.New("not stubbed: " + key)
		},
		Has: func(name string) bool {
			for k := range f.cmds {
				if k == name || strings.HasPrefix(k, name+" ") {
					return true
				}
			}
			return false
		},
	}
	return f
}

func (f *fixture) file(path, content string) {
	p := filepath.Join(f.env.Root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) link(path, target string) {
	p := filepath.Join(f.env.Root, path)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
}

const ubuntuRelease = `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
`

func TestOSUbuntu(t *testing.T) {
	f := newFixture(t)
	f.file("/etc/os-release", ubuntuRelease)
	f.file("/proc/sys/kernel/hostname", "web1\n")
	f.file("/proc/sys/kernel/osrelease", "6.8.0-85-generic\n")
	f.file("/proc/sys/kernel/arch", "x86_64\n")
	f.file("/etc/machine-id", "0123456789abcdef0123456789abcdef\n")
	f.file("/etc/timezone", "America/Chicago\n")

	o, err := f.env.OS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := model.OS{Hostname: "web1", ID: "ubuntu", IDLike: "debian", Name: "Ubuntu", Version: "24.04.3 LTS (Noble Numbat)",
		VersionID: "24.04", PrettyName: "Ubuntu 24.04.3 LTS", Kernel: "6.8.0-85-generic", Arch: "x86_64",
		MachineID: "0123456789abcdef0123456789abcdef", Timezone: "America/Chicago"}
	if o != want {
		t.Fatalf("got  %+v\nwant %+v", o, want)
	}
}

const bazziteStatus = `{
  "deployments": [
    {
      "id": "default-1", "osname": "default", "booted": false, "staged": true,
      "version": "42.20261008", "checksum": "bbbb",
      "container-image-reference": "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable",
      "requested-packages": ["htop"], "packages": ["htop"]
    },
    {
      "id": "default-0", "osname": "default", "booted": true, "staged": false,
      "version": "42.20261001", "checksum": "aaaa",
      "origin": "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable",
      "container-image-reference": "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable",
      "container-image-reference-digest": "sha256:1234",
      "requested-packages": ["htop", "tmux"], "packages": ["htop", "tmux"]
    }
  ],
  "transaction": null
}`

func TestOSAndPackagesBazzite(t *testing.T) {
	f := newFixture(t)
	f.file("/etc/os-release", "NAME=\"Bazzite\"\nID=bazzite\nID_LIKE=\"fedora\"\nVERSION_ID=42\nVARIANT_ID=bazzite-nvidia\nPRETTY_NAME=\"Bazzite 42 (FROM Fedora Kinoite)\"\n")
	f.file("/run/ostree-booted", "")
	f.cmds["rpm-ostree status --json"] = bazziteStatus
	f.cmds["rpm -qa --queryformat %{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"] =
		"tmux\t0\t3.5a\t3.fc42\tx86_64\ttmux-3.5a-3.fc42.src.rpm\n" +
			"kernel-core\t0\t6.16.4\t116.bazzite.fc42\tx86_64\tkernel-6.16.4-116.bazzite.fc42.src.rpm\n" +
			"gpg-pubkey\t0\t105ef944\t65ca83d1\t(none)\t(none)\n"
	f.cmds["dnf"] = "" // dnf exists on Bazzite but must not be used
	f.cmds["flatpak list --columns=application,version,branch,arch,origin"] =
		"org.mozilla.firefox\t131.0\tstable\tx86_64\tflathub\norg.freedesktop.Platform\t\t24.08\tx86_64\tflathub\n"

	o, _ := f.env.OS(context.Background())
	if o.Image == nil || o.Image.Version != "42.20261001" || o.Image.Digest != "sha256:1234" ||
		o.Image.Staged == nil || o.Image.Staged.Version != "42.20261008" || o.VariantID != "bazzite-nvidia" {
		t.Fatalf("image = %+v", o.Image)
	}

	p, err := f.env.Packages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Managers, ",") != "rpm-ostree,flatpak" {
		t.Fatalf("managers = %v", p.Managers)
	}
	byName := map[string]model.Package{}
	for _, pk := range p.Packages {
		byName[pk.Name] = pk
	}
	if len(p.Packages) != 4 {
		t.Fatalf("packages = %+v", p.Packages)
	}
	if !byName["tmux"].Layered || byName["kernel-core"].Layered || byName["kernel-core"].Source != "kernel" {
		t.Errorf("rpm-ostree packages = %+v / %+v", byName["tmux"], byName["kernel-core"])
	}
	if fp := byName["org.freedesktop.Platform"]; fp.Version != "24.08" || fp.Repo != "flathub" {
		t.Errorf("runtime = %+v", fp)
	}
}

func TestPackagesApt(t *testing.T) {
	f := newFixture(t)
	f.cmds["dpkg-query -W -f ${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n"] =
		"ii \topenssl\t3.0.13-0ubuntu3.5\tamd64\topenssl\n" +
			"ii \tlibssl3t64\t3.0.13-0ubuntu3.5\tamd64\topenssl\n" +
			"ii \tbash\t5.2.21-2ubuntu4\tamd64\tbash\n" +
			"rc \told-removed\t1.0\tamd64\told-removed\n" +
			"ii \tgnupg\t2.4.4-2ubuntu17\tall\tgnupg2\n" +
			"ii \tlibc6\t1:2.39-0ubuntu8.6\tamd64\tglibc\n"
	f.cmds["snap list --unicode=never --color=never"] = "Name    Version   Rev    Tracking       Publisher   Notes\ncore22  20250923  2139   latest/stable  canonical✓  base\nlxd     5.21.3    35624  5.21/stable    canonical✓  -\n"
	f.file("/run/snapd.socket", "")

	p, err := f.env.Packages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Managers, ",") != "apt,snap" || len(p.Packages) != 7 {
		t.Fatalf("got %v %+v", p.Managers, p.Packages)
	}
	// Sorted by manager then name.
	if p.Packages[0].Name != "bash" || p.Packages[5].Name != "core22" {
		t.Errorf("order: %s ... %s", p.Packages[0].Name, p.Packages[5].Name)
	}
	for _, pk := range p.Packages {
		switch pk.Name {
		case "libssl3t64":
			if pk.Source != "openssl" {
				t.Errorf("libssl source = %q", pk.Source)
			}
		case "openssl":
			if pk.Source != "" {
				t.Errorf("source equal to name should be omitted: %q", pk.Source)
			}
		case "libc6":
			if pk.Epoch != "1" || pk.Version != "2.39-0ubuntu8.6" || pk.FullVersion() != "1:2.39-0ubuntu8.6" {
				t.Errorf("libc6 = %+v", pk)
			}
		case "lxd":
			if pk.Version != "5.21.3" || pk.Release != "35624" || pk.Repo != "5.21/stable" {
				t.Errorf("lxd = %+v", pk)
			}
		case "old-removed":
			t.Error("removed package listed")
		}
	}
}

func TestPackagesRockyWithKernels(t *testing.T) {
	f := newFixture(t)
	f.cmds["dnf"] = ""
	f.cmds["rpm -qa --queryformat %{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"] =
		"kernel-core\t0\t5.14.0\t570.17.1.el9_6\tx86_64\tkernel-5.14.0-570.17.1.el9_6.src.rpm\n" +
			"kernel-core\t0\t5.14.0\t570.22.1.el9_6\tx86_64\tkernel-5.14.0-570.22.1.el9_6.src.rpm\n" +
			"openssl\t1\t3.2.2\t6.el9_5.1\tx86_64\topenssl-3.2.2-6.el9_5.1.src.rpm\n"
	p, err := f.env.Packages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Managers[0] != "dnf" || len(p.Packages) != 3 {
		t.Fatalf("%+v", p)
	}
	if o := p.Packages[2]; o.Name != "openssl" || o.FullVersion() != "1:3.2.2-6.el9_5.1" || o.Source != "" {
		t.Errorf("openssl = %+v", o)
	}
}

func TestPackagesFailureFailsSection(t *testing.T) {
	f := newFixture(t)
	f.cmds["rpm"] = "" // detected, but the query isn't stubbed, so it fails
	if _, err := f.env.Packages(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSourceRPMName(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.2.2-6.el10.src.rpm":                   "openssl",
		"python3.12-3.12.5-2.fc41.src.rpm":               "python3.12",
		"kernel-6.16.4-116.bazzite.fc42.src.rpm":         "kernel",
		"xorg-x11-server-Xwayland-24.1.1-1.fc41.src.rpm": "xorg-x11-server-Xwayland",
		"(none)": "",
	} {
		if got := sourceRPMName(in); got != want {
			t.Errorf("%s = %q, want %q", in, got, want)
		}
	}
}

const cpuinfo = `processor	: 0
vendor_id	: AuthenticAMD
model name	: AMD Ryzen 7 5800X 8-Core Processor
physical id	: 0
core id		: 0
microcode	: 0xa201205
flags		: fpu vme lm svm aes avx avx2 sha_ni

processor	: 1
vendor_id	: AuthenticAMD
model name	: AMD Ryzen 7 5800X 8-Core Processor
physical id	: 0
core id		: 0
microcode	: 0xa201205
flags		: fpu vme lm svm aes avx avx2 sha_ni

processor	: 2
vendor_id	: AuthenticAMD
model name	: AMD Ryzen 7 5800X 8-Core Processor
physical id	: 0
core id		: 1
microcode	: 0xa201205
flags		: fpu vme lm svm aes avx avx2 sha_ni
`

const dmidecodeMem = `# dmidecode 3.5
Getting SMBIOS data from sysfs.

Handle 0x000F, DMI type 16, 23 bytes
Physical Memory Array
	Location: System Board Or Motherboard
	Use: System Memory
	Error Correction Type: Multi-bit ECC
	Maximum Capacity: 128 GB
	Number Of Devices: 4

Handle 0x0011, DMI type 17, 92 bytes
Memory Device
	Size: 32 GB
	Form Factor: DIMM
	Locator: DIMM 1
	Bank Locator: P0 CHANNEL A
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 0367E8A1
	Part Number: M391A4G43AB1-CWE
	Configured Memory Speed: 2666 MT/s

Handle 0x0012, DMI type 17, 92 bytes
Memory Device
	Size: No Module Installed
	Locator: DIMM 0
	Bank Locator: P0 CHANNEL A
`

const lsblkOut = `{
   "blockdevices": [
      {"name":"loop0", "type":"loop", "model":null, "serial":null, "wwn":null, "size":4096, "rota":false, "tran":null, "rev":null},
      {"name":"nvme0n1", "type":"disk", "model":"Samsung SSD 980 PRO 1TB", "serial":"S5GXNX0T123456", "wwn":"eui.002538b911b2c3d4", "size":1000204886016, "rota":false, "tran":"nvme", "rev":"5B2QGXA7"},
      {"name":"sda", "type":"disk", "model":"WDC WD80EFZZ-68B", "serial":"WD-CA1234567", "wwn":"0x5000cca2c1234567", "size":8001563222016, "rota":true, "tran":"sata", "rev":"81.00A81"}
   ]
}`

const mountinfo = `22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:2 - proc proc rw
30 22 259:1 / /boot/efi rw,relatime shared:3 - vfat /dev/nvme0n1p1 rw
31 22 8:1 / /mnt/My\040Data rw,relatime shared:4 - xfs /dev/sda1 rw
40 22 0:50 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw
41 22 259:2 /var/lib/docker /var/lib/docker/volumes/x rw - ext4 /dev/nvme0n1p2 rw
42 22 0:30 / /run rw - tmpfs tmpfs rw
`

func TestHardware(t *testing.T) {
	f := newFixture(t)
	f.file("/sys/class/dmi/id/sys_vendor", "ASUS\n")
	f.file("/sys/class/dmi/id/product_name", "System Product Name\n") // placeholder → dropped
	f.file("/sys/class/dmi/id/board_name", "ROG STRIX B550-F GAMING\n")
	f.file("/sys/class/dmi/id/chassis_type", "3\n")
	f.file("/sys/class/dmi/id/product_uuid", "ABCD-1234\n")
	f.file("/proc/cpuinfo", cpuinfo)
	f.file("/proc/meminfo", "MemTotal:       65768224 kB\nMemFree: 1 kB\n")
	f.file("/proc/self/mountinfo", mountinfo)
	f.file("/sys/class/net/enp5s0/address", "a8:5e:45:00:00:01\n")
	f.file("/sys/class/net/enp5s0/speed", "1000\n")
	f.file("/sys/class/net/enp5s0/device/vendor", "0x10ec\n")
	f.link("/sys/class/net/enp5s0/device/driver", "../../../bus/pci/drivers/r8169")
	f.link("/sys/class/net/enp5s0/master", "../br0")
	f.file("/sys/class/net/br0/address", "a8:5e:45:00:00:01\n")
	f.file("/sys/class/net/br0/bridge/stp_state", "0\n")
	f.file("/sys/class/net/veth1234/address", "aa:aa:aa:aa:aa:aa\n")
	f.file("/sys/class/net/lo/address", "00:00:00:00:00:00\n")
	f.cmds["systemd-detect-virt"] = "none\n"
	f.cmds["dmidecode -t 16,17"] = dmidecodeMem
	f.cmds["lsblk -J -b -d -o NAME,TYPE,MODEL,SERIAL,WWN,SIZE,ROTA,TRAN,REV"] = lsblkOut
	f.cmds["lspci -mm -nn"] = `00:00.0 "Host bridge [0600]" "Advanced Micro Devices, Inc. [AMD] [1022]" "Starship/Matisse Root Complex [1480]" "ASUSTeK Computer Inc. [1043]" "Device [87c0]"
05:00.0 "Ethernet controller [0200]" "Intel Corporation [8086]" "I225-V [15f3]" -r03 "ASUSTeK Computer Inc. [1043]" "Device [87d2]"
`
	hw, err := f.env.Hardware(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hw.System.Vendor != "ASUS" || hw.System.Product != "" || hw.System.Chassis != "desktop" || hw.System.UUID != "abcd-1234" {
		t.Errorf("system = %+v", hw.System)
	}
	if hw.Virtualization != "none" {
		t.Errorf("virt = %q", hw.Virtualization)
	}
	c := hw.CPU
	if c.Model != "AMD Ryzen 7 5800X 8-Core Processor" || c.Sockets != 1 || c.Cores != 2 || c.Threads != 3 ||
		strings.Join(c.Flags, ",") != "aes,avx,avx2,lm,sha_ni,svm" || c.Microcode != "0xa201205" {
		t.Errorf("cpu = %+v", c)
	}
	m := hw.Memory
	if m.TotalBytes != 65768224*1024 || m.ECC != "Multi-bit ECC" || len(m.DIMMs) != 1 {
		t.Fatalf("memory = %+v", m)
	}
	if d := m.DIMMs[0]; d.Locator != "P0 CHANNEL A DIMM 1" || d.SizeBytes != 32<<30 || d.SpeedMTs != 2666 || d.PartNumber != "M391A4G43AB1-CWE" {
		t.Errorf("dimm = %+v", d)
	}
	if len(hw.Disks) != 2 || hw.Disks[0].Name != "nvme0n1" || hw.Disks[0].Rotational || !hw.Disks[1].Rotational || hw.Disks[1].Serial != "WD-CA1234567" {
		t.Errorf("disks = %+v", hw.Disks)
	}
	var mounts []string
	for _, fs := range hw.Filesystems {
		mounts = append(mounts, fs.Mountpoint)
	}
	if strings.Join(mounts, "|") != "/|/boot/efi|/mnt/My Data" {
		t.Errorf("mounts = %v", mounts)
	}
	if len(hw.NICs) != 2 {
		t.Fatalf("nics = %+v", hw.NICs)
	}
	if br, eth := hw.NICs[0], hw.NICs[1]; br.Kind != "bridge" || eth.Kind != "physical" || eth.Driver != "r8169" || eth.SpeedMbps != 1000 || eth.Master != "br0" {
		t.Errorf("nics = %+v", hw.NICs)
	}
	if len(hw.PCI) != 2 || hw.PCI[1].Class != "Ethernet controller [0200]" || hw.PCI[1].Device != "I225-V [15f3]" {
		t.Errorf("pci = %+v", hw.PCI)
	}
}

func TestHardwareHighSecurity(t *testing.T) {
	f := newFixture(t)
	dev := func(name, vendor, product, class string) {
		f.file("/sys/bus/usb/devices/"+name+"/idVendor", vendor+"\n")
		f.file("/sys/bus/usb/devices/"+name+"/idProduct", product+"\n")
		f.file("/sys/bus/usb/devices/"+name+"/bDeviceClass", class+"\n")
	}
	dev("usb1", "1d6b", "0002", "09") // root hub
	f.file("/sys/bus/usb/devices/usb1/manufacturer", "Linux 6.8.0-45-generic xhci-hcd\n")
	dev("1-1", "05e3", "0610", "09")
	dev("1-1.2", "0781", "5581", "00")
	f.file("/sys/bus/usb/devices/1-1.2/product", "Ultra\n")
	f.file("/sys/bus/usb/devices/1-1.2/serial", "4C530001\n")
	f.file("/sys/bus/usb/devices/1-1.2/1-1.2:1.0/bInterfaceClass", "08\n")
	f.file("/sys/bus/usb/devices/1-1.2:1.0/bInterfaceClass", "08\n") // interface
	f.file("/sys/class/drm/card0/dev", "226:0\n")
	f.file("/sys/class/drm/card0-VGA-1/status", "disconnected\n")
	f.file("/sys/class/drm/card0-HDMI-A-1/status", "connected\n")
	f.file("/sys/class/drm/card0-HDMI-A-1/edid", string(testEDID()))
	f.file("/sys/class/drm/renderD128/dev", "226:128\n")
	f.file("/sys/class/net/eno1/address", "a8:5e:45:00:00:01\n")
	f.file("/sys/class/net/eno1/device/vendor", "0x8086\n")
	f.file("/sys/class/net/eno1/carrier", "1\n")
	f.file("/sys/class/net/eno2/address", "a8:5e:45:00:00:02\n")
	f.file("/sys/class/net/eno2/device/vendor", "0x8086\n")
	f.file("/sys/class/net/eno2/carrier", "0\n")
	f.file("/sys/class/net/eno3/address", "a8:5e:45:00:00:03\n")
	f.file("/sys/class/net/eno3/device/vendor", "0x8086\n") // disabled: no carrier file
	f.file("/sys/class/net/br0/address", "a8:5e:45:00:00:01\n")
	f.file("/sys/class/net/br0/bridge/stp_state", "0\n")
	f.file("/sys/class/net/br0/carrier", "1\n")
	f.cmds["systemd-detect-virt"] = "none\n"

	hw, err := f.env.Hardware(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hw.Peripherals != nil || hw.NICs[1].Link != "" {
		t.Fatalf("collected while off: %+v %+v", hw.Peripherals, hw.NICs)
	}
	if !f.env.SetHighSecurity(true) || f.env.SetHighSecurity(true) {
		t.Fatal("SetHighSecurity should report only a change")
	}
	if hw, err = f.env.Hardware(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := hw.Peripherals
	if p == nil || len(p.USB) != 2 || len(p.Displays) != 2 {
		t.Fatalf("peripherals = %+v", p)
	}
	hub, stick := p.USB[0], p.USB[1]
	if hub.Name != "1-1" || hub.Class != "Hub [09]" {
		t.Errorf("hub = %+v", hub)
	}
	if stick.Name != "1-1.2" || stick.VendorID != "0781" || stick.ProductID != "5581" || stick.Serial != "4C530001" ||
		stick.Product != "Ultra" || stick.Class != "Mass Storage [08]" {
		t.Errorf("stick = %+v", stick)
	}
	if d := p.Displays[0]; d.Name != "card0-HDMI-A-1" || d.Status != "connected" || d.Monitor != "DEL DELL U2720Q" || d.Serial != "7XQ1234" {
		t.Errorf("hdmi = %+v", d)
	}
	if d := p.Displays[1]; d.Name != "card0-VGA-1" || d.Status != "disconnected" || d.Monitor != "" {
		t.Errorf("vga = %+v", d)
	}
	var links []string
	for _, n := range hw.NICs {
		links = append(links, n.Name+":"+n.Link)
	}
	if strings.Join(links, " ") != "br0: eno1:up eno2:down eno3:off" {
		t.Errorf("links = %v", links)
	}
}

// testEDID is a 128-byte EDID block for a Dell U2720Q.
func testEDID() []byte {
	b := make([]byte, 128)
	copy(b, "\x00\xff\xff\xff\xff\xff\xff\x00")
	b[8], b[9] = 0x10, 0xac // DEL
	b[10], b[11] = 0x0b, 0xa1
	desc := func(off int, tag byte, text string) {
		b[off+3] = tag
		copy(b[off+5:off+18], text+"\n            ")
	}
	b[54], b[55] = 0x56, 0x5e // a detailed timing
	desc(72, 0xff, "7XQ1234")
	desc(90, 0xfc, "DELL U2720Q")
	return b
}

func TestParseEDIDFallbacks(t *testing.T) {
	b := testEDID()
	for i := 72; i < 108; i++ {
		b[i] = 0
	}
	b[12], b[13] = 0x39, 0x30
	if m, s := parseEDID(b); m != "DEL a10b" || s != "12345" {
		t.Errorf("got %q %q", m, s)
	}
	if m, s := parseEDID(b[:100]); m != "" || s != "" {
		t.Errorf("short EDID: %q %q", m, s)
	}
}

func TestDeviceEvents(t *testing.T) {
	ev := func(kv ...string) []byte { return []byte(kv[0] + "@/devices/x\x00" + strings.Join(kv[1:], "\x00")) }
	for _, c := range []struct {
		msg  []byte
		want bool
	}{
		{ev("add", "ACTION=add", "SUBSYSTEM=usb", "DEVTYPE=usb_device"), true},
		{ev("add", "ACTION=add", "SUBSYSTEM=usb", "DEVTYPE=usb_interface"), false},
		{ev("remove", "ACTION=remove", "SUBSYSTEM=block", "DEVTYPE=disk"), true},
		{ev("add", "ACTION=add", "SUBSYSTEM=block", "DEVTYPE=partition"), false},
		{ev("change", "ACTION=change", "SUBSYSTEM=drm", "HOTPLUG=1"), true},
		{ev("change", "ACTION=change", "SUBSYSTEM=block", "DEVTYPE=disk"), false},
		{ev("add", "ACTION=add", "SUBSYSTEM=pci"), true},
		{ev("bind", "ACTION=bind", "SUBSYSTEM=pci"), false},
		{ev("add", "ACTION=add", "SUBSYSTEM=tty"), false},
		{ev("add", "ACTION=add", "SUBSYSTEM=net", "INTERFACE=veth1a2b"), false},
		{ev("add", "ACTION=add", "SUBSYSTEM=net", "INTERFACE=enp3s0"), true},
		{ev("add", "ACTION=add", "SUBSYSTEM=block", "DEVTYPE=disk", "DEVNAME=loop7"), false},
		{ev("add", "ACTION=add", "SUBSYSTEM=block", "DEVTYPE=disk", "DEVNAME=sdc"), true},
	} {
		if got := deviceUevent(c.msg); got != c.want {
			t.Errorf("%q: %v", c.msg, got)
		}
	}

	link := func(name string) []byte {
		attr := append([]byte(name), 0)
		alen := syscall.SizeofRtAttr + len(attr)
		total := syscall.NLMSG_HDRLEN + syscall.SizeofIfInfomsg + (alen+3)&^3
		b := make([]byte, total)
		binary.NativeEndian.PutUint32(b[0:], uint32(total))
		binary.NativeEndian.PutUint16(b[4:], syscall.RTM_NEWLINK)
		a := b[syscall.NLMSG_HDRLEN+syscall.SizeofIfInfomsg:]
		binary.NativeEndian.PutUint16(a[0:], uint16(alen))
		binary.NativeEndian.PutUint16(a[2:], syscall.IFLA_IFNAME)
		copy(a[syscall.SizeofRtAttr:], attr)
		return b
	}
	if !linkMessage(link("eno1")) || linkMessage(link("veth1a2b")) || linkMessage(link("lo")) {
		t.Error("link messages")
	}
}

func TestIdentityAndCapabilities(t *testing.T) {
	f := newFixture(t)
	f.file("/etc/machine-id", "m1\n")
	f.file("/sys/class/dmi/id/product_uuid", "DMI-UUID\n")
	f.file("/proc/sys/kernel/hostname", "h1")
	f.file("/proc/sys/kernel/random/boot_id", "b1")
	f.file("/proc/stat", "cpu 1 2 3\nbtime 1760000000\nprocesses 5\n")
	f.file("/run/ostree-booted", "")
	f.cmds["rpm-ostree"] = ""
	f.cmds["flatpak"] = ""
	id := f.env.Identity()
	if id.MachineID != "m1" || id.DMIUUID != "dmi-uuid" || id.Hostname != "h1" || id.BootID != "b1" || id.BootTime.Unix() != 1760000000 {
		t.Fatalf("identity = %+v", id)
	}
	if caps := strings.Join(f.env.Capabilities(), ","); caps != "rpm-ostree,flatpak,image-based,pkg-pin" {
		t.Fatalf("caps = %s", caps)
	}
}

func TestParseKVQuoting(t *testing.T) {
	m := parseKV("A=\"x \\\"y\\\"\"\nB='single'\n# comment\nC=plain\n")
	if m["A"] != `x "y"` || m["B"] != "single" || m["C"] != "plain" {
		t.Fatalf("%q", m)
	}
}

package inventory

import (
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

func hwChanges(t *testing.T, before, after model.Hardware) []string {
	t.Helper()
	cur := enc(t, after)
	d, err := Compare(model.SectionHardware, enc(t, before), cur)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		return nil
	}
	var out []string
	for _, c := range HardwareComponents(*d, cur) {
		out = append(out, c.String())
	}
	return out
}

func baseHardware() model.Hardware {
	return model.Hardware{
		System: model.System{BIOSVersion: "1.0"},
		CPU:    model.CPU{Model: "EPYC", Microcode: "0x1"},
		Memory: model.Memory{TotalBytes: 32 << 30, DIMMs: []model.DIMM{
			{Locator: "A1", SizeBytes: 16 << 30, PartNumber: "M1", Serial: "D1"},
			{Locator: "A2", SizeBytes: 16 << 30, PartNumber: "M1", Serial: "D2"},
		}},
		Disks:       []model.Disk{{Name: "sda", Model: "WD", Serial: "S1", Firmware: "01"}},
		Filesystems: []model.Filesystem{{Mountpoint: "/", Device: "/dev/sda1", FSType: "ext4"}},
		NICs: []model.NIC{
			{Name: "br0", MAC: "aa:00:00:00:00:01", Kind: "bridge", Addresses: []string{"10.0.0.5/24"}},
			{Name: "eno1", MAC: "aa:00:00:00:00:02", Kind: "physical", Master: "br0"},
		},
		PCI: []model.PCIDevice{{Address: "00:1f.0", Class: "ISA bridge", Vendor: "Intel", Device: "C620"}},
		Peripherals: &model.Peripherals{USB: []model.USBDevice{}, Displays: []model.Display{
			{Name: "card0-VGA-1", Status: "disconnected"},
		}},
	}
}

func TestHardwareComponentsIgnoresNonComponents(t *testing.T) {
	a, b := baseHardware(), baseHardware()
	b.System.BIOSVersion = "1.1"
	b.CPU.Microcode = "0x2"
	b.Disks[0].Firmware = "02"
	b.Filesystems = append(b.Filesystems, model.Filesystem{Mountpoint: "/data", Device: "/dev/sda2", FSType: "xfs"})
	b.NICs[0].Addresses = []string{"10.0.0.6/24"}
	b.NICs[0].MAC = "aa:00:00:00:00:09" // a bridge's MAC follows its ports
	b.NICs = append(b.NICs, model.NIC{Name: "wg0", Kind: "virtual"})
	if got := hwChanges(t, a, b); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
	// High security collection starting or stopping isn't a change.
	a.Peripherals = nil
	b = baseHardware()
	b.Peripherals.USB = append(b.Peripherals.USB, model.USBDevice{Name: "1-1", VendorID: "0781", ProductID: "5581"})
	b.Peripherals.Displays[0].Status = "connected"
	b.NICs[1].Link = "up"
	if got := hwChanges(t, a, b); len(got) != 0 {
		t.Fatalf("on: %q", got)
	}
	if got := hwChanges(t, b, a); len(got) != 0 {
		t.Fatalf("off: %q", got)
	}
}

func TestHardwareComponentsAddRemoveSwap(t *testing.T) {
	a, b := baseHardware(), baseHardware()
	b.Disks = append(b.Disks, model.Disk{Name: "sdb", Model: "Samsung", Serial: "S9"})
	b.Memory.DIMMs = b.Memory.DIMMs[:1]
	b.Memory.DIMMs[0].Serial = "D7"
	b.NICs = append(b.NICs, model.NIC{Name: "enp1s0", MAC: "aa:00:00:00:00:03", Kind: "physical"})
	b.NICs[1].MAC = "aa:00:00:00:00:04"
	b.PCI[0].Device = "C621"
	b.Peripherals.USB = []model.USBDevice{{Name: "1-1.2", VendorID: "0781", ProductID: "5581", Product: "Ultra", Serial: "4C53"}}
	got := strings.Join(hwChanges(t, a, b), "\n")
	for _, want := range []string{
		"disk sdb added (model Samsung, serial S9)",
		"DIMM A2 removed (part number M1, serial D2)",
		"DIMM A1 swapped (serial D1 → D7)",
		"NIC enp1s0 added (mac aa:00:00:00:00:03)",
		"NIC eno1 swapped (mac aa:00:00:00:00:02 → aa:00:00:00:00:04)",
		"PCI device 00:1f.0 swapped (device C620 → C621)",
		"USB device 1-1.2 added (product Ultra, vendor id 0781, product id 5581, serial 4C53)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "\n") + 1; n != 7 {
		t.Errorf("%d changes:\n%s", n, got)
	}

	// A USB device moved to another port, and one swapped in place.
	a, b = b, baseHardware()
	b.Peripherals.USB = []model.USBDevice{{Name: "1-1.3", VendorID: "0781", ProductID: "5581", Product: "Ultra", Serial: "4C53"}}
	a.Disks, a.Memory, a.NICs, a.PCI = b.Disks, b.Memory, b.NICs, b.PCI
	got = strings.Join(hwChanges(t, a, b), "\n")
	if got != "USB device 1-1.3 added (product Ultra, vendor id 0781, product id 5581, serial 4C53)\n"+
		"USB device 1-1.2 removed (product Ultra, vendor id 0781, product id 5581, serial 4C53)" {
		t.Errorf("moved:\n%s", got)
	}
	a = b
	b = baseHardware()
	b.Peripherals.USB = []model.USBDevice{{Name: "1-1.3", VendorID: "046d", ProductID: "c52b", Product: "Unifying Receiver"}}
	if got := hwChanges(t, a, b); len(got) != 1 || !strings.HasPrefix(got[0], "USB device 1-1.3 swapped (") ||
		!strings.Contains(got[0], "vendor id 0781 → 046d") || !strings.Contains(got[0], "serial 4C53 → none") {
		t.Errorf("swapped: %q", got)
	}
}

func TestHardwareComponentsLinksAndDisplays(t *testing.T) {
	a, b := baseHardware(), baseHardware()
	a.NICs[0].Link, a.NICs[1].Link = "up", "up"
	b.NICs[0].Link, b.NICs[1].Link = "down", "down" // the bridge isn't a cable
	b.Peripherals.Displays[0] = model.Display{Name: "card0-VGA-1", Status: "connected", Monitor: "DEL DELL P2419H", Serial: "CN0X"}
	if got := strings.Join(hwChanges(t, a, b), "\n"); got != "NIC eno1 link down (was up)\n"+
		"display connector card0-VGA-1 connected (monitor DEL DELL P2419H, serial CN0X)" {
		t.Errorf("unplugged and plugged:\n%s", got)
	}

	// A monitor swapped while connected, then unplugged.
	a, b = b, baseHardware()
	b.NICs[0].Link, b.NICs[1].Link = "down", "off"
	b.Peripherals.Displays[0] = model.Display{Name: "card0-VGA-1", Status: "connected", Monitor: "AOC 2470W"}
	if got := strings.Join(hwChanges(t, a, b), "\n"); got != "display connector card0-VGA-1 swapped (serial CN0X → none, monitor DEL DELL P2419H → AOC 2470W)\n"+
		"NIC eno1 link off (was down)" {
		t.Errorf("swapped:\n%s", got)
	}
	a, b = b, baseHardware()
	b.NICs[0].Link, b.NICs[1].Link = "down", "off"
	if got := strings.Join(hwChanges(t, a, b), "\n"); got != "display connector card0-VGA-1 disconnected (monitor AOC 2470W)" {
		t.Errorf("unplugged:\n%s", got)
	}
}

func TestHardwareComponentsNullList(t *testing.T) {
	a, b := baseHardware(), baseHardware()
	a.Disks = nil
	if got := strings.Join(hwChanges(t, a, b), "\n"); got != "disk sda added (model WD, serial S1)" {
		t.Errorf("null to list:\n%s", got)
	}
	if got := strings.Join(hwChanges(t, b, a), "\n"); got != "disk sda removed (model WD, serial S1)" {
		t.Errorf("list to null:\n%s", got)
	}
}

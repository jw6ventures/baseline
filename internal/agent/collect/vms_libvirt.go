package collect

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
)

// libvirtDomain is the part of a domain's XML that is read. Everything else
// (description, title, metadata other than libosinfo, graphics passwords,
// qemu:commandline) is never decoded.
type libvirtDomain struct {
	Type   string `xml:"type,attr"`
	Name   string `xml:"name"`
	UUID   string `xml:"uuid"`
	Memory struct {
		Unit  string `xml:"unit,attr"`
		Value string `xml:",chardata"`
	} `xml:"memory"`
	VCPU struct {
		Current string `xml:"current,attr"`
		Value   string `xml:",chardata"`
	} `xml:"vcpu"`
	OS struct {
		Type struct {
			Machine string `xml:"machine,attr"`
		} `xml:"type"`
	} `xml:"os"`
	// <libosinfo:os id="http://ubuntu.com/ubuntu/24.04"/>, as virt-install
	// and virt-manager write it.
	Metadata struct {
		Libosinfo struct {
			OS struct {
				ID string `xml:"id,attr"`
			} `xml:"http://libosinfo.org/xmlns/libvirt/domain/1.0 os"`
		} `xml:"http://libosinfo.org/xmlns/libvirt/domain/1.0 libosinfo"`
	} `xml:"metadata"`
	Sysinfo []struct {
		Type    string `xml:"type,attr"`
		Entries []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"system>entry"`
	} `xml:"sysinfo"`
	Disks []struct {
		Device string `xml:"device,attr"`
		Source struct {
			File   string `xml:"file,attr"`
			Dev    string `xml:"dev,attr"`
			Pool   string `xml:"pool,attr"`
			Volume string `xml:"volume,attr"`
			Name   string `xml:"name,attr"` // network disks: pool/image
		} `xml:"source"`
		Target struct {
			Dev string `xml:"dev,attr"`
		} `xml:"target"`
	} `xml:"devices>disk"`
	Interfaces []struct {
		MAC struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
		Source struct {
			Network string `xml:"network,attr"`
			Bridge  string `xml:"bridge,attr"`
		} `xml:"source"`
		Model struct {
			Type string `xml:"type,attr"`
		} `xml:"model"`
		VLAN []struct {
			ID string `xml:"id,attr"`
		} `xml:"vlan>tag"`
	} `xml:"devices>interface"`
}

// libvirtVMs reads the domains of qemu:///system (the agent runs as root).
// Each domain's persistent config is read with dumpxml --inactive, which has
// no runtime vnet names, ports or aliases.
func (e *Env) libvirtVMs(ctx context.Context) (model.Hypervisor, []model.Guest) {
	h := model.Hypervisor{Platform: "libvirt"}
	if out, err := e.Run(ctx, "virsh", "--version"); err == nil {
		h.Version = strings.TrimSpace(string(out))
	}
	list, err := e.Run(ctx, "virsh", "list", "--all", "--uuid")
	if err != nil {
		h.Error = firstLine(err)
		return h, nil
	}
	auto, err := e.Run(ctx, "virsh", "list", "--all", "--uuid", "--autostart")
	if err != nil {
		h.Error = firstLine(err)
		return h, nil
	}
	autostart := map[string]bool{}
	for _, u := range strings.Fields(string(auto)) {
		autostart[strings.ToLower(u)] = true
	}
	var guests []model.Guest
	for _, uuid := range strings.Fields(string(list)) {
		g, err := e.libvirtGuest(ctx, uuid)
		if err != nil {
			h.Error = firstLine(err)
			return h, nil
		}
		g.Autostart = autostart[g.ID]
		guests = append(guests, g)
	}
	return h, guests
}

func (e *Env) libvirtGuest(ctx context.Context, uuid string) (model.Guest, error) {
	raw, err := e.Run(ctx, "virsh", "dumpxml", "--inactive", uuid)
	if err != nil {
		return model.Guest{}, fmt.Errorf("dumpxml %s: %s", uuid, firstLine(err))
	}
	g, err := parseLibvirtDomain(raw)
	if err != nil {
		return model.Guest{}, fmt.Errorf("dumpxml %s: %v", uuid, err)
	}
	state, err := e.Run(ctx, "virsh", "domstate", uuid)
	if err != nil {
		return model.Guest{}, fmt.Errorf("domstate %s: %s", uuid, firstLine(err))
	}
	g.State = libvirtState(string(state))
	return g, nil
}

func parseLibvirtDomain(raw []byte) (model.Guest, error) {
	var d libvirtDomain
	if err := xml.Unmarshal(raw, &d); err != nil {
		return model.Guest{}, fmt.Errorf("unreadable XML")
	}
	g := model.Guest{
		Platform:    "libvirt",
		Kind:        d.Type,
		ID:          strings.ToLower(strings.TrimSpace(d.UUID)),
		Name:        strings.TrimSpace(d.Name),
		MemoryBytes: libvirtBytes(d.Memory.Value, d.Memory.Unit),
		Machine:     d.OS.Type.Machine,
	}
	if g.ID == "" {
		return g, fmt.Errorf("no domain UUID")
	}
	// vcpu is the maximum; current, when set, is how many are plugged in.
	g.CPUs, _ = strconv.Atoi(strings.TrimSpace(firstNonEmpty(d.VCPU.Current, d.VCPU.Value)))
	g.OSType = d.Metadata.Libosinfo.OS.ID
	// The guest's SMBIOS UUID is the domain's unless sysinfo sets one.
	// (libvirt rejects a sysinfo UUID that differs from the domain's, so in
	// practice this only matters for its formatting.)
	g.UUID = g.ID
	for _, s := range d.Sysinfo {
		if s.Type != "smbios" {
			continue
		}
		for _, en := range s.Entries {
			if en.Name == "uuid" && strings.TrimSpace(en.Value) != "" {
				g.UUID = strings.ToLower(strings.TrimSpace(en.Value))
			}
		}
	}
	for _, dk := range d.Disks {
		src := dk.Source
		source := firstNonEmpty(src.File, src.Dev, src.Name)
		if src.Volume != "" {
			source = src.Pool + "/" + src.Volume
		}
		g.Disks = append(g.Disks, model.GuestDisk{Name: dk.Target.Dev, Source: source,
			Device: firstNonEmpty(dk.Device, "disk")})
	}
	for i, in := range d.Interfaces {
		n := model.GuestNIC{Name: "net" + strconv.Itoa(i), MAC: strings.ToLower(in.MAC.Address),
			Bridge: in.Source.Bridge, Network: in.Source.Network, Model: in.Model.Type}
		// A trunk has several tags; the first is reported.
		if len(in.VLAN) > 0 {
			n.VLAN, _ = strconv.Atoi(in.VLAN[0].ID)
		}
		g.NICs = append(g.NICs, n)
	}
	return g, nil
}

// libvirtBytes converts a libvirt memory value with its unit (KiB when
// unset) to bytes.
func libvirtBytes(value, unit string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	switch unit {
	case "b", "bytes":
		return n
	case "KB":
		return n * 1000
	case "", "k", "KiB":
		return n << 10
	case "MB":
		return n * 1000 * 1000
	case "M", "MiB":
		return n << 20
	case "GB":
		return n * 1000 * 1000 * 1000
	case "G", "GiB":
		return n << 30
	case "TB":
		return n * 1000 * 1000 * 1000 * 1000
	case "T", "TiB":
		return n << 40
	}
	return 0
}

// libvirtState maps `virsh domstate` to the section's states.
func libvirtState(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "running", "idle", "blocked", "in shutdown":
		return "running"
	case "shut off":
		return "stopped"
	case "paused":
		return "paused"
	case "pmsuspended":
		return "suspended"
	case "crashed":
		return "crashed"
	}
	return s
}

package collect

import (
	"context"
	"sort"
	"strconv"

	"github.com/jw6ventures/baseline/internal/model"
)

// VMs collects the "vms" section from Proxmox VE and libvirt
// (docs/agent.md §4). ErrAbsent when the host runs neither.
//
// Only configuration is read, with read-only commands: usage, uptime and
// anything assigned at start (tap devices, VNC ports) would change the
// section's hash on every run. Fields are whitelisted, so descriptions,
// cloud-init passwords, SSH keys, hook scripts and extra QEMU arguments
// never leave the host.
//
// A platform that can't be read gets Hypervisor.Error and none of its
// guests, so the server keeps its earlier copy. That includes one guest's
// config failing to read: a guest with a half-empty config would look like
// a real change, and dropping it alone would look like a removal.
func (e *Env) VMs(ctx context.Context) (model.VMs, error) {
	pve, virt := e.Has("pvesh"), e.Has("virsh")
	if !pve && !virt {
		return model.VMs{}, ErrAbsent
	}
	out := model.VMs{Hypervisors: []model.Hypervisor{}, Guests: []model.Guest{}}
	if pve {
		h, guests, storage := e.proxmoxVMs(ctx)
		out.Hypervisors = append(out.Hypervisors, h)
		out.Guests = append(out.Guests, guests...)
		out.Storage = storage
	}
	if virt {
		h, guests := e.libvirtVMs(ctx)
		out.Hypervisors = append(out.Hypervisors, h)
		out.Guests = append(out.Guests, guests...)
	}
	for i := range out.Guests {
		g := &out.Guests[i]
		sort.Slice(g.Disks, func(a, b int) bool { return vmNameLess(g.Disks[a].Name, g.Disks[b].Name) })
		sort.Slice(g.NICs, func(a, b int) bool { return vmNameLess(g.NICs[a].Name, g.NICs[b].Name) })
	}
	sort.Slice(out.Hypervisors, func(i, j int) bool { return out.Hypervisors[i].Platform < out.Hypervisors[j].Platform })
	sort.Slice(out.Guests, func(i, j int) bool { return out.Guests[i].Key() < out.Guests[j].Key() })
	sort.Slice(out.Storage, func(i, j int) bool { return out.Storage[i].Name < out.Storage[j].Name })
	return out, nil
}

// vmNameLess orders device names by prefix, then by their trailing number,
// so scsi10 follows scsi9 and net10 follows net9.
func vmNameLess(a, b string) bool {
	pa, na := vmSplitName(a)
	pb, nb := vmSplitName(b)
	if pa != pb || na == nb {
		return a < b
	}
	return na < nb
}

func vmSplitName(s string) (string, int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	n, err := strconv.Atoi(s[i:])
	if err != nil {
		return s, -1
	}
	return s[:i], n
}

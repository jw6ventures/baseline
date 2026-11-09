// Package model defines the inventory sections the agent sends and the server
// stores. Both sides compile against these types; on the wire each section is
// JSON inside agentv1.InventorySection.payload_json.
//
// Sections hold state that changes when the host changes, not readings:
// filesystem usage, uptime and link state belong to metrics, or every
// collection would look like a change.
package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion is bumped when a section's JSON changes incompatibly.
const SchemaVersion = 1

const (
	SectionOS         = "os"
	SectionHardware   = "hardware"
	SectionPackages   = "packages"
	SectionUpdates    = "updates"
	SectionSmart      = "smart"
	SectionContainers = "containers"
	SectionServices   = "services"
	SectionPorts      = "ports"
	SectionReboot     = "reboot"
	SectionCerts      = "certs"
	SectionVMs        = "vms"
	SectionK8sNode    = "k8s_node"
	SectionK8s        = "k8s"
)

// CapK8sCluster is the capability a cluster-mode agent (baseline-agent
// --mode=k8s) reports in Hello instead of a host's. It sends only the "k8s"
// section, runs no jobs and is updated by changing its image.
const CapK8sCluster = "k8s-cluster"

// Polls a cluster agent answers for the server (IntegrationPoll kinds):
// a workload's pods, and a pod's logs.
const (
	PollK8sPods = "k8s.pods"
	PollK8sLogs = "k8s.logs"
)

// Sections lists every section in the order the UI shows them. Slow ones
// (updates refreshes repository metadata, certs probes listeners) come last.
var Sections = []string{SectionOS, SectionHardware, SectionPackages, SectionSmart, SectionContainers,
	SectionVMs, SectionK8sNode, SectionK8s, SectionServices, SectionPorts, SectionReboot, SectionCerts, SectionUpdates}

// Tracked reports whether changes to a section are recorded in the host's
// history. Available updates are not configuration: they change whenever a
// repository publishes something, not when the host changes. Whether a
// reboot is pending follows from changes that are recorded (packages).
// A Kubernetes node's pods come and go with every rollout and CronJob run;
// the cluster's workloads are what's configured.
func Tracked(section string) bool {
	return section != SectionUpdates && section != SectionReboot && section != SectionK8sNode
}

// Encode returns a section's canonical JSON and its content hash. Struct
// fields encode in declaration order and collectors sort their lists, so the
// same state always hashes the same.
//
// NUL characters are dropped: collectors read strings from firmware, device
// trees and sysfs that are NUL-padded, and PostgreSQL can't store U+0000.
func Encode(v any) ([]byte, string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	b = StripNUL(b)
	return b, Hash(b), nil
}

// StripNUL removes \u0000 escapes from a JSON document, which PostgreSQL
// rejects in jsonb and text ("unsupported Unicode escape sequence"). Valid
// JSON has no raw control characters and no backslashes outside strings, so
// a scan over escapes is enough. b is returned unchanged when it has none.
func StripNUL(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		if bytes.HasPrefix(b[i+1:], []byte("u0000")) {
			i += 5
			continue
		}
		out = append(out, b[i], b[i+1]) // keep the escape, e.g. \\ before "u0000"
		i++
	}
	return out
}

// Hash is the hex SHA-256 of a section payload.
func Hash(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// OS is the "os" section.
type OS struct {
	Hostname   string `json:"hostname"`
	FQDN       string `json:"fqdn,omitempty"`
	ID         string `json:"id"`                // os-release ID: ubuntu, rocky, bazzite...
	IDLike     string `json:"id_like,omitempty"` // os-release ID_LIKE
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	VariantID  string `json:"variant_id,omitempty"`
	PrettyName string `json:"pretty_name"`
	Kernel     string `json:"kernel"` // uname -r
	Arch       string `json:"arch"`   // uname -m
	MachineID  string `json:"machine_id"`
	Timezone   string `json:"timezone,omitempty"`
	// Image is set on image-based hosts (rpm-ostree/bootc, e.g. Bazzite).
	Image *OSImage `json:"image,omitempty"`
}

// OSImage describes the booted deployment of an image-based host.
type OSImage struct {
	Origin   string `json:"origin"` // container image ref or ostree refspec
	Version  string `json:"version,omitempty"`
	Checksum string `json:"checksum,omitempty"`
	Digest   string `json:"digest,omitempty"` // container image digest
	// Staged is a newer deployment waiting for a reboot.
	Staged *OSImageStaged `json:"staged,omitempty"`
}

type OSImageStaged struct {
	Version  string `json:"version,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}

// Hardware is the "hardware" section (docs/agent.md §1.1).
type Hardware struct {
	System         System       `json:"system"`
	Virtualization string       `json:"virtualization"` // "none" on bare metal, else the hypervisor
	CPU            CPU          `json:"cpu"`
	Memory         Memory       `json:"memory"`
	Disks          []Disk       `json:"disks"`
	Filesystems    []Filesystem `json:"filesystems"`
	NICs           []NIC        `json:"nics"`
	PCI            []PCIDevice  `json:"pci,omitempty"`
	// Peripherals are collected on high security hosts only
	// (Config.high_security); nil, and left out, elsewhere.
	Peripherals *Peripherals `json:"peripherals,omitempty"`
}

type System struct {
	Vendor      string `json:"vendor,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version,omitempty"`
	Serial      string `json:"serial,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Chassis     string `json:"chassis,omitempty"`
	BIOSVendor  string `json:"bios_vendor,omitempty"`
	BIOSVersion string `json:"bios_version,omitempty"`
	BIOSDate    string `json:"bios_date,omitempty"`
	BoardVendor string `json:"board_vendor,omitempty"`
	BoardName   string `json:"board_name,omitempty"`
	BoardSerial string `json:"board_serial,omitempty"`
}

type CPU struct {
	Model     string   `json:"model"`
	Vendor    string   `json:"vendor,omitempty"`
	Sockets   int      `json:"sockets"`
	Cores     int      `json:"cores"`
	Threads   int      `json:"threads"`
	Microcode string   `json:"microcode,omitempty"`
	Flags     []string `json:"flags,omitempty"` // flags of interest only
}

type Memory struct {
	TotalBytes uint64 `json:"total_bytes"`
	ECC        string `json:"ecc,omitempty"` // dmidecode error correction type
	DIMMs      []DIMM `json:"dimms,omitempty"`
}

type DIMM struct {
	Locator      string `json:"locator"`
	SizeBytes    uint64 `json:"size_bytes"`
	Type         string `json:"type,omitempty"`
	SpeedMTs     int    `json:"speed_mts,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
	Serial       string `json:"serial,omitempty"`
}

type Disk struct {
	Name       string `json:"name"` // kernel name: sda, nvme0n1
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	WWN        string `json:"wwn,omitempty"`
	SizeBytes  uint64 `json:"size_bytes"`
	Rotational bool   `json:"rotational"`
	Transport  string `json:"transport,omitempty"` // sata, nvme, usb, virtio...
	Firmware   string `json:"firmware,omitempty"`
}

type Filesystem struct {
	Mountpoint string `json:"mountpoint"`
	Device     string `json:"device"`
	FSType     string `json:"fstype"`
	SizeBytes  uint64 `json:"size_bytes"`
}

type NIC struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Driver    string   `json:"driver,omitempty"`
	SpeedMbps int      `json:"speed_mbps,omitempty"`
	Kind      string   `json:"kind"`             // physical | bond | bridge | vlan | virtual
	Master    string   `json:"master,omitempty"` // bond or bridge this NIC belongs to
	Addresses []string `json:"addresses,omitempty"`
	// Link is a physical NIC's link on high security hosts: up, down (no
	// carrier: unplugged, or the far end is off) or off (the interface is
	// disabled). Elsewhere it is left out, since links flap.
	Link string `json:"link,omitempty"`
}

type PCIDevice struct {
	Address string `json:"address"`
	Class   string `json:"class"`
	Vendor  string `json:"vendor"`
	Device  string `json:"device"`
}

// Peripherals are what can be plugged into a running machine without
// opening it: USB devices and displays.
type Peripherals struct {
	USB      []USBDevice `json:"usb"`
	Displays []Display   `json:"displays"`
}

// USBDevice is a device plugged into a USB port, hubs included. Root hubs
// are the controllers themselves and are listed under PCI.
type USBDevice struct {
	Name         string `json:"name"` // port path: 1-1.2
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Class        string `json:"class,omitempty"` // "Mass Storage [08]"
}

// Display is a display connector and the monitor on it, from DRM and the
// monitor's EDID.
type Display struct {
	Name    string `json:"name"`   // connector: card0-HDMI-A-1
	Status  string `json:"status"` // connected | disconnected | unknown
	Monitor string `json:"monitor,omitempty"`
	Serial  string `json:"serial,omitempty"`
}

// Packages is the "packages" section.
type Packages struct {
	Managers []string  `json:"managers"`
	Packages []Package `json:"packages"`
}

type Package struct {
	Manager string `json:"manager"` // apt | dnf | rpm-ostree | flatpak | snap
	Name    string `json:"name"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version"`
	Release string `json:"release,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"` // source package (CVE matching)
	Repo    string `json:"repo,omitempty"`
	// Layered marks a package layered on top of an image (rpm-ostree).
	Layered bool `json:"layered,omitempty"`
}

// FullVersion is epoch:version-release, omitting empty parts.
func (p Package) FullVersion() string {
	v := p.Version
	if p.Release != "" {
		v += "-" + p.Release
	}
	if p.Epoch != "" && p.Epoch != "0" {
		v = p.Epoch + ":" + v
	}
	return v
}

// Updates is the "updates" section: what upgrading would install now.
type Updates struct {
	Managers []string `json:"managers"`
	Updates  []Update `json:"updates"`
	// Held lists packages pinned against upgrades (apt-mark hold).
	Held []string `json:"held,omitempty"`
	// Warnings are problems that didn't stop the check, such as a repository
	// that couldn't be refreshed (the list then comes from cached metadata).
	Warnings []string `json:"warnings,omitempty"`
}

type Update struct {
	Manager   string `json:"manager"`
	Name      string `json:"name"`
	Arch      string `json:"arch,omitempty"`
	Installed string `json:"installed,omitempty"` // empty for a newly pulled-in package (e.g. a new kernel)
	Candidate string `json:"candidate"`
	Repo      string `json:"repo,omitempty"`
	Security  bool   `json:"security,omitempty"`
	// Advisories are the vendor advisory IDs (RLSA-..., FEDORA-...).
	Advisories []string `json:"advisories,omitempty"`
	// Image marks a whole-image update on an image-based host: Name is the
	// image reference, and the versions are image versions.
	Image  bool   `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// Smart is the "smart" section (smartctl). Readings that move on their own,
// such as temperature and power-on hours, are metrics instead.
type Smart struct {
	Devices []SmartDevice `json:"devices"`
}

type SmartDevice struct {
	Name     string `json:"name"`           // kernel name: sda, nvme0n1
	Type     string `json:"type,omitempty"` // smartctl device type: sat, nvme, scsi...
	Model    string `json:"model,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	// Passed is the drive's overall self-assessment; nil when it couldn't be
	// read (no SMART support, or a USB bridge that hides it).
	Passed *bool `json:"passed,omitempty"`
	// The counters that predict failure. Any non-zero value is worth a look.
	Reallocated     int64 `json:"reallocated,omitempty"`
	Pending         int64 `json:"pending,omitempty"`
	Uncorrectable   int64 `json:"uncorrectable,omitempty"`
	MediaErrors     int64 `json:"media_errors,omitempty"`     // NVMe
	PercentUsed     int64 `json:"percent_used,omitempty"`     // NVMe endurance used
	CriticalWarning int64 `json:"critical_warning,omitempty"` // NVMe bit field
	// Error is why the device couldn't be read, if it couldn't.
	Error string `json:"error,omitempty"`
}

// Failing reports whether the drive says it is failing.
func (d SmartDevice) Failing() bool { return d.Passed != nil && !*d.Passed }

// BadSectors is the count the smart alert watches rise: reallocated,
// pending and uncorrectable sectors and NVMe media errors together. A
// pending sector that gets reallocated moves between them without a rise.
func (d SmartDevice) BadSectors() int64 {
	return d.Reallocated + d.Pending + d.Uncorrectable + d.MediaErrors
}

// Degrading reports early warning signs on a drive that still passes.
func (d SmartDevice) Degrading() bool {
	return !d.Failing() && (d.Reallocated > 0 || d.Pending > 0 || d.Uncorrectable > 0 || d.MediaErrors > 0 ||
		d.CriticalWarning != 0 || d.PercentUsed >= 90)
}

// DedupeSmart keeps one entry per drive serial. A drive behind a RAID HBA
// in JBOD mode shows up twice, through the controller (bus/0:sat+megaraid,1)
// and as its block device (sdb). The block device name is kept, with the
// reading that has the most data, and a missing model or firmware is filled
// in from the other path. Drives without a serial are kept as they are. The
// result is sorted by name.
func DedupeSmart(devs []SmartDevice) []SmartDevice {
	score := func(d SmartDevice) int {
		n := 0
		if d.Error == "" {
			n += 4
		}
		if d.Passed != nil {
			n += 2
		}
		if d.Model != "" {
			n++
		}
		return n
	}
	block := func(d SmartDevice) bool { return !strings.Contains(d.Name, ":") }
	better := func(a, b SmartDevice) bool {
		if sa, sb := score(a), score(b); sa != sb {
			return sa > sb
		}
		if block(a) != block(b) {
			return block(a)
		}
		return a.Name < b.Name
	}
	out := make([]SmartDevice, 0, len(devs))
	at := map[string]int{}
	for _, d := range devs {
		if d.Serial == "" {
			out = append(out, d)
			continue
		}
		i, ok := at[d.Serial]
		if !ok {
			at[d.Serial] = len(out)
			out = append(out, d)
			continue
		}
		keep, other := out[i], d
		if better(d, keep) {
			keep, other = d, keep
		}
		if keep.Model == "" {
			keep.Model = other.Model
		}
		if keep.Firmware == "" {
			keep.Firmware = other.Firmware
		}
		if !block(keep) && block(other) {
			keep.Name = other.Name
		}
		out[i] = keep
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Containers is the "containers" section: the container engines on the host,
// their containers and images, and the Compose stacks those containers
// belong to (docs/agent.md §3).
type Containers struct {
	Engines    []ContainerEngine `json:"engines"`
	Containers []Container       `json:"containers"`
	Images     []ContainerImage  `json:"images"`
	Stacks     []ComposeStack    `json:"stacks"`
}

// ContainerEngine is one Docker or Podman API socket.
type ContainerEngine struct {
	// Name identifies the engine on the host: "docker", "podman" (rootful)
	// or "podman:<user>" (rootless).
	Name       string `json:"name"`
	Kind       string `json:"kind"` // docker | podman
	Socket     string `json:"socket"`
	Version    string `json:"version,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
	// Error is why the engine couldn't be read. Its containers are then
	// missing from the section, so the server keeps its earlier copy of
	// them rather than reading the gap as removals.
	Error string `json:"error,omitempty"`
}

// Container is one container. Volatile details (uptime, CPU use) are metrics,
// not inventory. A container is identified by engine and name, which stay the
// same when Compose recreates it; the engine ID doesn't.
type Container struct {
	Engine       string `json:"engine"`
	Name         string `json:"name"`
	ID           string `json:"id"`
	Image        string `json:"image"`    // the reference it was created from, e.g. nginx:1.27
	ImageID      string `json:"image_id"` // sha256:...
	Created      string `json:"created,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	State        string `json:"state"`            // created | running | paused | restarting | exited | dead
	Health       string `json:"health,omitempty"` // starting | healthy | unhealthy; "" without a healthcheck
	ExitCode     int    `json:"exit_code,omitempty"`
	RestartCount int    `json:"restart_count,omitempty"`
	// RestartPolicy is no | always | unless-stopped | on-failure.
	RestartPolicy  string            `json:"restart_policy,omitempty"`
	Ports          []ContainerPort   `json:"ports,omitempty"`
	Mounts         []ContainerMount  `json:"mounts,omitempty"`
	Networks       []string          `json:"networks,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	ComposeProject string            `json:"compose_project,omitempty"`
	ComposeService string            `json:"compose_service,omitempty"`
	Pod            string            `json:"pod,omitempty"` // Podman pod name
}

// Key identifies a container on its host.
func (c Container) Key() string { return c.Engine + "/" + c.Name }

type ContainerPort struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"` // 0: exposed, not published
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"` // tcp | udp | sctp
}

type ContainerMount struct {
	Type        string `json:"type"`             // bind | volume | tmpfs
	Source      string `json:"source,omitempty"` // host path, or volume name
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// ContainerImage is an image in an engine's store.
type ContainerImage struct {
	Engine string   `json:"engine"`
	ID     string   `json:"id"`
	Tags   []string `json:"tags,omitempty"`
	// Digests are the RepoDigests ("repo@sha256:..."): what the registry
	// served when the image was pulled. A registry digest that isn't among
	// them means the tag has moved on.
	Digests   []string `json:"digests,omitempty"`
	SizeBytes int64    `json:"size_bytes"`
	Created   string   `json:"created,omitempty"`
}

// ComposeStack is a Compose project, discovered from container labels, or
// from its directory under a Compose root when nothing of it runs.
type ComposeStack struct {
	Engine     string   `json:"engine"`
	Project    string   `json:"project"`
	WorkingDir string   `json:"working_dir,omitempty"`
	Services   []string `json:"services"`
	// CLI is how the stack can be driven on this host: "docker compose",
	// "docker-compose", "podman compose" or "podman-compose"; "" if none.
	CLI         string        `json:"cli,omitempty"`
	ConfigFiles []ComposeFile `json:"config_files,omitempty"`
	// Orphaned is set when the stack's Compose files aren't on disk (it was
	// started from somewhere else), so Baseline can't update it.
	Orphaned bool `json:"orphaned,omitempty"`
	// Stopped is set for a stack found on disk under one of the host's
	// Compose roots with no container on the engine: it isn't running.
	// Its services then come from its Compose file.
	Stopped bool `json:"stopped,omitempty"`
}

// Key identifies a stack on its host.
func (s ComposeStack) Key() string { return s.Engine + "/" + s.Project }

// ComposeFile is one of a stack's config files, read so the UI can show it.
// Values of keys that look like secrets are masked by the agent.
type ComposeFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Content string `json:"content,omitempty"` // capped; Truncated says so
	// Truncated is set when the file was larger than the agent sends.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"` // missing or unreadable
}

// Services is the "services" section: systemd service units.
type Services struct {
	Units []Service `json:"units"`
}

type Service struct {
	Name        string `json:"name"` // unit name, e.g. sshd.service
	Description string `json:"description,omitempty"`
	Load        string `json:"load,omitempty"`    // loaded | not-found | masked; "" when not loaded
	Active      string `json:"active"`            // active | inactive | failed | activating | deactivating
	Sub         string `json:"sub,omitempty"`     // running | exited | dead | failed...
	Enabled     string `json:"enabled,omitempty"` // enabled | disabled | static | masked | indirect...
}

// Failed reports whether the unit is in the failed state.
func (s Service) Failed() bool { return s.Active == "failed" }

// Ports is the "ports" section: sockets listening on the host.
type Ports struct {
	Listeners []Listener `json:"listeners"`
}

type Listener struct {
	Proto   string `json:"proto"` // tcp | udp
	Addr    string `json:"addr"`  // bind address: 0.0.0.0, ::, 127.0.0.1...
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"` // command name; "" for kernel sockets
	PID     int    `json:"pid,omitempty"`
	Unit    string `json:"unit,omitempty"` // systemd unit owning the process
}

// Key identifies a listener on its host.
func (l Listener) Key() string { return l.Proto + " " + l.Addr + ":" + strconv.Itoa(l.Port) }

// Reboot is the "reboot" section (docs/agent.md §1.4).
type Reboot struct {
	Required bool `json:"required"`
	// Reasons say why, one line each.
	Reasons []string `json:"reasons,omitempty"`
	// Packages asked for the reboot (Debian's reboot-required.pkgs).
	Packages []string `json:"packages,omitempty"`
	// Services still run code from deleted libraries: they need a restart,
	// not a reboot.
	Services []string `json:"services,omitempty"`
}

// Certs is the "certs" section: TLS certificates in files and on listeners.
type Certs struct {
	Certs []Cert `json:"certs"`
}

type Cert struct {
	// Location is a file path, or "tcp:<port>" for a listener probe, with
	// "/<server name>" when it was found with SNI.
	Location    string   `json:"location"`
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`  // RFC 3339, UTC
	NotAfter    string   `json:"not_after"`   // RFC 3339, UTC
	Serial      string   `json:"serial"`      // hex
	Fingerprint string   `json:"fingerprint"` // SHA-256 of the DER, hex
	SelfSigned  bool     `json:"self_signed,omitempty"`
}

// VMs is the "vms" section: the guests of the hypervisors on the host
// (docs/agent.md §4). A Proxmox node reports its own guests, not the whole
// cluster's, so a guest that migrates moves with the node that runs it.
type VMs struct {
	Hypervisors []Hypervisor `json:"hypervisors"`
	Guests      []Guest      `json:"guests"`
	// Storage lists Proxmox storage pools: their definitions, not usage.
	Storage []VMStorage `json:"storage,omitempty"`
}

// Hypervisor is one virtualization platform found on the host.
type Hypervisor struct {
	Platform string `json:"platform"` // proxmox | libvirt
	Version  string `json:"version,omitempty"`
	// Node is the Proxmox node name; Cluster the Proxmox cluster's name, ""
	// for a standalone node.
	Node    string `json:"node,omitempty"`
	Cluster string `json:"cluster,omitempty"`
	// Error is why the platform couldn't be read. Its guests are then
	// missing from the section, so the server keeps its earlier copy of
	// them rather than reading the gap as removals.
	Error string `json:"error,omitempty"`
}

// Guest is a VM or a Proxmox LXC container. Configuration only, apart from
// State: usage is for metrics.
type Guest struct {
	Platform string `json:"platform"` // proxmox | libvirt
	// Kind is qemu or lxc on Proxmox, and the domain type on libvirt (kvm,
	// qemu...).
	Kind string `json:"kind"`
	// ID identifies the guest on its platform: the VMID on Proxmox, the
	// domain UUID on libvirt.
	ID   string `json:"id"`
	Name string `json:"name"`
	// UUID is the SMBIOS UUID the guest sees as its DMI product UUID,
	// lowercase; "" for containers.
	UUID      string `json:"uuid,omitempty"`
	State     string `json:"state"` // running | stopped | paused | suspended | crashed...
	Template  bool   `json:"template,omitempty"`
	Autostart bool   `json:"autostart,omitempty"` // Proxmox onboot, libvirt autostart
	CPUs      int    `json:"cpus"`                // vCPUs: sockets × cores on Proxmox
	// MemoryBytes is the memory allocated (the maximum, with ballooning).
	MemoryBytes uint64      `json:"memory_bytes"`
	OSType      string      `json:"os_type,omitempty"` // Proxmox ostype (l26, win11, debian), libosinfo ID
	Machine     string      `json:"machine,omitempty"` // machine type: q35, pc-q35-10.2...
	Disks       []GuestDisk `json:"disks,omitempty"`
	NICs        []GuestNIC  `json:"nics,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	HAState     string      `json:"ha_state,omitempty"` // Proxmox HA: started, stopped, ignored...
}

// Key identifies a guest on its host.
func (g Guest) Key() string { return g.Platform + "/" + g.ID }

type GuestDisk struct {
	Name      string `json:"name"`             // scsi0, rootfs, mp0, vda
	Source    string `json:"source,omitempty"` // volume (local-lvm:vm-100-disk-0) or file or device path
	SizeBytes uint64 `json:"size_bytes,omitempty"`
	Device    string `json:"device,omitempty"` // disk | cdrom
}

type GuestNIC struct {
	Name    string `json:"name"` // net0; libvirt: the index (net0, net1...)
	MAC     string `json:"mac,omitempty"`
	Bridge  string `json:"bridge,omitempty"`
	Network string `json:"network,omitempty"` // libvirt network
	Model   string `json:"model,omitempty"`   // virtio, e1000; veth for LXC
	VLAN    int    `json:"vlan,omitempty"`
}

type VMStorage struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"` // dir, lvmthin, zfspool, nfs, pbs...
	Content []string `json:"content,omitempty"`
	Shared  bool     `json:"shared,omitempty"`
	Path    string   `json:"path,omitempty"`
}

// K8sNode is the "k8s_node" section: what the node's container runtime runs,
// read with crictl (docs/agent.md §3.4). Pods churn with every rollout, so
// this section isn't kept in history; the cluster's "k8s" section is.
type K8sNode struct {
	Runtime        string         `json:"runtime"` // containerd | cri-o
	RuntimeVersion string         `json:"runtime_version,omitempty"`
	Endpoint       string         `json:"endpoint"` // unix:///run/containerd/containerd.sock...
	Pods           []CRIPod       `json:"pods"`
	Containers     []CRIContainer `json:"containers"`
	Images         []CRIImage     `json:"images"`
}

type CRIPod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	State     string `json:"state"` // ready | notready
	Created   string `json:"created,omitempty"`
}

type CRIContainer struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Name      string `json:"name"`
	Image     string `json:"image"`              // the reference it runs
	ImageID   string `json:"image_id,omitempty"` // image ID or digest
	State     string `json:"state"`              // running | exited | created | unknown
	Attempt   int    `json:"attempt,omitempty"`  // restarts
	Created   string `json:"created,omitempty"`
}

type CRIImage struct {
	ID        string   `json:"id"`
	Tags      []string `json:"tags,omitempty"`
	Digests   []string `json:"digests,omitempty"`
	SizeBytes int64    `json:"size_bytes"`
}

// K8s is the "k8s" section, sent by an agent in cluster mode
// (baseline-agent --mode=k8s): the cluster's nodes and the workloads,
// services and ingresses configured in it. Pods are left out, except
// ones no controller owns.
type K8s struct {
	Cluster    K8sCluster    `json:"cluster"`
	Nodes      []K8sNodeInfo `json:"nodes"`
	Namespaces []string      `json:"namespaces"`
	Workloads  []K8sWorkload `json:"workloads"`
	Services   []K8sService  `json:"services"`
	Ingresses  []K8sIngress  `json:"ingresses"`
	// Errors are resources that couldn't be listed (forbidden, or an API
	// the cluster doesn't serve). The server keeps its earlier copy of
	// what they hold rather than reading the gap as removals.
	Errors []K8sError `json:"errors,omitempty"`
	// DenyNamespaces are the namespaces the cluster agent's actions may not
	// touch (BASELINE_DENY_NAMESPACES), so the UI doesn't offer them.
	DenyNamespaces []string `json:"deny_namespaces,omitempty"`
}

type K8sCluster struct {
	// UID is the kube-system namespace's UID: Kubernetes has no cluster ID,
	// and that one lasts as long as the cluster.
	UID      string `json:"uid"`
	Name     string `json:"name"`     // from the agent's configuration
	Version  string `json:"version"`  // API server gitVersion
	Platform string `json:"platform"` // linux/amd64
}

type K8sNodeInfo struct {
	Name             string   `json:"name"`
	Roles            []string `json:"roles,omitempty"` // node-role.kubernetes.io/* labels
	Ready            bool     `json:"ready"`
	Unschedulable    bool     `json:"unschedulable,omitempty"`
	KubeletVersion   string   `json:"kubelet_version"`
	ContainerRuntime string   `json:"container_runtime,omitempty"` // containerd://1.7.27
	OSImage          string   `json:"os_image,omitempty"`
	KernelVersion    string   `json:"kernel_version,omitempty"`
	Arch             string   `json:"arch,omitempty"`
	// MachineID and SystemUUID are the node's /etc/machine-id and DMI
	// product UUID (lowercase): the server links the node to the host
	// agent running on it with them.
	MachineID   string   `json:"machine_id,omitempty"`
	SystemUUID  string   `json:"system_uuid,omitempty"`
	InternalIPs []string `json:"internal_ips,omitempty"`
	CPU         string   `json:"cpu,omitempty"` // capacity, as Kubernetes writes it ("4", "3500m")
	MemoryBytes int64    `json:"memory_bytes,omitempty"`
	Taints      []string `json:"taints,omitempty"` // key=value:effect
	Created     string   `json:"created,omitempty"`
}

// K8sWorkload is a Deployment, StatefulSet, DaemonSet, CronJob, or a Pod no
// controller owns.
type K8sWorkload struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Replicas is the desired count (a DaemonSet's: the nodes it should run
	// on); Ready how many are ready now.
	Replicas int      `json:"replicas"`
	Ready    int      `json:"ready"`
	Images   []string `json:"images"` // of every container and init container, sorted
	// Containers are the pod template's containers and init containers,
	// in the template's order: what k8s.set_image changes.
	Containers []K8sContainer `json:"containers,omitempty"`
	Schedule   string         `json:"schedule,omitempty"` // CronJob
	Suspend    bool           `json:"suspend,omitempty"`  // CronJob
	Node       string         `json:"node,omitempty"`     // a bare Pod's node
	Created    string         `json:"created,omitempty"`
}

// K8sContainer is a container of a workload's pod template.
type K8sContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Init  bool   `json:"init,omitempty"`
}

// Key identifies a workload in its cluster.
func (w K8sWorkload) Key() string { return w.Kind + "/" + w.Namespace + "/" + w.Name }

type K8sService struct {
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // ClusterIP | NodePort | LoadBalancer | ExternalName
	ClusterIP   string   `json:"cluster_ip,omitempty"`
	ExternalIPs []string `json:"external_ips,omitempty"` // load balancer and external IPs
	// Ports read "80/TCP→8080", with ":30080" for a node port.
	Ports        []string          `json:"ports,omitempty"`
	Selector     map[string]string `json:"selector,omitempty"`
	ExternalName string            `json:"external_name,omitempty"`
	// Workloads are the workloads (K8sWorkload.Key) whose pods the
	// selector matches, worked out by the agent from their pod labels.
	Workloads []string `json:"workloads,omitempty"`
}

type K8sIngress struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Class     string   `json:"class,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	TLS       bool     `json:"tls,omitempty"`
	// Backends read "host/path → service:port".
	Backends []string `json:"backends,omitempty"`
}

// K8sPodsRequest is the "k8s.pods" poll's config: the workload whose
// pods to list.
type K8sPodsRequest struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// K8sPod is a workload's pod as a cluster agent lists it for the server
// ("k8s.pods"). Pods aren't kept: they are read when a page shows them.
type K8sPod struct {
	Name       string   `json:"name"`
	Node       string   `json:"node,omitempty"`
	Phase      string   `json:"phase"`
	Ready      int      `json:"ready"` // containers ready
	Total      int      `json:"total"` // containers
	Restarts   int      `json:"restarts"`
	Reason     string   `json:"reason,omitempty"` // CrashLoopBackOff, ImagePullBackOff, Evicted...
	Created    string   `json:"created,omitempty"`
	Containers []string `json:"containers"`       // for logs
	Init       []string `json:"init,omitempty"`   // init containers
	Images     []string `json:"images,omitempty"` // sorted
}

// K8sLogsRequest is the "k8s.logs" poll's config.
type K8sLogsRequest struct {
	// The workload, which the pod must belong to.
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	// Tail is how many lines from the end; 0 is DefaultLogLines.
	Tail int `json:"tail"`
	// Previous reads the container's previous instance (before a restart).
	Previous bool `json:"previous"`
}

const (
	DefaultLogLines = 200
	MaxLogLines     = 5000
)

// K8sLogs is the "k8s.logs" poll's answer: the end of a container's log,
// with timestamps.
type K8sLogs struct {
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Text      string `json:"text"`
	// Truncated: the lines asked for came to more than the agent sends.
	Truncated bool `json:"truncated,omitempty"`
}

// K8sError is a resource the agent couldn't list.
type K8sError struct {
	// Resource is the plural API resource: nodes, deployments, statefulsets,
	// daemonsets, cronjobs, pods, services, ingresses, namespaces.
	Resource string `json:"resource"`
	Error    string `json:"error"`
}

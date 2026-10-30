package collect

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

const (
	pveStatusCmd    = "pvesh get /cluster/status --output-format json"
	pveVersionCmd   = "pvesh get /version --output-format json"
	pveResourcesCmd = "pvesh get /cluster/resources --type vm --output-format json"
	pveStorageCmd   = "pvesh get /storage --output-format json"
)

func pveConfigCmd(kind, vmid string) string {
	return "pvesh get /nodes/pve1/" + kind + "/" + vmid + "/config --output-format json"
}

// A node of a two-node cluster. pvesh prints some numbers as strings.
const pveClusterStatus = `[
{"id":"cluster","name":"homelab","nodes":2,"quorate":1,"type":"cluster","version":4},
{"id":"node/pve2","ip":"10.0.0.12","local":0,"name":"pve2","nodeid":2,"online":1,"type":"node"},
{"id":"node/pve1","ip":"10.0.0.11","local":"1","name":"pve1","nodeid":1,"online":1,"type":"node"}
]`

const pveVersion = `{"release":"8.2","repoid":"faa83925c9641325","version":"8.2.4"}`

const pveResources = `[
{"id":"qemu/100","vmid":100,"name":"web","node":"pve1","type":"qemu","status":"running","template":0,"maxcpu":4,"maxmem":4294967296,"tags":"prod;web","hastate":"started","uptime":123456,"cpu":0.031,"mem":2147483648,"netin":99,"diskread":5},
{"id":"qemu/101","vmid":"101","name":"tmpl-debian","node":"pve1","type":"qemu","status":"stopped","template":"1","maxcpu":"3","maxmem":"2147483648"},
{"id":"lxc/200","vmid":200,"name":"dns","node":"pve1","type":"lxc","status":"running","template":0,"maxcpu":8,"maxmem":1073741824,"tags":"infra, dns infra","uptime":99},
{"id":"qemu/300","vmid":300,"name":"db","node":"pve2","type":"qemu","status":"running","template":0,"maxcpu":2,"maxmem":2147483648,"tags":"prod"}
]`

const pveQemu100 = `{
"boot":"order=scsi0;ide2;net0","cores":2,"sockets":"2","cpu":"x86-64-v2-AES","memory":"4096","balloon":2048,
"machine":"q35","ostype":"l26","onboot":1,"scsihw":"virtio-scsi-single","numa":0,
"smbios1":"uuid=6B7C1E2A-3D4F-4A5B-9C8D-0E1F2A3B4C5D,manufacturer=QUNNRQ==,base64=1",
"vmgenid":"11111111-2222-3333-4444-555555555555","digest":"0123abcd",
"scsi0":"local-lvm:vm-100-disk-0,iothread=1,size=32G",
"scsi1":"tank:vm-100-disk-1,size=1T,backup=0",
"ide2":"none,media=cdrom",
"efidisk0":"local-lvm:vm-100-disk-2,efitype=4m,pre-enrolled-keys=1,size=528K",
"unused0":"local-lvm:vm-100-disk-9",
"net0":"virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=10",
"net1":"model=e1000,macaddr=BC:24:11:DD:EE:FF,bridge=vmbr1,link_down=1",
"description":"root password is hunter2",
"cipassword":"$5$supersecrethash","ciuser":"admin",
"sshkeys":"ssh-ed25519%20AAAAC3NzaSECRETKEY",
"args":"-fw_cfg name=opt/secret,string=topsecret",
"hookscript":"local:snippets/hook-secret.pl",
"tags":"prod;web"
}`

const pveQemu101 = `{
"cores":4,"sockets":1,"vcpus":3,"memory":"current=2048","template":1,"ostype":"win11",
"machine":"type=pc-q35-8.1,viommu=virtio",
"smbios1":"uuid=a1b2c3d4-0000-1111-2222-333344445555",
"sata0":"local:iso/debian-12.iso,media=cdrom,size=628M",
"virtio0":"local-lvm:base-101-disk-0,size=20G",
"tpmstate0":"local-lvm:base-101-disk-1,size=4M,version=v2.0",
"net0":"e1000,macaddr=BC:24:11:00:00:01,bridge=vmbr0"
}`

const pveLXC200 = `{
"arch":"amd64","hostname":"dns","memory":1024,"swap":512,"ostype":"debian","onboot":0,
"rootfs":"local-lvm:vm-200-disk-0,size=8G",
"mp0":"tank:subvol-200-disk-1,mp=/srv/data,backup=1,size=16G",
"mp1":"/mnt/media,mp=/media,ro=1",
"net0":"name=eth0,bridge=vmbr0,firewall=1,gw=10.0.0.1,hwaddr=BC:24:11:12:34:56,ip=10.0.0.53/24,type=veth,tag=5",
"unprivileged":1,"features":"nesting=1",
"description":"api token: PVEAPIToken=root@pam!x=secret-uuid",
"lxc.idmap":"u 0 100000 65536"
}`

const pveStorage = `[
{"storage":"local","type":"dir","content":"vztmpl,iso,backup","path":"/var/lib/vz","digest":"abc"},
{"storage":"local-lvm","type":"lvmthin","content":"rootdir,images","thinpool":"data","vgname":"pve"},
{"storage":"tank","type":"zfspool","content":"images,rootdir","pool":"tank","nodes":"pve1,pve2","sparse":"1"},
{"storage":"pve2-only","type":"dir","content":"images","path":"/data","nodes":"pve2"},
{"storage":"nas","type":"nfs","content":"backup,iso","shared":"1","path":"/mnt/pve/nas","server":"10.0.0.5","export":"/volume1/pve"},
{"storage":"pbs","type":"pbs","content":"backup","shared":1,"server":"10.0.0.6","datastore":"main","username":"backup@pbs","fingerprint":"aa:bb"}
]`

func proxmoxFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.cmds[pveStatusCmd] = pveClusterStatus
	f.cmds[pveVersionCmd] = pveVersion
	f.cmds[pveResourcesCmd] = pveResources
	f.cmds[pveStorageCmd] = pveStorage
	f.cmds[pveConfigCmd("qemu", "100")] = pveQemu100
	f.cmds[pveConfigCmd("qemu", "101")] = pveQemu101
	f.cmds[pveConfigCmd("lxc", "200")] = pveLXC200
	// pve2's guest 300 isn't stubbed: reading it would fail the platform.
	return f
}

func guestsByID(gs []model.Guest) map[string]model.Guest {
	m := map[string]model.Guest{}
	for _, g := range gs {
		m[g.Key()] = g
	}
	return m
}

func TestVMsAbsent(t *testing.T) {
	f := newFixture(t)
	if _, err := f.env.VMs(context.Background()); !errors.Is(err, ErrAbsent) {
		t.Fatalf("err = %v, want ErrAbsent", err)
	}
}

func TestVMsProxmoxCluster(t *testing.T) {
	f := proxmoxFixture(t)
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := model.Hypervisor{Platform: "proxmox", Version: "8.2.4", Node: "pve1", Cluster: "homelab"}
	if len(v.Hypervisors) != 1 || v.Hypervisors[0] != want {
		t.Fatalf("hypervisors = %+v", v.Hypervisors)
	}
	var keys []string
	for _, g := range v.Guests {
		keys = append(keys, g.Key())
	}
	if strings.Join(keys, " ") != "proxmox/100 proxmox/101 proxmox/200" {
		t.Fatalf("guests = %v (only pve1's, sorted)", keys)
	}
	m := guestsByID(v.Guests)

	web := m["proxmox/100"]
	if web.Kind != "qemu" || web.ID != "100" || web.Name != "web" || web.State != "running" || web.Template ||
		!web.Autostart || web.CPUs != 4 || web.MemoryBytes != 4096<<20 || web.OSType != "l26" ||
		web.Machine != "q35" || web.UUID != "6b7c1e2a-3d4f-4a5b-9c8d-0e1f2a3b4c5d" ||
		strings.Join(web.Tags, ",") != "prod,web" || web.HAState != "started" {
		t.Errorf("web = %+v", web)
	}
	wantDisks := []model.GuestDisk{
		{Name: "efidisk0", Source: "local-lvm:vm-100-disk-2", SizeBytes: 528 << 10, Device: "disk"},
		{Name: "ide2", Device: "cdrom"},
		{Name: "scsi0", Source: "local-lvm:vm-100-disk-0", SizeBytes: 32 << 30, Device: "disk"},
		{Name: "scsi1", Source: "tank:vm-100-disk-1", SizeBytes: 1 << 40, Device: "disk"},
	}
	if !slices.Equal(web.Disks, wantDisks) {
		t.Errorf("web disks = %+v\nwant %+v", web.Disks, wantDisks)
	}
	wantNICs := []model.GuestNIC{
		{Name: "net0", MAC: "bc:24:11:aa:bb:cc", Bridge: "vmbr0", Model: "virtio", VLAN: 10},
		{Name: "net1", MAC: "bc:24:11:dd:ee:ff", Bridge: "vmbr1", Model: "e1000"},
	}
	if !slices.Equal(web.NICs, wantNICs) {
		t.Errorf("web nics = %+v\nwant %+v", web.NICs, wantNICs)
	}

	tmpl := m["proxmox/101"]
	if !tmpl.Template || tmpl.State != "stopped" || tmpl.CPUs != 3 || tmpl.MemoryBytes != 2048<<20 ||
		tmpl.Machine != "pc-q35-8.1" || tmpl.UUID != "a1b2c3d4-0000-1111-2222-333344445555" ||
		tmpl.Tags != nil || tmpl.HAState != "" || tmpl.Autostart {
		t.Errorf("template = %+v", tmpl)
	}
	wantDisks = []model.GuestDisk{
		{Name: "sata0", Source: "local:iso/debian-12.iso", SizeBytes: 628 << 20, Device: "cdrom"},
		{Name: "tpmstate0", Source: "local-lvm:base-101-disk-1", SizeBytes: 4 << 20, Device: "disk"},
		{Name: "virtio0", Source: "local-lvm:base-101-disk-0", SizeBytes: 20 << 30, Device: "disk"},
	}
	if !slices.Equal(tmpl.Disks, wantDisks) {
		t.Errorf("template disks = %+v", tmpl.Disks)
	}
	if want := (model.GuestNIC{Name: "net0", MAC: "bc:24:11:00:00:01", Bridge: "vmbr0", Model: "e1000"}); len(tmpl.NICs) != 1 || tmpl.NICs[0] != want {
		t.Errorf("template nics = %+v", tmpl.NICs)
	}

	ct := m["proxmox/200"]
	if ct.Kind != "lxc" || ct.UUID != "" || ct.CPUs != 8 || ct.MemoryBytes != 1024<<20 || ct.OSType != "debian" ||
		ct.Autostart || ct.Machine != "" || strings.Join(ct.Tags, ",") != "dns,infra" {
		t.Errorf("container = %+v", ct)
	}
	wantDisks = []model.GuestDisk{
		{Name: "mp0", Source: "tank:subvol-200-disk-1", SizeBytes: 16 << 30},
		{Name: "mp1", Source: "/mnt/media"},
		{Name: "rootfs", Source: "local-lvm:vm-200-disk-0", SizeBytes: 8 << 30},
	}
	if !slices.Equal(ct.Disks, wantDisks) {
		t.Errorf("container disks = %+v", ct.Disks)
	}
	if want := (model.GuestNIC{Name: "net0", MAC: "bc:24:11:12:34:56", Bridge: "vmbr0", Model: "veth", VLAN: 5}); len(ct.NICs) != 1 || ct.NICs[0] != want {
		t.Errorf("container nics = %+v", ct.NICs)
	}

	var names []string
	for _, s := range v.Storage {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "local,local-lvm,nas,pbs,tank" {
		t.Fatalf("storage = %v (pve2-only left out)", names)
	}
	if s := v.Storage[0]; s.Type != "dir" || strings.Join(s.Content, ",") != "backup,iso,vztmpl" || s.Shared || s.Path != "/var/lib/vz" {
		t.Errorf("local = %+v", s)
	}
	if s := v.Storage[2]; !s.Shared || s.Type != "nfs" {
		t.Errorf("nas = %+v", s)
	}
}

func TestVMsProxmoxCPUsWithLimitedCores(t *testing.T) {
	f := proxmoxFixture(t)
	f.cmds[pveConfigCmd("lxc", "200")] = `{"cores":"2","memory":512,"rootfs":"local-lvm:vm-200-disk-0,size=8G"}`
	v, _ := f.env.VMs(context.Background())
	if g := guestsByID(v.Guests)["proxmox/200"]; g.CPUs != 2 {
		t.Errorf("cores = %d", g.CPUs)
	}
}

func TestVMsProxmoxDefaults(t *testing.T) {
	f := proxmoxFixture(t)
	f.cmds[pveConfigCmd("qemu", "100")] = `{"ostype":"l26","scsi0":"local-lvm:vm-100-disk-0,size=10G"}`
	v, _ := f.env.VMs(context.Background())
	if g := guestsByID(v.Guests)["proxmox/100"]; g.CPUs != 1 || g.MemoryBytes != 512<<20 || g.UUID != "" || g.NICs != nil {
		t.Errorf("defaults = %+v", g)
	}
}

func TestVMsProxmoxConfigFailure(t *testing.T) {
	f := proxmoxFixture(t)
	key := pveConfigCmd("lxc", "200")
	f.cmds[key] = ""
	f.exits[key] = 2
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h := v.Hypervisors[0]
	if h.Error != "lxc 200: exit status 2" || h.Node != "pve1" {
		t.Errorf("hypervisor = %+v", h)
	}
	if len(v.Guests) != 0 || v.Guests == nil {
		t.Errorf("guests = %+v, want [] (the server keeps its copy)", v.Guests)
	}
	if len(v.Storage) != 5 {
		t.Errorf("storage = %+v", v.Storage)
	}
	if b, _, _ := model.Encode(v); !strings.Contains(string(b), `"guests":[]`) {
		t.Errorf("encoded = %s", b)
	}
}

func TestVMsProxmoxListFailures(t *testing.T) {
	for _, cmd := range []string{pveStatusCmd, pveResourcesCmd} {
		f := proxmoxFixture(t)
		f.env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Join(append([]string{name}, args...), " ") == cmd {
				return nil, &CmdError{Err: errors.New("exit status 255"), Stderr: "ipcc_send_rec[1] failed: Connection refused\nUnable to load access control list: Connection refused"}
			}
			return newFixtureRun(f)(ctx, name, args...)
		}
		v, err := f.env.VMs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if h := v.Hypervisors[0]; h.Error != "Unable to load access control list: Connection refused" || len(v.Guests) != 0 {
			t.Errorf("%s: %+v %+v", cmd, h, v.Guests)
		}
	}
}

// newFixtureRun is the fixture's stubbed Run, for wrapping.
func newFixtureRun(f *fixture) func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		if out, ok := f.cmds[key]; ok {
			if code := f.exits[key]; code != 0 {
				return []byte(out), exitError(code)
			}
			return []byte(out), nil
		}
		return nil, errors.New("not stubbed: " + key)
	}
}

func TestVMsProxmoxStandalone(t *testing.T) {
	f := proxmoxFixture(t)
	f.cmds[pveStatusCmd] = `[{"id":"node/pve1","ip":"10.0.0.11","level":"","local":1,"name":"pve1","nodeid":0,"online":1,"type":"node"}]`
	delete(f.cmds, pveStorageCmd) // storage unreadable: guests still reported
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h := v.Hypervisors[0]; h.Node != "pve1" || h.Cluster != "" || h.Error != "" {
		t.Errorf("hypervisor = %+v", h)
	}
	if len(v.Guests) != 3 || v.Storage != nil {
		t.Errorf("guests = %d, storage = %+v", len(v.Guests), v.Storage)
	}
}

const virtWeb = `<domain type='kvm'>
  <name>web01</name>
  <uuid>4C0E2D3C-4B5A-4697-8877-665544332211</uuid>
  <title>Web server</title>
  <description>admin password: hunter2</description>
  <metadata>
    <libosinfo:libosinfo xmlns:libosinfo="http://libosinfo.org/xmlns/libvirt/domain/1.0">
      <libosinfo:os id="http://ubuntu.com/ubuntu/24.04"/>
    </libosinfo:libosinfo>
  </metadata>
  <memory unit='GiB'>4</memory>
  <currentMemory unit='GiB'>2</currentMemory>
  <vcpu placement='static' current='2'>4</vcpu>
  <sysinfo type='smbios'>
    <system>
      <entry name='manufacturer'>Homelab</entry>
      <entry name='uuid'>0F0E0D0C-0B0A-0908-0706-050403020100</entry>
    </system>
  </sysinfo>
  <os>
    <type arch='x86_64' machine='pc-q35-10.2'>hvm</type>
    <smbios mode='sysinfo'/>
  </os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/web01.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='volume' device='disk'>
      <source pool='default' volume='web01-data.qcow2'/>
      <target dev='vdb' bus='virtio'/>
    </disk>
    <disk type='network' device='disk'>
      <source protocol='rbd' name='rbd/web01-logs'>
        <host name='10.0.0.20' port='6789'/>
        <auth username='libvirt'><secret type='ceph' uuid='deadbeef-0000-0000-0000-000000000000'/></auth>
      </source>
      <target dev='vdc' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:12:34:56'/>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:aa:bb:01'/>
      <source bridge='br0'/>
      <vlan><tag id='20'/></vlan>
      <model type='e1000e'/>
    </interface>
    <graphics type='vnc' port='-1' autoport='yes' passwd='vncsecret'/>
    <video><model type='virtio' heads='1' primary='yes'/></video>
  </devices>
  <qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    <qemu:arg value='-secret'/>
  </qemu:commandline>
</domain>`

const virtDB = `<domain type='qemu'>
  <name>db01</name>
  <uuid>2a1b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d</uuid>
  <memory unit='MB'>2000</memory>
  <vcpu>2</vcpu>
  <os><type arch='aarch64' machine='virt-9.0'>hvm</type></os>
  <devices>
    <disk type='block' device='disk'>
      <source dev='/dev/vg0/db01'/>
      <target dev='sda' bus='scsi'/>
    </disk>
    <interface type='bridge'>
      <mac address='52:54:00:43:d5:0b'/>
      <source bridge='br1'/>
    </interface>
  </devices>
</domain>`

const virtOld = `<domain type='kvm'>
  <name>legacy</name>
  <uuid>3b2c4d5e-6f70-4b8c-9dae-1f203a4b5c6d</uuid>
  <memory>1048576</memory>
  <vcpu>1</vcpu>
  <os><type>hvm</type></os>
</domain>`

const (
	virtUUIDWeb = "4c0e2d3c-4b5a-4697-8877-665544332211"
	virtUUIDDB  = "2a1b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	virtUUIDOld = "3b2c4d5e-6f70-4b8c-9dae-1f203a4b5c6d"
)

func libvirtFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.cmds["virsh --version"] = "12.0.0\n"
	f.cmds["virsh list --all --uuid"] = virtUUIDWeb + "\n" + virtUUIDOld + "\n" + virtUUIDDB + "\n\n"
	f.cmds["virsh list --all --uuid --autostart"] = virtUUIDWeb + "\n\n"
	for uuid, xml := range map[string]string{virtUUIDWeb: virtWeb, virtUUIDDB: virtDB, virtUUIDOld: virtOld} {
		f.cmds["virsh dumpxml --inactive "+uuid] = xml
	}
	f.cmds["virsh domstate "+virtUUIDWeb] = "running\n\n"
	f.cmds["virsh domstate "+virtUUIDDB] = "pmsuspended\n\n"
	f.cmds["virsh domstate "+virtUUIDOld] = "shut off\n\n"
	return f
}

func TestVMsLibvirt(t *testing.T) {
	f := libvirtFixture(t)
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Hypervisors) != 1 || v.Hypervisors[0] != (model.Hypervisor{Platform: "libvirt", Version: "12.0.0"}) {
		t.Fatalf("hypervisors = %+v", v.Hypervisors)
	}
	if len(v.Guests) != 3 || v.Guests[0].ID != virtUUIDDB || v.Guests[1].ID != virtUUIDOld || v.Guests[2].ID != virtUUIDWeb {
		t.Fatalf("guests = %+v", v.Guests)
	}
	db, old, web := v.Guests[0], v.Guests[1], v.Guests[2]

	if web.Kind != "kvm" || web.Name != "web01" || web.State != "running" || !web.Autostart || web.CPUs != 2 ||
		web.MemoryBytes != 4<<30 || web.Machine != "pc-q35-10.2" || web.OSType != "http://ubuntu.com/ubuntu/24.04" ||
		web.UUID != "0f0e0d0c-0b0a-0908-0706-050403020100" {
		t.Errorf("web = %+v", web)
	}
	wantDisks := []model.GuestDisk{
		{Name: "sda", Device: "cdrom"},
		{Name: "vda", Source: "/var/lib/libvirt/images/web01.qcow2", Device: "disk"},
		{Name: "vdb", Source: "default/web01-data.qcow2", Device: "disk"},
		{Name: "vdc", Source: "rbd/web01-logs", Device: "disk"},
	}
	if !slices.Equal(web.Disks, wantDisks) {
		t.Errorf("web disks = %+v", web.Disks)
	}
	wantNICs := []model.GuestNIC{
		{Name: "net0", MAC: "52:54:00:12:34:56", Network: "default", Model: "virtio"},
		{Name: "net1", MAC: "52:54:00:aa:bb:01", Bridge: "br0", Model: "e1000e", VLAN: 20},
	}
	if !slices.Equal(web.NICs, wantNICs) {
		t.Errorf("web nics = %+v", web.NICs)
	}

	if db.Kind != "qemu" || db.State != "suspended" || db.Autostart || db.CPUs != 2 || db.MemoryBytes != 2000*1000*1000 ||
		db.UUID != virtUUIDDB || db.OSType != "" || db.Machine != "virt-9.0" {
		t.Errorf("db = %+v", db)
	}
	if want := (model.GuestDisk{Name: "sda", Source: "/dev/vg0/db01", Device: "disk"}); len(db.Disks) != 1 || db.Disks[0] != want {
		t.Errorf("db disks = %+v", db.Disks)
	}
	if want := (model.GuestNIC{Name: "net0", MAC: "52:54:00:43:d5:0b", Bridge: "br1"}); len(db.NICs) != 1 || db.NICs[0] != want {
		t.Errorf("db nics = %+v", db.NICs)
	}

	if old.State != "stopped" || old.MemoryBytes != 1<<30 || old.CPUs != 1 || old.Machine != "" || old.Disks != nil || old.NICs != nil {
		t.Errorf("legacy = %+v", old)
	}
}

func TestVMsLibvirtFailures(t *testing.T) {
	for _, tc := range []struct{ cmd, want string }{
		{"virsh list --all --uuid", "exit status 1"},
		{"virsh list --all --uuid --autostart", "exit status 1"},
		{"virsh dumpxml --inactive " + virtUUIDDB, "dumpxml " + virtUUIDDB + ": exit status 1"},
		{"virsh domstate " + virtUUIDOld, "domstate " + virtUUIDOld + ": exit status 1"},
	} {
		f := libvirtFixture(t)
		f.exits[tc.cmd] = 1
		v, err := f.env.VMs(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if h := v.Hypervisors[0]; h.Error != tc.want || h.Version != "12.0.0" || len(v.Guests) != 0 {
			t.Errorf("%s: %+v, %d guests", tc.cmd, h, len(v.Guests))
		}
	}

	// libvirtd down: virsh's complaint is on stderr.
	f := libvirtFixture(t)
	run := newFixtureRun(f)
	f.env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "list" {
			return nil, &CmdError{Err: errors.New("exit status 1"),
				Stderr: "error: failed to connect to the hypervisor\nerror: Failed to connect socket to '/var/run/libvirt/virtqemud-sock': No such file or directory"}
		}
		return run(ctx, name, args...)
	}
	v, _ := f.env.VMs(context.Background())
	if h := v.Hypervisors[0]; h.Error != "error: Failed to connect socket to '/var/run/libvirt/virtqemud-sock': No such file or directory" {
		t.Errorf("error = %q", h.Error)
	}

	f = libvirtFixture(t)
	f.cmds["virsh dumpxml --inactive "+virtUUIDDB] = "<domain"
	v, _ = f.env.VMs(context.Background())
	if h := v.Hypervisors[0]; h.Error != "dumpxml "+virtUUIDDB+": unreadable XML" || len(v.Guests) != 0 {
		t.Errorf("bad XML: %+v", h)
	}
}

func TestVMsLibvirtNoDomains(t *testing.T) {
	f := newFixture(t)
	f.cmds["virsh --version"] = "10.0.0\n"
	f.cmds["virsh list --all --uuid"] = "\n"
	f.cmds["virsh list --all --uuid --autostart"] = "\n"
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := model.Encode(v)
	if string(b) != `{"hypervisors":[{"platform":"libvirt","version":"10.0.0"}],"guests":[]}` {
		t.Errorf("encoded = %s", b)
	}
}

func TestVMsBothPlatforms(t *testing.T) {
	f := proxmoxFixture(t)
	for k, v := range libvirtFixture(t).cmds {
		f.cmds[k] = v
	}
	v, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Hypervisors) != 2 || v.Hypervisors[0].Platform != "libvirt" || v.Hypervisors[1].Platform != "proxmox" {
		t.Fatalf("hypervisors = %+v", v.Hypervisors)
	}
	if len(v.Guests) != 6 || v.Guests[0].Platform != "libvirt" || v.Guests[5].Key() != "proxmox/200" {
		t.Errorf("guests = %+v", v.Guests)
	}
}

// The section is hashed: the same state must encode the same way every
// time, whatever the order of map iteration or concurrent reads.
func TestVMsDeterministic(t *testing.T) {
	f := proxmoxFixture(t)
	for k, v := range libvirtFixture(t).cmds {
		f.cmds[k] = v
	}
	first, err := f.env.VMs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, want, _ := model.Encode(first)
	for i := 0; i < 20; i++ {
		v, _ := f.env.VMs(context.Background())
		if _, h, _ := model.Encode(v); h != want {
			t.Fatalf("run %d: hash %s, want %s", i, h, want)
		}
	}
}

func TestVMsNoSecretsOrVolatileFields(t *testing.T) {
	f := proxmoxFixture(t)
	for k, v := range libvirtFixture(t).cmds {
		f.cmds[k] = v
	}
	v, _ := f.env.VMs(context.Background())
	b, _, _ := model.Encode(v)
	for _, s := range []string{"hunter2", "supersecret", "SECRETKEY", "topsecret", "hook-secret", "secret-uuid",
		"vncsecret", "-secret", "deadbeef", "username", "Web server", "fingerprint", "backup@pbs", "digest",
		"vmgenid", "11111111", "10.0.0", "uptime", "123456", "balloon", "idmap", "unused"} {
		if strings.Contains(string(b), s) {
			t.Errorf("encoded section contains %q:\n%s", s, b)
		}
	}
}

func TestPveSize(t *testing.T) {
	for in, want := range map[string]uint64{
		"32G": 32 << 30, "528K": 528 << 10, "4M": 4 << 20, "1T": 1 << 40, "1.5G": 3 << 29,
		"1048576": 1 << 20, "": 0, "big": 0, "10g": 10 << 30,
	} {
		if got := pveSize(in); got != want {
			t.Errorf("pveSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLibvirtBytes(t *testing.T) {
	for _, tc := range []struct {
		value, unit string
		want        uint64
	}{
		{"4194304", "", 4 << 30}, {"4194304", "KiB", 4 << 30}, {"4194304", "k", 4 << 30},
		{"512", "b", 512}, {"512", "bytes", 512}, {"1000", "KB", 1000 * 1000},
		{"4096", "MiB", 4 << 30}, {"4096", "M", 4 << 30}, {"4", "G", 4 << 30}, {"2", "GB", 2e9},
		{"1", "TiB", 1 << 40}, {"1", "T", 1 << 40}, {"1", "TB", 1e12}, {"7", "parsecs", 0}, {"x", "", 0},
	} {
		if got := libvirtBytes(tc.value, tc.unit); got != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.value, tc.unit, got, tc.want)
		}
	}
}

func TestLibvirtState(t *testing.T) {
	for in, want := range map[string]string{
		"running\n": "running", "shut off": "stopped", "paused": "paused", "pmsuspended": "suspended",
		"crashed": "crashed", "in shutdown": "running", "idle": "running", "blocked": "running", "no state": "no state",
	} {
		if got := libvirtState(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

func TestVMNameLess(t *testing.T) {
	names := []string{"scsi10", "efidisk0", "scsi2", "net10", "net9", "ide2", "rootfs", "mp1", "mp0"}
	sort.Slice(names, func(i, j int) bool { return vmNameLess(names[i], names[j]) })
	if got := strings.Join(names, " "); got != "efidisk0 ide2 mp0 mp1 net9 net10 rootfs scsi2 scsi10" {
		t.Errorf("order = %s", got)
	}
}

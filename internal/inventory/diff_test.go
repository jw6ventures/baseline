package inventory

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

func enc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestComparePackages(t *testing.T) {
	before := model.Packages{Packages: []model.Package{
		{Manager: "apt", Name: "openssl", Version: "3.0.13-1", Arch: "amd64"},
		{Manager: "apt", Name: "htop", Version: "3.3.0-4", Arch: "amd64"},
		{Manager: "dnf", Name: "kernel", Version: "6.12.0", Release: "55.el10", Arch: "x86_64"},
		{Manager: "dnf", Name: "kernel", Version: "6.12.0", Release: "60.el10", Arch: "x86_64"},
	}}
	after := model.Packages{Packages: []model.Package{
		{Manager: "apt", Name: "openssl", Version: "3.0.15-1", Arch: "amd64"},
		{Manager: "apt", Name: "curl", Version: "8.5.0-2", Arch: "amd64"},
		{Manager: "dnf", Name: "kernel", Version: "6.12.0", Release: "60.el10", Arch: "x86_64"},
		{Manager: "dnf", Name: "kernel", Version: "6.12.0", Release: "66.el10", Arch: "x86_64"},
	}}
	d, err := Compare(model.SectionPackages, enc(t, before), enc(t, after))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changed) != 1 || d.Changed[0].Field != "apt/openssl.amd64" || d.Changed[0].From != "3.0.13-1" || d.Changed[0].To != "3.0.15-1" {
		t.Errorf("changed = %+v", d.Changed)
	}
	if len(d.Added) != 2 || d.Added[0].Field != "apt/curl.amd64" || d.Added[1].To != "6.12.0-66.el10" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed) != 2 || d.Removed[0].Field != "apt/htop.amd64" || d.Removed[1].From != "6.12.0-55.el10" {
		t.Errorf("removed = %+v", d.Removed)
	}
	if s := d.Summary(model.SectionPackages); s != "2 added, 2 removed, 1 upgraded or downgraded" {
		t.Errorf("summary = %q", s)
	}
}

func TestCompareIdentical(t *testing.T) {
	hw := model.Hardware{CPU: model.CPU{Model: "EPYC", Flags: []string{"aes", "svm"}}}
	d, err := Compare(model.SectionHardware, enc(t, hw), enc(t, hw))
	if err != nil || d != nil {
		t.Fatalf("d = %+v, err = %v", d, err)
	}
}

func TestCompareHardwareByIdentity(t *testing.T) {
	before := model.Hardware{
		CPU:   model.CPU{Model: "Ryzen 5", Flags: []string{"aes", "svm"}},
		Disks: []model.Disk{{Name: "sda", Serial: "A1", SizeBytes: 1000}, {Name: "sdb", Serial: "B1", SizeBytes: 2000}},
		NICs:  []model.NIC{{Name: "eth0", Kind: "physical", Addresses: []string{"10.0.0.5/24"}}},
	}
	after := model.Hardware{
		CPU: model.CPU{Model: "Ryzen 7", Flags: []string{"aes", "svm", "avx512f"}},
		// sda gone, sdb now listed first, a new sdc
		Disks: []model.Disk{{Name: "sdb", Serial: "B1", SizeBytes: 2000}, {Name: "sdc", Serial: "C1", SizeBytes: 4000}},
		NICs:  []model.NIC{{Name: "eth0", Kind: "physical", Addresses: []string{"10.0.0.9/24"}}},
	}
	d, err := Compare(model.SectionHardware, enc(t, before), enc(t, after))
	if err != nil {
		t.Fatal(err)
	}
	fields := func(cs []Change) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Field)
		}
		return out
	}
	if got := fields(d.Changed); len(got) != 1 || got[0] != "cpu.model" {
		t.Errorf("changed = %v", got)
	}
	// CPU flag and address lists are sets; disks are keyed by name.
	if got := fields(d.Added); len(got) != 3 || got[0] != "cpu.flags" || got[1] != "disks[sdc]" || got[2] != "nics[eth0].addresses" {
		t.Errorf("added = %v", got)
	}
	if got := fields(d.Removed); len(got) != 2 || got[0] != "disks[sda]" || got[1] != "nics[eth0].addresses" {
		t.Errorf("removed = %v", got)
	}
}

func TestCompareOSFieldAppears(t *testing.T) {
	before := model.OS{Hostname: "a", Kernel: "6.8.0-40"}
	after := model.OS{Hostname: "a", Kernel: "6.8.0-45", Image: &model.OSImage{Origin: "ghcr.io/ublue-os/bazzite:stable", Version: "42.20261001"}}
	d, err := Compare(model.SectionOS, enc(t, before), enc(t, after))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changed) != 1 || d.Changed[0].Field != "kernel" || len(d.Added) != 1 || d.Added[0].Field != "image" {
		t.Fatalf("diff = %+v", d)
	}
}

func TestKeyedSections(t *testing.T) {
	enc := func(v any) []byte { return enc(t, v) }
	before := model.Containers{
		Containers: []model.Container{
			{Engine: "docker", Name: "web", ID: "a", Image: "nginx:1.27", State: "running", Health: "healthy"},
			{Engine: "podman", Name: "web", ID: "b", Image: "nginx:1.27", State: "running"},
		},
		Images: []model.ContainerImage{{Engine: "docker", ID: "x"}},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "p", ConfigFiles: []model.ComposeFile{{Path: "/c.yaml", SHA256: "1", Content: "a: 1"}}}},
	}
	after := model.Containers{
		Containers: []model.Container{
			{Engine: "docker", Name: "web", ID: "a", Image: "nginx:1.27", State: "exited", Health: "unhealthy", RestartCount: 3},
			{Engine: "podman", Name: "web", ID: "b", Image: "nginx:1.28", State: "running"},
		},
		Images: []model.ContainerImage{{Engine: "docker", ID: "y"}},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "p", ConfigFiles: []model.ComposeFile{{Path: "/c.yaml", SHA256: "2", Content: "a: 2"}}}},
	}
	d, err := Compare(model.SectionContainers, enc(before), enc(after))
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, c := range d.Changed {
		fields = append(fields, c.Field)
	}
	got := strings.Join(fields, " ")
	if got != "containers[podman/web].image stacks[docker/p].config_files[/c.yaml].sha256" || len(d.Added)+len(d.Removed) != 0 {
		t.Fatalf("diff = %+v", d)
	}

	// Only state changed: no history entry at all.
	before.Containers[0].State = "exited"
	after = before
	after.Containers = []model.Container{before.Containers[0], before.Containers[1]}
	after.Containers[0].Health = "starting"
	if d, _ := Compare(model.SectionContainers, enc(before), enc(after)); d != nil {
		t.Fatalf("state-only diff = %+v", d)
	}

	ports := func(pid int) []byte {
		return enc(model.Ports{Listeners: []model.Listener{{Proto: "tcp", Addr: "::", Port: 22, Process: "sshd", PID: pid}}})
	}
	if d, _ := Compare(model.SectionPorts, ports(1), ports(2)); d != nil {
		t.Fatalf("pid-only diff = %+v", d)
	}
}

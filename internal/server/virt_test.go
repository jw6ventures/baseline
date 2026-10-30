package server

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

const vmUUID = "6b7c1d2e-0000-4000-8000-000000000100"

func vmsFixture(node string, guests ...model.Guest) model.VMs {
	return model.VMs{
		Hypervisors: []model.Hypervisor{{Platform: "proxmox", Version: "8.4.1", Node: node, Cluster: "lab"}},
		Guests:      guests,
		Storage:     []model.VMStorage{{Name: "local-lvm", Type: "lvmthin", Content: []string{"images", "rootdir"}}},
	}
}

var (
	webGuest = model.Guest{Platform: "proxmox", Kind: "qemu", ID: "100", Name: "web01", UUID: vmUUID, State: "running",
		CPUs: 4, MemoryBytes: 4 << 30, OSType: "l26", Tags: []string{"prod"},
		Disks: []model.GuestDisk{{Name: "scsi0", Source: "local-lvm:vm-100-disk-0", SizeBytes: 32 << 30, Device: "disk"}},
		NICs:  []model.GuestNIC{{Name: "net0", MAC: "bc:24:11:00:01:00", Bridge: "vmbr0", Model: "virtio", VLAN: 10}}}
	dnsGuest = model.Guest{Platform: "proxmox", Kind: "lxc", ID: "101", Name: "dns", State: "running", CPUs: 1, MemoryBytes: 512 << 20,
		NICs: []model.GuestNIC{{Name: "net0", MAC: "bc:24:11:00:01:01", Bridge: "vmbr0", Model: "veth"}}}
)

// relCount counts discovered runs_on relationships between two CIs.
func relCount(t *testing.T, h *harness, from, to string) int {
	t.Helper()
	rels, err := h.st.CIRelationships(context.Background(), from)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rels {
		if r.Outgoing && r.Kind == "runs_on" && r.Other.ID == to {
			n++
		}
	}
	return n
}

func TestVirtualMachines(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	virt, _ := h.st.CreateHostGroup(ctx, store.System, "virt", "")
	pve1 := h.addHost("pve1", virt.ID)
	pve2 := h.addHost("pve2", virt.ID)
	web := h.addHost("web01")
	dns := h.addHost("dns")
	// web01's agent sees the VM's SMBIOS UUID; the LXC container only a MAC.
	if _, err := h.st.AgentConnected(ctx, web.HostID, web.AgentID, store.Hello{AgentVersion: "t", BootID: "b", DMIUUID: vmUUID}); err != nil {
		t.Fatal(err)
	}
	h.ingest(dns, model.SectionHardware, model.Hardware{NICs: []model.NIC{{Name: "eth0", MAC: "BC:24:11:00:01:01", Kind: "virtual"}}})
	h.ingest(pve1, model.SectionVMs, vmsFixture("pve1", webGuest, dnsGuest))
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "virt-ops", Role: rbac.Viewer, ScopeGroupID: virt.ID})

	admin := h.signIn("ann", "lab-admins")
	_, body := h.do(admin, "GET", "/vms", nil)
	for _, want := range []string{">web01<", ">dns<", "2<span class=\"of\"> / 2", ">Proxmox VE<", ">LXC<", ">prod<"} {
		if !strings.Contains(body, want) {
			t.Fatalf("vms page lacks %q:\n%s", want, body)
		}
	}
	m := regexp.MustCompile(`href="(/vms/[0-9a-f-]{36})">web01<`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link to web01:\n%s", body)
	}
	vmPath := m[1]
	if _, body := h.do(admin, "GET", "/", nil); !strings.Contains(body, "VMs and LXC running") {
		t.Fatalf("dashboard:\n%s", body)
	}
	webCI := strings.TrimPrefix(vmPath, "/vms/")
	_, body = h.do(admin, "GET", vmPath, nil)
	if !strings.Contains(body, "/hosts/"+web.HostID) || !strings.Contains(body, "local-lvm:vm-100-disk-0") || !strings.Contains(body, "bc:24:11:00:01:00") {
		t.Fatalf("vm page:\n%s", body)
	}
	// Both guests are linked to the hosts their agents report.
	if relCount(t, h, web.HostID, webCI) != 1 {
		t.Fatal("web01 isn't linked to its VM by DMI UUID")
	}
	g, err := h.st.HostGuest(ctx, dns.HostID)
	if err != nil || g.Name != "dns" || g.Kind != "lxc" {
		t.Fatalf("dns guest link: %+v %v", g, err)
	}
	_, body = h.do(admin, "GET", "/hosts/"+web.HostID, nil)
	if !strings.Contains(body, "VM web01</a> on <a") {
		t.Fatalf("guest host overview:\n%s", body)
	}
	_, body = h.do(admin, "GET", "/hosts/"+pve1.HostID+"/vms", nil)
	if !strings.Contains(body, "Proxmox VE 8.4.1") || !strings.Contains(body, "local-lvm") || !strings.Contains(body, ">web01<") {
		t.Fatalf("hypervisor vms tab:\n%s", body)
	}
	// Hosts that aren't hypervisors have no VMs tab.
	if _, body = h.do(admin, "GET", "/hosts/"+dns.HostID, nil); strings.Contains(body, dns.HostID+"/vms") {
		t.Fatal("VMs tab on a host without guests")
	}

	// A viewer scoped to the hypervisors' group sees the guests; one
	// without sees nothing, and can't open the page.
	scoped := h.signIn("vic", "virt-ops")
	if _, body = h.do(scoped, "GET", "/vms", nil); !strings.Contains(body, ">web01<") {
		t.Fatalf("scoped viewer:\n%s", body)
	}
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "nobody", Role: rbac.Viewer, ScopeGroupID: mustGroup(t, h, "other")})
	outsider := h.signIn("olga", "nobody")
	if _, body = h.do(outsider, "GET", "/vms", nil); strings.Contains(body, ">web01<") {
		t.Fatal("outsider sees guests")
	}
	if resp, _ := h.do(outsider, "GET", vmPath, nil); resp.StatusCode != 404 {
		t.Fatalf("outsider opens a guest: %d", resp.StatusCode)
	}

	// web01 migrates to pve2: same CI, now running on pve2 only. dns is
	// gone from pve1.
	h.ingest(pve2, model.SectionVMs, vmsFixture("pve2", webGuest))
	h.ingest(pve1, model.SectionVMs, vmsFixture("pve1"))
	gst, err := h.st.GetGuest(ctx, webCI)
	if err != nil || gst.HostID != pve2.HostID || !gst.Present || gst.AgentHostID != web.HostID {
		t.Fatalf("migrated guest: %+v %v", gst, err)
	}
	if relCount(t, h, webCI, pve2.HostID) != 1 || relCount(t, h, webCI, pve1.HostID) != 0 {
		t.Fatal("migrated guest's runs_on wasn't moved")
	}
	if _, err := h.st.HostGuest(ctx, dns.HostID); err == nil {
		t.Fatal("a gone guest is still linked to its agent")
	}
	if n, err := h.st.MarkMissing(ctx, time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("mark missing: %d %v", n, err)
	}

	// libvirtd down: the earlier guests are kept rather than removed.
	down := vmsFixture("pve2")
	down.Hypervisors[0].Error = "pvesh: connection refused"
	h.ingest(pve2, model.SectionVMs, down)
	if gst, _ = h.st.GetGuest(ctx, webCI); !gst.Present {
		t.Fatal("a platform that couldn't be read dropped its guests")
	}
	_, body = h.do(admin, "GET", "/hosts/"+pve2.HostID+"/vms", nil)
	if !strings.Contains(body, "connection refused") || !strings.Contains(body, ">web01<") {
		t.Fatalf("failed platform:\n%s", body)
	}

	// Configuration changes are history; the state isn't.
	stopped := webGuest
	stopped.State = "stopped"
	h.ingest(pve2, model.SectionVMs, vmsFixture("pve2", stopped))
	bigger := stopped
	bigger.MemoryBytes = 8 << 30
	h.ingest(pve2, model.SectionVMs, vmsFixture("pve2", bigger))
	hist, err := h.st.HostHistory(ctx, pve2.HostID, 20)
	if err != nil {
		t.Fatal(err)
	}
	var vmEntries []string
	for _, e := range hist {
		if e.Section == model.SectionVMs {
			vmEntries = append(vmEntries, string(e.Diff))
		}
	}
	if len(vmEntries) != 2 || !strings.Contains(vmEntries[0], "guests[proxmox/100].memory_bytes") {
		t.Fatalf("vms history: %v", vmEntries)
	}

	// Revoking the hypervisor retires its guests.
	if err := h.st.RevokeHost(ctx, store.System, pve2.HostID); err != nil {
		t.Fatal(err)
	}
	if c, _ := h.st.GetCI(ctx, webCI); c.Status != "retired" {
		t.Fatalf("guest of a revoked hypervisor: %s", c.Status)
	}
}

func k8sFixture() model.K8s {
	return model.K8s{
		Cluster: model.K8sCluster{UID: "kube-system-uid", Name: "homelab", Version: "v1.33.5+k3s1", Platform: "linux/amd64"},
		Nodes: []model.K8sNodeInfo{
			{Name: "node1", Roles: []string{"control-plane"}, Ready: true, KubeletVersion: "v1.33.5+k3s1",
				ContainerRuntime: "containerd://2.1.4", MachineID: "node1", InternalIPs: []string{"10.0.0.11"}, CPU: "4", MemoryBytes: 8 << 30},
			{Name: "node2", Ready: false, KubeletVersion: "v1.33.5+k3s1", SystemUUID: "unknown-uuid"},
		},
		Namespaces: []string{"default", "kube-system"},
		Workloads: []model.K8sWorkload{
			{Kind: "Deployment", Namespace: "default", Name: "web", Replicas: 2, Ready: 1, Images: []string{"nginx:1.27"}},
			{Kind: "CronJob", Namespace: "default", Name: "backup", Schedule: "0 3 * * *", Images: []string{"restic/restic:0.18"}},
			{Kind: "DaemonSet", Namespace: "kube-system", Name: "svclb", Replicas: 2, Ready: 2, Images: []string{"rancher/klipper-lb:v0.4"}},
		},
		Services: []model.K8sService{{Namespace: "default", Name: "web", Type: "LoadBalancer", ClusterIP: "10.43.0.10",
			ExternalIPs: []string{"10.0.0.50"}, Ports: []string{"80:30080/TCP→8080"}, Selector: map[string]string{"app": "web"}}},
		Ingresses: []model.K8sIngress{{Namespace: "default", Name: "web", Class: "traefik", Hosts: []string{"web.lab"}, TLS: true,
			Backends: []string{"web.lab/ → web:80"}}},
	}
}

func TestKubernetes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	agent := h.addHost("baseline-agent-7d9f")
	h.connect(agent, []string{model.CapK8sCluster}, nil)
	node1 := h.addHost("node1") // machine-id "node1"
	h.ingest(node1, model.SectionK8sNode, model.K8sNode{Runtime: "containerd", RuntimeVersion: "v2.1.4",
		Endpoint: "unix:///run/k3s/containerd/containerd.sock",
		Pods:     []model.CRIPod{{Namespace: "default", Name: "web-5d8f-abcde", State: "ready"}},
		Containers: []model.CRIContainer{{Namespace: "default", Pod: "web-5d8f-abcde", Name: "nginx", Image: "docker.io/library/nginx:1.27",
			State: "running", Attempt: 2}},
		Images: []model.CRIImage{{ID: "sha256:" + strings.Repeat("a", 64), Tags: []string{"docker.io/library/nginx:1.27"}, SizeBytes: 70 << 20}}})
	h.ingest(agent, model.SectionK8s, k8sFixture())

	admin := h.signIn("ann", "lab-admins")
	_, body := h.do(admin, "GET", "/kubernetes", nil)
	if !strings.Contains(body, ">homelab<") || !strings.Contains(body, "1 / 2") || !strings.Contains(body, "1 not ready") {
		t.Fatalf("clusters:\n%s", body)
	}
	cpath := firstLink(t, body, `/kubernetes/[0-9a-f-]{36}`)
	if _, body = h.do(admin, "GET", "/", nil); !strings.Contains(body, "Kubernetes nodes not ready") {
		t.Fatalf("dashboard:\n%s", body)
	}
	_, body = h.do(admin, "GET", cpath, nil)
	if !strings.Contains(body, ">node1<") || !strings.Contains(body, "/hosts/"+node1.HostID+"?tab=kubernetes") || !strings.Contains(body, "not ready") {
		t.Fatalf("cluster nodes:\n%s", body)
	}
	_, body = h.do(admin, "GET", cpath+"?tab=workloads&ns=default", nil)
	if !strings.Contains(body, ">web<") || !strings.Contains(body, "0 3 * * *") || strings.Contains(body, "svclb") {
		t.Fatalf("cluster workloads:\n%s", body)
	}
	_, body = h.do(admin, "GET", cpath+"?tab=services", nil)
	if !strings.Contains(body, "80:30080/TCP→8080") || !strings.Contains(body, "app=web") {
		t.Fatalf("cluster services:\n%s", body)
	}
	_, body = h.do(admin, "GET", cpath+"?tab=ingresses", nil)
	if !strings.Contains(body, "web.lab/ → web:80") {
		t.Fatalf("cluster ingresses:\n%s", body)
	}

	// The node's host links to its node and shows its runtime's pods.
	_, body = h.do(admin, "GET", "/hosts/"+node1.HostID+"?tab=kubernetes", nil)
	if !strings.Contains(body, ">node1<") || !strings.Contains(body, "web-5d8f-abcde") || !strings.Contains(body, "↻2") {
		t.Fatalf("node host kubernetes tab:\n%s", body)
	}
	// The cluster agent is named after its cluster and has no host tabs.
	_, body = h.do(admin, "GET", "/hosts/"+agent.HostID, nil)
	if !strings.Contains(body, "<h1>homelab</h1>") || !strings.Contains(body, "cluster agent of") || strings.Contains(body, "tab=packages") {
		t.Fatalf("cluster agent host page:\n%s", body)
	}

	// Readiness isn't history; an upgrade and a new image are. A resource
	// the agent can't list keeps its earlier copy.
	k := k8sFixture()
	k.Nodes[1].Ready = true
	h.ingest(agent, model.SectionK8s, k)
	k.Cluster.Version = "v1.34.1+k3s1"
	k.Workloads[0].Images = []string{"nginx:1.28"}
	k.Ingresses = nil
	k.Errors = []model.K8sError{{Resource: "ingresses", Error: "forbidden"}}
	h.ingest(agent, model.SectionK8s, k)
	hist, err := h.st.HostHistory(ctx, agent.HostID, 20)
	if err != nil {
		t.Fatal(err)
	}
	var diffs []string
	for _, e := range hist {
		if e.Section == model.SectionK8s {
			diffs = append(diffs, string(e.Diff))
		}
	}
	if len(diffs) != 2 || !strings.Contains(diffs[0], "cluster.version") || !strings.Contains(diffs[0], "nginx:1.28") ||
		strings.Contains(diffs[0], "ingresses") {
		t.Fatalf("k8s history: %v", diffs)
	}
	_, body = h.do(admin, "GET", cpath+"?tab=ingresses", nil)
	if !strings.Contains(body, "web.lab/ → web:80") || !strings.Contains(body, "forbidden") {
		t.Fatalf("ingresses after a failed list:\n%s", body)
	}

	// A workload that goes away turns missing; the agent's revocation
	// retires the cluster.
	k.Workloads = k.Workloads[1:]
	h.ingest(agent, model.SectionK8s, k)
	if n, err := h.st.MarkMissing(ctx, time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("mark missing: %d %v", n, err)
	}
	if err := h.st.RevokeHost(ctx, store.System, agent.HostID); err != nil {
		t.Fatal(err)
	}
	if c, _ := h.st.GetCluster(ctx, strings.TrimPrefix(cpath, "/kubernetes/")); c.Status != "retired" {
		t.Fatalf("cluster of a revoked agent: %s", c.Status)
	}
}

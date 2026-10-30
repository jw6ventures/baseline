package collect

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

const (
	k3sSock        = "/run/k3s/containerd/containerd.sock"
	containerdSock = "/run/containerd/containerd.sock"
	crioSock       = "/var/run/crio/crio.sock"
)

func crictlCmd(sock string, args ...string) string {
	s := "crictl --runtime-endpoint unix://" + sock + " --timeout 20s"
	for _, a := range args {
		s += " " + a
	}
	return s
}

func crictlFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/crictl/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stubCrictl serves a set of fixtures (testdata/crictl/<set>-*) on sock.
func stubCrictl(t *testing.T, f *fixture, sock, set string) {
	f.cmds[crictlCmd(sock, "version")] = crictlFixture(t, set+"-version.txt")
	f.cmds[crictlCmd(sock, "pods", "-o", "json")] = crictlFixture(t, set+"-pods.json")
	f.cmds[crictlCmd(sock, "ps", "-a", "-o", "json")] = crictlFixture(t, set+"-ps.json")
	f.cmds[crictlCmd(sock, "images", "-o", "json")] = crictlFixture(t, set+"-images.json")
}

// From k3s v1.36.5 (containerd 2.3), trimmed.
func TestK8sNodeK3s(t *testing.T) {
	f := newFixture(t)
	f.file(k3sSock, "")
	f.file(containerdSock, "") // Docker's, also present
	stubCrictl(t, f, k3sSock, "k3s")

	got, err := f.env.K8sNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Runtime != "containerd" || got.RuntimeVersion != "v2.3.4-k3s1.36" || got.Endpoint != "unix://"+k3sSock {
		t.Errorf("runtime = %q %q %q", got.Runtime, got.RuntimeVersion, got.Endpoint)
	}
	wantPods := []model.CRIPod{
		{Namespace: "demo", Name: "debug", State: "ready", Created: "2026-10-14T06:38:23Z"},
		{Namespace: "demo", Name: "web-6bbd86ffb9-kjcbk", State: "ready", Created: "2026-10-14T06:38:23Z"},
		{Namespace: "kube-system", Name: "coredns-7cfb7bc9c7-xd8vh", State: "ready", Created: "2026-10-14T06:37:55Z"},
		{Namespace: "kube-system", Name: "helm-install-traefik-mvtqp", State: "notready", Created: "2026-10-14T06:37:55Z"},
	}
	if !reflect.DeepEqual(got.Pods, wantPods) {
		t.Errorf("pods:\n got %+v\nwant %+v", got.Pods, wantPods)
	}
	// containerd 2 reports the reference as the pod spec wrote it.
	busybox := "sha256:30ecbe1509090b38ef3260f3609d64d8261230464eaa4d235901db496e9647fb"
	wantCtrs := []model.CRIContainer{
		{Namespace: "demo", Pod: "debug", Name: "debug", Image: "busybox:1.37", ImageID: busybox, State: "running", Created: "2026-10-14T06:38:26Z"},
		{Namespace: "demo", Pod: "web-6bbd86ffb9-kjcbk", Name: "init", Image: "busybox:1.37", ImageID: busybox, State: "exited", Created: "2026-10-14T06:38:26Z"},
		{Namespace: "demo", Pod: "web-6bbd86ffb9-kjcbk", Name: "web", Image: "nginx:1.29-alpine",
			ImageID: "sha256:812d47f806db497c53f9b47e76bdab38bcf5d724c69d3986df5ee4336c210559", State: "running", Created: "2026-10-14T06:38:32Z"},
		{Namespace: "kube-system", Pod: "coredns-7cfb7bc9c7-xd8vh", Name: "coredns", Image: "rancher/mirrored-coredns-coredns:1.14.7",
			ImageID: "sha256:97efff2babf85310d6f87bd969ac64d7006bbbadb147c90579d68d57634750f4", State: "running", Created: "2026-10-14T06:38:00Z"},
		{Namespace: "kube-system", Pod: "helm-install-traefik-mvtqp", Name: "helm", Image: "rancher/klipper-helm:v0.13.3-build20260727",
			ImageID: "sha256:8e0d8d2218ec831bae4293da6ebb77a000dfea7a35fc18175fe9d24bf2a4cb31", State: "exited", Attempt: 2, Created: "2026-10-14T06:38:17Z"},
	}
	if !reflect.DeepEqual(got.Containers, wantCtrs) {
		t.Errorf("containers:\n got %+v\nwant %+v", got.Containers, wantCtrs)
	}
	if len(got.Images) != 5 {
		t.Fatalf("images = %+v", got.Images)
	}
	for i := 1; i < len(got.Images); i++ {
		if got.Images[i-1].ID >= got.Images[i].ID {
			t.Errorf("images not sorted: %q before %q", got.Images[i-1].ID, got.Images[i].ID)
		}
	}
	want := model.CRIImage{ID: busybox, Tags: []string{"docker.io/library/busybox:1.37"},
		Digests:   []string{"docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"},
		SizeBytes: 2222118}
	if !reflect.DeepEqual(got.Images[0], want) {
		t.Errorf("image = %+v\nwant  %+v", got.Images[0], want)
	}

	// The same input always encodes the same.
	_, h1, _ := model.Encode(got)
	again, _ := f.env.K8sNode(context.Background())
	if _, h2, _ := model.Encode(again); h1 != h2 {
		t.Error("hash differs between two collections")
	}
}

// containerd 1.7 reports only the image ID, which is resolved through the
// image list. Also: sandboxes and containers left from before a reboot, and
// a container without the kubelet's labels.
func TestK8sNodeContainerd17(t *testing.T) {
	f := newFixture(t)
	f.file(containerdSock, "")
	stubCrictl(t, f, containerdSock, "containerd17")

	got, err := f.env.K8sNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Runtime != "containerd" || got.RuntimeVersion != "v1.7.27-k3s1" || got.Endpoint != "unix://"+containerdSock {
		t.Errorf("runtime = %q %q %q", got.Runtime, got.RuntimeVersion, got.Endpoint)
	}
	wantPods := []model.CRIPod{
		{Namespace: "demo", Name: "web-6d4cf56db6-jx2tq", State: "ready", Created: "2025-10-14T06:40:00Z"},
		{Namespace: "kube-system", Name: "coredns-64fd4b4794-7xk2p", State: "ready", Created: "2025-10-14T06:31:55Z"},
		{Namespace: "kube-system", Name: "helm-install-traefik-crd-5wz9l", State: "notready", Created: "2025-10-14T06:31:56Z"},
		// The sandbox recreated after a reboot replaces the old one.
		{Namespace: "kube-system", Name: "local-path-provisioner-774c6665dc-q8h4m", State: "ready", Created: "2025-10-14T07:31:42Z"},
	}
	if !reflect.DeepEqual(got.Pods, wantPods) {
		t.Errorf("pods:\n got %+v\nwant %+v", got.Pods, wantPods)
	}
	wantCtrs := []model.CRIContainer{
		// No labels: namespace and pod come from the sandbox.
		{Namespace: "demo", Pod: "web-6d4cf56db6-jx2tq", Name: "web", Image: "docker.io/library/nginx:1.29-alpine",
			ImageID: "sha256:4e1b6bae1e48ea2a6b6f8f0d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b", State: "running", Created: "2025-10-14T06:40:03Z"},
		{Namespace: "kube-system", Pod: "coredns-64fd4b4794-7xk2p", Name: "coredns", Image: "docker.io/rancher/mirrored-coredns-coredns:1.12.3",
			ImageID: "sha256:1cf5f116067c67da67f97bff78c4bbc76913f59057c18627b96facaced73ea0b", State: "running", Created: "2025-10-14T06:32:00Z"},
		// An image without tags is named by its digest.
		{Namespace: "kube-system", Pod: "helm-install-traefik-crd-5wz9l", Name: "helm",
			Image:   "docker.io/rancher/klipper-helm@sha256:c35ab4bd2e0d3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
			ImageID: "sha256:9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e", State: "exited", Created: "2025-10-14T06:32:01Z"},
		// Only the newest attempt.
		{Namespace: "kube-system", Pod: "local-path-provisioner-774c6665dc-q8h4m", Name: "local-path-provisioner",
			Image:   "docker.io/rancher/local-path-provisioner:v0.0.32",
			ImageID: "sha256:fbc6d8b1d4ac3fbe8a8b9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a", State: "running", Attempt: 1, Created: "2025-10-14T07:31:45Z"},
	}
	if !reflect.DeepEqual(got.Containers, wantCtrs) {
		t.Errorf("containers:\n got %+v\nwant %+v", got.Containers, wantCtrs)
	}
	if len(got.Images) != 5 || got.Images[3].Tags != nil {
		t.Errorf("images = %+v", got.Images)
	}
}

// Docker's containerd has its CRI plugin disabled: not a Kubernetes node.
func TestK8sNodeDockerContainerd(t *testing.T) {
	f := newFixture(t)
	f.file(containerdSock, "")
	f.cmds[crictlCmd(containerdSock, "version")] = ""
	f.exits[crictlCmd(containerdSock, "version")] = 1
	if _, err := f.env.K8sNode(context.Background()); !errors.Is(err, ErrAbsent) {
		t.Fatalf("err = %v, want ErrAbsent", err)
	}
}

func TestK8sNodeAbsent(t *testing.T) {
	f := newFixture(t)
	f.file(containerdSock, "")
	if _, err := f.env.K8sNode(context.Background()); !errors.Is(err, ErrAbsent) {
		t.Fatalf("no crictl: err = %v, want ErrAbsent", err)
	}
	f = newFixture(t)
	stubCrictl(t, f, k3sSock, "k3s") // crictl installed, no socket
	if _, err := f.env.K8sNode(context.Background()); !errors.Is(err, ErrAbsent) {
		t.Fatalf("no socket: err = %v, want ErrAbsent", err)
	}
}

// A k3s socket left behind by an uninstalled k3s doesn't answer; the
// system containerd does.
func TestK8sNodeFallsBackToContainerd(t *testing.T) {
	f := newFixture(t)
	f.file(k3sSock, "")
	f.file(containerdSock, "")
	f.cmds[crictlCmd(k3sSock, "version")] = ""
	f.exits[crictlCmd(k3sSock, "version")] = 1
	stubCrictl(t, f, containerdSock, "k3s")
	got, err := f.env.K8sNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != "unix://"+containerdSock || len(got.Containers) != 5 {
		t.Errorf("endpoint %q, %d containers", got.Endpoint, len(got.Containers))
	}
}

// A runtime that answers `version` but fails a list fails the section.
func TestK8sNodeListFails(t *testing.T) {
	f := newFixture(t)
	f.file(k3sSock, "")
	stubCrictl(t, f, k3sSock, "k3s")
	delete(f.cmds, crictlCmd(k3sSock, "ps", "-a", "-o", "json"))
	if _, err := f.env.K8sNode(context.Background()); err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("err = %v, want a failure", err)
	}
}

// CRI-O reports JSON from `crictl version -o json`-capable builds, the
// reference the pod asked for, and a digest as the image ref.
func TestK8sNodeCRIO(t *testing.T) {
	f := newFixture(t)
	f.file(crioSock, "")
	f.cmds[crictlCmd(crioSock, "version")] = `{"version":"0.1.0","runtimeName":"cri-o","runtimeVersion":"1.33.4","runtimeApiVersion":"v1"}`
	f.cmds[crictlCmd(crioSock, "pods", "-o", "json")] = `{"items":[{"id":"p1","metadata":{"name":"app-0","namespace":"prod","attempt":0},
		"state":"SANDBOX_READY","createdAt":"1760423515000000000"}]}`
	f.cmds[crictlCmd(crioSock, "ps", "-a", "-o", "json")] = `{"containers":[{"id":"c1","podSandboxId":"p1","metadata":{"name":"app","attempt":2},
		"image":{"image":"quay.io/example/app:2.1","userSpecifiedImage":"quay.io/example/app:2.1"},
		"imageRef":"quay.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"state":"CONTAINER_UNKNOWN","createdAt":"1760423516000000000",
		"labels":{"io.kubernetes.container.name":"app","io.kubernetes.pod.name":"app-0","io.kubernetes.pod.namespace":"prod"}}]}`
	f.cmds[crictlCmd(crioSock, "images", "-o", "json")] = `{"images":[]}`
	got, err := f.env.K8sNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := model.K8sNode{Runtime: "cri-o", RuntimeVersion: "1.33.4", Endpoint: "unix://" + crioSock,
		Pods: []model.CRIPod{{Namespace: "prod", Name: "app-0", State: "ready", Created: "2025-10-14T06:31:55Z"}},
		Containers: []model.CRIContainer{{Namespace: "prod", Pod: "app-0", Name: "app", Image: "quay.io/example/app:2.1",
			ImageID: "quay.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			State:   "unknown", Attempt: 2, Created: "2025-10-14T06:31:56Z"}},
		Images: []model.CRIImage{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

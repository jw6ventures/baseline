package kube

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// TestCollectReal reads a real cluster with a service account's token, which
// also checks that the ClusterRole in deploy/k8s/baseline-agent.yaml covers
// everything collected. Set BASELINE_TEST_K8S_URL (https://127.0.0.1:6443),
// BASELINE_TEST_K8S_TOKEN (kubectl -n baseline create token baseline-agent) and
// BASELINE_TEST_K8S_CA (the cluster CA's PEM file); BASELINE_TEST_K8S_OUT=<file>
// also writes the section.
func TestCollectReal(t *testing.T) {
	url, token, ca := os.Getenv("BASELINE_TEST_K8S_URL"), os.Getenv("BASELINE_TEST_K8S_TOKEN"), os.Getenv("BASELINE_TEST_K8S_CA")
	if url == "" || token == "" || ca == "" {
		t.Skip("set BASELINE_TEST_K8S_URL, BASELINE_TEST_K8S_TOKEN and BASELINE_TEST_K8S_CA to read a real cluster")
	}
	roots, err := LoadCA(ca)
	if err != nil {
		t.Fatal(err)
	}
	c := New(url, roots)
	c.Token = strings.TrimSpace(token)
	col := &Collector{Client: c, ClusterName: "test"}
	start := time.Now()
	got, err := col.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, hash, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("collected in %v: %d bytes; cluster %s %s %s; %d nodes, %d namespaces, %d workloads, %d services, %d ingresses",
		time.Since(start).Round(time.Millisecond), len(b), got.Cluster.UID, got.Cluster.Version, got.Cluster.Platform,
		len(got.Nodes), len(got.Namespaces), len(got.Workloads), len(got.Services), len(got.Ingresses))
	for _, e := range got.Errors {
		t.Errorf("%s: %s", e.Resource, e.Error)
	}
	for _, n := range got.Nodes {
		t.Logf("node %s roles=%v ready=%v %s %s mem=%d", n.Name, n.Roles, n.Ready, n.KubeletVersion, n.ContainerRuntime, n.MemoryBytes)
	}
	for _, w := range got.Workloads {
		t.Logf("%s %d/%d %v", w.Key(), w.Ready, w.Replicas, w.Images)
	}
	for _, s := range got.Services {
		t.Logf("service %s/%s %s %s %v %v", s.Namespace, s.Name, s.Type, s.ClusterIP, s.ExternalIPs, s.Ports)
	}
	for _, i := range got.Ingresses {
		t.Logf("ingress %s/%s class=%s tls=%v %v", i.Namespace, i.Name, i.Class, i.TLS, i.Backends)
	}
	if out := os.Getenv("BASELINE_TEST_K8S_OUT"); out != "" {
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := col.Collect(context.Background()); err == nil {
		if _, h2, _ := model.Encode(again); h2 != hash {
			t.Log("hash differs between two collections (a ready count may have changed)")
		}
	}
}

package kube

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

var update = flag.Bool("update", false, "rewrite testdata/k8s.golden.json")

// apiServer serves testdata/*.json (from k3s v1.36, trimmed, plus a made-up
// worker node and load balancer) the way the API server does: bearer token
// required, lists paginated with continue tokens, forbidden resources
// answered with a Status.
type apiServer struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	token     string          // the token accepted
	forbidden map[string]bool // paths answered 403
	missing   map[string]bool // paths answered 404
	requests  []string
}

func newAPIServer(t *testing.T) *apiServer {
	a := &apiServer{t: t, token: "token-1", forbidden: map[string]bool{}, missing: map[string]bool{}}
	files := map[string]string{
		"/version":                             "version",
		"/api/v1/namespaces/kube-system":       "kube-system",
		"/api/v1/nodes":                        "nodes",
		"/api/v1/namespaces":                   "namespaces",
		"/apis/apps/v1/deployments":            "deployments",
		"/apis/apps/v1/statefulsets":           "statefulsets",
		"/apis/apps/v1/daemonsets":             "daemonsets",
		"/apis/batch/v1/cronjobs":              "cronjobs",
		"/api/v1/services":                     "services",
		"/apis/networking.k8s.io/v1/ingresses": "ingresses",
	}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		token, forbidden, missing := a.token, a.forbidden[r.URL.Path], a.missing[r.URL.Path]
		a.requests = append(a.requests, r.URL.RequestURI())
		a.mu.Unlock()
		status := func(code int, reason, msg string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure",
				"message": msg, "reason": reason, "code": code})
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			status(401, "Unauthorized", "Unauthorized")
			return
		}
		if forbidden {
			res := filepath.Base(r.URL.Path)
			status(403, "Forbidden", res+`.networking.k8s.io is forbidden: User "system:serviceaccount:baseline:baseline-agent" cannot list resource "`+
				res+`" in API group "networking.k8s.io" at the cluster scope`)
			return
		}
		if missing {
			status(404, "NotFound", "the server could not find the requested resource")
			return
		}
		name := files[r.URL.Path]
		if r.URL.Path == "/api/v1/pods" {
			name = "pods-1"
			if c := r.URL.Query().Get("continue"); c == "page-2-token" {
				name = "pods-2"
			} else if c != "" {
				status(410, "Expired", "The provided continue parameter is too old")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") && r.URL.Path != "/api/v1/namespaces/kube-system" ||
			strings.HasPrefix(r.URL.Path, "/apis/") {
			if r.URL.Query().Get("limit") != "250" {
				t.Errorf("%s: limit = %q", r.URL.RequestURI(), r.URL.Query().Get("limit"))
			}
		}
		if name == "" {
			status(404, "NotFound", "the server could not find the requested resource")
			return
		}
		b, err := os.ReadFile("testdata/" + name + ".json")
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// client trusts only the test server's certificate.
func (a *apiServer) client() *Client {
	pool := x509.NewCertPool()
	pool.AddCert(a.srv.Certificate())
	c := New(a.srv.URL, pool)
	c.Token = a.token
	return c
}

func (a *apiServer) set(f func(a *apiServer)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f(a)
}

func TestCollect(t *testing.T) {
	a := newAPIServer(t)
	col := &Collector{Client: a.client(), ClusterName: "homelab"}
	got, err := col.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, hash, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}

	if got.Cluster != (model.K8sCluster{UID: "9e4d51ab-82aa-4227-b2c9-a260fd8d4c9b", Name: "homelab", Version: "v1.36.5+k3s1", Platform: "linux/amd64"}) {
		t.Errorf("cluster = %+v", got.Cluster)
	}
	if len(got.Errors) != 0 {
		t.Errorf("errors = %+v", got.Errors)
	}

	// Nodes: the real k3s server and the made-up worker.
	if len(got.Nodes) != 2 {
		t.Fatalf("nodes = %+v", got.Nodes)
	}
	server := got.Nodes[0]
	if !server.Ready || !reflect.DeepEqual(server.Roles, []string{"control-plane"}) || server.CPU != "64" ||
		server.MemoryBytes != 96242776*1024 || server.KubeletVersion != "v1.36.5+k3s1" ||
		server.ContainerRuntime != "containerd://2.3.4-k3s1.36" || !reflect.DeepEqual(server.InternalIPs, []string{"10.200.0.5"}) ||
		server.SystemUUID != "00000000-0000-0000-0000-ac1f6bd134e0" || server.Taints != nil {
		t.Errorf("server node = %+v", server)
	}
	want := model.K8sNodeInfo{Name: "worker-1", Roles: []string{"gpu", "worker"}, Unschedulable: true,
		KubeletVersion: "v1.36.5+k3s1", ContainerRuntime: "containerd://2.3.4-k3s1.36", OSImage: "Ubuntu 24.04.3 LTS",
		KernelVersion: "6.8.0-85-generic", Arch: "arm64", MachineID: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
		SystemUUID: "4c4c4544-0042-3510-8052-b4c04f4e3732", InternalIPs: []string{"192.168.1.21", "fd00::21"},
		CPU: "3500m", MemoryBytes: 16 << 30, Taints: []string{"dedicated=gpu:NoSchedule", "node.kubernetes.io/unschedulable:NoSchedule"},
		Created: "2026-10-01T10:00:00Z"}
	if !reflect.DeepEqual(got.Nodes[1], want) {
		t.Errorf("worker node:\n got %+v\nwant %+v", got.Nodes[1], want)
	}

	if !reflect.DeepEqual(got.Namespaces, []string{"baseline", "default", "demo", "kube-node-lease", "kube-public", "kube-system"}) {
		t.Errorf("namespaces = %q", got.Namespaces)
	}

	byKey := map[string]model.K8sWorkload{}
	for _, w := range got.Workloads {
		byKey[w.Key()] = w
		if w.Kind == "Pod" && w.Name != "debug" {
			t.Errorf("pod %s/%s has a controller and should be left out", w.Namespace, w.Name)
		}
	}
	web := byKey["Deployment/demo/web"]
	if web.Replicas != 2 || web.Ready != 2 || !reflect.DeepEqual(web.Images, []string{"busybox:1.37", "nginx:1.29-alpine"}) {
		t.Errorf("web = %+v", web)
	}
	if db := byKey["StatefulSet/demo/db"]; db.Replicas != 1 || db.Ready != 1 || !reflect.DeepEqual(db.Images, []string{"busybox:1.37"}) {
		t.Errorf("db = %+v", db)
	}
	if svclb := byKey["DaemonSet/kube-system/svclb-traefik-26765718"]; svclb.Replicas != 1 || svclb.Ready != 1 ||
		!reflect.DeepEqual(svclb.Images, []string{"rancher/klipper-lb:v0.4.17"}) {
		t.Errorf("svclb = %+v", svclb)
	}
	if cj := byKey["CronJob/demo/backup"]; cj.Schedule != "17 3 * * *" || !cj.Suspend || cj.Replicas != 0 ||
		!reflect.DeepEqual(cj.Images, []string{"busybox:1.37"}) {
		t.Errorf("cronjob = %+v", cj)
	}
	if p := byKey["Pod/demo/debug"]; p.Replicas != 1 || p.Ready != 1 || p.Node == "" || !reflect.DeepEqual(p.Images, []string{"busybox:1.37"}) {
		t.Errorf("bare pod = %+v", p)
	}

	svcs := map[string]model.K8sService{}
	for _, s := range got.Services {
		svcs[s.Namespace+"/"+s.Name] = s
	}
	if s := svcs["demo/web"]; s.Type != "ClusterIP" || !reflect.DeepEqual(s.Ports, []string{"80/TCP→http"}) ||
		!reflect.DeepEqual(s.Selector, map[string]string{"app": "web"}) {
		t.Errorf("web service = %+v", s)
	}
	if s := svcs["demo/web-np"]; s.Type != "NodePort" || !reflect.DeepEqual(s.Ports, []string{"8080:30080/TCP→80"}) ||
		!reflect.DeepEqual(s.ExternalIPs, []string{"192.0.2.10"}) {
		t.Errorf("node port service = %+v", s)
	}
	if s := svcs["demo/db"]; s.ClusterIP != "None" || !reflect.DeepEqual(s.Ports, []string{"5432/TCP→5432"}) {
		t.Errorf("headless service = %+v", s)
	}
	if s := svcs["demo/docs"]; s.Type != "ExternalName" || s.ExternalName != "docs.example.test" || s.Ports != nil {
		t.Errorf("external name service = %+v", s)
	}
	if s := svcs["demo/edge"]; !reflect.DeepEqual(s.ExternalIPs, []string{"198.51.100.7", "lb-1234.elb.example.test"}) ||
		!reflect.DeepEqual(s.Ports, []string{"443:31443/TCP→https"}) {
		t.Errorf("load balancer = %+v", s)
	}
	if s := svcs["kube-system/traefik"]; s.Type != "LoadBalancer" || !reflect.DeepEqual(s.ExternalIPs, []string{"10.200.0.5"}) {
		t.Errorf("traefik = %+v", s)
	}

	wantIng := model.K8sIngress{Namespace: "demo", Name: "web", Class: "traefik", Hosts: []string{"web.example.test"}, TLS: true,
		Backends: []string{"* → web:80", "*/health → web:80", "web.example.test/ → web:http", "web.example.test/api → web-np:8080"}}
	if len(got.Ingresses) != 1 || !reflect.DeepEqual(got.Ingresses[0], wantIng) {
		t.Errorf("ingresses:\n got %+v\nwant %+v", got.Ingresses, wantIng)
	}

	// Environment variables and annotations never make it in.
	if bytes.Contains(b, []byte("do-not-collect")) {
		t.Error("the section holds an env var or annotation")
	}

	// The whole section, and its encoding, is stable.
	golden := "testdata/k8s.golden.json"
	var pretty bytes.Buffer
	json.Indent(&pretty, b, "", "  ")
	pretty.WriteByte('\n')
	if *update {
		if err := os.WriteFile(golden, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if g, err := os.ReadFile(golden); err != nil || !bytes.Equal(g, pretty.Bytes()) {
		t.Errorf("section differs from %s (run with -update and review the diff): %v", golden, err)
	}
	again, err := col.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, h2, _ := model.Encode(again); h2 != hash {
		t.Error("hash differs between two collections")
	}
}

func TestCollectPaginates(t *testing.T) {
	a := newAPIServer(t)
	pods, err := List[pod](context.Background(), a.client(), "/api/v1/pods")
	if err != nil {
		t.Fatal(err)
	}
	var p1, p2 struct{ Items []json.RawMessage }
	for name, v := range map[string]any{"pods-1": &p1, "pods-2": &p2} {
		b, _ := os.ReadFile("testdata/" + name + ".json")
		json.Unmarshal(b, v)
	}
	if len(p1.Items) == 0 || len(p2.Items) == 0 || len(pods) != len(p1.Items)+len(p2.Items) {
		t.Errorf("%d pods, want %d + %d", len(pods), len(p1.Items), len(p2.Items))
	}
	want := []string{"/api/v1/pods?limit=250", "/api/v1/pods?continue=page-2-token&limit=250"}
	if !reflect.DeepEqual(a.requests, want) {
		t.Errorf("requests = %q\nwant       %q", a.requests, want)
	}
}

// A list that fails is reported and the rest is still collected.
func TestCollectForbidden(t *testing.T) {
	a := newAPIServer(t)
	a.set(func(a *apiServer) {
		a.forbidden["/apis/networking.k8s.io/v1/ingresses"] = true
		a.missing["/apis/batch/v1/cronjobs"] = true
	})
	got, err := (&Collector{Client: a.client(), ClusterName: "homelab"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []model.K8sError{
		{Resource: "cronjobs", Error: "404 NotFound: the server could not find the requested resource"},
		{Resource: "ingresses", Error: `403 Forbidden: ingresses.networking.k8s.io is forbidden: User "system:serviceaccount:baseline:baseline-agent" cannot list resource "ingresses" in API group "networking.k8s.io" at the cluster scope`},
	}
	if !reflect.DeepEqual(got.Errors, want) {
		t.Errorf("errors:\n got %+v\nwant %+v", got.Errors, want)
	}
	if len(got.Ingresses) != 0 || len(got.Services) == 0 || len(got.Nodes) != 2 {
		t.Errorf("%d ingresses, %d services, %d nodes", len(got.Ingresses), len(got.Services), len(got.Nodes))
	}
	for _, w := range got.Workloads {
		if w.Kind == "CronJob" {
			t.Errorf("cronjob %+v from a failed list", w)
		}
	}
}

// Without the cluster's identity and version there is no section.
func TestCollectIdentityFails(t *testing.T) {
	for _, path := range []string{"/api/v1/namespaces/kube-system", "/version"} {
		a := newAPIServer(t)
		a.set(func(a *apiServer) { a.forbidden[path] = true })
		_, err := (&Collector{Client: a.client()}).Collect(context.Background())
		var e *Error
		if !errors.As(err, &e) || e.Code != 403 || e.Path != path {
			t.Errorf("%s forbidden: err = %v", path, err)
		}
	}
}

func TestClientRejectsUnknownCA(t *testing.T) {
	a := newAPIServer(t)
	c := New(a.srv.URL, x509.NewCertPool())
	c.Token = "token-1"
	var v any
	if err := c.Get(context.Background(), "/version", &v); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate error", err)
	}
}

// Bound service-account tokens rotate: the file is read again once the copy
// in memory is a minute old, and at once when the server rejects it.
func TestClientTokenRotation(t *testing.T) {
	a := newAPIServer(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokenFile, []byte("token-1\n"), 0o600)
	c := a.client()
	c.Token, c.TokenFile = "", tokenFile
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	get := func() error {
		var v any
		return c.Get(context.Background(), "/version", &v)
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}

	// The kubelet writes a new token; the old one still works for a while.
	os.WriteFile(tokenFile, []byte("token-2\n"), 0o600)
	now = now.Add(30 * time.Second)
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if c.token != "token-1" {
		t.Errorf("token re-read after 30s: %q", c.token)
	}
	a.set(func(a *apiServer) { a.token = "token-2" })
	now = now.Add(31 * time.Second)
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if c.token != "token-2" {
		t.Errorf("token = %q after a minute", c.token)
	}

	// Rejected before the minute is up: read again and retried.
	os.WriteFile(tokenFile, []byte("token-3\n"), 0o600)
	a.set(func(a *apiServer) { a.token = "token-3" })
	if err := get(); err != nil {
		t.Fatalf("after rotation: %v", err)
	}

	// A token nobody accepts is an error with the server's message.
	a.set(func(a *apiServer) { a.token = "token-4" })
	var e *Error
	if err := get(); !errors.As(err, &e) || e.Code != 401 || e.Short() != "401 Unauthorized: Unauthorized" {
		t.Fatalf("err = %v", err)
	}
}

// An expired continue token restarts the listing once.
func TestListRestartsOnExpiredContinue(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("continue") {
		case "":
			w.Write([]byte(`{"metadata":{"continue":"c1"},"items":[{"metadata":{"name":"a"}}]}`))
		case "c1":
			if calls == 2 {
				w.WriteHeader(410)
				w.Write([]byte(`{"kind":"Status","reason":"Expired","message":"too old","code":410}`))
				return
			}
			w.Write([]byte(`{"metadata":{},"items":[{"metadata":{"name":"b"}}]}`))
		}
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	items, err := List[objectRef](context.Background(), New(srv.URL, pool), "/api/v1/namespaces")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Metadata.Name != "a" || items[1].Metadata.Name != "b" || calls != 4 {
		t.Errorf("items = %+v after %d calls", items, calls)
	}
}

func TestParseQuantity(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"8044176Ki", 8044176 * 1024, true},
		{"16Gi", 16 << 30, true},
		{"1Mi", 1 << 20, true},
		{"2Ti", 2 << 40, true},
		{"1Pi", 1 << 50, true},
		{"1Ei", 1 << 60, true},
		{"1.5Gi", 1610612736, true},
		{"500k", 500000, true},
		{"1M", 1000000, true},
		{"1.5G", 1500000000, true},
		{"2T", 2000000000000, true},
		{"1P", 1000000000000000, true},
		{"1E", 1000000000000000000, true},
		{"17179869184", 17179869184, true},
		{"128974848000m", 128974848, true},
		{"1500m", 2, true}, // rounded up, as Kubernetes does
		{"1e9", 1000000000, true},
		{"1E3", 1000, true},
		{"0", 0, true},
		{"8Ei", 0, false}, // overflows int64
		{"", 0, false},
		{"Gi", 0, false},
		{"12Xi", 0, false},
		{"1.2.3", 0, false},
	} {
		got, ok := ParseQuantity(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseQuantity(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSelf(t *testing.T) {
	s := Self{Name: "homelab"}
	id := s.Identity()
	if id.Hostname != "homelab" || id.BootID != BootID || id.MachineID != "" || id.DMIUUID != "" || !id.BootTime.IsZero() {
		t.Errorf("identity = %+v", id)
	}
	if !reflect.DeepEqual(s.Capabilities(), []string{model.CapK8sCluster, "k8s-actions", "k8s-pods"}) {
		t.Errorf("capabilities = %q", s.Capabilities())
	}
	s.Logs = true
	if !reflect.DeepEqual(s.Capabilities(), []string{model.CapK8sCluster, "k8s-actions", "k8s-pods", "k8s-logs"}) {
		t.Errorf("capabilities with logs = %q", s.Capabilities())
	}
}

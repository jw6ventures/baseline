package kube

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
)

// cluster is a fake API server that keeps objects by path, applies merge
// and strategic patches (containers merged by name), stores server-side
// apply documents as they come, and rolls workloads out at once unless an
// image has "broken" in it.
type cluster struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	objs    map[string]map[string]any // by path
	applied map[string]string         // apply documents by path
	log     []string                  // "METHOD path" of changing requests
	logs    string                    // what pods/<x>/log returns
}

func newCluster(t *testing.T) *cluster {
	c := &cluster{t: t, objs: map[string]map[string]any{}, applied: map[string]string{}}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *cluster) manager() *Manager {
	pool := x509.NewCertPool()
	pool.AddCert(c.srv.Certificate())
	cl := New(c.srv.URL, pool)
	cl.Token = "t"
	return &Manager{Client: cl, DenyNamespaces: []string{"kube-system"}, PollEvery: time.Millisecond,
		Now: func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }}
}

func (c *cluster) put(path, doc string) {
	var o map[string]any
	if err := json.Unmarshal([]byte(doc), &o); err != nil {
		c.t.Fatal(err)
	}
	c.objs[path] = o
	c.rollout(path)
}

func (c *cluster) changes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

func status(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "status": "Failure", "reason": reason, "code": code, "message": reason})
}

func (c *cluster) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	path, q := r.URL.Path, r.URL.Query()
	if r.Method != http.MethodGet && q.Get("dryRun") == "" {
		c.log = append(c.log, r.Method+" "+path)
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/log"):
		w.Write([]byte(c.logs))
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/pods"):
		items := []any{}
		for _, k := range slices.Sorted(mapsKeys(c.objs)) {
			if strings.HasPrefix(k, path+"/") && matches(c.objs[k], q.Get("labelSelector")) {
				items = append(items, c.objs[k])
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "metadata": map[string]any{}})
	case r.Method == http.MethodGet:
		o, ok := c.objs[path]
		if !ok {
			if doc, ok := c.applied[path]; ok {
				st := `"availableReplicas":1`
				if strings.Contains(doc, "broken") {
					st = `"availableReplicas":0,"conditions":[{"type":"Progressing","reason":"ProgressDeadlineExceeded","message":"timed out"}]`
				}
				w.Write([]byte(`{"metadata":{"generation":1},"status":{"observedGeneration":1,"replicas":1,"updatedReplicas":1,` + st + `}}`))
				return
			}
			status(w, 404, "NotFound")
			return
		}
		json.NewEncoder(w).Encode(o)
	case r.Method == http.MethodPatch && r.Header.Get("Content-Type") == ApplyPatch:
		if bytes.Contains(body, []byte("rejected")) {
			status(w, 422, "Invalid")
			return
		}
		if q.Get("dryRun") == "" {
			c.applied[path] = string(body)
		}
		w.Write([]byte(`{}`))
	case r.Method == http.MethodPatch:
		o, ok := c.objs[path]
		if !ok {
			status(w, 404, "NotFound")
			return
		}
		var p map[string]any
		json.Unmarshal(body, &p)
		merge(o, p, r.Header.Get("Content-Type") == StrategicPatch)
		meta := o["metadata"].(map[string]any)
		g, _ := meta["generation"].(float64)
		meta["generation"] = g + 1
		c.rollout(path)
		json.NewEncoder(w).Encode(o)
	case r.Method == http.MethodPost:
		var o map[string]any
		json.Unmarshal(body, &o)
		c.objs[path+"/"+o["metadata"].(map[string]any)["name"].(string)] = o
		w.WriteHeader(201)
		w.Write(body)
	case r.Method == http.MethodDelete:
		_, ok := c.objs[path]
		_, applied := c.applied[path]
		if !ok && !applied {
			status(w, 404, "NotFound")
			return
		}
		delete(c.objs, path)
		delete(c.applied, path)
		w.Write([]byte(`{}`))
	default:
		status(w, 405, "MethodNotAllowed")
	}
}

func mapsKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func matches(o map[string]any, selector string) bool {
	if selector == "" {
		return true
	}
	labels, _ := o["metadata"].(map[string]any)["labels"].(map[string]any)
	for _, kv := range strings.Split(selector, ",") {
		k, v, _ := strings.Cut(kv, "=")
		if labels[k] != v {
			return false
		}
	}
	return true
}

// merge applies a JSON merge patch; strategic merges lists of named
// objects by name.
func merge(dst, patch map[string]any, strategic bool) {
	for k, v := range patch {
		pm, isMap := v.(map[string]any)
		dm, dstMap := dst[k].(map[string]any)
		pl, isList := v.([]any)
		dl, dstList := dst[k].([]any)
		switch {
		case v == nil:
			delete(dst, k)
		case isMap && dstMap:
			merge(dm, pm, strategic)
		case isMap:
			n := map[string]any{}
			merge(n, pm, strategic)
			dst[k] = n
		case strategic && isList && dstList:
			for _, e := range pl {
				em := e.(map[string]any)
				found := false
				for _, d := range dl {
					if d.(map[string]any)["name"] == em["name"] {
						merge(d.(map[string]any), em, true)
						found = true
					}
				}
				if !found {
					dl = append(dl, em)
				}
			}
			dst[k] = dl
		default:
			dst[k] = v
		}
	}
}

// rollout sets a workload's status: rolled out, or stalled when an image
// is "broken".
func (c *cluster) rollout(path string) {
	o := c.objs[path]
	kind, _ := o["kind"].(string)
	if kind != "Deployment" && kind != "StatefulSet" && kind != "DaemonSet" {
		return
	}
	meta := o["metadata"].(map[string]any)
	if meta["generation"] == nil {
		meta["generation"] = float64(1)
	}
	spec := o["spec"].(map[string]any)
	want := float64(1)
	if r, ok := spec["replicas"].(float64); ok {
		want = r
	}
	b, _ := json.Marshal(spec["template"])
	st := map[string]any{"observedGeneration": meta["generation"], "replicas": want, "updatedReplicas": want,
		"availableReplicas": want, "readyReplicas": want, "desiredNumberScheduled": want, "updatedNumberScheduled": want,
		"numberAvailable": want}
	if bytes.Contains(b, []byte("broken")) {
		st["availableReplicas"] = float64(0)
		st["conditions"] = []any{map[string]any{"type": "Progressing", "status": "False",
			"reason": "ProgressDeadlineExceeded", "message": `ReplicaSet "web-2" has timed out progressing.`}}
	}
	o["status"] = st
}

const (
	deployPath = "/apis/apps/v1/namespaces/default/deployments/web"
	podsPath   = "/api/v1/namespaces/default/pods"
	cronPath   = "/apis/batch/v1/namespaces/default/cronjobs/backup"
)

func webCluster(t *testing.T) *cluster {
	c := newCluster(t)
	c.put(deployPath, `{"kind":"Deployment","metadata":{"name":"web","namespace":"default","generation":3},
		"spec":{"replicas":2,"selector":{"matchLabels":{"app":"web"}},
		"template":{"spec":{"containers":[{"name":"nginx","image":"nginx:1.27"},{"name":"envoy","image":"envoy:1.30"}]}}}}`)
	c.put(podsPath+"/web-5d8f-abcde", `{"metadata":{"name":"web-5d8f-abcde","uid":"u1","labels":{"app":"web","pod-template-hash":"5d8f"},
		"ownerReferences":[{"kind":"ReplicaSet","name":"web-5d8f","controller":true}]},
		"spec":{"nodeName":"n1","containers":[{"name":"nginx","image":"nginx:1.27"}]},
		"status":{"phase":"Running","containerStatuses":[{"name":"nginx","ready":true,"restartCount":2}]}}`)
	// Matches the selector, but another controller owns it.
	c.put(podsPath+"/web-other", `{"metadata":{"name":"web-other","uid":"u2","labels":{"app":"web","pod-template-hash":"9"},
		"ownerReferences":[{"kind":"ReplicaSet","name":"other-9","controller":true}]},"spec":{},"status":{}}`)
	c.put(cronPath, `{"kind":"CronJob","metadata":{"name":"backup","namespace":"default","uid":"cj1"},
		"spec":{"suspend":false,"jobTemplate":{"metadata":{"labels":{"app":"backup"}},
		"spec":{"template":{"spec":{"containers":[{"name":"b","image":"backup:1"}]}}}}}}`)
	return c
}

func TestWorkloadActions(t *testing.T) {
	ctx := context.Background()
	c := webCluster(t)
	m := c.manager()
	var out bytes.Buffer
	web := action.K8sParams{Kind: "Deployment", Namespace: "default", Name: "web", HealthTimeout: 60}

	res, err := m.Workload(ctx, action.K8sRestart, web, &out)
	if err != nil || !slices.Equal(res.Objects, []string{"Deployment default/web"}) || !strings.Contains(out.String(), "rolled out") {
		t.Fatalf("restart: %v %+v\n%s", err, res, out.String())
	}
	tmpl := c.objs[deployPath]["spec"].(map[string]any)["template"].(map[string]any)
	if ann := tmpl["metadata"].(map[string]any)["annotations"].(map[string]any); ann[restartedAt] != "2026-11-03T12:00:00Z" {
		t.Errorf("annotations %v", ann)
	}

	three := 3
	scale := web
	scale.Replicas = &three
	if _, err := m.Workload(ctx, action.K8sScale, scale, &out); err != nil || c.objs[deployPath]["spec"].(map[string]any)["replicas"] != float64(3) {
		t.Fatalf("scale: %v", err)
	}

	img := web
	img.Images = map[string]string{"nginx": "nginx:1.28"}
	res, err = m.Workload(ctx, action.K8sSetImage, img, &out)
	if err != nil || res.Previous["nginx"] != "nginx:1.27" || res.RolledBack {
		t.Fatalf("set_image: %v %+v", err, res)
	}
	images := func() string {
		var s []string
		for _, ct := range tmpl["spec"].(map[string]any)["containers"].([]any) {
			s = append(s, ct.(map[string]any)["image"].(string))
		}
		return strings.Join(s, ",")
	}
	if images() != "nginx:1.28,envoy:1.30" {
		t.Errorf("images %s", images())
	}
	// A rollout that stalls puts the previous image back.
	img.Images = map[string]string{"envoy": "envoy:broken"}
	res, err = m.Workload(ctx, action.K8sSetImage, img, &out)
	if err == nil || !strings.Contains(err.Error(), "stalled") || !res.RolledBack || images() != "nginx:1.28,envoy:1.30" {
		t.Fatalf("broken set_image: %v %+v %s", err, res, images())
	}
	img.Images = map[string]string{"sidecar": "x:1"}
	if _, err := m.Workload(ctx, action.K8sSetImage, img, &out); err == nil || !strings.Contains(err.Error(), "has no container sidecar") {
		t.Errorf("unknown container: %v", err)
	}

	del := action.K8sParams{Kind: "Deployment", Namespace: "default", Name: "web", Pod: "web-other"}
	if _, err := m.Workload(ctx, action.K8sDeletePod, del, &out); err == nil || !strings.Contains(err.Error(), "doesn't belong") {
		t.Errorf("deleting another workload's pod: %v", err)
	}
	del.Pod = "web-5d8f-abcde"
	if _, err := m.Workload(ctx, action.K8sDeletePod, del, &out); err != nil || c.objs[podsPath+"/web-5d8f-abcde"] != nil {
		t.Errorf("delete_pod: %v", err)
	}

	cron := action.K8sParams{Kind: "CronJob", Namespace: "default", Name: "backup"}
	if _, err := m.Workload(ctx, action.K8sSuspend, cron, &out); err != nil || c.objs[cronPath]["spec"].(map[string]any)["suspend"] != true {
		t.Fatalf("suspend: %v", err)
	}
	if res, err := m.Workload(ctx, action.K8sSuspend, cron, &out); err != nil || res.Objects != nil {
		t.Errorf("suspend again: %v %+v", err, res)
	}
	res, err = m.Workload(ctx, action.K8sTrigger, cron, &out)
	job := c.objs["/apis/batch/v1/namespaces/default/jobs/backup-manual-1793707200"]
	if err != nil || res.Job != "backup-manual-1793707200" || job == nil {
		t.Fatalf("trigger: %v %+v", err, res)
	}
	owner := job["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)
	if owner["uid"] != "cj1" || owner["kind"] != "CronJob" || job["metadata"].(map[string]any)["labels"].(map[string]any)["app"] != "backup" {
		t.Errorf("job metadata %v", job["metadata"])
	}

	sys := action.K8sParams{Kind: "Deployment", Namespace: "kube-system", Name: "coredns", HealthTimeout: 60}
	before := len(c.changes())
	if _, err := m.Workload(ctx, action.K8sRestart, sys, &out); err == nil || !strings.Contains(err.Error(), "off limits") ||
		len(c.changes()) != before {
		t.Errorf("kube-system: %v", err)
	}
}

func TestPodsAndLogs(t *testing.T) {
	ctx := context.Background()
	c := webCluster(t)
	c.logs = "2026-11-03T12:00:00Z hello\n"
	m := c.manager()
	pods, err := m.Pods(ctx, model.K8sPodsRequest{Kind: "Deployment", Namespace: "default", Name: "web"})
	if err != nil || len(pods) != 1 || pods[0].Name != "web-5d8f-abcde" || pods[0].Ready != 1 || pods[0].Restarts != 2 || pods[0].Node != "n1" {
		t.Fatalf("pods %+v %v", pods, err)
	}
	logs, err := m.Logs(ctx, model.K8sLogsRequest{Kind: "Deployment", Namespace: "default", Name: "web", Pod: "web-5d8f-abcde"})
	if err != nil || logs.Text != c.logs || logs.Truncated {
		t.Fatalf("logs %+v %v", logs, err)
	}
	if _, err := m.Logs(ctx, model.K8sLogsRequest{Kind: "Deployment", Namespace: "default", Name: "web", Pod: "web-other"}); err == nil {
		t.Error("read the logs of another workload's pod")
	}
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

const shopV1 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop
spec:
  image: shop:1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: shop-old
`

const shopV2 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop
spec:
  image: shop:2
---
apiVersion: v1
kind: Service
metadata:
  name: shop
`

func TestManifest(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	m := c.manager()
	var out bytes.Buffer
	const dep, cm, svc = "/apis/apps/v1/namespaces/default/deployments/shop", "/api/v1/namespaces/default/configmaps/shop-old",
		"/api/v1/namespaces/default/services/shop"
	p := action.K8sManifestParams{Bundle: "shop", Namespace: "default", ManifestSHA256: hash(shopV1), HealthTimeout: 60}

	if _, err := m.Manifest(ctx, action.K8sDeploy, action.K8sManifestParams{ManifestSHA256: "x"}, []byte(shopV1), nil, &out); err == nil ||
		!strings.Contains(err.Error(), "hash") {
		t.Errorf("hash mismatch: %v", err)
	}
	res, err := m.Manifest(ctx, action.K8sDeploy, p, []byte(shopV1), nil, &out)
	if err != nil || !slices.Equal(res.Objects, []string{"Deployment default/shop", "ConfigMap default/shop-old"}) {
		t.Fatalf("deploy: %v %+v\n%s", err, res, out.String())
	}
	if !strings.Contains(c.applied[dep], "shop:1") || c.applied[cm] == "" {
		t.Fatalf("applied %v", c.applied)
	}
	// Deploying it again finds the objects there.
	if _, err := m.Manifest(ctx, action.K8sDeploy, p, []byte(shopV1), nil, &out); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("second deploy: %v", err)
	}

	// The edit changes the Deployment, adds the Service and deletes the
	// ConfigMap.
	e := action.K8sManifestParams{Bundle: "shop", Namespace: "default", ManifestSHA256: hash(shopV2), BaseSHA256: hash(shopV1),
		HealthTimeout: 60}
	res, err = m.Manifest(ctx, action.K8sEdit, e, []byte(shopV2), []byte(shopV1), &out)
	if err != nil || !slices.Equal(res.Deleted, []string{"ConfigMap default/shop-old"}) {
		t.Fatalf("edit: %v %+v", err, res)
	}
	if !strings.Contains(c.applied[dep], "shop:2") || c.applied[svc] == "" || c.applied[cm] != "" {
		t.Fatalf("applied after the edit %v", c.applied)
	}

	// An edit whose rollout stalls applies the base again and deletes
	// what it added.
	bad := strings.Replace(shopV2, "shop:2", "shop:broken", 1) + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: shop-extra\n"
	e2 := action.K8sManifestParams{Bundle: "shop", Namespace: "default", ManifestSHA256: hash(bad), BaseSHA256: hash(shopV2),
		HealthTimeout: 60}
	res, err = m.Manifest(ctx, action.K8sEdit, e2, []byte(bad), []byte(shopV2), &out)
	if err == nil || !strings.Contains(err.Error(), "stalled") || !res.RolledBack {
		t.Fatalf("stalled edit: %v %+v", err, res)
	}
	if !strings.Contains(c.applied[dep], "shop:2") || c.applied["/api/v1/namespaces/default/configmaps/shop-extra"] != "" ||
		c.applied[svc] == "" {
		t.Fatalf("applied after the stalled edit %v", c.applied)
	}

	if _, err := m.Manifest(ctx, action.K8sDeploy, action.K8sManifestParams{Bundle: "sys", Namespace: "kube-system",
		ManifestSHA256: hash(shopV1), HealthTimeout: 60}, []byte(shopV1), nil, &out); err == nil || !strings.Contains(err.Error(), "off limits") {
		t.Errorf("kube-system deploy: %v", err)
	}
	rej := strings.Replace(shopV1, "shop-old", "rejected", 1)
	if _, err := m.Manifest(ctx, action.K8sDeploy, action.K8sManifestParams{Bundle: "x", Namespace: "other",
		ManifestSHA256: hash(rej), HealthTimeout: 60}, []byte(rej), nil, &out); err == nil {
		t.Error("a manifest the dry run rejects")
	}
	for _, ch := range c.changes() {
		if strings.Contains(ch, "/namespaces/other/") {
			t.Errorf("dry run failure still changed %s", ch)
		}
	}
}

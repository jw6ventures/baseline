package k8smanifest

import (
	"strconv"
	"strings"
	"testing"
)

const shop = `# the shop
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop   # the web side
  labels:
    app: shop
spec:
  replicas: 2
---
apiVersion: v1
kind: Service
metadata:
  namespace: "edge"
  name: 'shop'
spec:
  ports: [{port: 80}]
...
---
{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "shop-config"}, "data": {"a": "b"}}
--- 
`

func TestParse(t *testing.T) {
	objs, err := Parse([]byte(shop), "default")
	if err != nil {
		t.Fatal(err)
	}
	var keys, paths []string
	for _, o := range objs {
		keys, paths = append(keys, o.Key()), append(paths, o.Path())
	}
	if got := strings.Join(keys, ","); got != "Deployment default/shop,Service edge/shop,ConfigMap default/shop-config" {
		t.Errorf("keys = %s", got)
	}
	if got := strings.Join(paths, ","); got != "/apis/apps/v1/namespaces/default/deployments/shop,/api/v1/namespaces/edge/services/shop,"+
		"/api/v1/namespaces/default/configmaps/shop-config" {
		t.Errorf("paths = %s", got)
	}
	if !objs[0].Workload || objs[1].Workload {
		t.Error("workload flags")
	}
	// Documents go to the API server as they are.
	if !strings.Contains(string(objs[0].Doc), "replicas: 2") || strings.Contains(string(objs[0].Doc), "kind: Service") {
		t.Errorf("doc 1 = %q", objs[0].Doc)
	}
}

func TestParseRefuses(t *testing.T) {
	for _, tc := range []struct{ manifest, want string }{
		{"", "no objects"},
		{"---\n# nothing\n---\n", "no objects"},
		{"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n", "doesn't apply Secrets"},
		{"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\n", "doesn't apply rbac.authorization.k8s.io/v1 ClusterRole"},
		{"apiVersion: apps/v1beta1\nkind: Deployment\nmetadata:\n  name: d\n", "Deployment is apps/v1 here"},
		{"apiVersion: v1\nkind: List\nitems: []\n", "rather than a List"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  generateName: c-\n", "no metadata.name"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n", "not in flow style"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: Bad_Name\n", "isn't a ConfigMap name"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: Bad\n", "isn't a namespace"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: &a c\n", "plain value"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n", "appears twice"},
		{"%YAML 1.2\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n", "directives"},
		{"[1, 2]", "isn't a YAML mapping"},
		{`{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}} {}`, "JSON"},
	} {
		if _, err := Parse([]byte(tc.manifest), "default"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %v, want %q", tc.manifest, err, tc.want)
		}
	}
	if _, err := Parse([]byte(shop), "Default"); err == nil {
		t.Error("bad default namespace accepted")
	}
	var many strings.Builder
	for i := 0; i <= MaxObjects; i++ {
		many.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c" + strconv.Itoa(i) + "\n---\n")
	}
	if _, err := Parse([]byte(many.String()), "default"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too many objects: %v", err)
	}
	if _, err := Parse([]byte(strings.Repeat("#", MaxSize+1)), "default"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("too large: %v", err)
	}
}

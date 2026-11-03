package action

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestValidateK8s(t *testing.T) {
	ok := []struct{ name, params, want string }{
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"web"}`, "Restart Deployment default/web"},
		{K8sScale, `{"kind":"StatefulSet","namespace":"db","name":"pg","replicas":0}`, "Scale StatefulSet db/pg to 0"},
		{K8sSetImage, `{"kind":"Deployment","namespace":"default","name":"web","images":{"sidecar":"envoy:1.30","nginx":"nginx:1.28"}}`,
			"Set the image of Deployment default/web: nginx=nginx:1.28, sidecar=envoy:1.30"},
		{K8sSetImage, `{"kind":"CronJob","namespace":"ops","name":"backup","images":{"b":"ghcr.io/x/b@sha256:` + strings.Repeat("a", 64) + `"}}`, ""},
		{K8sDeletePod, `{"kind":"Deployment","namespace":"default","name":"web","pod":"web-5d8f-abcde"}`,
			"Delete pod default/web-5d8f-abcde of Deployment web"},
		{K8sDeletePod, `{"kind":"Pod","namespace":"default","name":"debug"}`, "Delete pod default/debug"},
		{K8sSuspend, `{"kind":"CronJob","namespace":"ops","name":"backup"}`, "Suspend CronJob ops/backup"},
		{K8sResume, `{"kind":"CronJob","namespace":"ops","name":"backup"}`, "Resume CronJob ops/backup"},
		{K8sTrigger, `{"kind":"CronJob","namespace":"ops","name":"backup"}`, "Run CronJob ops/backup now"},
	}
	for _, tc := range ok {
		out, err := Validate(tc.name, []byte(tc.params))
		if err != nil {
			t.Errorf("%s %s: %v", tc.name, tc.params, err)
			continue
		}
		if tc.want != "" && Describe(tc.name, out) != tc.want {
			t.Errorf("Describe(%s) = %q, want %q", tc.name, Describe(tc.name, out), tc.want)
		}
	}
	// Rollouts get the default timeout; the others none.
	out, _ := Validate(K8sRestart, []byte(`{"kind":"DaemonSet","namespace":"default","name":"agent"}`))
	var p K8sParams
	if json.Unmarshal(out, &p); p.HealthTimeout != DefaultHealthTimeout {
		t.Errorf("restart timeout = %d", p.HealthTimeout)
	}

	bad := []struct{ name, params, want string }{
		{K8sScale, `{"kind":"DaemonSet","namespace":"default","name":"x","replicas":2}`, "works on a"},
		{K8sSuspend, `{"kind":"Deployment","namespace":"default","name":"x"}`, "works on a"},
		{K8sRestart, `{"kind":"Deployment","namespace":"Default","name":"x"}`, "isn't a namespace"},
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"-x"}`, "isn't a Deployment name"},
		{K8sScale, `{"kind":"Deployment","namespace":"default","name":"x"}`, "number of replicas"},
		{K8sScale, `{"kind":"Deployment","namespace":"default","name":"x","replicas":1001}`, "between 0 and 1000"},
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"x","replicas":1}`, "k8s.scale's"},
		{K8sSetImage, `{"kind":"Deployment","namespace":"default","name":"x"}`, "at least one container"},
		{K8sSetImage, `{"kind":"Deployment","namespace":"default","name":"x","images":{"web":"nginx latest"}}`, "isn't an image"},
		{K8sSetImage, `{"kind":"Deployment","namespace":"default","name":"x","images":{"Web":"nginx"}}`, "isn't a container name"},
		{K8sDeletePod, `{"kind":"Deployment","namespace":"default","name":"x"}`, "pick the pod"},
		{K8sDeletePod, `{"kind":"Pod","namespace":"default","name":"x","pod":"y"}`, "its own workload"},
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"x","pod":"y"}`, "k8s.delete_pod's"},
		{K8sTrigger, `{"kind":"CronJob","namespace":"default","name":"x","health_timeout":60}`, "roll a workload out"},
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"x","health_timeout":5}`, "rollout timeout"},
		{K8sRestart, `{"kind":"Deployment","namespace":"default","name":"x","command":"sh"}`, "unknown field"},
	}
	for _, tc := range bad {
		if _, err := Validate(tc.name, []byte(tc.params)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: err = %v, want %q", tc.name, tc.params, err, tc.want)
		}
	}
}

func TestValidateK8sManifest(t *testing.T) {
	const rev = "8a3f2c1e-1111-4222-8333-944455556666"
	sha := strings.Repeat("ab", 32)
	deploy := `{"bundle":"shop","namespace":"default","revision":"` + rev + `","manifest_sha256":"` + sha + `"}`
	out, err := Validate(K8sDeploy, []byte(deploy))
	if err != nil || Describe(K8sDeploy, out) != "Deploy manifest shop (namespace default)" {
		t.Fatalf("deploy: %v %s", err, Describe(K8sDeploy, out))
	}
	if _, err := Validate(K8sEdit, []byte(deploy)); err == nil || !strings.Contains(err.Error(), "names the revision") {
		t.Errorf("edit without a base: %v", err)
	}
	edit := strings.TrimSuffix(deploy, "}") + `,"base_revision":"` + rev + `","base_sha256":"` + sha + `"}`
	if out, err := Validate(K8sEdit, []byte(edit)); err != nil || Describe(K8sEdit, out) != "Edit manifest shop" {
		t.Errorf("edit: %v", err)
	}
	if _, err := Validate(K8sDeploy, []byte(edit)); err == nil || !strings.Contains(err.Error(), "nothing to edit") {
		t.Errorf("deploy with a base: %v", err)
	}
	if _, err := Validate(K8sDeploy, []byte(`{"bundle":"Shop!","namespace":"default","revision":"`+rev+`","manifest_sha256":"`+sha+`"}`)); err == nil {
		t.Error("bad bundle name accepted")
	}
}

func TestK8sSupportedAndPolicy(t *testing.T) {
	cluster := []string{"k8s-cluster", CapK8sActions}
	if ok, why := MustGet(K8sRestart).Supported(cluster); !ok {
		t.Errorf("restart on a cluster agent: %s", why)
	}
	if ok, why := MustGet(PkgUpgrade).Supported(cluster); ok || !strings.Contains(why, "runs only Kubernetes actions") {
		t.Errorf("pkg.upgrade on a cluster agent: %v %s", ok, why)
	}
	if ok, _ := MustGet(K8sRestart).Supported([]string{"k8s-cluster"}); ok {
		t.Error("restart on a cluster agent too old to run it")
	}
	if ok, _ := MustGet(K8sRestart).Supported([]string{"apt"}); ok {
		t.Error("restart on a host agent")
	}
	off := Policy{Jobs: true, AllowActions: []string{}}
	if ok, why := off.Allows(K8sScale); ok || !strings.Contains(why, "BASELINE_ALLOW_ACTIONS") {
		t.Errorf("actions off: %v %s", ok, why)
	}
	on := Policy{Jobs: true, AllowActions: []string{CategoryKubernetes}}
	if ok, why := on.Allows(K8sScale); !ok {
		t.Errorf("actions on: %s", why)
	}
	// An empty list survives the round trip through JSON: it means none,
	// not all.
	b, _ := json.Marshal(off)
	var back Policy
	if json.Unmarshal(b, &back); back.AllowActions == nil || back.AllActions() {
		t.Errorf("round trip of %s: %#v", b, back.AllowActions)
	}
	b, _ = json.Marshal(Policy{Jobs: true})
	if back = (Policy{}); json.Unmarshal(b, &back) != nil || !back.AllActions() {
		t.Errorf("round trip of %s: %#v", b, back.AllowActions)
	}
}

func TestParseClusterSettings(t *testing.T) {
	for in, want := range map[string][]string{"": {"kube-system"}, "none": {}, " shop, ops ,shop": {"shop", "ops"}} {
		if got, err := ParseDenyNamespaces(in); err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseDenyNamespaces(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseDenyNamespaces("kube-system,Bad_NS"); err == nil {
		t.Error("bad namespace accepted")
	}
	for in, want := range map[string][]string{"": {}, "none": {}, "kubernetes": {CategoryKubernetes}, "all": {CategoryKubernetes}} {
		if got, err := ParseClusterAllowActions(in); err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseClusterAllowActions(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseClusterAllowActions("patch"); err == nil {
		t.Error("patch accepted on a cluster agent")
	}
}

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

type fakeKube struct {
	calls          []string
	manifest, base string
	err            error
	res            action.K8sResult
}

func (f *fakeKube) Workload(_ context.Context, name string, p action.K8sParams, out io.Writer) (action.K8sResult, error) {
	f.calls = append(f.calls, name+" "+p.Kind+" "+p.Namespace+"/"+p.Name)
	fmt.Fprintln(out, "working on it")
	return f.res, f.err
}

func (f *fakeKube) Manifest(_ context.Context, name string, p action.K8sManifestParams, manifest, base []byte, out io.Writer) (action.K8sResult, error) {
	f.calls = append(f.calls, name+" "+p.Bundle)
	f.manifest, f.base = string(manifest), string(base)
	return f.res, f.err
}

func kubeRunner(t *testing.T, k *fakeKube) *Runner {
	r := newRunner(t, &fakeExec{})
	r.Kube = k
	r.Policy = action.Policy{Jobs: true, AllowActions: []string{action.CategoryKubernetes}, SelfUpdateOff: true}
	return r
}

func TestKubeActions(t *testing.T) {
	k := &fakeKube{res: action.K8sResult{Objects: []string{"Deployment default/web"}}}
	r := kubeRunner(t, k)
	id := jobID(1)
	start(r, id, action.K8sRestart, `{"kind":"Deployment","namespace":"default","name":"web"}`)
	evs, res := untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if strings.Join(k.calls, ";") != "k8s.restart Deployment default/web" || !strings.Contains(outputOf(evs, "info"), "working on it") ||
		!strings.Contains(string(res.GetResultJson()), "Deployment default/web") {
		t.Errorf("calls %v, output %q, result %s", k.calls, outputOf(evs, ""), res.GetResultJson())
	}

	// A failed image update that was rolled back says so.
	k.err, k.res = errors.New("the rollout stalled"), action.K8sResult{RolledBack: true}
	id = jobID(2)
	start(r, id, action.K8sSetImage, `{"kind":"Deployment","namespace":"default","name":"web","images":{"web":"nginx:1"}}`)
	_, res = untilResult(t, r, id)
	checkResult(t, res, stateRolledBack, -1, "stalled")

	// The manifest comes in the job's files.
	k.err, k.res = nil, action.K8sResult{}
	id = jobID(3)
	sha := strings.Repeat("ab", 32)
	r.Start(context.Background(), &agentv1.RunJob{JobId: id, Action: action.K8sEdit, ParamsJson: []byte(`{"bundle":"shop","namespace":"default",` +
		`"revision":"8a3f2c1e-1111-4222-8333-944455556666","manifest_sha256":"` + sha + `",` +
		`"base_revision":"8a3f2c1e-1111-4222-8333-944455556667","base_sha256":"` + sha + `"}`),
		StackFiles: &agentv1.StackFiles{Compose: []byte("new"), Env: []byte("old")}})
	_, res = untilResult(t, r, id)
	checkResult(t, res, "succeeded", 0, "")
	if k.manifest != "new" || k.base != "old" {
		t.Errorf("manifest %q base %q", k.manifest, k.base)
	}
}

func TestKubeRefusals(t *testing.T) {
	k := &fakeKube{}
	r := kubeRunner(t, k)
	id := jobID(5)
	start(r, id, action.HostReboot, `{}`)
	_, res := untilResult(t, r, id)
	checkResult(t, res, "rejected", -1, "runs only Kubernetes actions")

	// Turned off: BASELINE_ALLOW_ACTIONS=none.
	r = kubeRunner(t, k)
	r.Policy.AllowActions = []string{}
	id = jobID(6)
	start(r, id, action.K8sRestart, `{"kind":"Deployment","namespace":"default","name":"web"}`)
	_, res = untilResult(t, r, id)
	checkResult(t, res, "rejected", -1, "BASELINE_ALLOW_ACTIONS")

	// A host agent has no Kubernetes to act on.
	r = newRunner(t, &fakeExec{})
	id = jobID(7)
	start(r, id, action.K8sRestart, `{"kind":"Deployment","namespace":"default","name":"web"}`)
	_, res = untilResult(t, r, id)
	if res.GetState() == "succeeded" {
		t.Error("a host agent ran k8s.restart")
	}
	if len(k.calls) != 0 {
		t.Errorf("calls %v", k.calls)
	}
}

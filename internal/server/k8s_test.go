package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// fakeCluster answers the pods and logs polls the way a cluster agent
// would.
type fakeCluster struct {
	mu    sync.Mutex
	polls []string
	err   error
}

func (f *fakeCluster) PollIntegration(_ context.Context, hostID, kind, capability string, config []byte, _ string,
	_ time.Duration) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls = append(f.polls, kind+" "+string(config))
	if f.err != nil {
		return nil, f.err
	}
	switch kind {
	case model.PollK8sPods:
		return json.Marshal([]model.K8sPod{
			{Name: "web-5d8f-abcde", Node: "node1", Phase: "Running", Ready: 1, Total: 1, Restarts: 2, Containers: []string{"nginx"}},
			{Name: "web-5d8f-fghij", Node: "node2", Phase: "Pending", Reason: "ImagePullBackOff", Total: 1, Containers: []string{"nginx"}},
		})
	case model.PollK8sLogs:
		var r model.K8sLogsRequest
		json.Unmarshal(config, &r)
		return json.Marshal(model.K8sLogs{Pod: r.Pod, Container: "nginx", Text: "2026-11-03T06:00:00Z GET / 200\n"})
	}
	return nil, errors.New("unknown poll")
}

func k8sManagedFixture() model.K8s {
	k := k8sFixture()
	k.Workloads[0].Containers = []model.K8sContainer{{Name: "nginx", Image: "nginx:1.27"}, {Name: "migrate", Image: "busybox:1.37", Init: true}}
	k.Workloads[1].Containers = []model.K8sContainer{{Name: "restic", Image: "restic/restic:0.18"}}
	k.DenyNamespaces = []string{"kube-system"}
	return k
}

const webManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop
  labels:
    app: shop
spec:
  selector:
    matchLabels: {app: shop}
  template:
    metadata:
      labels: {app: shop}
    spec:
      containers:
        - name: shop
          image: ghcr.io/example/shop:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: shop
spec:
  selector: {app: shop}
  ports: [{port: 80}]
`

func TestKubernetesActions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	fake := &fakeCluster{}
	h.srv.SetAgentPolls(fake)
	k8s, _ := h.st.CreateHostGroup(ctx, store.System, "k8s", "")
	agent := h.addHost("baseline-agent-7d9f", k8s.ID)
	h.connect(agent, []string{model.CapK8sCluster, action.CapK8sActions, action.CapK8sPods, action.CapK8sLogs},
		&action.Policy{Jobs: true, AllowActions: []string{action.CategoryKubernetes}})
	h.ingest(agent, model.SectionK8s, k8sManagedFixture())
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "k8s-ops", Role: rbac.Operator, ScopeGroupID: k8s.ID})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "approvers", Role: rbac.Approver})
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	ops := h.signIn("carl", "k8s-ops", "approvers")
	viewer := h.signIn("vera", "viewers")

	cl, err := h.st.ClusterOfAgent(ctx, agent.HostID)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	objs, _ := h.st.ClusterObjects(ctx, cl.CIID)
	for _, o := range objs {
		ids[o.Name] = o.CIID
	}
	wpath := "/kubernetes/" + cl.CIID + "/workloads/"

	// The workload page: its actions, its containers, and its pods read
	// live, with logs and delete for operators only.
	_, body := h.do(ops, "GET", wpath+ids["web"], nil)
	for _, want := range []string{"Restart…", "Scale…", "Change image…", "web-5d8f-abcde", "ImagePullBackOff",
		"logs?pod=web-5d8f-abcde&amp;container=nginx", "action=k8s.delete_pod&amp;workload=" + ids["web"] + "&amp;pod=web-5d8f-fghij",
		"busybox:1.37"} {
		if !strings.Contains(body, want) {
			t.Fatalf("workload page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Suspend…") {
		t.Fatal("a Deployment offers CronJob actions")
	}
	if _, body := h.do(viewer, "GET", wpath+ids["web"], nil); strings.Contains(body, "Restart…") || strings.Contains(body, "logs?pod") ||
		!strings.Contains(body, "web-5d8f-abcde") {
		t.Fatalf("viewer's workload page:\n%s", body)
	}
	if _, body := h.do(ops, "GET", wpath+ids["svclb"], nil); !strings.Contains(body, "off limits") {
		t.Fatalf("kube-system workload page:\n%s", body)
	}
	if resp, _ := h.do(ops, "GET", "/kubernetes/"+ids["web"]+"/workloads/"+ids["web"], nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("workload under the wrong cluster: %d", resp.StatusCode)
	}
	// The cluster's workloads link to their pages.
	if _, body := h.do(ops, "GET", "/kubernetes/"+cl.CIID+"?tab=workloads", nil); !strings.Contains(body, wpath+ids["web"]) {
		t.Fatalf("cluster workloads:\n%s", body)
	}

	// Logs: operators only, audited.
	if resp, _ := h.do(viewer, "GET", wpath+ids["web"]+"/logs?pod=web-5d8f-abcde", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer read logs: %d", resp.StatusCode)
	}
	if _, body := h.do(ops, "GET", wpath+ids["web"]+"/logs?pod=web-5d8f-abcde&container=nginx&tail=50", nil); !strings.Contains(body, "GET / 200") {
		t.Fatalf("logs page:\n%s", body)
	}
	if !strings.Contains(h.auditActions(), "k8s.logs_view") {
		t.Fatal("reading logs wasn't audited")
	}
	if last := fake.polls[len(fake.polls)-2]; !strings.Contains(last, `"pod":"web-5d8f-abcde"`) || !strings.Contains(last, `"tail":50`) ||
		!strings.Contains(last, `"kind":"Deployment"`) {
		t.Fatalf("logs poll %s", last)
	}

	// Restart from the form: a step on the cluster agent, sent as a job.
	_, body = h.do(ops, "GET", "/changes/new?action=k8s.restart&workload="+ids["web"], nil)
	if !strings.Contains(body, `value="`+ids["web"]+`" id="pick-`+ids["web"]+`" aria-label="default/web in homelab" checked`) ||
		!strings.Contains(body, "off limits") || strings.Contains(body, ">backup<") {
		t.Fatalf("restart form:\n%s", body)
	}
	resp, body := h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.restart"}, "workload": {ids["web"]},
		"health_timeout": {"60"}, "submit": {"approve"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("restart: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, _ := h.st.GetChange(ctx, h.changeOrJob(resp))
	if c.Title != "Restart Deployment default/web on homelab" || len(c.Plan) != 1 ||
		!strings.Contains(string(c.Plan[0].Params), `"health_timeout": 60`) {
		t.Fatalf("restart change %q %s", c.Title, c.Plan[0].Params)
	}
	d.Pass(ctx)
	if got := h.sentRunJobs(); len(got) != 1 || got[0] != action.K8sRestart {
		t.Fatalf("sent %v", got)
	}

	// Namespaces the agent leaves alone are refused.
	resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.restart"}, "workload": {ids["svclb"]}, "submit": {"approve"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "off limits") {
		t.Fatalf("restart in kube-system: %d", resp.StatusCode)
	}

	// Change an image: pick the workload first, then its containers.
	if _, body := h.do(ops, "GET", "/changes/new?action=k8s.set_image", nil); !strings.Contains(body, `type="radio" name="workload"`) {
		t.Fatalf("set_image chooser:\n%s", body)
	}
	_, body = h.do(ops, "GET", "/changes/new?action=k8s.set_image&workload="+ids["web"], nil)
	if !strings.Contains(body, `name="image.nginx" value="nginx:1.27"`) || !strings.Contains(body, `name="image.migrate"`) {
		t.Fatalf("set_image form:\n%s", body)
	}
	resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.set_image"}, "workload": {ids["web"]},
		"image.nginx": {"nginx:1.28"}, "image.migrate": {"busybox:1.37"}, "submit": {"submit"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set_image: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	c, _ = h.st.GetChange(ctx, h.changeOrJob(resp))
	if c.Title != "Set the image of Deployment default/web: nginx=nginx:1.28 on homelab" {
		t.Fatalf("set_image change %q %s", c.Title, c.Plan[0].Params)
	}
	resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.set_image"}, "workload": {ids["web"]},
		"image.nginx": {"nginx:1.27"}, "submit": {"submit"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "at least one container") {
		t.Fatalf("set_image without a change: %d", resp.StatusCode)
	}

	// Delete a pod, picked from the live list.
	_, body = h.do(ops, "GET", "/changes/new?action=k8s.delete_pod&workload="+ids["web"]+"&pod=web-5d8f-fghij", nil)
	if !strings.Contains(body, `<option value="web-5d8f-fghij" selected>`) {
		t.Fatalf("delete_pod form:\n%s", body)
	}
	resp, _ = h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.delete_pod"}, "workload": {ids["web"]},
		"pod": {"web-5d8f-fghij"}, "submit": {"submit"}})
	c, _ = h.st.GetChange(ctx, h.changeOrJob(resp))
	if c.Title != "Delete pod default/web-5d8f-fghij of Deployment web on homelab" {
		t.Fatalf("delete_pod change %q", c.Title)
	}

	// CronJobs: the actions that apply to them, through the API.
	tok := h.mintToken(ops, "ci", "operator")
	var out changeDetailTest
	if resp := h.api(tok, "POST", "/changes", map[string]any{"action": "k8s.suspend", "workloads": []string{ids["backup"]}}, &out); resp.StatusCode != http.StatusCreated ||
		out.Title != "Suspend CronJob default/backup on homelab" {
		t.Fatalf("suspend through the API: %d %+v", resp.StatusCode, out)
	}
	var apiErr map[string]any
	if resp := h.api(tok, "POST", "/changes", map[string]any{"action": "k8s.scale", "workload": ids["backup"],
		"params": map[string]any{"replicas": 2}}, &apiErr); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("scaling a CronJob: %d %v", resp.StatusCode, apiErr)
	}
	if resp := h.api(tok, "POST", "/changes", map[string]any{"action": "k8s.scale", "workload": ids["web"],
		"params": map[string]any{"replicas": 3, "namespace": "x"}}, &apiErr); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("scale naming the namespace: %d %v", resp.StatusCode, apiErr)
	}
	if resp := h.api(tok, "POST", "/changes", map[string]any{"action": "k8s.scale", "workload": ids["web"],
		"params": map[string]any{"replicas": 3}}, &out); resp.StatusCode != http.StatusCreated ||
		out.Title != "Scale Deployment default/web to 3 on homelab" {
		t.Fatalf("scale through the API: %d %+v", resp.StatusCode, out)
	}
	var pods k8sPodsJSON
	if resp := h.api(tok, "GET", wpath+ids["web"]+"/pods", nil, &pods); resp.StatusCode != http.StatusOK || len(pods.Pods) != 2 {
		t.Fatalf("pods through the API: %d %+v", resp.StatusCode, pods)
	}

	// An agent that has them off isn't offered them.
	h.connect(agent, []string{model.CapK8sCluster, action.CapK8sActions, action.CapK8sPods},
		&action.Policy{Jobs: true, AllowActions: []string{}})
	if _, body := h.do(ops, "GET", wpath+ids["web"], nil); !strings.Contains(body, "Kubernetes actions are turned off") ||
		strings.Contains(body, "logs?pod") {
		t.Fatalf("workload page with actions off:\n%s", body)
	}
	resp, body = h.do(ops, "POST", "/changes", url.Values{"action": {"k8s.restart"}, "workload": {ids["web"]}, "submit": {"approve"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "BASELINE_ALLOW_ACTIONS") {
		t.Fatalf("restart with actions off: %d", resp.StatusCode)
	}
	// Host actions never go to a cluster agent.
	h.connect(agent, []string{model.CapK8sCluster, action.CapK8sActions, action.CapK8sPods}, &action.Policy{Jobs: true, AllowScripts: true})
	if _, body := h.do(ops, "GET", "/changes/new?action=host.reboot", nil); !strings.Contains(body, "runs only Kubernetes actions") {
		t.Fatalf("reboot form:\n%s", body)
	}
}

func TestKubernetesManifests(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.dispatcher()
	agent := h.addHost("baseline-agent-7d9f")
	h.connect(agent, []string{model.CapK8sCluster, action.CapK8sActions, action.CapK8sPods},
		&action.Policy{Jobs: true, AllowActions: []string{action.CategoryKubernetes}})
	h.ingest(agent, model.SectionK8s, k8sManagedFixture())
	admin := h.signIn("ann", "lab-admins")
	cl, _ := h.st.ClusterOfAgent(ctx, agent.HostID)
	cpath := "/kubernetes/" + cl.CIID

	_, body := h.do(admin, "GET", cpath+"?tab=manifests", nil)
	if !strings.Contains(body, "action=k8s.deploy&amp;cluster="+cl.CIID) || !strings.Contains(body, "hasn't applied any") {
		t.Fatalf("manifests tab:\n%s", body)
	}
	if _, body := h.do(admin, "GET", "/changes/new?action=k8s.deploy&cluster="+cl.CIID, nil); !strings.Contains(body, `name="manifest"`) ||
		!strings.Contains(body, "<option>default</option>") || strings.Contains(body, "<option>kube-system</option>") {
		t.Fatalf("deploy form:\n%s", body)
	}
	if _, body := h.do(admin, "GET", "/changes/new", nil); strings.Contains(body, "k8s.deploy") {
		t.Fatal("the general form offers manifest deploys")
	}

	form := url.Values{"action": {"k8s.deploy"}, "cluster": {cl.CIID}, "bundle": {"shop"}, "namespace": {"default"},
		"posted": {"1"}, "submit": {"approve"}}
	for _, tc := range []struct{ manifest, err string }{
		{"apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\n", "doesn&#39;t apply Secrets"},
		{"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: x\n", "doesn&#39;t apply"},
		{"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  namespace: kube-system\n", "off limits"},
		{"", "empty"},
	} {
		form.Set("manifest", tc.manifest)
		if resp, body := h.do(admin, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, tc.err) {
			t.Fatalf("manifest %q: %d %s", tc.manifest, resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
		}
	}
	form.Set("manifest", strings.ReplaceAll(webManifest, "\n", "\r\n"))
	resp, body := h.do(admin, "POST", "/changes", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", resp.StatusCode, regexp.MustCompile(`notice bad">[^<]*`).FindString(body))
	}
	cid := h.changeOrJob(resp)
	ms, err := h.st.ChangeManifests(ctx, cid)
	if err != nil || len(ms) != 1 || ms[0].Manifest != webManifest || strings.Join(ms[0].Objects, ",") != "Deployment default/shop,Service default/shop" {
		t.Fatalf("manifests %+v %v", ms, err)
	}
	c, _ := h.st.GetChange(ctx, cid)
	if c.Title != "Deploy manifest shop (namespace default) on homelab" {
		t.Fatalf("deploy change %q", c.Title)
	}
	if _, body := h.do(admin, "GET", "/changes/"+cid, nil); !strings.Contains(body, "New bundle shop") || !strings.Contains(body, "ghcr.io/example/shop:1.0") {
		t.Fatalf("change page:\n%s", body)
	}

	// The job carries the manifest; the bundle can't be deployed twice.
	d.Pass(ctx)
	sent := func(act string) (string, string) {
		h.hub.mu.Lock()
		defer h.hub.mu.Unlock()
		for _, m := range h.hub.messages {
			if j := m.GetRunJob(); j != nil && j.GetAction() == act {
				return string(j.GetStackFiles().GetCompose()), string(j.GetStackFiles().GetEnv())
			}
		}
		return "", ""
	}
	if m, base := sent(action.K8sDeploy); m != webManifest || base != "" {
		t.Fatalf("sent %q %q", m, base)
	}
	if resp, body := h.do(admin, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "changes bundle shop already") {
		t.Fatalf("second deploy while the first runs: %d", resp.StatusCode)
	}
	jobs, _ := h.st.ListJobs(ctx, store.JobFilter{ChangeID: cid})
	code := 0
	if _, err := h.st.FinishJob(ctx, store.System, agent.HostID, jobs[0].ID, store.JobResult{State: store.JobSucceeded, ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	if resp, body := h.do(admin, "POST", "/changes", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "deployed already") {
		t.Fatalf("second deploy: %d", resp.StatusCode)
	}

	// Edit starts from the applied manifest and sends it along.
	_, body = h.do(admin, "GET", cpath+"?tab=manifests", nil)
	if !strings.Contains(body, "Deployment default/shop") || !strings.Contains(body, "action=k8s.edit&amp;cluster="+cl.CIID+"&amp;bundle=shop") {
		t.Fatalf("manifests tab after the deploy:\n%s", body)
	}
	if _, body := h.do(admin, "GET", "/changes/new?action=k8s.edit&cluster="+cl.CIID+"&bundle=shop", nil); !strings.Contains(body, "ghcr.io/example/shop:1.0") {
		t.Fatalf("edit form:\n%s", body)
	}
	edit := url.Values{"action": {"k8s.edit"}, "cluster": {cl.CIID}, "bundle": {"shop"}, "posted": {"1"}, "manifest": {webManifest},
		"submit": {"approve"}}
	if resp, body := h.do(admin, "POST", "/changes", edit); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "unchanged") {
		t.Fatalf("unchanged edit: %d", resp.StatusCode)
	}
	edited := strings.Replace(webManifest, "shop:1.0", "shop:1.1", 1)
	tok := h.mintToken(admin, "ci", "operator")
	var out changeDetailTest
	if resp := h.api(tok, "POST", "/changes", map[string]any{"action": "k8s.edit",
		"params": map[string]any{"cluster": cl.CIID, "bundle": "shop", "manifest": edited}}, &out); resp.StatusCode != http.StatusCreated {
		t.Fatalf("edit through the API: %d %+v", resp.StatusCode, out)
	}
	if !strings.Contains(strings.ReplaceAll(string(out.Plan[0].Params), " ", ""), `"base_revision":"`+ms[0].ID+`"`) {
		t.Fatalf("edit params %s", out.Plan[0].Params)
	}
	if len(out.Manifests) != 1 || out.Manifests[0].BaseRevision != ms[0].ID || out.Manifests[0].Manifest != edited {
		t.Fatalf("edit revisions %+v", out.Manifests)
	}
	if err := h.st.ApproveChange(ctx, store.UserActor(mustUser(t, h, "ann"), ""), out.ID, ""); err != nil {
		t.Fatal(err)
	}
	d.Pass(ctx)
	if m, base := sent(action.K8sEdit); m != edited || base != webManifest {
		t.Fatalf("sent edit %q %q", m, base)
	}
	var bundles []k8sBundleJSON
	if resp := h.api(tok, "GET", cpath+"/manifests", nil, &bundles); resp.StatusCode != http.StatusOK || len(bundles) != 1 ||
		!bundles[0].Pending || bundles[0].Manifest != webManifest {
		t.Fatalf("bundles %d %+v", resp.StatusCode, bundles)
	}
}

// changeDetailTest is the part of a change's API detail these tests read.
type changeDetailTest struct {
	ID        string                 `json:"id"`
	Title     string                 `json:"title"`
	Plan      []store.PlanStep       `json:"plan"`
	Manifests []manifestRevisionJSON `json:"manifests"`
}

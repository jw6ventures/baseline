package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/k8smanifest"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Kubernetes workload management (docs/change-management.md §5.2): changes
// that act on the workloads a cluster agent reports (k8s.restart, k8s.scale,
// k8s.set_image, k8s.delete_pod and the CronJob actions), changes that apply
// manifests (k8s.deploy, k8s.edit), and a workload's page with its live pods
// and their logs, which the cluster agent reads when asked.

// AgentPoller asks a connected agent to read something for the server
// (internal/gateway).
type AgentPoller interface {
	PollIntegration(ctx context.Context, hostID, kind, capability string, config []byte, secret string, timeout time.Duration) ([]byte, error)
}

// SetAgentPolls lets the server read pods and logs through cluster agents.
func (s *Server) SetAgentPolls(p AgentPoller) { s.polls = p }

// k8sPollTimeout bounds a pods or logs read.
const k8sPollTimeout = 20 * time.Second

// pollCluster has a cluster agent answer a poll and decodes the answer.
func (s *Server) pollCluster(ctx context.Context, hostID, kind, capability string, req, into any) error {
	if s.polls == nil {
		return errors.New("the server can't reach agents")
	}
	cfg, err := json.Marshal(req)
	if err != nil {
		return err
	}
	out, err := s.polls.PollIntegration(ctx, hostID, kind, capability, cfg, "", k8sPollTimeout)
	if err != nil {
		return err
	}
	return json.Unmarshal(out, into)
}

// denyNamespaces are the namespaces a cluster agent's actions may not
// touch, from its latest section.
func (s *Server) denyNamespaces(r *http.Request, hostID string) []string {
	var k struct {
		DenyNamespaces []string `json:"deny_namespaces"`
	}
	s.section(r, hostID, model.SectionK8s, &k)
	return k.DenyNamespaces
}

// k8sVerb is what a workload action does, for messages.
func k8sVerb(act string) string {
	switch act {
	case action.K8sRestart:
		return "restart"
	case action.K8sScale:
		return "scale"
	case action.K8sSetImage:
		return "change the image of"
	case action.K8sDeletePod:
		return "delete a pod of"
	case action.K8sSuspend:
		return "suspend"
	case action.K8sResume:
		return "resume"
	case action.K8sTrigger:
		return "run"
	}
	return act
}

// workloadBlock says why a workload action can't act on the workload, or "".
func workloadBlock(spec action.Spec, w store.Workload, h store.Host, deny []string) string {
	switch {
	case !action.AppliesTo(spec.Name, w.Kind):
		return "Baseline can't " + k8sVerb(spec.Name) + " a " + w.Kind
	case !w.Present:
		return "it is gone from the cluster"
	case slices.Contains(deny, w.Namespace):
		return "namespace " + w.Namespace + " is off limits to the cluster agent (BASELINE_DENY_NAMESPACES)"
	case h.Revoked:
		return h.DisplayName() + " is revoked"
	case spec.Name == action.K8sSuspend && w.Workload.Suspend:
		return "it is suspended already"
	case spec.Name == action.K8sResume && !w.Workload.Suspend:
		return "it isn't suspended"
	}
	if ok, why := h.Policy.Allows(spec.Name); !ok {
		return why
	}
	if ok, why := spec.Supported(h.Capabilities); !ok {
		return "the cluster agent can't do this: it " + why + " (update it)"
	}
	return ""
}

// workloadChoice is a workload offered on the new-change form.
type workloadChoice struct {
	store.Workload
	Checked  bool
	Disabled string
}

// workloadChoices lists the workloads the action applies to in clusters
// whose agents the user may change.
func (s *Server) workloadChoices(r *http.Request, spec action.Spec, f url.Values, hosts map[string]store.Host,
	ids []string) ([]workloadChoice, error) {
	ws, err := s.store.ListWorkloads(r.Context(), ids)
	if err != nil {
		return nil, err
	}
	deny := map[string][]string{}
	var out []workloadChoice
	for _, w := range ws {
		if !action.AppliesTo(spec.Name, w.Kind) {
			continue
		}
		if _, ok := deny[w.HostID]; !ok {
			deny[w.HostID] = s.denyNamespaces(r, w.HostID)
		}
		out = append(out, workloadChoice{Workload: w, Checked: slices.Contains(f["workload"], w.CIID),
			Disabled: workloadBlock(spec, w, hosts[w.HostID], deny[w.HostID])})
	}
	return out, nil
}

// singleWorkload: these actions need what one workload has (its containers,
// its pods), so a change acts on one.
func singleWorkload(name string) bool {
	return name == action.K8sSetImage || name == action.K8sDeletePod
}

// k8sInput is a workload action's parameters beside the workload: the same
// for every workload of the change.
type k8sInput struct {
	Pod           string            `json:"pod"`
	Replicas      *int              `json:"replicas"`
	Images        map[string]string `json:"images"`
	HealthTimeout int               `json:"health_timeout"`
}

// formK8sInput reads a workload action's parameters from the form; w is the
// workload of a single-workload action, whose containers' image fields it
// reads.
func formK8sInput(f url.Values, w *store.Workload) k8sInput {
	var in k8sInput
	in.Pod = strings.TrimSpace(f.Get("pod"))
	if v := strings.TrimSpace(f.Get("replicas")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			in.Replicas = &n
		} else {
			n = -1
			in.Replicas = &n
		}
	}
	in.HealthTimeout, _ = strconv.Atoi(f.Get("health_timeout"))
	if w != nil {
		for _, c := range w.Workload.Containers {
			if v := strings.TrimSpace(f.Get("image." + c.Name)); v != "" && v != c.Image {
				if in.Images == nil {
					in.Images = map[string]string{}
				}
				in.Images[c.Name] = v
			}
		}
	}
	return in
}

// loadWorkloads reads the workloads a change names and checks that each can
// take the action.
func (s *Server) loadWorkloads(r *http.Request, spec action.Spec, ids []string, hosts map[string]store.Host) ([]store.Workload, error) {
	var out []store.Workload
	deny := map[string][]string{}
	for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
		w, err := s.store.GetWorkload(r.Context(), id)
		if err != nil {
			return nil, fmt.Errorf("no such Kubernetes workload: %s", id)
		}
		if _, ok := deny[w.HostID]; !ok {
			deny[w.HostID] = s.denyNamespaces(r, w.HostID)
		}
		if why := workloadBlock(spec, w, hosts[w.HostID], deny[w.HostID]); why != "" {
			return nil, fmt.Errorf("Baseline can't %s %s in %s: %s", k8sVerb(spec.Name), w.Ref(), w.Cluster, why)
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, errors.New("pick at least one workload")
	}
	if singleWorkload(spec.Name) && len(out) != 1 {
		return nil, fmt.Errorf("%s changes one workload", spec.Name)
	}
	return out, nil
}

// workloadSteps are a change's steps: one per workload, on its cluster
// agent.
func workloadSteps(spec action.Spec, ws []store.Workload, in k8sInput) (steps []store.PlanStep, cis, objects []string, err error) {
	for _, w := range ws {
		p := action.K8sParams{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, Pod: in.Pod, Replicas: in.Replicas,
			Images: in.Images, HealthTimeout: in.HealthTimeout}
		if spec.Name == action.K8sDeletePod && w.Kind == action.KindPod && p.Pod == "" {
			p.Pod = w.Name
		}
		raw, _ := json.Marshal(p)
		norm, err := action.Validate(spec.Name, raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", w.Ref(), err)
		}
		steps = append(steps, store.PlanStep{Action: spec.Name, Params: norm, Summary: action.Describe(spec.Name, norm),
			HostIDs: []string{w.HostID}})
		cis, objects = append(cis, w.CIID), append(objects, w.Namespace+"/"+w.Name)
	}
	return steps, cis, objects, nil
}

// Manifests ---------------------------------------------------------------------

// manifestInput is a k8s.deploy or k8s.edit request.
type manifestInput struct {
	Cluster   string // the cluster CI
	Bundle    string
	Namespace string // k8s.deploy; an edit keeps its bundle's
	Manifest  string
	// HealthTimeout is how long, in seconds, the workloads get to roll out.
	HealthTimeout int
}

// formManifest reads the manifest part of the new-change form.
func formManifest(f url.Values) manifestInput {
	ht, _ := strconv.Atoi(f.Get("health_timeout"))
	return manifestInput{Cluster: f.Get("cluster"), Bundle: strings.TrimSpace(f.Get("bundle")),
		Namespace: strings.TrimSpace(f.Get("namespace")), Manifest: f.Get("manifest"), HealthTimeout: ht}
}

// manifestForm is the k8s.deploy or k8s.edit part of the new-change form.
type manifestForm struct {
	Cluster store.Cluster
	Block   string // why the change can't be made, or ""
	// Namespaces the cluster has, to pick from.
	Namespaces []string
	Deny       []string
	// Base (k8s.edit) is the revision applied last, which the edit starts
	// from and replaces.
	Base  *store.Manifest
	Kinds string
}

// manifestClusterBlock says why a cluster's agent can't take k8s.deploy or
// k8s.edit, or "".
func manifestClusterBlock(spec action.Spec, h store.Host) string {
	if h.Revoked {
		return h.DisplayName() + " is revoked"
	}
	if ok, why := h.Policy.Allows(spec.Name); !ok {
		return why
	}
	if ok, why := spec.Supported(h.Capabilities); !ok {
		return "the cluster agent can't do this: it " + why + " (update it)"
	}
	return ""
}

// manifestFormView fills in the form's k8s.deploy or k8s.edit part. On the
// first look at an edit, the manifest starts from the bundle's current one.
func (s *Server) manifestFormView(r *http.Request, spec action.Spec, mine map[string]store.Host) (*manifestForm, error) {
	ctx := r.Context()
	f := r.Form
	v := &manifestForm{Kinds: k8smanifest.Kinds()}
	c, err := s.store.GetCluster(ctx, f.Get("cluster"))
	if errors.Is(err, store.ErrNotFound) {
		v.Block = "Pick a cluster: open its page and use Deploy a manifest"
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	v.Cluster = c
	h, ok := mine[c.HostID]
	if !ok {
		v.Block = "Changing " + c.Name + " needs the operator role on its cluster agent"
		return v, nil
	}
	if v.Block = manifestClusterBlock(spec, h); v.Block != "" {
		return v, nil
	}
	var k model.K8s
	if _, err := s.section(r, c.HostID, model.SectionK8s, &k); err == nil {
		v.Namespaces, v.Deny = k.Namespaces, k.DenyNamespaces
	}
	if spec.Name == action.K8sEdit {
		base, err := s.store.CurrentManifest(ctx, c.CIID, f.Get("bundle"))
		if errors.Is(err, store.ErrNotFound) {
			v.Block = "Baseline hasn't applied a bundle " + f.Get("bundle") + " to " + c.Name
			return v, nil
		}
		if err != nil {
			return nil, err
		}
		v.Base = &base
		if f.Get("posted") == "" {
			f.Set("manifest", base.Manifest)
		}
	}
	return v, nil
}

// manifestPlan checks a k8s.deploy or k8s.edit and builds its step and
// revision.
func (s *Server) manifestPlan(r *http.Request, spec action.Spec, in manifestInput, hosts map[string]store.Host) (
	store.PlanStep, store.Manifest, string, error) {
	ctx := r.Context()
	var step store.PlanStep
	var rev store.Manifest
	c, err := s.store.GetCluster(ctx, in.Cluster)
	if err != nil {
		return step, rev, "", errors.New("no such cluster")
	}
	h, ok := hosts[c.HostID]
	if !ok || !principal(r).Grants.HasOn(rbac.Operator, h.GroupIDs) {
		return step, rev, "", errors.New("changing a cluster needs the operator role on its cluster agent")
	}
	if why := manifestClusterBlock(spec, h); why != "" {
		return step, rev, "", errors.New(why)
	}
	if !action.ValidProject(in.Bundle) {
		return step, rev, "", errors.New("name the bundle with lowercase letters, digits, -, _ and .")
	}
	revs, err := s.store.BundleRevisions(ctx, c.CIID, in.Bundle, 50)
	if err != nil {
		return step, rev, "", err
	}
	for _, m := range revs {
		if openChange(m.ChangeState) {
			return step, rev, "", fmt.Errorf("%s changes bundle %s already; wait for it to end, or cancel it", m.ChangeRef(), in.Bundle)
		}
	}
	p := action.K8sManifestParams{Bundle: in.Bundle, HealthTimeout: in.HealthTimeout}
	if spec.Name == action.K8sDeploy {
		for _, m := range revs {
			if m.Applied() {
				return step, rev, "", fmt.Errorf("bundle %s is deployed already; edit it instead", in.Bundle)
			}
		}
		p.Namespace = in.Namespace
	} else {
		base, err := s.store.CurrentManifest(ctx, c.CIID, in.Bundle)
		if errors.Is(err, store.ErrNotFound) {
			return step, rev, "", fmt.Errorf("Baseline hasn't applied a bundle %s to %s", in.Bundle, c.Name)
		}
		if err != nil {
			return step, rev, "", err
		}
		if in.Namespace != "" && in.Namespace != base.Namespace {
			return step, rev, "", errors.New("an edit keeps its bundle's namespace")
		}
		p.Namespace, p.BaseRevision, p.BaseSHA256 = base.Namespace, base.ID, base.ManifestSHA256
		rev.BaseRevision = base.ID
	}
	text := strings.ReplaceAll(in.Manifest, "\r\n", "\n")
	if strings.TrimSpace(text) == "" {
		return step, rev, "", errors.New("the manifest is empty")
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	objs, err := k8smanifest.Parse([]byte(text), p.Namespace)
	if err != nil {
		return step, rev, "", fmt.Errorf("the manifest: %w", err)
	}
	deny := s.denyNamespaces(r, c.HostID)
	for _, o := range objs {
		if slices.Contains(deny, o.Namespace) {
			return step, rev, "", fmt.Errorf("%s: namespace %s is off limits to the cluster agent", o.Key(), o.Namespace)
		}
		rev.Objects = append(rev.Objects, o.Key())
	}
	sum := sha256.Sum256([]byte(text))
	p.ManifestSHA256 = hex.EncodeToString(sum[:])
	if p.ManifestSHA256 == p.BaseSHA256 {
		return step, rev, "", errors.New("the manifest is unchanged")
	}
	rev.ID = store.NewID()
	p.Revision = rev.ID
	raw, _ := json.Marshal(p)
	norm, err := action.Validate(spec.Name, raw)
	if err != nil {
		return step, rev, "", err
	}
	rev.ClusterCI, rev.HostID, rev.Bundle, rev.Namespace, rev.Action = c.CIID, c.HostID, in.Bundle, p.Namespace, spec.Name
	rev.Manifest, rev.ManifestSHA256 = text, p.ManifestSHA256
	step = store.PlanStep{Action: spec.Name, Params: norm, Summary: action.Describe(spec.Name, norm), HostIDs: []string{c.HostID}}
	return step, rev, c.CIID, nil
}

func openChange(state string) bool {
	switch state {
	case store.ChangeDraft, store.ChangeSubmitted, store.ChangeApproved, store.ChangeScheduled, store.ChangeInProgress:
		return true
	}
	return false
}

// Workload page -------------------------------------------------------------------

type workloadView struct {
	W       store.Workload
	Cluster store.Cluster
	// CanChange: the user is an operator on the cluster agent.
	CanChange bool
	// Actions are the workload actions offered, with why each can't run.
	Actions []workloadAction
	Deny    bool // its namespace is off limits to the agent's actions
	// ActionsOff: the cluster agent's BASELINE_ALLOW_ACTIONS leaves them
	// off; AgentOld: it is too old to run them.
	ActionsOff, AgentOld bool
	// Pods are read from the cluster when the page is shown; PodsError says
	// why they couldn't be.
	Pods      []model.K8sPod
	PodsError string
	CanLogs   bool // the agent reads logs, and the user is an operator
	DeletePod string
	Bundle    string // the Baseline bundle that deployed it, if any
	Notice    string
}

type workloadAction struct {
	Spec     action.Spec
	Disabled string
}

// loadWorkload reads the workload in the path, if the user may see its
// cluster.
func (s *Server) loadWorkload(w http.ResponseWriter, r *http.Request, need rbac.Role) (store.Workload, store.Host, bool) {
	wl, err := s.store.GetWorkload(r.Context(), r.PathValue("wid"))
	if err == nil && wl.ClusterCI != r.PathValue("id") {
		err = store.ErrNotFound
	}
	var h store.Host
	if err == nil {
		h, err = s.store.GetHost(r.Context(), wl.HostID)
	}
	if errors.Is(err, store.ErrNotFound) || (err == nil && !principal(r).Grants.HasOn(rbac.Viewer, h.GroupIDs)) {
		s.errorPage(w, r, http.StatusNotFound, "No such workload.")
		return wl, h, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return wl, h, false
	}
	if !principal(r).Grants.HasOn(need, h.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "This needs the "+string(need)+" role on the cluster agent.")
		return wl, h, false
	}
	return wl, h, true
}

func (s *Server) workloadPage(w http.ResponseWriter, r *http.Request) {
	wl, h, ok := s.loadWorkload(w, r, rbac.Viewer)
	if !ok {
		return
	}
	ctx := r.Context()
	c, err := s.store.GetCluster(ctx, wl.ClusterCI)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	g := principal(r).Grants
	v := workloadView{W: wl, Cluster: c, CanChange: g.HasOn(rbac.Operator, h.GroupIDs) && !h.Revoked,
		Notice: r.URL.Query().Get("notice")}
	deny := s.denyNamespaces(r, wl.HostID)
	v.Deny = slices.Contains(deny, wl.Namespace)
	for _, n := range action.Names {
		if !action.IsK8sWorkloadAction(n) || !action.AppliesTo(n, wl.Kind) {
			continue
		}
		spec := action.MustGet(n)
		v.Actions = append(v.Actions, workloadAction{Spec: spec, Disabled: workloadBlock(spec, wl, h, deny)})
	}
	v.CanLogs = v.CanChange && slices.Contains(h.Capabilities, action.CapK8sLogs)
	v.AgentOld = !slices.Contains(h.Capabilities, action.CapK8sActions)
	v.ActionsOff, _ = h.Policy.Allows(action.K8sRestart)
	v.ActionsOff = !v.ActionsOff
	switch {
	case !wl.Present:
		v.PodsError = "The workload is gone from the cluster."
	case !h.Connected:
		v.PodsError = "The cluster agent is offline, so its pods can't be listed."
	case !slices.Contains(h.Capabilities, action.CapK8sPods):
		v.PodsError = "The cluster agent is too old to list pods; update its image."
	default:
		req := model.K8sPodsRequest{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name}
		if err := s.pollCluster(ctx, wl.HostID, model.PollK8sPods, action.CapK8sPods, req, &v.Pods); err != nil {
			v.PodsError = "Couldn't list its pods: " + err.Error()
		}
	}
	if spec := action.MustGet(action.K8sDeletePod); v.CanChange {
		v.DeletePod = workloadBlock(spec, wl, h, deny)
	}
	s.pages.render(w, http.StatusOK, "workload", s.data(r, wl.Namespace+"/"+wl.Name, v))
}

type logsView struct {
	W         store.Workload
	Cluster   store.Cluster
	Pod       model.K8sPod
	Container string
	Tail      int
	Previous  bool
	Logs      *model.K8sLogs
	Error     string
}

// workloadLogs shows the end of a pod's log. Logs may hold anything the
// application prints, so reading them needs the operator role on the
// cluster agent, and each read is audited.
func (s *Server) workloadLogs(w http.ResponseWriter, r *http.Request) {
	wl, h, ok := s.loadWorkload(w, r, rbac.Operator)
	if !ok {
		return
	}
	ctx := r.Context()
	c, err := s.store.GetCluster(ctx, wl.ClusterCI)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	v := logsView{W: wl, Cluster: c, Container: q.Get("container"), Previous: q.Get("previous") != ""}
	v.Tail, _ = strconv.Atoi(q.Get("tail"))
	if v.Tail <= 0 {
		v.Tail = model.DefaultLogLines
	}
	v.Tail = min(v.Tail, model.MaxLogLines)
	v.Pod.Name = q.Get("pod")
	logs, err := s.readLogs(r, wl, h, model.K8sLogsRequest{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name,
		Pod: v.Pod.Name, Container: v.Container, Tail: v.Tail, Previous: v.Previous}, "page")
	if err != nil {
		v.Error = err.Error()
	} else {
		v.Logs = &logs
		v.Container = logs.Container
	}
	// The pod's containers, to switch between.
	var pods []model.K8sPod
	if s.pollCluster(ctx, wl.HostID, model.PollK8sPods, action.CapK8sPods,
		model.K8sPodsRequest{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name}, &pods) == nil {
		for _, p := range pods {
			if p.Name == v.Pod.Name {
				v.Pod = p
			}
		}
	}
	s.pages.render(w, http.StatusOK, "workload_logs", s.data(r, v.Pod.Name+" logs", v))
}

// readLogs has the cluster agent read a pod's log, and audits the read.
func (s *Server) readLogs(r *http.Request, wl store.Workload, h store.Host, req model.K8sLogsRequest, via string) (model.K8sLogs, error) {
	var out model.K8sLogs
	switch {
	case !h.Connected:
		return out, errors.New("the cluster agent is offline")
	case !slices.Contains(h.Capabilities, action.CapK8sLogs):
		return out, errors.New("the cluster agent doesn't read logs: set BASELINE_K8S_LOGS=on on it, and grant it pods/log")
	case !action.ValidK8sName(req.Pod):
		return out, errors.New("pick a pod")
	}
	if err := s.store.Audit(r.Context(), s.actor(r), store.AuditEvent{Action: "k8s.logs_view", ObjectType: "ci", ObjectID: wl.CIID,
		Details: map[string]any{"cluster": wl.Cluster, "workload": wl.Ref(), "pod": req.Pod, "container": req.Container,
			"previous": req.Previous, "via": via}}); err != nil {
		return out, err
	}
	err := s.pollCluster(r.Context(), wl.HostID, model.PollK8sLogs, action.CapK8sLogs, req, &out)
	return out, err
}

// API -----------------------------------------------------------------------------

// k8sWorkloadJSON is a workload with its live pods.
type k8sPodsJSON struct {
	Workload string         `json:"workload"`
	Pods     []model.K8sPod `json:"pods"`
}

func (s *Server) apiLoadWorkload(r *http.Request, need rbac.Role) (store.Workload, store.Host, error) {
	wl, err := s.store.GetWorkload(r.Context(), r.PathValue("wid"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && wl.ClusterCI != r.PathValue("id")) {
		return wl, store.Host{}, errAPINotFound
	}
	if err != nil {
		return wl, store.Host{}, err
	}
	h, err := s.apiLoadHost(r, wl.HostID, need)
	return wl, h, err
}

// apiWorkloadPods is GET /kubernetes/{id}/workloads/{wid}/pods: the
// workload's pods, read from the cluster now.
func (s *Server) apiWorkloadPods(w http.ResponseWriter, r *http.Request) {
	wl, h, err := s.apiLoadWorkload(r, rbac.Viewer)
	if err == nil && !h.Connected {
		err = failf(http.StatusServiceUnavailable, "the cluster agent is offline")
	}
	var pods []model.K8sPod
	if err == nil {
		err = s.pollCluster(r.Context(), wl.HostID, model.PollK8sPods, action.CapK8sPods,
			model.K8sPodsRequest{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name}, &pods)
		if err != nil && !errors.Is(err, errAPINotFound) {
			err = failf(http.StatusBadGateway, "%s", err)
		}
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, k8sPodsJSON{Workload: wl.CIID, Pods: pods})
}

// apiWorkloadLogs is GET /kubernetes/{id}/workloads/{wid}/logs?pod=&container=&tail=&previous=1.
func (s *Server) apiWorkloadLogs(w http.ResponseWriter, r *http.Request) {
	wl, h, err := s.apiLoadWorkload(r, rbac.Operator)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	q := r.URL.Query()
	tail, _ := strconv.Atoi(q.Get("tail"))
	logs, err := s.readLogs(r, wl, h, model.K8sLogsRequest{Kind: wl.Kind, Namespace: wl.Namespace, Name: wl.Name,
		Pod: q.Get("pod"), Container: q.Get("container"), Tail: tail, Previous: queryBool(r, "previous")}, "api")
	if err != nil {
		s.respond(w, r, nil, failf(http.StatusBadGateway, "%s", err))
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// k8sBundleJSON is a bundle in GET /kubernetes/{id}/manifests.
type k8sBundleJSON struct {
	Bundle    string   `json:"bundle"`
	Namespace string   `json:"namespace"`
	Revision  string   `json:"revision"` // the one applied last; "" when none was
	SHA256    string   `json:"sha256,omitempty"`
	Objects   []string `json:"objects"`
	Manifest  string   `json:"manifest,omitempty"`
	Pending   bool     `json:"pending"` // an open change edits it
	Change    string   `json:"change,omitempty"`
}

// apiClusterManifests is GET /kubernetes/{id}/manifests: the bundles
// Baseline applied to the cluster, with their current manifests.
func (s *Server) apiClusterManifests(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCluster(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err == nil {
		_, err = s.apiLoadHost(r, c.HostID, rbac.Viewer)
	}
	var bs []store.Bundle
	if err == nil {
		bs, err = s.store.ClusterBundles(r.Context(), c.CIID)
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out := []k8sBundleJSON{}
	for _, b := range bs {
		j := k8sBundleJSON{Bundle: b.Latest.Bundle, Namespace: b.Latest.Namespace, Pending: b.Pending, Objects: []string{}}
		if m := b.Current; m != nil {
			j.Revision, j.SHA256, j.Objects, j.Manifest, j.Change = m.ID, m.ManifestSHA256, m.Objects, m.Manifest, m.ChangeRef()
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

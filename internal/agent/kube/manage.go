package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/k8smanifest"
	"github.com/jw6ventures/baseline/internal/model"
)

// FieldManager is the name Baseline's changes carry in managedFields.
const FieldManager = "baseline"

// restartedAt is the annotation `kubectl rollout restart` sets on a pod
// template; setting it rolls the pods.
const restartedAt = "kubectl.kubernetes.io/restartedAt"

// Manager runs the Kubernetes actions (docs/agent.md §6.1) through the API,
// never in namespaces it is told to leave alone.
type Manager struct {
	Client *Client
	// DenyNamespaces are namespaces no action may touch.
	DenyNamespaces []string
	// PollEvery is how often a rollout is checked; 0 is every 2 seconds.
	PollEvery time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) pollEvery() time.Duration {
	if m.PollEvery > 0 {
		return m.PollEvery
	}
	return 2 * time.Second
}

// allowed refuses namespaces the agent may not touch.
func (m *Manager) allowed(ns string) error {
	if slices.Contains(m.DenyNamespaces, ns) {
		return fmt.Errorf("namespace %s is off limits to this cluster agent (BASELINE_DENY_NAMESPACES)", ns)
	}
	return nil
}

// workloadPath is where the API serves a workload.
func workloadPath(kind, ns, name string) (string, error) {
	var api, plural string
	switch kind {
	case action.KindDeployment:
		api, plural = "apps/v1", "deployments"
	case action.KindStatefulSet:
		api, plural = "apps/v1", "statefulsets"
	case action.KindDaemonSet:
		api, plural = "apps/v1", "daemonsets"
	case action.KindCronJob:
		api, plural = "batch/v1", "cronjobs"
	case action.KindPod:
		api, plural = "v1", "pods"
	default:
		return "", fmt.Errorf("unknown workload kind %q", kind)
	}
	return k8smanifest.CollectionPath(api, ns, plural) + "/" + name, nil
}

// Workload runs one of the workload actions (k8s.restart, k8s.scale,
// k8s.set_image, k8s.delete_pod, k8s.suspend, k8s.resume, k8s.trigger),
// writing what it does to out. A k8s.set_image whose rollout fails puts the
// previous images back and reports RolledBack.
func (m *Manager) Workload(ctx context.Context, name string, p action.K8sParams, out io.Writer) (action.K8sResult, error) {
	var res action.K8sResult
	if !action.AppliesTo(name, p.Kind) {
		return res, fmt.Errorf("%s doesn't apply to a %s", name, p.Kind)
	}
	if err := m.allowed(p.Namespace); err != nil {
		return res, err
	}
	path, err := workloadPath(p.Kind, p.Namespace, p.Name)
	if err != nil {
		return res, err
	}
	obj := p.Kind + " " + p.Namespace + "/" + p.Name
	timeout := time.Duration(p.HealthTimeout) * time.Second
	switch name {
	case action.K8sRestart:
		if err := m.Client.Get(ctx, path, &struct{}{}); err != nil {
			return res, err
		}
		ts := m.now().UTC().Format(time.RFC3339)
		body, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{restartedAt: ts}}}}})
		fmt.Fprintf(out, "Restarting %s (%s=%s)\n", obj, restartedAt, ts)
		if err := m.patch(ctx, path, MergePatch, body); err != nil {
			return res, err
		}
		res.Objects = []string{obj}
		return res, m.waitRollout(ctx, p.Kind, path, obj, timeout, out)
	case action.K8sScale:
		var cur struct {
			Spec struct {
				Replicas *int `json:"replicas"`
			} `json:"spec"`
		}
		if err := m.Client.Get(ctx, path, &cur); err != nil {
			return res, err
		}
		from := 1
		if cur.Spec.Replicas != nil {
			from = *cur.Spec.Replicas
		}
		fmt.Fprintf(out, "Scaling %s from %d to %d replicas\n", obj, from, *p.Replicas)
		body, _ := json.Marshal(map[string]any{"spec": map[string]any{"replicas": *p.Replicas}})
		if err := m.patch(ctx, path, MergePatch, body); err != nil {
			return res, err
		}
		res.Objects = []string{obj}
		return res, m.waitRollout(ctx, p.Kind, path, obj, timeout, out)
	case action.K8sSetImage:
		return m.setImage(ctx, p, path, obj, out)
	case action.K8sDeletePod:
		pod, err := m.ownedPod(ctx, p.Kind, p.Namespace, p.Name, p.Pod)
		if err != nil {
			return res, err
		}
		fmt.Fprintf(out, "Deleting pod %s/%s (on %s)\n", p.Namespace, p.Pod, orDash(pod.Spec.NodeName))
		podPath := k8smanifest.CollectionPath("v1", p.Namespace, "pods") + "/" + p.Pod
		// Preconditions: the pod checked above, not a new one of that name.
		body, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions",
			"preconditions": map[string]string{"uid": pod.Metadata.UID}})
		if err := m.Client.Do(ctx, http.MethodDelete, podPath, "application/json", body, nil); err != nil {
			return res, err
		}
		res.Objects = []string{"Pod " + p.Namespace + "/" + p.Pod}
		if p.Kind != action.KindPod {
			fmt.Fprintf(out, "%s replaces it.\n", obj)
		}
		return res, nil
	case action.K8sSuspend, action.K8sResume:
		suspend := name == action.K8sSuspend
		var cur struct {
			Spec struct {
				Suspend bool `json:"suspend"`
			} `json:"spec"`
		}
		if err := m.Client.Get(ctx, path, &cur); err != nil {
			return res, err
		}
		if cur.Spec.Suspend == suspend {
			fmt.Fprintf(out, "%s is %s already.\n", obj, map[bool]string{true: "suspended", false: "running on its schedule"}[suspend])
			return res, nil
		}
		body, _ := json.Marshal(map[string]any{"spec": map[string]any{"suspend": suspend}})
		if err := m.patch(ctx, path, MergePatch, body); err != nil {
			return res, err
		}
		fmt.Fprintf(out, "%s %s.\n", obj, map[bool]string{true: "suspended", false: "resumed"}[suspend])
		res.Objects = []string{obj}
		return res, nil
	case action.K8sTrigger:
		job, err := m.trigger(ctx, p, path)
		if err != nil {
			return res, err
		}
		fmt.Fprintf(out, "Created Job %s/%s from %s.\n", p.Namespace, job, obj)
		res.Objects, res.Job = []string{"Job " + p.Namespace + "/" + job}, job
		return res, nil
	}
	return res, fmt.Errorf("this agent doesn't know the action %q", name)
}

func (m *Manager) patch(ctx context.Context, path, contentType string, body []byte) error {
	return m.Client.Do(ctx, http.MethodPatch, path+"?fieldManager="+FieldManager, contentType, body, nil)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// templateSpec nests a pod spec where the workload kind keeps it.
func templateSpec(kind string, spec map[string]any) map[string]any {
	if kind == action.KindCronJob {
		return map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": spec}}}}
	}
	return map[string]any{"template": map[string]any{"spec": spec}}
}

// setImage changes container images and waits for the rollout; when it
// fails, it puts the previous images back.
func (m *Manager) setImage(ctx context.Context, p action.K8sParams, path, obj string, out io.Writer) (action.K8sResult, error) {
	var res action.K8sResult
	var cur struct {
		Spec struct {
			Template    podTemplate `json:"template"`
			JobTemplate struct {
				Spec struct {
					Template podTemplate `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := m.Client.Get(ctx, path, &cur); err != nil {
		return res, err
	}
	spec := cur.Spec.Template.Spec
	if p.Kind == action.KindCronJob {
		spec = cur.Spec.JobTemplate.Spec.Template.Spec
	}
	prev := map[string]string{}
	init := map[string]bool{}
	for _, c := range spec.Containers {
		prev[c.Name] = c.Image
	}
	for _, c := range spec.InitContainers {
		prev[c.Name], init[c.Name] = c.Image, true
	}
	for _, c := range slices.Sorted(maps.Keys(p.Images)) {
		if _, ok := prev[c]; !ok {
			return res, fmt.Errorf("%s has no container %s (it has %s)", obj, c, strings.Join(slices.Sorted(maps.Keys(prev)), ", "))
		}
	}
	res.Previous = map[string]string{}
	changed := false
	for _, c := range slices.Sorted(maps.Keys(p.Images)) {
		res.Previous[c] = prev[c]
		if prev[c] == p.Images[c] {
			fmt.Fprintf(out, "%s runs %s already.\n", c, prev[c])
			continue
		}
		changed = true
		fmt.Fprintf(out, "%s: %s → %s\n", c, prev[c], p.Images[c])
	}
	if !changed {
		return res, nil
	}
	body := imagePatch(p.Kind, p.Images, init)
	if err := m.patch(ctx, path, StrategicPatch, body); err != nil {
		return res, err
	}
	res.Objects = []string{obj}
	if p.Kind == action.KindCronJob {
		fmt.Fprintln(out, "The CronJob's next run uses the new images.")
		return res, nil
	}
	err := m.waitRollout(ctx, p.Kind, path, obj, time.Duration(p.HealthTimeout)*time.Second, out)
	if err == nil {
		return res, nil
	}
	// Undo, even when the job was cancelled or timed out.
	fmt.Fprintf(out, "\nThe rollout failed (%v). Putting the previous images back.\n", err)
	back := map[string]string{}
	for c := range p.Images {
		back[c] = prev[c]
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(p.HealthTimeout)*time.Second+time.Minute)
	defer cancel()
	if rerr := m.patch(rctx, path, StrategicPatch, imagePatch(p.Kind, back, init)); rerr != nil {
		return res, fmt.Errorf("%v; putting the previous images back failed too: %v", err, rerr)
	}
	if rerr := m.waitRollout(rctx, p.Kind, path, obj, time.Duration(p.HealthTimeout)*time.Second, out); rerr != nil {
		return res, fmt.Errorf("%v; the previous images were put back but didn't roll out either: %v", err, rerr)
	}
	res.RolledBack = true
	return res, err
}

// imagePatch is a strategic merge patch that sets container images, which
// merges containers by name.
func imagePatch(kind string, images map[string]string, init map[string]bool) []byte {
	var cs, ics []map[string]string
	for _, c := range slices.Sorted(maps.Keys(images)) {
		e := map[string]string{"name": c, "image": images[c]}
		if init[c] {
			ics = append(ics, e)
		} else {
			cs = append(cs, e)
		}
	}
	spec := map[string]any{}
	if cs != nil {
		spec["containers"] = cs
	}
	if ics != nil {
		spec["initContainers"] = ics
	}
	b, _ := json.Marshal(map[string]any{"spec": templateSpec(kind, spec)})
	return b
}

// rollout is the status of a Deployment, StatefulSet or DaemonSet, enough
// to tell whether a rollout finished.
type rollout struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas       *int `json:"replicas"`
		UpdateStrategy struct {
			Type          string `json:"type"`
			RollingUpdate *struct {
				Partition *int `json:"partition"`
			} `json:"rollingUpdate"`
		} `json:"updateStrategy"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		// Deployment and StatefulSet.
		Replicas          int `json:"replicas"`
		UpdatedReplicas   int `json:"updatedReplicas"`
		ReadyReplicas     int `json:"readyReplicas"`
		AvailableReplicas int `json:"availableReplicas"`
		// DaemonSet.
		DesiredNumberScheduled int `json:"desiredNumberScheduled"`
		UpdatedNumberScheduled int `json:"updatedNumberScheduled"`
		NumberAvailable        int `json:"numberAvailable"`
		Conditions             []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

// done reports whether the rollout finished, what it is at, and an error
// once it can't finish (a Deployment past its progress deadline).
func (r rollout) done(kind string) (bool, string, error) {
	want := 1
	if r.Spec.Replicas != nil {
		want = *r.Spec.Replicas
	}
	st := r.Status
	if st.ObservedGeneration < r.Metadata.Generation {
		return false, "waiting for the controller to see the change", nil
	}
	switch kind {
	case action.KindDeployment:
		for _, c := range st.Conditions {
			if c.Type == "Progressing" && c.Reason == "ProgressDeadlineExceeded" {
				return false, "", fmt.Errorf("the rollout stalled: %s", c.Message)
			}
		}
		at := fmt.Sprintf("%d of %d updated, %d available, %d old", st.UpdatedReplicas, want, st.AvailableReplicas,
			max(st.Replicas-st.UpdatedReplicas, 0))
		return st.UpdatedReplicas >= want && st.Replicas <= want && st.AvailableReplicas >= want, at, nil
	case action.KindStatefulSet:
		if r.Spec.UpdateStrategy.Type == "OnDelete" {
			return true, "OnDelete: pods change when they are deleted", nil
		}
		target := want
		if ru := r.Spec.UpdateStrategy.RollingUpdate; ru != nil && ru.Partition != nil {
			target = max(want-*ru.Partition, 0)
		}
		at := fmt.Sprintf("%d of %d updated, %d ready", st.UpdatedReplicas, want, st.ReadyReplicas)
		return st.UpdatedReplicas >= target && st.ReadyReplicas >= want && st.Replicas <= want, at, nil
	case action.KindDaemonSet:
		if r.Spec.UpdateStrategy.Type == "OnDelete" {
			return true, "OnDelete: pods change when they are deleted", nil
		}
		d := st.DesiredNumberScheduled
		at := fmt.Sprintf("%d of %d nodes updated, %d available", st.UpdatedNumberScheduled, d, st.NumberAvailable)
		return st.UpdatedNumberScheduled >= d && st.NumberAvailable >= d, at, nil
	}
	return true, "", nil
}

// waitRollout waits until a Deployment, StatefulSet or DaemonSet has rolled
// out, printing its progress when it changes.
func (m *Manager) waitRollout(ctx context.Context, kind, path, obj string, timeout time.Duration, out io.Writer) error {
	if kind != action.KindDeployment && kind != action.KindStatefulSet && kind != action.KindDaemonSet {
		return nil
	}
	if timeout <= 0 {
		timeout = time.Duration(action.DefaultHealthTimeout) * time.Second
	}
	deadline := m.now().Add(timeout)
	last := ""
	for {
		var r rollout
		if err := m.Client.Get(ctx, path, &r); err != nil {
			return err
		}
		ok, at, err := r.done(kind)
		if at != last {
			fmt.Fprintf(out, "%s: %s\n", obj, at)
			last = at
		}
		if err != nil {
			return err
		}
		if ok {
			fmt.Fprintf(out, "%s rolled out.\n", obj)
			return nil
		}
		if !m.now().Before(deadline) {
			return fmt.Errorf("%s didn't roll out within %v (%s)", obj, timeout, at)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.pollEvery()):
		}
	}
}

// trigger creates a Job from a CronJob's template, as `kubectl create job
// --from=cronjob/...` does, and returns its name.
func (m *Manager) trigger(ctx context.Context, p action.K8sParams, path string) (string, error) {
	var cj struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			JobTemplate struct {
				Metadata struct {
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec json.RawMessage `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := m.Client.Get(ctx, path, &cj); err != nil {
		return "", err
	}
	suffix := "-manual-" + strconv.FormatInt(m.now().Unix(), 10)
	name := p.Name
	if len(name)+len(suffix) > 63 {
		name = strings.TrimRight(name[:63-len(suffix)], "-.")
	}
	name += suffix
	ann := map[string]string{"cronjob.kubernetes.io/instantiate": "manual"}
	maps.Copy(ann, cj.Spec.JobTemplate.Metadata.Annotations)
	ctrl := true
	job := map[string]any{
		"apiVersion": "batch/v1", "kind": "Job",
		"metadata": map[string]any{
			"name": name, "namespace": p.Namespace, "labels": cj.Spec.JobTemplate.Metadata.Labels, "annotations": ann,
			"ownerReferences": []map[string]any{{"apiVersion": "batch/v1", "kind": "CronJob", "name": p.Name,
				"uid": cj.Metadata.UID, "controller": &ctrl}},
		},
		"spec": cj.Spec.JobTemplate.Spec,
	}
	body, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	jobs := k8smanifest.CollectionPath("batch/v1", p.Namespace, "jobs") + "?fieldManager=" + FieldManager
	if err := m.Client.Do(ctx, http.MethodPost, jobs, "application/json", body, nil); err != nil {
		return "", err
	}
	return name, nil
}

// Pods ------------------------------------------------------------------------

// livePod is the part of a pod the agent reads to list and check pods.
type livePod struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		Labels            map[string]string `json:"labels"`
		CreationTimestamp string            `json:"creationTimestamp"`
		OwnerReferences   []ownerRef        `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName       string      `json:"nodeName"`
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		Phase             string            `json:"phase"`
		Reason            string            `json:"reason"`
		ContainerStatuses []containerStatus `json:"containerStatuses"`
	} `json:"status"`
}

type ownerRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller bool   `json:"controller"`
}

type containerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	State        struct {
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting"`
		Terminated *struct {
			Reason string `json:"reason"`
		} `json:"terminated"`
	} `json:"state"`
}

func (p livePod) controller() (ownerRef, bool) {
	for _, o := range p.Metadata.OwnerReferences {
		if o.Controller {
			return o, true
		}
	}
	return ownerRef{}, false
}

// ownedBy reports whether the pod belongs to the workload. A Deployment's
// pods belong to a ReplicaSet named after it and the pod-template-hash;
// a CronJob's to a Job the CronJob owns, which jobOwner looks up.
func (p livePod) ownedBy(kind, name string, jobOwner func(job string) (string, error)) (bool, error) {
	c, ok := p.controller()
	switch kind {
	case action.KindPod:
		return p.Metadata.Name == name && len(p.Metadata.OwnerReferences) == 0, nil
	case action.KindDeployment:
		hash := p.Metadata.Labels["pod-template-hash"]
		return ok && c.Kind == "ReplicaSet" && hash != "" && c.Name == name+"-"+hash, nil
	case action.KindStatefulSet, action.KindDaemonSet:
		return ok && c.Kind == kind && c.Name == name, nil
	case action.KindCronJob:
		if !ok || c.Kind != "Job" {
			return false, nil
		}
		owner, err := jobOwner(c.Name)
		return owner == name, err
	}
	return false, nil
}

// jobOwner returns the name of the CronJob that owns a Job, "" if none.
func (m *Manager) jobOwner(ctx context.Context, ns string) func(string) (string, error) {
	cache := map[string]string{}
	return func(job string) (string, error) {
		if o, ok := cache[job]; ok {
			return o, nil
		}
		var j struct {
			Metadata struct {
				OwnerReferences []ownerRef `json:"ownerReferences"`
			} `json:"metadata"`
		}
		err := m.Client.Get(ctx, k8smanifest.CollectionPath("batch/v1", ns, "jobs")+"/"+job, &j)
		if IsNotFound(err) {
			err = nil
		}
		if err != nil {
			return "", err
		}
		owner := ""
		for _, o := range j.Metadata.OwnerReferences {
			if o.Controller && o.Kind == "CronJob" {
				owner = o.Name
			}
		}
		cache[job] = owner
		return owner, nil
	}
}

// ownedPod reads a pod and checks that it belongs to the workload.
func (m *Manager) ownedPod(ctx context.Context, kind, ns, workload, pod string) (livePod, error) {
	var p livePod
	if err := m.Client.Get(ctx, k8smanifest.CollectionPath("v1", ns, "pods")+"/"+pod, &p); err != nil {
		return p, err
	}
	ok, err := p.ownedBy(kind, workload, m.jobOwner(ctx, ns))
	if err != nil {
		return p, err
	}
	if !ok {
		return p, fmt.Errorf("pod %s/%s doesn't belong to %s %s", ns, pod, kind, workload)
	}
	return p, nil
}

// Pods lists a workload's pods.
func (m *Manager) Pods(ctx context.Context, r model.K8sPodsRequest) ([]model.K8sPod, error) {
	if !action.ValidK8sNamespace(r.Namespace) || !action.ValidK8sName(r.Name) {
		return nil, errors.New("name a workload by namespace and name")
	}
	path, err := workloadPath(r.Kind, r.Namespace, r.Name)
	if err != nil {
		return nil, err
	}
	pods := k8smanifest.CollectionPath("v1", r.Namespace, "pods")
	var list []livePod
	switch r.Kind {
	case action.KindPod:
		var p livePod
		if err := m.Client.Get(ctx, path, &p); err != nil {
			return nil, err
		}
		list = []livePod{p}
	case action.KindCronJob:
		list, err = List[livePod](ctx, m.Client, pods)
	default:
		var w struct {
			Spec struct {
				Selector struct {
					MatchLabels map[string]string `json:"matchLabels"`
				} `json:"selector"`
			} `json:"spec"`
		}
		if err := m.Client.Get(ctx, path, &w); err != nil {
			return nil, err
		}
		var sel []string
		for _, k := range slices.Sorted(maps.Keys(w.Spec.Selector.MatchLabels)) {
			sel = append(sel, k+"="+w.Spec.Selector.MatchLabels[k])
		}
		q := pods
		if len(sel) > 0 {
			q += "?labelSelector=" + url.QueryEscape(strings.Join(sel, ","))
		}
		list, err = listQuery[livePod](ctx, m.Client, q)
	}
	if err != nil {
		return nil, err
	}
	owner := m.jobOwner(ctx, r.Namespace)
	out := []model.K8sPod{}
	for _, p := range list {
		ok, err := p.ownedBy(r.Kind, r.Name, owner)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, p.view())
		}
	}
	slices.SortFunc(out, func(a, b model.K8sPod) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// listQuery is List for a path that has a query already.
func listQuery[T any](ctx context.Context, c *Client, pathQuery string) ([]T, error) {
	path, q, _ := strings.Cut(pathQuery, "?")
	if q == "" {
		return List[T](ctx, c, path)
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return nil, err
	}
	return listWith[T](ctx, c, path, vals)
}

func (p livePod) view() model.K8sPod {
	v := model.K8sPod{Name: p.Metadata.Name, Node: p.Spec.NodeName, Phase: p.Status.Phase, Reason: p.Status.Reason,
		Created: timestamp(p.Metadata.CreationTimestamp), Total: len(p.Spec.Containers), Containers: []string{}}
	var images []string
	for _, c := range p.Spec.Containers {
		v.Containers = append(v.Containers, c.Name)
		images = append(images, c.Image)
	}
	for _, c := range p.Spec.InitContainers {
		v.Init = append(v.Init, c.Name)
	}
	v.Images = sortedUnique(images)
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Ready {
			v.Ready++
		}
		v.Restarts += cs.RestartCount
		if v.Reason == "" && cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "ContainerCreating" {
			v.Reason = cs.State.Waiting.Reason
		}
		if v.Reason == "" && cs.State.Terminated != nil && cs.State.Terminated.Reason != "" && cs.State.Terminated.Reason != "Completed" {
			v.Reason = cs.State.Terminated.Reason
		}
	}
	return v
}

const (
	// maxLogBytes caps what one request returns.
	maxLogBytes = 1 << 20
)

// Logs reads the end of a container's log, with timestamps.
func (m *Manager) Logs(ctx context.Context, r model.K8sLogsRequest) (model.K8sLogs, error) {
	out := model.K8sLogs{Pod: r.Pod, Container: r.Container}
	if !action.ValidK8sNamespace(r.Namespace) || !action.ValidK8sName(r.Pod) {
		return out, errors.New("name the pod by namespace and name")
	}
	if r.Container != "" && !action.ValidK8sNamespace(r.Container) { // container names are DNS labels
		return out, fmt.Errorf("%q isn't a container name", r.Container)
	}
	if r.Tail <= 0 {
		r.Tail = model.DefaultLogLines
	}
	r.Tail = min(r.Tail, model.MaxLogLines)
	if _, err := m.ownedPod(ctx, r.Kind, r.Namespace, r.Name, r.Pod); err != nil {
		return out, err
	}
	q := url.Values{"tailLines": {strconv.Itoa(r.Tail)}, "timestamps": {"true"}, "limitBytes": {strconv.Itoa(maxLogBytes)}}
	if r.Container != "" {
		q.Set("container", r.Container)
	}
	if r.Previous {
		q.Set("previous", "true")
	}
	var b []byte
	path := k8smanifest.CollectionPath("v1", r.Namespace, "pods") + "/" + r.Pod + "/log?" + q.Encode()
	if err := m.Client.Do(ctx, http.MethodGet, path, "", nil, &b); err != nil {
		return out, err
	}
	out.Text, out.Truncated = strings.ToValidUTF8(string(b), "�"), len(b) >= maxLogBytes
	return out, nil
}

// Manifests ---------------------------------------------------------------------

// Manifest runs k8s.deploy or k8s.edit: it checks the manifest (and an
// edit's base) against their hashes, applies every object with server-side
// apply after a dry run of all of them, and waits for the workloads to roll
// out. A deploy that fails deletes what it created; an edit that fails
// applies the base again and deletes what it added. An edit that succeeds
// deletes the objects the base had and the manifest doesn't.
func (m *Manager) Manifest(ctx context.Context, name string, p action.K8sManifestParams, manifest, base []byte,
	out io.Writer) (action.K8sResult, error) {
	var res action.K8sResult
	if sum(manifest) != p.ManifestSHA256 {
		return res, errors.New("the manifest doesn't match its hash")
	}
	objs, err := k8smanifest.Parse(manifest, p.Namespace)
	if err != nil {
		return res, err
	}
	var baseObjs []k8smanifest.Object
	if name == action.K8sEdit {
		if sum(base) != p.BaseSHA256 {
			return res, errors.New("the previous manifest doesn't match its hash")
		}
		if baseObjs, err = k8smanifest.Parse(base, p.Namespace); err != nil {
			return res, fmt.Errorf("the previous manifest: %w", err)
		}
	} else if len(base) > 0 {
		return res, errors.New("a deploy has no previous manifest")
	}
	inBase := map[string]bool{}
	for _, o := range baseObjs {
		inBase[o.Key()] = true
	}
	inNew := map[string]bool{}
	for _, o := range objs {
		inNew[o.Key()] = true
		if err := m.allowed(o.Namespace); err != nil {
			return res, fmt.Errorf("%s: %w", o.Key(), err)
		}
	}
	var gone []k8smanifest.Object // in the base, not in the manifest
	for _, o := range baseObjs {
		if !inNew[o.Key()] {
			if err := m.allowed(o.Namespace); err != nil {
				return res, fmt.Errorf("%s: %w", o.Key(), err)
			}
			gone = append(gone, o)
		}
	}
	// New objects must be new: Baseline doesn't take over what someone else
	// made, and undoing a failed change deletes them.
	var added []k8smanifest.Object
	for _, o := range objs {
		if inBase[o.Key()] {
			continue
		}
		err := m.Client.Get(ctx, o.Path(), &struct{}{})
		switch {
		case err == nil:
			return res, fmt.Errorf("%s exists already; Baseline only creates new objects (or changes ones it deployed)", o.Key())
		case !IsNotFound(err):
			return res, err
		}
		added = append(added, o)
	}
	fmt.Fprintf(out, "Checking %d objects with a dry run\n", len(objs))
	for _, o := range objs {
		if err := m.apply(ctx, o, true); err != nil {
			return res, fmt.Errorf("%s: %w", o.Key(), err)
		}
	}
	deadline := m.now().Add(time.Duration(p.HealthTimeout) * time.Second)
	err = m.applyAll(ctx, objs, deadline, out, &res)
	if err == nil {
		for _, o := range gone {
			fmt.Fprintf(out, "Deleting %s, which the manifest no longer has\n", o.Key())
			if derr := m.delete(ctx, o); derr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("couldn't delete %s: %v", o.Key(), derr))
				continue
			}
			res.Deleted = append(res.Deleted, o.Key())
		}
		return res, nil
	}
	// Undo, even when the job was cancelled or timed out.
	fmt.Fprintf(out, "\n%v\n", err)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(p.HealthTimeout)*time.Second+2*time.Minute)
	defer cancel()
	var undo []string
	if name == action.K8sEdit {
		fmt.Fprintln(out, "Applying the previous manifest again.")
		var back action.K8sResult
		if uerr := m.applyAll(rctx, baseObjs, m.now().Add(time.Duration(p.HealthTimeout)*time.Second), out, &back); uerr != nil {
			undo = append(undo, "the previous manifest: "+uerr.Error())
		}
	}
	for i := len(added) - 1; i >= 0; i-- {
		o := added[i]
		fmt.Fprintf(out, "Deleting %s\n", o.Key())
		if derr := m.delete(rctx, o); derr != nil && !IsNotFound(derr) {
			undo = append(undo, o.Key()+": "+derr.Error())
		}
	}
	if len(undo) > 0 {
		return res, fmt.Errorf("%v; undoing it failed too: %s", err, strings.Join(undo, "; "))
	}
	res.RolledBack = true
	return res, err
}

// applyAll applies objects in order, then waits for the workloads among
// them to roll out by the deadline.
func (m *Manager) applyAll(ctx context.Context, objs []k8smanifest.Object, deadline time.Time, out io.Writer,
	res *action.K8sResult) error {
	for _, o := range objs {
		fmt.Fprintf(out, "Applying %s\n", o.Key())
		if err := m.apply(ctx, o, false); err != nil {
			return fmt.Errorf("%s: %w", o.Key(), err)
		}
		res.Objects = append(res.Objects, o.Key())
	}
	for _, o := range objs {
		if !o.Workload {
			continue
		}
		left := deadline.Sub(m.now())
		if left <= 0 {
			left = time.Second
		}
		if err := m.waitRollout(ctx, o.Kind, o.Path(), o.Key(), left, out); err != nil {
			return err
		}
	}
	return nil
}

// apply sends one object as a server-side apply patch, taking over fields
// other managers set (force), as `kubectl apply --server-side
// --force-conflicts` does.
func (m *Manager) apply(ctx context.Context, o k8smanifest.Object, dryRun bool) error {
	q := url.Values{"fieldManager": {FieldManager}, "force": {"true"}}
	if dryRun {
		q.Set("dryRun", "All")
	}
	return m.Client.Do(ctx, http.MethodPatch, o.Path()+"?"+q.Encode(), ApplyPatch, o.Doc, nil)
}

func (m *Manager) delete(ctx context.Context, o k8smanifest.Object) error {
	body := []byte(`{"apiVersion":"v1","kind":"DeleteOptions","propagationPolicy":"Background"}`)
	err := m.Client.Do(ctx, http.MethodDelete, o.Path(), "application/json", body, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

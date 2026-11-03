package action

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Kubernetes actions (docs/agent.md §6.1) run on a cluster-mode agent,
// through the Kubernetes API, on the workloads the "k8s" section reports.
// A cluster agent runs nothing else.
const (
	K8sRestart   = "k8s.restart"
	K8sScale     = "k8s.scale"
	K8sSetImage  = "k8s.set_image"
	K8sDeletePod = "k8s.delete_pod"
	K8sSuspend   = "k8s.suspend"
	K8sResume    = "k8s.resume"
	K8sTrigger   = "k8s.trigger"
	K8sDeploy    = "k8s.deploy"
	K8sEdit      = "k8s.edit"
)

// Capabilities of cluster-mode agents.
const (
	// CapK8sActions: the cluster agent runs the k8s.* actions (when its
	// BASELINE_ALLOW_ACTIONS lets it, and its ClusterRole does).
	CapK8sActions = "k8s-actions"
	// CapK8sPods: the agent lists a workload's pods for the server (the
	// "k8s.pods" poll).
	CapK8sPods = "k8s-pods"
	// CapK8sLogs: the agent reads pod logs for the server (the "k8s.logs"
	// poll); BASELINE_K8S_LOGS turns it on.
	CapK8sLogs = "k8s-logs"
	// capK8sCluster is model.CapK8sCluster: a cluster-mode agent, which runs
	// only Kubernetes actions.
	capK8sCluster = "k8s-cluster"
)

// Workload kinds the actions take.
const (
	KindDeployment  = "Deployment"
	KindStatefulSet = "StatefulSet"
	KindDaemonSet   = "DaemonSet"
	KindCronJob     = "CronJob"
	KindPod         = "Pod"
)

// K8sKinds lists the workload kinds each workload action applies to.
var K8sKinds = map[string][]string{
	K8sRestart:   {KindDeployment, KindStatefulSet, KindDaemonSet},
	K8sScale:     {KindDeployment, KindStatefulSet},
	K8sSetImage:  {KindDeployment, KindStatefulSet, KindDaemonSet, KindCronJob},
	K8sDeletePod: {KindDeployment, KindStatefulSet, KindDaemonSet, KindCronJob, KindPod},
	K8sSuspend:   {KindCronJob},
	K8sResume:    {KindCronJob},
	K8sTrigger:   {KindCronJob},
}

// IsK8sWorkloadAction reports whether the action acts on one workload the
// cluster reports (every k8s.* action but deploy and edit).
func IsK8sWorkloadAction(name string) bool { _, ok := K8sKinds[name]; return ok }

// AppliesTo reports whether a workload action can act on a workload of
// this kind.
func AppliesTo(name, kind string) bool { return slices.Contains(K8sKinds[name], kind) }

// K8sParams are the workload actions'. A workload is named by kind,
// namespace and name, as the "k8s" section reports it.
type K8sParams struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Pod (k8s.delete_pod) is the pod to delete. The agent checks that it
	// belongs to the workload; for a bare Pod it is the workload itself.
	Pod string `json:"pod,omitempty"`
	// Replicas (k8s.scale) is the new desired count.
	Replicas *int `json:"replicas,omitempty"`
	// Images (k8s.set_image) maps container (or init container) names to
	// the image they should run.
	Images map[string]string `json:"images,omitempty"`
	// HealthTimeout (k8s.restart, k8s.scale, k8s.set_image) is how long, in
	// seconds, the rollout gets to finish. k8s.set_image puts the previous
	// images back when it doesn't.
	HealthTimeout int `json:"health_timeout,omitempty"`
}

// K8sManifestParams are k8s.deploy's and k8s.edit's. The manifest travels
// in RunJob (StackFiles), never here, like a Compose file: Revision names
// the server's copy.
type K8sManifestParams struct {
	// Bundle names the set of objects the manifest holds, the way a project
	// names a Compose stack. Namespace is where objects that name none go.
	Bundle    string `json:"bundle"`
	Namespace string `json:"namespace"`
	Revision  string `json:"revision"`
	// ManifestSHA256 is the manifest's SHA-256, which the agent checks.
	ManifestSHA256 string `json:"manifest_sha256"`
	// BaseRevision and BaseSHA256 (k8s.edit) are the revision the edit
	// replaces. Its manifest goes with the job too: the agent applies it
	// again when the edit fails, and deletes what the edit leaves out.
	BaseRevision string `json:"base_revision,omitempty"`
	BaseSHA256   string `json:"base_sha256,omitempty"`
	// HealthTimeout is how long, in seconds, the manifest's workloads get to
	// roll out before the change is undone.
	HealthTimeout int `json:"health_timeout,omitempty"`
}

const MaxReplicas = 1000

var (
	// Kubernetes object names: DNS-1123 labels (namespaces, containers) and
	// subdomains (most objects).
	reK8sLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	reK8sSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	// An image reference: registry/repository[:tag][@digest].
	reImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}$`)
)

// ValidK8sNamespace reports whether s is a namespace name.
func ValidK8sNamespace(s string) bool { return reK8sLabel.MatchString(s) }

// ValidK8sName reports whether s is an object name.
func ValidK8sName(s string) bool { return reK8sSubdomain.MatchString(s) }

// ValidImage reports whether s reads as an image reference.
func ValidImage(s string) bool { return reImage.MatchString(s) && !strings.Contains(s, "//") }

func validateK8s(name string, raw []byte) (any, error) {
	var p K8sParams
	if err := strictJSON(raw, &p); err != nil {
		return nil, err
	}
	if !AppliesTo(name, p.Kind) {
		return nil, fmt.Errorf("%s works on a %s, not %q", name, strings.Join(K8sKinds[name], ", "), p.Kind)
	}
	if !reK8sLabel.MatchString(p.Namespace) {
		return nil, fmt.Errorf("%q isn't a namespace", p.Namespace)
	}
	if !reK8sSubdomain.MatchString(p.Name) {
		return nil, fmt.Errorf("%q isn't a %s name", p.Name, p.Kind)
	}
	if name == K8sDeletePod {
		if p.Pod == "" && p.Kind == KindPod {
			p.Pod = p.Name
		}
		if !reK8sSubdomain.MatchString(p.Pod) {
			return nil, errors.New("pick the pod to delete")
		}
		if p.Kind == KindPod && p.Pod != p.Name {
			return nil, errors.New("a bare pod is its own workload")
		}
	} else if p.Pod != "" {
		return nil, errors.New("pod is k8s.delete_pod's")
	}
	if name == K8sScale {
		if p.Replicas == nil {
			return nil, errors.New("scaling needs the number of replicas")
		}
		if *p.Replicas < 0 || *p.Replicas > MaxReplicas {
			return nil, fmt.Errorf("replicas must be between 0 and %d", MaxReplicas)
		}
	} else if p.Replicas != nil {
		return nil, errors.New("replicas are k8s.scale's")
	}
	if name == K8sSetImage {
		if len(p.Images) == 0 {
			return nil, errors.New("name at least one container and its new image")
		}
		if len(p.Images) > 50 {
			return nil, errors.New("too many containers")
		}
		for c, img := range p.Images {
			if !reK8sLabel.MatchString(c) {
				return nil, fmt.Errorf("%q isn't a container name", c)
			}
			if !ValidImage(img) {
				return nil, fmt.Errorf("%q isn't an image reference", img)
			}
		}
	} else if p.Images != nil {
		return nil, errors.New("images are k8s.set_image's")
	}
	switch {
	case name == K8sRestart || name == K8sScale || (name == K8sSetImage && p.Kind != KindCronJob):
		if p.HealthTimeout == 0 {
			p.HealthTimeout = DefaultHealthTimeout
		}
		if p.HealthTimeout < 10 || p.HealthTimeout > MaxHealthTimeout {
			return nil, fmt.Errorf("the rollout timeout must be between 10 seconds and %d minutes", MaxHealthTimeout/60)
		}
	case p.HealthTimeout != 0:
		return nil, errors.New("health_timeout is for actions that roll a workload out")
	}
	return p, nil
}

func validateK8sManifest(name string, raw []byte) (any, error) {
	var p K8sManifestParams
	if err := strictJSON(raw, &p); err != nil {
		return nil, err
	}
	if !reProject.MatchString(p.Bundle) {
		return nil, errors.New("a manifest needs a bundle name (lowercase letters, digits, -, _ and .)")
	}
	if !reK8sLabel.MatchString(p.Namespace) {
		return nil, fmt.Errorf("%q isn't a namespace", p.Namespace)
	}
	if !reUUID.MatchString(p.Revision) {
		return nil, errors.New("the manifest is missing")
	}
	if !reSHA256.MatchString(p.ManifestSHA256) {
		return nil, errors.New("the manifest's hash isn't a SHA-256")
	}
	if name == K8sDeploy {
		if p.BaseRevision != "" || p.BaseSHA256 != "" {
			return nil, errors.New("a new bundle has nothing to edit")
		}
	} else {
		if !reUUID.MatchString(p.BaseRevision) || !reSHA256.MatchString(p.BaseSHA256) {
			return nil, errors.New("an edit names the revision it replaces")
		}
	}
	if p.HealthTimeout == 0 {
		p.HealthTimeout = DefaultHealthTimeout
	}
	if p.HealthTimeout < 10 || p.HealthTimeout > MaxHealthTimeout {
		return nil, fmt.Errorf("the rollout timeout must be between 10 seconds and %d minutes", MaxHealthTimeout/60)
	}
	return p, nil
}

func describeK8s(name string, p K8sParams) string {
	obj := p.Namespace + "/" + p.Name
	switch name {
	case K8sRestart:
		return "Restart " + p.Kind + " " + obj
	case K8sScale:
		n := 0
		if p.Replicas != nil {
			n = *p.Replicas
		}
		return fmt.Sprintf("Scale %s %s to %d", p.Kind, obj, n)
	case K8sSetImage:
		var parts []string
		for _, c := range slices.Sorted(maps.Keys(p.Images)) {
			parts = append(parts, c+"="+p.Images[c])
		}
		return "Set the image of " + p.Kind + " " + obj + ": " + strings.Join(parts, ", ")
	case K8sDeletePod:
		if p.Kind == KindPod {
			return "Delete pod " + obj
		}
		return "Delete pod " + p.Namespace + "/" + p.Pod + " of " + p.Kind + " " + p.Name
	case K8sSuspend:
		return "Suspend CronJob " + obj
	case K8sResume:
		return "Resume CronJob " + obj
	case K8sTrigger:
		return "Run CronJob " + obj + " now"
	}
	return name
}

func describeK8sManifest(name string, p K8sManifestParams) string {
	if name == K8sDeploy {
		return "Deploy manifest " + p.Bundle + " (namespace " + p.Namespace + ")"
	}
	return "Edit manifest " + p.Bundle
}

// K8sResult is the structured result of the Kubernetes actions.
type K8sResult struct {
	// Objects are what the action changed, "Deployment default/web".
	Objects []string `json:"objects,omitempty"`
	// Previous (k8s.set_image) are the images the containers ran before.
	Previous map[string]string `json:"previous,omitempty"`
	// Job (k8s.trigger) is the Job made from the CronJob.
	Job string `json:"job,omitempty"`
	// Deleted (k8s.edit) are objects the previous revision had and this one
	// doesn't, which the edit deleted.
	Deleted    []string `json:"deleted,omitempty"`
	RolledBack bool     `json:"rolled_back,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// ParseDenyNamespaces reads the cluster agent's BASELINE_DENY_NAMESPACES: a
// comma-separated list of namespaces its actions may not touch, "none" for
// none. Empty is the default, kube-system.
func ParseDenyNamespaces(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	switch v {
	case "":
		return []string{"kube-system"}, nil
	case "none":
		return []string{}, nil
	}
	out := []string{}
	for _, ns := range strings.Split(v, ",") {
		ns = strings.TrimSpace(ns)
		if !reK8sLabel.MatchString(ns) {
			return nil, fmt.Errorf("%q isn't a namespace", ns)
		}
		if !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out, nil
}

// ParseClusterAllowActions reads the cluster agent's BASELINE_ALLOW_ACTIONS:
// "kubernetes" (or "all", or empty: the default) turns its actions on,
// "none" leaves it read-only. A cluster agent runs no other category.
func ParseClusterAllowActions(v string) ([]string, error) {
	switch strings.TrimSpace(v) {
	case "none":
		return []string{}, nil
	case "", "kubernetes", "all", "*":
		return []string{CategoryKubernetes}, nil
	}
	return nil, fmt.Errorf("BASELINE_ALLOW_ACTIONS takes kubernetes or none, not %s", strconv.Quote(v))
}

package runner

import (
	"context"
	"io"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

// Kube runs the Kubernetes actions on a cluster-mode agent
// (kube.Manager).
type Kube interface {
	Workload(ctx context.Context, name string, p action.K8sParams, out io.Writer) (action.K8sResult, error)
	// Manifest applies a k8s.deploy's or k8s.edit's manifest; base is an
	// edit's previous manifest.
	Manifest(ctx context.Context, name string, p action.K8sManifestParams, manifest, base []byte, out io.Writer) (action.K8sResult, error)
}

// kubeOutcome turns a Kubernetes action's result into the job's.
func kubeOutcome(res action.K8sResult, err error) outcome {
	o := outcome{result: res}
	if err != nil {
		o.failed, o.exitCode, o.err = true, -1, err.Error()
		if res.RolledBack {
			o.state = stateRolledBack
		}
	}
	return o
}

func (r *Runner) kubeWorkload(ctx context.Context, name string, p action.K8sParams, out *output) outcome {
	if r.Kube == nil {
		return failed("Kubernetes actions run on a cluster agent (baseline-agent --mode=k8s)")
	}
	return kubeOutcome(r.Kube.Workload(ctx, name, p, out.stream("info")))
}

// kubeManifest applies a manifest, which travels in the job's StackFiles:
// the new manifest as Compose, an edit's previous one as Env.
func (r *Runner) kubeManifest(ctx context.Context, name string, p action.K8sManifestParams, files *agentv1.StackFiles, out *output) outcome {
	if r.Kube == nil {
		return failed("Kubernetes actions run on a cluster agent (baseline-agent --mode=k8s)")
	}
	if files == nil || len(files.GetCompose()) == 0 {
		return failed("the server sent no manifest")
	}
	return kubeOutcome(r.Kube.Manifest(ctx, name, p, files.GetCompose(), files.GetEnv(), out.stream("info")))
}

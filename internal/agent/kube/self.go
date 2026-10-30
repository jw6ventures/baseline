package kube

import (
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
)

// BootID is what a cluster-mode agent reports as its boot ID. It is the
// same for every pod: the gateway refuses a second stream for an agent from
// a different boot (a cloned host), but a rescheduled pod is the same agent
// and must replace the old stream.
const BootID = "k8s-cluster"

// Self is the agent.Host of a cluster-mode agent: the cluster, not the
// machine the pod happens to run on.
type Self struct {
	Name string // the cluster's name
}

// Identity names the cluster. Machine-id and DMI UUID stay empty: inside a
// pod they would be the node's, and collide with the host agent running on
// that node.
func (s Self) Identity() collect.Identity {
	return collect.Identity{Hostname: s.Name, BootID: BootID}
}

func (s Self) Capabilities() []string { return []string{model.CapK8sCluster} }

package gateway_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/release"
	"github.com/jw6ventures/baseline/internal/store"
)

// clusterSelf is what a cluster-mode agent says about itself in Hello.
type clusterSelf struct{}

func (clusterSelf) Identity() collect.Identity {
	return collect.Identity{Hostname: "homelab", BootID: "k8s-cluster"}
}
func (clusterSelf) Capabilities() []string { return []string{model.CapK8sCluster} }

// A cluster-mode agent reports its cluster, is named after it, and is never
// asked to update itself: its image is.
func TestClusterAgent(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	agentDir := t.TempDir()
	os.WriteFile(filepath.Join(agentDir, release.Prefix+runtime.GOARCH), []byte("agent"), 0o755)
	if _, err := release.Publish(ctx, e.st, e.ca, nil, agentDir, t.TempDir(), "2.0"); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if _, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "1.0", clusterSelf{}); err != nil {
		t.Fatal(err)
	}
	st, _ := agent.LoadState(stateDir)
	a := &agent.Agent{Server: e.addr, State: st, Env: clusterSelf{}, Version: "1.0", Log: quiet,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		Collectors: map[string]agent.CollectFunc{
			model.SectionK8s: func(context.Context) (any, error) {
				return model.K8s{Cluster: model.K8sCluster{UID: "uid-1", Name: "homelab", Version: "v1.33.5"},
					Nodes: []model.K8sNodeInfo{{Name: "n1", Ready: true}}}, nil
			},
			// Host sections a cluster agent doesn't have.
			model.SectionVMs: func(context.Context) (any, error) { return nil, collect.ErrAbsent },
		}}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	defer func() { cancel(); <-done }()

	var hostID string
	eventually(t, "cluster stored", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 || !hosts[0].ClusterAgent() {
			return false
		}
		hostID = hosts[0].ID
		c, err := e.st.ClusterOfAgent(ctx, hostID)
		return err == nil && c.Name == "homelab" && c.Nodes == 1 && hosts[0].Hostname == "homelab"
	})
	if _, _, err := e.st.HostSection(ctx, hostID, model.SectionVMs); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an absent section was sent: %v", err)
	}
	changed, err := e.st.RequestAgentUpdate(ctx, store.System, []string{hostID}, "2.0")
	if err != nil || len(changed) != 0 {
		t.Fatalf("a cluster agent was asked to update itself: %v %v", changed, err)
	}
}

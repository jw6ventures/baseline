package gateway_test

import (
	"context"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/model"
)

func TestInventorySectionsReachTheServer(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	h := newFakeHost(t, "sections")
	cols := h.collectors()
	cols[model.SectionContainers] = func(context.Context) (any, error) {
		return model.Containers{
			Engines:    []model.ContainerEngine{{Name: "docker", Kind: "docker"}},
			Containers: []model.Container{{Engine: "docker", Name: "web", ID: "a", Image: "nginx:1.27", ImageID: "i", State: "running"}},
		}, nil
	}
	cols[model.SectionServices] = func(context.Context) (any, error) {
		return model.Services{Units: []model.Service{{Name: "sshd.service", Active: "active", Sub: "running"}}}, nil
	}
	cols[model.SectionPorts] = func(context.Context) (any, error) {
		return model.Ports{Listeners: []model.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd"}}}, nil
	}
	cols[model.SectionReboot] = func(context.Context) (any, error) {
		return model.Reboot{Required: true, Reasons: []string{"test"}}, nil
	}
	cols[model.SectionCerts] = func(context.Context) (any, error) { return model.Certs{Certs: []model.Cert{}}, nil }

	stateDir := t.TempDir()
	if _, err := agent.Enroll(ctx, e.addr, e.token(0), stateDir, "test", h.env); err != nil {
		t.Fatal(err)
	}
	st, _ := agent.LoadState(stateDir)
	a := &agent.Agent{Server: e.addr, State: st, Env: h.env, Collectors: cols, Version: "test", Log: quiet,
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Run(runCtx)

	eventually(t, "M3 sections stored", func() bool {
		hosts, _ := e.st.ListHosts(ctx)
		if len(hosts) != 1 {
			return false
		}
		hst := hosts[0]
		ports, _ := e.st.HostPorts(ctx, hst.ID)
		svcs, _ := e.st.HostServices(ctx, hst.ID)
		return hst.Containers == 1 && hst.RebootRequired && len(ports) == 1 && len(svcs) == 1
	})
	hosts, _ := e.st.ListHosts(ctx)
	if _, _, err := e.st.HostSection(ctx, hosts[0].ID, model.SectionCerts); err != nil {
		t.Fatalf("certs section: %v", err)
	}
}

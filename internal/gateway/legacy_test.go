package gateway_test

import (
	"testing"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/gateway"
	"github.com/jw6ventures/baseline/internal/pki"
)

// Agents from before the rename to Baseline dial the old service name.
func TestLegacyServiceName(t *testing.T) {
	ca, err := pki.Load(t.TempDir(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	info := gateway.New(nil, ca, quiet).NewServer().GetServiceInfo()
	for _, name := range []string{agentv1.AgentGateway_ServiceDesc.ServiceName, gateway.LegacyServiceName} {
		if len(info[name].Methods) != 3 {
			t.Errorf("%s: methods %v", name, info[name].Methods)
		}
	}
}

package collect

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// TestVMsReal reads this machine's hypervisors, read-only. Run with
// BASELINE_TEST_VIRSH=1; BASELINE_TEST_VIRSH_OUT=<file> also writes the section.
func TestVMsReal(t *testing.T) {
	if os.Getenv("BASELINE_TEST_VIRSH") != "1" {
		t.Skip("set BASELINE_TEST_VIRSH=1 to read the local hypervisors")
	}
	env := Host()
	ctx := context.Background()
	start := time.Now()
	got, err := env.VMs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, hash, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	kinds, states := map[string]int{}, map[string]int{}
	nics := 0
	for _, g := range got.Guests {
		kinds[g.Kind]++
		states[g.State]++
		nics += len(g.NICs)
	}
	t.Logf("collected in %v: %d bytes, %d hypervisors, %d guests (kinds %s, states %s), %d NICs, %d storage",
		time.Since(start).Round(time.Millisecond), len(b), len(got.Hypervisors), len(got.Guests),
		vmCounts(kinds), vmCounts(states), nics, len(got.Storage))
	for _, h := range got.Hypervisors {
		t.Logf("hypervisor %s version=%s node=%s cluster=%s error=%q", h.Platform, h.Version, h.Node, h.Cluster, h.Error)
		if h.Error != "" {
			t.Errorf("%s: %s", h.Platform, h.Error)
		}
	}
	for _, g := range got.Guests {
		t.Logf("guest %s %s %q state=%s cpus=%d mem=%d os=%s machine=%s disks=%d nics=%+v",
			g.Key(), g.Kind, g.Name, g.State, g.CPUs, g.MemoryBytes, g.OSType, g.Machine, len(g.Disks), g.NICs)
	}
	if out := os.Getenv("BASELINE_TEST_VIRSH_OUT"); out != "" {
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	again, err := env.VMs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, h2, _ := model.Encode(again); h2 != hash {
		t.Error("hash differs between two collections (a guest may have changed state)")
	}
}

func vmCounts(m map[string]int) string {
	var s []string
	for k, n := range m {
		s = append(s, k+"="+itoa(uint64(n)))
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

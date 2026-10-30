package collect

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// TestK8sNodeReal reads this machine's CRI runtime with crictl, read-only.
// Run as root on a Kubernetes node with BASELINE_TEST_CRICTL=1;
// BASELINE_TEST_CRICTL_OUT=<file> also writes the section.
func TestK8sNodeReal(t *testing.T) {
	if os.Getenv("BASELINE_TEST_CRICTL") != "1" {
		t.Skip("set BASELINE_TEST_CRICTL=1 to read the local CRI runtime")
	}
	start := time.Now()
	got, err := Host().K8sNode(context.Background())
	if errors.Is(err, ErrAbsent) {
		t.Skip("no CRI runtime here")
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("collected in %v: %d bytes; %s %s at %s; %d pods, %d containers, %d images",
		time.Since(start).Round(time.Millisecond), len(b), got.Runtime, got.RuntimeVersion, got.Endpoint,
		len(got.Pods), len(got.Containers), len(got.Images))
	for _, c := range got.Containers {
		t.Logf("%s/%s/%s %s %s attempt=%d", c.Namespace, c.Pod, c.Name, c.State, c.Image, c.Attempt)
		if c.Namespace == "" || c.Pod == "" || c.Name == "" || c.Image == "" {
			t.Errorf("incomplete container %+v", c)
		}
	}
	if out := os.Getenv("BASELINE_TEST_CRICTL_OUT"); out != "" {
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

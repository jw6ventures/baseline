package collect

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// TestContainersRealEngine reads this machine's engines, read-only. Run with
// BASELINE_TEST_DOCKER=1; BASELINE_TEST_DOCKER_OUT=<file> also writes the section.
func TestContainersRealEngine(t *testing.T) {
	if os.Getenv("BASELINE_TEST_DOCKER") != "1" {
		t.Skip("set BASELINE_TEST_DOCKER=1 to read the local container engines")
	}
	c := &ContainerCollector{Env: Host()}
	ctx := context.Background()
	start := time.Now()
	got, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, hash, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("collected in %v: %d bytes, %d engines, %d containers, %d images, %d stacks",
		time.Since(start).Round(time.Millisecond), len(b), len(got.Engines), len(got.Containers), len(got.Images), len(got.Stacks))
	for _, e := range got.Engines {
		t.Logf("engine %s kind=%s version=%s api=%s error=%q", e.Name, e.Kind, e.Version, e.APIVersion, e.Error)
	}
	if out := os.Getenv("BASELINE_TEST_DOCKER_OUT"); out != "" {
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if again, err := c.Collect(ctx); err == nil {
		if _, h2, _ := model.Encode(again); h2 != hash {
			t.Log("hash differs between two collections (a container may have changed)")
		}
	}

	t0 := time.Now()
	first := c.Sample(ctx, t0)
	time.Sleep(2 * time.Second)
	second := c.Sample(ctx, time.Now())
	viaCgroup := 0
	for _, st := range c.stats {
		if st.cgroup != "" {
			viaCgroup++
		}
	}
	t.Logf("samples: %d then %d (sampling took %v); %d of %d containers read from cgroup files",
		len(first), len(second), time.Since(t0)-2*time.Second, viaCgroup, len(c.stats))
	n := 0
	for _, s := range second {
		if s.Name == "cpu_pct" && n < 5 {
			t.Logf("%s %s = %.2f", s.Instance, s.Name, s.Value)
			n++
		}
	}
}

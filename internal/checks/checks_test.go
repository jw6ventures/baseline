package checks_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/checks"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

var ctx = context.Background()

// fakeRegistry serves digests and tags per repository.
type fakeRegistry struct {
	mu      sync.Mutex
	digests map[string]string
	tags    map[string][]string
	asked   []string
}

func (f *fakeRegistry) Digest(_ context.Context, ref registry.Ref) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, ref.String())
	if d, ok := f.digests[ref.String()]; ok {
		return d, nil
	}
	return "", errors.New("manifest unknown (404)")
}

func (f *fakeRegistry) Tags(_ context.Context, ref registry.Ref) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "tags "+ref.Repo())
	return f.tags[ref.Repo()], nil
}

func host(t *testing.T, s *store.Store) store.EnrollResult {
	t.Helper()
	hash := []byte(strings.Repeat("h", 32))
	if _, err := s.CreateEnrollmentToken(ctx, store.System, "", store.EnrollmentToken{Name: "t", ExpiresAt: time.Now().Add(time.Hour)}, hash); err != nil {
		t.Fatal(err)
	}
	r, err := s.Enroll(ctx, store.EnrollRequest{SecretHash: hash, MachineID: "m", Hostname: "h"},
		func(string) (string, time.Time, error) { return "s1", time.Now().Add(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPass(t *testing.T) {
	s, _ := storetest.New(t)
	r := host(t, s)
	old := "sha256:" + strings.Repeat("1", 64)
	c := model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker"}},
		Containers: []model.Container{
			{Engine: "docker", Name: "web", Image: "nginx:1.27.0", ImageID: "i1", State: "running"},
			{Engine: "docker", Name: "gone", Image: "ghcr.io/x/missing:1", ImageID: "i2", State: "running"},
		},
		Images: []model.ContainerImage{
			{Engine: "docker", ID: "i1", Digests: []string{"nginx@" + old}},
			{Engine: "docker", ID: "i2", Digests: []string{"ghcr.io/x/missing@" + old}},
		},
	}
	b, h, _ := model.Encode(c)
	if _, err := s.IngestSection(ctx, r.HostID, r.AgentID, model.SectionContainers, h, b, ""); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListContainers(ctx, []string{r.HostID})
	var web store.ContainerRow
	for _, x := range rows {
		if x.Name == "web" {
			web = x
		}
	}
	if err := s.SetSemverRule(ctx, store.System, web.CIID, &registry.Rule{Track: "minor"}); err != nil {
		t.Fatal(err)
	}

	reg := &fakeRegistry{
		digests: map[string]string{"docker.io/library/nginx:1.27.0": "sha256:" + strings.Repeat("2", 64)},
		tags:    map[string][]string{"docker.io/library/nginx": {"1.27.0", "1.27.3", "1.28.1", "2.0.0", "mainline"}},
	}
	ck := &checks.Checker{Store: s, Registry: reg}
	now := time.Now()
	ck.Pass(ctx, now)

	web, _ = s.GetContainer(ctx, web.CIID)
	if !web.Drift || web.CheckError != "" {
		t.Fatalf("web = %+v", web)
	}
	tags, _ := s.RepositoryTags(ctx, []string{"docker.io/library/nginx"})
	if tag, ok := registry.Advise("1.27.0", tags["docker.io/library/nginx"], registry.Rule{Track: "minor"}); !ok || tag != "1.28.1" {
		t.Fatalf("advice = %q from %v", tag, tags)
	}
	for _, x := range rows {
		if x.Name == "gone" {
			if g, _ := s.GetContainer(ctx, x.CIID); g.CheckError == "" {
				t.Fatalf("failed check not recorded: %+v", g)
			}
		}
	}

	// A second pass within the TTL asks nothing again.
	n := len(reg.asked)
	ck.Pass(ctx, now.Add(time.Minute))
	if len(reg.asked) != n {
		t.Fatalf("rechecked within the TTL: %v", reg.asked[n:])
	}
}

func TestProbe(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	ck := &checks.Checker{}
	addr := strings.TrimPrefix(ts.URL, "https://")
	c, err := ck.Probe(ctx, addr)
	if err != nil || c.Fingerprint == "" || c.NotAfter == "" || !strings.Contains(strings.Join(c.SANs, " "), "127.0.0.1") {
		t.Fatalf("probe = %+v %v", c, err)
	}
	if _, err := ck.Probe(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("probing a closed port succeeded")
	}
}

package vuln

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

// osvFake serves a bucket from memory and records what was asked.
type osvFake struct {
	mu    sync.Mutex
	files map[string][]byte
	asked []string
}

func (f *osvFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/")
	f.asked = append(f.asked, path)
	b, ok := f.files[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + model.Hash(b)[:16] + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Write(b)
}

func (f *osvFake) set(path string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = b
}

func (f *osvFake) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.asked
	f.asked = nil
	return a
}

func zipOf(t *testing.T, records ...string) []byte {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for i, r := range records {
		w, err := z.Create(string(rune('a'+i)) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(r))
	}
	z.Close()
	return buf.Bytes()
}

func addHost(t *testing.T, st *store.Store, name string, os model.OS, pkgs []model.Package, ups []model.Update) string {
	t.Helper()
	ctx := context.Background()
	secret := pki.NewTokenSecret()
	if _, err := st.CreateEnrollmentToken(ctx, store.System, "", store.EnrollmentToken{
		Name: name, ExpiresAt: time.Now().Add(time.Hour)}, pki.HashTokenSecret(secret)); err != nil {
		t.Fatal(err)
	}
	res, err := st.Enroll(ctx, store.EnrollRequest{SecretHash: pki.HashTokenSecret(secret), MachineID: name, Hostname: name},
		func(string) (string, time.Time, error) { return "serial-" + name, time.Now().Add(time.Hour), nil })
	if err != nil {
		t.Fatal(err)
	}
	os.Hostname = name
	for sec, v := range map[string]any{model.SectionOS: os, model.SectionPackages: model.Packages{Packages: pkgs},
		model.SectionUpdates: model.Updates{Updates: ups}} {
		b, hash, _ := model.Encode(v)
		if _, err := st.IngestSection(ctx, res.HostID, res.AgentID, sec, hash, b, ""); err != nil {
			t.Fatal(err)
		}
	}
	return res.HostID
}

func vulnIDs(t *testing.T, st *store.Store, host string) []string {
	t.Helper()
	ms, err := st.HostVulns(context.Background(), store.VulnFilter{HostIDs: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		s := m.VulnID + ":" + m.Package
		if m.FixAvailable {
			s += "!"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func TestSync(t *testing.T) {
	st, _ := storetest.New(t)
	ctx := context.Background()
	fake := &osvFake{files: map[string][]byte{
		"Rocky Linux/all.zip":         zipOf(t, rockyAdvisory, withdrawn),
		"Rocky Linux/modified_id.csv": []byte("2025-10-07T17:39:57.811960Z,RLSA-2025:9978\n"),
		"Ubuntu/all.zip":              zipOf(t, ubuntuFixed, ubuntuUnfixed, ubuntuNotice),
		// Stale since 2024: never read.
		"Ubuntu:24.04:LTS/all.zip": zipOf(t),
		"Ubuntu/modified_id.csv":   []byte("2026-10-12T14:20:24.496064664Z,UBUNTU-CVE-2025-15467\n2026-01-01T00:00:00Z,UBUNTU-CVE-2024-0001\n"),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	matched := map[string]int{}
	s := &Syncer{Store: st, URL: srv.URL, TempDir: t.TempDir(), Now: func() time.Time { return now },
		Matched: func(id string) { matched[id]++ }}

	rocky := addHost(t, st, "rocky", model.OS{ID: "rocky", VersionID: "9.6"},
		[]model.Package{{Manager: "dnf", Name: "sudo", Version: "1.9.5p2", Release: "10.el9_6", Arch: "x86_64"}},
		[]model.Update{{Manager: "dnf", Name: "sudo", Arch: "x86_64", Candidate: "1.9.5p2-10.el9_6.1"}})
	ubuntu := addHost(t, st, "ubuntu", model.OS{ID: "ubuntu", VersionID: "24.04"},
		[]model.Package{{Manager: "apt", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Arch: "amd64", Source: "openssl"},
			{Manager: "apt", Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64"}}, nil)
	fedora := addHost(t, st, "fedora", model.OS{ID: "fedora", VersionID: "42"},
		[]model.Package{{Manager: "dnf", Name: "sudo", Version: "1.9.15", Release: "1.fc42", Arch: "x86_64"}}, nil)

	if err := s.Pass(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := fake.take(); !slices.Equal(got, []string{"Rocky Linux/all.zip", "Ubuntu/all.zip"}) {
		t.Fatalf("asked %q", got)
	}
	if got := vulnIDs(t, st, rocky); !slices.Equal(got, []string{"RLSA-2025:9978:sudo!"}) {
		t.Fatalf("rocky: %q", got)
	}
	if got := vulnIDs(t, st, ubuntu); !slices.Equal(got, []string{"UBUNTU-CVE-2024-0001:bash", "UBUNTU-CVE-2025-15467:libssl3t64"}) {
		t.Fatalf("ubuntu: %q", got)
	}
	s.MatchHost(ctx, fedora)
	h, _ := st.GetHost(ctx, fedora)
	if h.VulnEcosystem != "" || h.VulnsAt.IsZero() || len(vulnIDs(t, st, fedora)) != 0 {
		t.Fatalf("fedora: %q %v", h.VulnEcosystem, h.VulnsAt)
	}
	if h, _ = st.GetHost(ctx, ubuntu); h.VulnEcosystem != "Ubuntu:24.04:LTS" || matched[ubuntu] == 0 {
		t.Fatalf("ubuntu host: %q", h.VulnEcosystem)
	}
	srcs, _ := st.VulnSources(ctx)
	if len(srcs) != 2 || srcs[0].Ecosystem != "Rocky Linux:9" || srcs[0].Dump != "Rocky Linux" || srcs[0].Vulns != 1 ||
		srcs[1].Vulns != 2 || srcs[1].Cursor.IsZero() || srcs[1].Error != "" {
		t.Fatalf("sources: %+v", srcs)
	}

	// Not due yet: nothing is asked.
	if s.Pass(ctx, false); len(fake.take()) != 0 {
		t.Fatal("synced before it was due")
	}

	// A day later: incremental. Ubuntu's fixed record now covers bash too,
	// and the unfixed one was withdrawn.
	now = now.Add(SyncEvery)
	fake.set("Ubuntu/modified_id.csv", []byte("2026-10-13T11:00:00Z,UBUNTU-CVE-2024-0001\n2026-10-13T10:00:00Z,UBUNTU-CVE-2025-15467\n"+
		"2026-10-12T14:20:24.496064664Z,UBUNTU-CVE-2025-15467\n"))
	fake.set("Ubuntu/UBUNTU-CVE-2024-0001.json", []byte(strings.Replace(ubuntuUnfixed, `"modified"`, `"withdrawn":"2026-10-13T11:00:00Z","modified"`, 1)))
	fake.set("Ubuntu/UBUNTU-CVE-2025-15467.json", []byte(strings.Replace(ubuntuFixed,
		`{"package":{"name":"openssl","ecosystem":"Ubuntu:22.04:LTS"}`,
		`{"package":{"name":"bash","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.2.21-2ubuntu5"}]}]},
		 {"package":{"name":"openssl","ecosystem":"Ubuntu:22.04:LTS"}`, 1)))
	if err := s.Pass(ctx, false); err != nil {
		t.Fatal(err)
	}
	asked := fake.take()
	if slices.Contains(asked, "Ubuntu/all.zip") || !slices.Contains(asked, "Ubuntu/UBUNTU-CVE-2024-0001.json") ||
		!slices.Contains(asked, "Rocky Linux/modified_id.csv") {
		t.Fatalf("incremental asked %q", asked)
	}
	if got := vulnIDs(t, st, ubuntu); !slices.Equal(got, []string{"UBUNTU-CVE-2025-15467:bash", "UBUNTU-CVE-2025-15467:libssl3t64"}) {
		t.Fatalf("ubuntu after update: %q", got)
	}
	if _, _, err := st.GetVuln(ctx, "UBUNTU-CVE-2024-0001"); err != store.ErrNotFound {
		t.Fatalf("withdrawn record kept: %v", err)
	}

	// Too many changes: a full sync, which finds the dump unchanged.
	now = now.Add(SyncEvery)
	var csv strings.Builder
	for i := range maxIncremental + 1 {
		fmt.Fprintf(&csv, "%s,UBUNTU-CVE-X%d\n", now.Add(-time.Duration(i)*time.Second).Format(time.RFC3339), i)
	}
	fake.set("Ubuntu/modified_id.csv", []byte(csv.String()))
	if err := s.Pass(ctx, false); err != nil {
		t.Fatal(err)
	}
	if asked := fake.take(); !slices.Contains(asked, "Ubuntu/all.zip") || slices.Contains(asked, "Ubuntu/UBUNTU-CVE-X0.json") {
		t.Fatalf("full asked %q", asked)
	}
	// The unchanged dump (304) doesn't undo the incremental changes.
	if got := vulnIDs(t, st, ubuntu); len(got) != 2 {
		t.Fatalf("after 304: %q", got)
	}

	// A broken mirror is recorded and retried an hour later, not sooner.
	now = now.Add(SyncEvery)
	fake.set("Rocky Linux/modified_id.csv", []byte("garbage"))
	if err := s.Pass(ctx, false); err == nil {
		t.Fatal("no error from a bad change list")
	}
	srcs, _ = st.VulnSources(ctx)
	if srcs[0].Error == "" || srcs[0].Vulns != 1 {
		t.Fatalf("error not recorded: %+v", srcs[0])
	}
	fake.take()
	if s.Pass(ctx, false); slices.Contains(fake.take(), "Rocky Linux/modified_id.csv") {
		t.Fatal("retried at once")
	}
}

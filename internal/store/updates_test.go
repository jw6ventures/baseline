package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestUpdatesProjection(t *testing.T) {
	s := newTestStore(t)
	tok := newToken(t, s, 0)
	a := enroll(t, s, tok, "m1", "d1", "s1")
	b := enroll(t, s, tok, "m2", "d2", "s2")
	ingest := func(r store.EnrollResult, u model.Updates) {
		t.Helper()
		p, h := payload(t, u)
		if _, err := s.IngestSection(ctx, r.HostID, r.AgentID, model.SectionUpdates, h, p, ""); err != nil {
			t.Fatal(err)
		}
	}
	openssl := model.Update{Manager: "apt", Name: "openssl", Arch: "amd64", Installed: "3.0.13-1", Candidate: "3.0.13-2",
		Security: true, Advisories: []string{"USN-1", "USN-2"}}
	tzdata := model.Update{Manager: "apt", Name: "tzdata", Installed: "2025a", Candidate: "2025b"}
	ingest(a, model.Updates{Managers: []string{"apt"}, Updates: []model.Update{openssl, tzdata}})
	ingest(b, model.Updates{Managers: []string{"apt"}, Updates: []model.Update{openssl}})

	ups, err := s.HostUpdates(ctx, a.HostID)
	if err != nil || len(ups) != 2 || ups[0].Name != "openssl" || strings.Join(ups[0].Advisories, ",") != "USN-1,USN-2" {
		t.Fatalf("%+v %v", ups, err)
	}
	firstSeen := ups[0].FirstSeen
	h, _ := s.GetHost(ctx, a.HostID)
	if h.Updates != 2 || h.SecurityUpdates != 1 || h.UpdatesAt.IsZero() {
		t.Fatalf("host counts = %d/%d at %v", h.Updates, h.SecurityUpdates, h.UpdatesAt)
	}

	// tzdata gets installed: openssl keeps its first_seen.
	time.Sleep(10 * time.Millisecond)
	ingest(a, model.Updates{Managers: []string{"apt"}, Updates: []model.Update{openssl}})
	ups, _ = s.HostUpdates(ctx, a.HostID)
	if len(ups) != 1 || !ups[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("after tzdata installed: %+v (first seen was %v)", ups, firstSeen)
	}

	// Available updates aren't configuration: no history.
	hist, _ := s.HostHistory(ctx, a.HostID, 10)
	for _, e := range hist {
		if e.Section == model.SectionUpdates {
			t.Fatalf("updates recorded in history: %+v", e)
		}
	}

	pkgs, err := s.UpdatesByPackage(ctx, []string{a.HostID, b.HostID}, "", false)
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "openssl" || len(pkgs[0].HostIDs) != 2 || !pkgs[0].Security {
		t.Fatalf("by package = %+v %v", pkgs, err)
	}
	// Scoped to hosts the caller may see.
	if pkgs, _ := s.UpdatesByPackage(ctx, []string{b.HostID}, "ssl", true); len(pkgs) != 1 || len(pkgs[0].HostIDs) != 1 {
		t.Fatalf("scoped = %+v", pkgs)
	}
	if pkgs, _ := s.UpdatesByPackage(ctx, nil, "", false); len(pkgs) != 0 {
		t.Fatalf("no hosts = %+v", pkgs)
	}
}

func TestSmartProjectionAndHistory(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	yes, no := true, false
	ingest := func(sm model.Smart) {
		t.Helper()
		p, h := payload(t, sm)
		if _, err := s.IngestSection(ctx, r.HostID, r.AgentID, model.SectionSmart, h, p, ""); err != nil {
			t.Fatal(err)
		}
	}
	ingest(model.Smart{Devices: []model.SmartDevice{{Name: "sda", Serial: "A", Passed: &yes}, {Name: "sdb", Serial: "B", Passed: &yes}}})
	ingest(model.Smart{Devices: []model.SmartDevice{{Name: "sda", Serial: "A", Passed: &yes, Pending: 3}, {Name: "sdb", Serial: "B", Passed: &no}}})
	h, _ := s.GetHost(ctx, r.HostID)
	if h.DisksFailing != 1 || h.DisksDegrading != 1 {
		t.Fatalf("failing %d, degrading %d", h.DisksFailing, h.DisksDegrading)
	}
	hist, _ := s.HostHistory(ctx, r.HostID, 10)
	if hist[0].Section != model.SectionSmart || !strings.Contains(string(hist[0].Diff), "devices[sdb].passed") {
		t.Fatalf("history = %s", hist[0].Diff)
	}
}

func TestReleasesAndAgentUpdates(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	connect := func(version, arch string) store.Connected {
		t.Helper()
		c, err := s.AgentConnected(ctx, r.HostID, r.AgentID, store.Hello{AgentVersion: version, Arch: arch, MachineID: "m1"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	connect("1.0", "amd64")

	for _, v := range []string{"1.0", "1.1", "1.2"} {
		if _, err := s.PublishRelease(ctx, store.Release{Version: v, Arch: "amd64", SHA256: "aa" + v, Signature: []byte("sig"), Size: 1, Path: "/x/" + v}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Re-publishing identical content changes nothing.
	if changed, _ := s.PublishRelease(ctx, store.Release{Version: "1.2", Arch: "amd64", SHA256: "aa1.2", Signature: []byte("sig"), Size: 1, Path: "/x/1.2"}); changed {
		t.Fatal("identical release republished")
	}
	rels, _ := s.ListReleases(ctx)
	if len(rels) != 3 || rels[0].Version != "1.2" {
		t.Fatalf("releases = %+v", rels)
	}

	// No arm64 build of 1.2, and the host is already on 1.0: only a real
	// move is recorded.
	if got, _ := s.RequestAgentUpdate(ctx, admin, []string{r.HostID}, "1.0"); len(got) != 0 {
		t.Fatal("update to the running version")
	}
	got, err := s.RequestAgentUpdate(ctx, admin, []string{r.HostID}, "1.1")
	if err != nil || len(got) != 1 || got[0].AgentID != r.AgentID {
		t.Fatalf("%+v %v", got, err)
	}
	if c := connect("1.0", "amd64"); c.UpdateTarget != "1.1" {
		t.Fatalf("target = %q", c.UpdateTarget)
	}
	// Pruning keeps a version some host is asked to move to.
	pruned, _ := s.PruneReleases(ctx, 1)
	if len(pruned) != 1 || pruned[0].Version != "1.0" {
		t.Fatalf("pruned = %+v", pruned)
	}

	// The agent comes back on 1.1: target cleared, version change recorded.
	if c := connect("1.1", "amd64"); c.UpdateTarget != "" {
		t.Fatalf("target after update = %q", c.UpdateTarget)
	}
	h, _ := s.GetHost(ctx, r.HostID)
	if h.AgentVersion != "1.1" || h.AgentUpdateTarget != "" || h.AgentArch != "amd64" {
		t.Fatalf("host = %+v", h)
	}
	hist, _ := s.HostHistory(ctx, r.HostID, 5)
	if hist[0].Section != "agent" || !strings.Contains(string(hist[0].Diff), `"to": "1.1"`) {
		t.Fatalf("history = %s %s", hist[0].Section, hist[0].Diff)
	}

	// A failed attempt drops the target, so it isn't retried on every connect.
	s.RequestAgentUpdate(ctx, admin, []string{r.HostID}, "1.2")
	if err := s.AgentUpdateFailed(ctx, r.HostID, r.AgentID, "1.2", "signature doesn't verify"); err != nil {
		t.Fatal(err)
	}
	h, _ = s.GetHost(ctx, r.HostID)
	if h.AgentUpdateTarget != "" || h.AgentUpdateError != "signature doesn't verify" {
		t.Fatalf("after failure: %+v", h)
	}
	if _, err := s.GetRelease(ctx, "1.0", "amd64"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pruned release: %v", err)
	}
	entries, _ := s.ListAudit(ctx, 0, 20)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if a := strings.Join(actions, " "); !strings.Contains(a, "host.agent_update_failed") || !strings.Contains(a, "host.agent_version") ||
		strings.Count(a, "host.agent_update ") != 2 {
		t.Fatalf("audit = %s", a)
	}
}

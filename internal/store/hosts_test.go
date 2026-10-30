package store_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

var admin = store.UserActor("00000000-0000-0000-0000-000000000001", "10.0.0.1")

func newToken(t *testing.T, s *store.Store, maxUses int, groups ...string) []byte {
	t.Helper()
	secretHash := []byte(t.Name() + strings.Repeat("x", 32))[:32]
	_, err := s.CreateEnrollmentToken(ctx, admin, "", store.EnrollmentToken{
		Name: "lab", MaxUses: maxUses, ExpiresAt: time.Now().Add(time.Hour), DefaultGroups: groups,
	}, secretHash)
	if err != nil {
		t.Fatal(err)
	}
	return secretHash
}

func issuer(serial string) store.IssueFunc {
	return func(string) (string, time.Time, error) { return serial, time.Now().Add(90 * 24 * time.Hour), nil }
}

func enroll(t *testing.T, s *store.Store, hash []byte, machineID, dmi, serial string) store.EnrollResult {
	t.Helper()
	res, err := s.Enroll(ctx, store.EnrollRequest{SecretHash: hash, MachineID: machineID, DMIUUID: dmi, Hostname: "web1"}, issuer(serial))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestEnrollmentTokenLimits(t *testing.T) {
	s := newTestStore(t)
	g, _ := s.CreateHostGroup(ctx, admin, "media", "")
	hash := newToken(t, s, 1, g.ID)

	res := enroll(t, s, hash, "m1", "d1", "s1")
	if res.AgentID == "" {
		t.Fatalf("res = %+v", res)
	}
	h, err := s.GetHost(ctx, res.HostID)
	if err != nil || len(h.GroupNames) != 1 || h.GroupNames[0] != "media" {
		t.Fatalf("host groups: %+v %v", h.GroupNames, err)
	}
	// Single-use: a second enrollment fails, as does an unknown secret.
	if _, err := s.Enroll(ctx, store.EnrollRequest{SecretHash: hash, MachineID: "m2"}, issuer("s2")); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("second use: %v", err)
	}
	if _, err := s.Enroll(ctx, store.EnrollRequest{SecretHash: []byte("nope")}, issuer("s3")); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("unknown token: %v", err)
	}
	toks, _ := s.ListEnrollmentTokens(ctx)
	if len(toks) != 1 || toks[0].Uses != 1 || toks[0].Usable() {
		t.Fatalf("tokens = %+v", toks)
	}
}

func TestRevokedTokenRejected(t *testing.T) {
	s := newTestStore(t)
	hash := newToken(t, s, 0)
	toks, _ := s.ListEnrollmentTokens(ctx)
	if err := s.RevokeEnrollmentToken(ctx, admin, toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, store.EnrollRequest{SecretHash: hash}, issuer("s")); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("revoked token: %v", err)
	}
}

// Enrolling with another host's machine-id and DMI UUID (both reported by
// the agent, and machine-id is world-readable) must not take that host over.
func TestSameIdentityNeverRebindsAHost(t *testing.T) {
	s := newTestStore(t)
	hash := newToken(t, s, 0)
	first := enroll(t, s, hash, "m1", "", "s1") // e.g. an LXC container: no DMI UUID
	if err := s.RevokeHost(ctx, admin, first.HostID); err != nil {
		t.Fatal(err)
	}
	second := enroll(t, s, hash, "m1", "", "s2")
	if second.HostID == first.HostID {
		t.Fatal("enrollment re-bound an existing host")
	}
	// The first host stays revoked; the second is separate.
	if h, _ := s.GetHost(ctx, first.HostID); !h.Revoked {
		t.Fatal("enrollment un-revoked a host")
	}

	live := enroll(t, s, hash, "m2", "d2", "s3")
	clone := enroll(t, s, hash, "m2", "d2", "s4")
	if clone.HostID == live.HostID {
		t.Fatal("clone took over the live host")
	}
	if _, err := s.AuthenticateAgent(ctx, live.AgentID, "s3"); err != nil {
		t.Fatalf("original agent locked out: %v", err)
	}
	for _, id := range []string{live.HostID, clone.HostID} {
		if h, _ := s.GetHost(ctx, id); !h.DuplicateIdentity {
			t.Errorf("host %s not flagged", id)
		}
	}
	// Revoked hosts don't count as duplicates.
	if h, _ := s.GetHost(ctx, second.HostID); h.DuplicateIdentity {
		t.Error("duplicate of a revoked host flagged")
	}
}

func TestAgentAuthAndCertRenewal(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")

	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "other"); !errors.Is(err, store.ErrUnknownCert) {
		t.Fatalf("wrong serial: %v", err)
	}
	if err := s.RenewCert(ctx, res.HostID, res.AgentID, "s1", "s2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Both serials work until the new one is used.
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s1"); err != nil {
		t.Fatalf("old serial before switch: %v", err)
	}
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s1"); !errors.Is(err, store.ErrUnknownCert) {
		t.Fatalf("old serial after switch: %v", err)
	}

	if err := s.RevokeHost(ctx, admin, res.HostID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s2"); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	// A stream that authenticated just before the revocation can't connect
	// or renew after it.
	if _, err := s.AgentConnected(ctx, res.HostID, res.AgentID, store.Hello{}); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("connect after revoke: %v", err)
	}
	if err := s.RenewCert(ctx, res.HostID, res.AgentID, "s2", "s3", time.Now()); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("renew after revoke: %v", err)
	}
}

// Renewal responses lost twice in a row: the agent still holds s1 and must
// still get in.
func TestRepeatedLostRenewals(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	s.RenewCert(ctx, res.HostID, res.AgentID, "s1", "s2", time.Now().Add(time.Hour))
	s.RenewCert(ctx, res.HostID, res.AgentID, "s1", "s3", time.Now().Add(time.Hour))
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s1"); err != nil {
		t.Fatalf("agent stranded: %v", err)
	}
	if _, err := s.AuthenticateAgent(ctx, res.AgentID, "s3"); err != nil {
		t.Fatal(err)
	}
}

func payload(t *testing.T, v any) ([]byte, string) {
	t.Helper()
	b, h, err := model.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b, h
}

func TestIngestAndHistory(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")

	osv := model.OS{Hostname: "web1", ID: "ubuntu", VersionID: "24.04", PrettyName: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-40-generic", Arch: "x86_64"}
	b, h := payload(t, osv)
	if changed, err := s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionOS, h, b, ""); err != nil || !changed {
		t.Fatalf("first ingest: %v %v", changed, err)
	}
	// Same hash: no change, no history.
	if changed, err := s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionOS, h, b, ""); err != nil || changed {
		t.Fatalf("repeat ingest: %v %v", changed, err)
	}
	osv.Kernel = "6.8.0-45-generic"
	b, h = payload(t, osv)
	s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionOS, h, b, "")

	pk := model.Packages{Managers: []string{"apt"}, Packages: []model.Package{
		{Manager: "apt", Name: "openssl", Version: "3.0.13-1", Arch: "amd64", Source: "openssl"},
		{Manager: "apt", Name: "curl", Version: "8.5.0-2", Arch: "amd64"},
	}}
	b, h = payload(t, pk)
	s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionPackages, h, b, "")
	pk.Packages[0].Version = "3.0.15-1"
	b, h = payload(t, pk)
	s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionPackages, h, b, "")

	host, err := s.GetHost(ctx, res.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if host.Kernel != "6.8.0-45-generic" || host.OSPretty != "Ubuntu 24.04.1 LTS" || host.PackageCount != 2 {
		t.Fatalf("host = %+v", host)
	}
	pkgs, _ := s.HostPackages(ctx, res.HostID, "SSL")
	if len(pkgs) != 1 || pkgs[0].Version != "3.0.15-1" || pkgs[0].Source != "openssl" {
		t.Fatalf("packages = %+v", pkgs)
	}

	hist, err := s.HostHistory(ctx, res.HostID, 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range hist {
		got = append(got, e.Section+":"+string(e.Diff))
	}
	if len(hist) != 4 {
		t.Fatalf("history = %v", got)
	}
	var d struct {
		Changed []struct{ Field, From, To string }
	}
	json.Unmarshal(hist[0].Diff, &d)
	if hist[0].Section != "packages" || len(d.Changed) != 1 || d.Changed[0].To != "3.0.15-1" {
		t.Fatalf("latest = %v", got[0])
	}
	if !strings.Contains(got[3], `"initial": true`) || hist[0].Actor != "agent:"+res.AgentID {
		t.Fatalf("oldest = %v, actor %s", got[3], hist[0].Actor)
	}
}

func TestAgentConnectedReportsHashesAndReboots(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	b, h := payload(t, model.OS{Hostname: "web1"})
	s.IngestSection(ctx, res.HostID, res.AgentID, model.SectionOS, h, b, "")

	hello := store.Hello{AgentVersion: "1.0", MachineID: "m1", DMIUUID: "d1", BootID: "boot-a", BootTime: time.Now().Add(-time.Hour), Capabilities: []string{"apt"}}
	c, err := s.AgentConnected(ctx, res.HostID, res.AgentID, hello)
	if err != nil || c.Hashes[model.SectionOS] != h || len(c.Hashes) != 1 {
		t.Fatalf("hashes = %v, %v", c.Hashes, err)
	}
	hello.BootID = "boot-b"
	s.AgentConnected(ctx, res.HostID, res.AgentID, hello)
	hist, _ := s.HostHistory(ctx, res.HostID, 10)
	if hist[0].Section != "boot" {
		t.Fatalf("expected a boot history entry, got %s", hist[0].Section)
	}
	host, _ := s.GetHost(ctx, res.HostID)
	if !host.Connected || host.AgentVersion != "1.0" || len(host.Capabilities) != 1 {
		t.Fatalf("host = %+v", host)
	}
	s.AgentDisconnected(ctx, res.HostID)
	if host, _ := s.GetHost(ctx, res.HostID); host.Connected {
		t.Fatal("still connected")
	}
}

func TestSetHostGroups(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	a, _ := s.CreateHostGroup(ctx, admin, "alpha", "")
	b, _ := s.CreateHostGroup(ctx, admin, "beta", "")
	if err := s.SetHostGroups(ctx, admin, res.HostID, []string{b.ID, a.ID, "not-a-group"}); err != nil {
		t.Fatal(err)
	}
	h, _ := s.GetHost(ctx, res.HostID)
	if strings.Join(h.GroupNames, ",") != "alpha,beta" {
		t.Fatalf("groups = %v", h.GroupNames)
	}
	if err := s.SetHostGroups(ctx, admin, "00000000-0000-0000-0000-000000000000", nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
}

func TestDuplicateFlagClearsWhenFixed(t *testing.T) {
	s := newTestStore(t)
	hash := newToken(t, s, 0)
	a := enroll(t, s, hash, "m1", "d1", "s1")
	b := enroll(t, s, hash, "m1", "d2", "s2") // clone: same machine-id
	if h, _ := s.GetHost(ctx, a.HostID); !h.DuplicateIdentity {
		t.Fatal("original not flagged")
	}
	// The clone gets a fresh machine-id and reconnects; then the original does.
	s.AgentConnected(ctx, b.HostID, b.AgentID, store.Hello{MachineID: "m2", DMIUUID: "d2"})
	s.AgentConnected(ctx, a.HostID, a.AgentID, store.Hello{MachineID: "m1", DMIUUID: "d1"})
	for _, id := range []string{a.HostID, b.HostID} {
		if h, _ := s.GetHost(ctx, id); h.DuplicateIdentity {
			t.Errorf("host %s still flagged", id)
		}
	}
}

// Clones of one VM template reconnecting together (after a server restart)
// flag each other without deadlocking.
func TestClonesConnectConcurrently(t *testing.T) {
	s := newTestStore(t)
	tok := newToken(t, s, 0)
	var hosts []store.EnrollResult
	for i := range 4 {
		hosts = append(hosts, enroll(t, s, tok, "m"+string(rune('a'+i)), "same-dmi", "s"+string(rune('a'+i))))
	}
	errs := make(chan error, 40)
	for round := range 10 {
		for _, h := range hosts {
			go func() {
				_, err := s.AgentConnected(ctx, h.HostID, h.AgentID, store.Hello{MachineID: h.HostID, DMIUUID: "same-dmi", BootID: string(rune('a' + round))})
				errs <- err
			}()
		}
	}
	for range 40 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range hosts {
		if got, _ := s.GetHost(ctx, h.HostID); !got.DuplicateIdentity {
			t.Fatalf("%s not flagged", h.HostID)
		}
	}
}

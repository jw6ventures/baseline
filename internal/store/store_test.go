package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/store/storetest"
)

func newTestStore(t *testing.T) *store.Store {
	s, _ := storetest.New(t)
	return s
}

var ctx = context.Background()

func TestSchemaVersionAndReopen(t *testing.T) {
	s, dbURL := storetest.New(t)

	// A second open finds the schema and leaves it alone.
	storetest.Open(t, dbURL).Close()

	want, err := store.SchemaVersion(filepath.Join("..", "..", "db", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var version string
	s.DB().QueryRow(`SELECT value FROM application WHERE key = 'version'`).Scan(&version)
	if strings.TrimPrefix(version, "v") != want {
		t.Fatalf("version = %q, want %q", version, want)
	}
}

func TestSchemaVersionFromMigrations(t *testing.T) {
	dir := t.TempDir()
	if _, err := store.SchemaVersion(dir); err == nil {
		t.Fatal("no migrations: no error")
	}
	for _, name := range []string{"v0.9.2.sql", "v0.10.0.sql", "v0.2.0.sql", "v1.0.0.sql.bak", ".gitkeep", "notes.md"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0o644)
	}
	if v, err := store.SchemaVersion(dir); err != nil || v != "0.10.0" {
		t.Fatalf("SchemaVersion = %q, %v; want 0.10.0 (numeric, not lexical, order)", v, err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	u, err := s.UpsertUser(ctx, "sub-1", "a@example.com", "Ann")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.UpsertUser(ctx, "sub-1", "ann@example.com", "Ann B")
	if err != nil || again.ID != u.ID {
		t.Fatalf("upsert should keep the ID: %v %v", again, err)
	}

	tok, err := s.CreateSession(ctx, store.NewSession{
		UserID: u.ID, IdPGroups: []string{"lab-admins"}, IdleTimeout: time.Hour, MaxLifetime: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ss, err := s.LookupSession(ctx, tok, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ss.User.Email != "ann@example.com" || len(ss.IdPGroups) != 1 || ss.IdPGroups[0] != "lab-admins" {
		t.Fatalf("session = %+v", ss)
	}

	// The cookie token itself is never stored.
	var n int
	s.DB().QueryRow(`SELECT count(*) FROM session WHERE id_hash = $1`, []byte(tok)).Scan(&n)
	if n != 0 {
		t.Fatal("raw token stored")
	}

	if _, err := s.LookupSession(ctx, "nope", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	if err := s.DeleteSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session still valid: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.UpsertUser(ctx, "sub-1", "", "")
	tok, err := s.CreateSession(ctx, store.NewSession{UserID: u.ID, IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.DB().Exec(`UPDATE session SET expires_at = now() - interval '1 second'`)
	if _, err := s.LookupSession(ctx, tok, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
	if n, err := s.PurgeSessions(ctx); err != nil || n != 1 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}

func TestSessionLookupWithoutSliding(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.UpsertUser(ctx, "sub-1", "", "")
	tok, _ := s.CreateSession(ctx, store.NewSession{UserID: u.ID, IdleTimeout: time.Hour, MaxLifetime: 2 * time.Hour})
	s.DB().Exec(`UPDATE session SET last_seen = now() - interval '10 minutes', expires_at = now() + interval '50 minutes'`)
	before, err := s.LookupSession(ctx, tok, 0)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(before.ExpiresAt) > 51*time.Minute {
		t.Fatalf("a lookup without sliding moved the expiry to %v", before.ExpiresAt)
	}
	var seen time.Time
	s.DB().QueryRow(`SELECT last_seen FROM session`).Scan(&seen)
	if time.Since(seen) < 9*time.Minute {
		t.Fatalf("a lookup without sliding touched last_seen: %v", seen)
	}
}

func TestSessionSlidesButNotPastAbsolute(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.UpsertUser(ctx, "sub-1", "", "")
	tok, _ := s.CreateSession(ctx, store.NewSession{UserID: u.ID, IdleTimeout: time.Hour, MaxLifetime: 2 * time.Hour})
	s.DB().Exec(`UPDATE session SET last_seen = now() - interval '10 minutes',
		absolute_expires = now() + interval '30 minutes'`)
	ss, err := s.LookupSession(ctx, tok, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ss.ExpiresAt.Equal(ss.AbsoluteExp) {
		t.Fatalf("expires %v should be capped at absolute %v", ss.ExpiresAt, ss.AbsoluteExp)
	}
}

func TestRoleBindingsAndHostGroups(t *testing.T) {
	s := newTestStore(t)
	actor := store.UserActor("00000000-0000-0000-0000-000000000001", "10.0.0.1")

	media, err := s.CreateHostGroup(ctx, actor, "media", "Plex and friends")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateHostGroup(ctx, actor, "media", ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate group: %v", err)
	}

	if _, err := s.CreateRoleBinding(ctx, actor, store.RoleBinding{IdPGroup: "lab-viewers", Role: rbac.Viewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRoleBinding(ctx, actor, store.RoleBinding{IdPGroup: "lab-viewers", Role: rbac.Viewer}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate global binding: %v", err)
	}
	scoped, err := s.CreateRoleBinding(ctx, actor, store.RoleBinding{IdPGroup: "lab-media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})
	if err != nil || scoped.ScopeGroupName != "media" {
		t.Fatalf("scoped binding: %+v %v", scoped, err)
	}
	admin, err := s.CreateRoleBinding(ctx, actor, store.RoleBinding{IdPGroup: "lab-admins", Role: rbac.Admin, ScopeGroupID: media.ID})
	if err != nil || admin.ScopeGroupID != "" {
		t.Fatalf("admin binding must be global: %+v %v", admin, err)
	}
	if _, err := s.CreateRoleBinding(ctx, actor, store.RoleBinding{IdPGroup: "x", Role: rbac.Viewer, ScopeGroupID: "not-a-uuid"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad scope: %v", err)
	}

	bs, err := s.RBACBindings(ctx)
	if err != nil || len(bs) != 3 {
		t.Fatalf("bindings = %v, %v", bs, err)
	}
	g := rbac.Resolve([]string{"lab-media-ops"}, bs, "")
	if !g.HasOn(rbac.Operator, []string{media.ID}) || g.Has(rbac.Operator) {
		t.Fatal("scoped grant did not round-trip")
	}

	// Deleting the group cascades its scoped bindings.
	if err := s.DeleteHostGroup(ctx, actor, media.ID); err != nil {
		t.Fatal(err)
	}
	if bs, _ := s.ListRoleBindings(ctx); len(bs) != 2 {
		t.Fatalf("after group delete: %d bindings", len(bs))
	}
	if err := s.DeleteRoleBinding(ctx, actor, admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoleBinding(ctx, actor, admin.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}

	// Every mutation above that succeeded was audited.
	entries, _ := s.ListAudit(ctx, 0, 100)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	want := "role_binding.delete host_group.delete role_binding.create role_binding.create role_binding.create host_group.create"
	if got := strings.Join(actions, " "); got != want {
		t.Fatalf("audit actions:\n got %s\nwant %s", got, want)
	}
	if entries[0].Actor != actor.ID || entries[0].ActorIP != "10.0.0.1" {
		t.Fatalf("actor = %q %q", entries[0].Actor, entries[0].ActorIP)
	}
}

func TestAuditChainVerifies(t *testing.T) {
	s := newTestStore(t)
	for i := range 5 {
		ev := store.AuditEvent{Action: "test.event", ObjectID: fmt.Sprint(i),
			Details: map[string]any{"z": i, "a": []string{"x"}, "nested": map[string]any{"k": "v"}}}
		if err := s.Audit(ctx, store.System, ev); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.VerifyAudit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK() || v.Checked != 5 {
		t.Fatalf("verify = %+v", v)
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	s := newTestStore(t)
	s.Audit(ctx, store.System, store.AuditEvent{Action: "test.event"})
	for _, q := range []string{
		`UPDATE audit_log SET action = 'x'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		if _, err := s.DB().Exec(q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v", q, err)
		}
	}
}

func TestAuditDetectsTampering(t *testing.T) {
	s := newTestStore(t)
	for i := range 3 {
		s.Audit(ctx, store.System, store.AuditEvent{Action: "test.event", ObjectID: fmt.Sprint(i)})
	}
	// Someone with superuser rights disables the guard and edits row 2.
	for _, q := range []string{
		`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update`,
		`UPDATE audit_log SET object_id = 'forged' WHERE id = 2`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.VerifyAudit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.BrokenAt != 2 || !strings.Contains(v.Reason, "altered") {
		t.Fatalf("verify = %+v", v)
	}

	// Removing a row breaks the link from the next one.
	s.DB().Exec(`UPDATE audit_log SET object_id = '1' WHERE id = 2`)
	s.DB().Exec(`DELETE FROM audit_log WHERE id = 2`)
	if v, _ := s.VerifyAudit(ctx); v.BrokenAt != 3 {
		t.Fatalf("after delete: %+v", v)
	}
}

func TestAuditConcurrentAppendsKeepOneChain(t *testing.T) {
	s := newTestStore(t)
	errs := make(chan error, 20)
	for i := range 20 {
		go func() {
			errs <- s.Audit(ctx, store.System, store.AuditEvent{Action: "test.event", ObjectID: fmt.Sprint(i)})
		}()
	}
	for range 20 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if v, err := s.VerifyAudit(ctx); err != nil || !v.OK() || v.Checked != 20 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}

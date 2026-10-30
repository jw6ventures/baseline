package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/rbac"
)

// apiTokenPrefix marks a token as Baseline's, so one in a log or a config
// file is recognizable and a secret scanner can match it.
const apiTokenPrefix = "baseline_api_"

// legacyAPITokenPrefix marks tokens made before the rename to Baseline,
// which keep working: the stored hash covers the whole token.
const legacyAPITokenPrefix = "jcmdb_api_"

// APIToken lets a script call /api/v1 as its user with at most the roles
// it names (docs/architecture.md §5.1). The secret is shown once, when the
// token is created; only its SHA-256 is stored.
type APIToken struct {
	ID        string
	UserID    string
	Name      string
	Roles     []rbac.Role
	IdPGroups []string // the creating session's, for resolving grants
	CreatedAt time.Time
	LastUsed  time.Time
	ExpiresAt time.Time // zero: never
	Revoked   bool
	RevokedAt time.Time

	User User // filled by LookupAPIToken
}

// Usable reports whether the token still authenticates.
func (t APIToken) Usable() bool {
	return !t.Revoked && (t.ExpiresAt.IsZero() || time.Now().Before(t.ExpiresAt))
}

// NewAPIToken creates a token for the user and returns the secret the
// caller gets to see once. roles must be a subset of what the user holds;
// the caller checks that. expires zero means never.
func (s *Store) NewAPIToken(ctx context.Context, actor Actor, userID, name string, roles []rbac.Role, idpGroups []string,
	expires time.Time) (APIToken, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return APIToken{}, "", err
	}
	secret := apiTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	t := APIToken{UserID: userID, Name: name, Roles: roles, IdPGroups: idpGroups, ExpiresAt: expires}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = string(r)
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var exp sql.NullTime
		if !expires.IsZero() {
			exp = sql.NullTime{Time: expires, Valid: true}
		}
		err := tx.QueryRowContext(ctx, `
			INSERT INTO api_token (user_id, name, hash, roles, idp_groups, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
			userID, name, hashToken(secret), pq.Array(names), pq.Array(nonNil(idpGroups)), exp).Scan(&t.ID, &t.CreatedAt)
		if err != nil {
			return mapErr(err)
		}
		details := map[string]any{"name": name, "roles": names}
		if !expires.IsZero() {
			details["expires_at"] = expires.UTC().Format(time.RFC3339)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "api_token.create", ObjectType: "api_token", ObjectID: t.ID,
			Details: details})
	})
	if err != nil {
		return APIToken{}, "", err
	}
	return t, secret, nil
}

const apiTokenCols = `t.id, t.user_id, t.name, t.roles, t.idp_groups, t.created_at, COALESCE(t.last_used, 'epoch'),
	COALESCE(t.expires_at, 'epoch'), t.revoked_at IS NOT NULL, COALESCE(t.revoked_at, 'epoch')`

func scanAPIToken(row interface{ Scan(...any) error }, t *APIToken) error {
	var roles []string
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, pq.Array(&roles), pq.Array(&t.IdPGroups), &t.CreatedAt, &t.LastUsed,
		&t.ExpiresAt, &t.Revoked, &t.RevokedAt); err != nil {
		return err
	}
	for _, r := range roles {
		t.Roles = append(t.Roles, rbac.Role(r))
	}
	for _, at := range []*time.Time{&t.LastUsed, &t.ExpiresAt, &t.RevokedAt} {
		if at.Unix() == 0 {
			*at = time.Time{}
		}
	}
	return nil
}

// ListAPITokens lists a user's tokens, newest first, revoked ones included.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiTokenCols+` FROM api_token t WHERE t.user_id = $1
		ORDER BY t.created_at DESC`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := scanAPIToken(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes one of the user's tokens. A token of another
// user, or one already revoked, is ErrNotFound.
func (s *Store) RevokeAPIToken(ctx context.Context, actor Actor, userID, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `UPDATE api_token SET revoked_at = now()
			WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING name`, id, userID).Scan(&name)
		if err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "api_token.revoke", ObjectType: "api_token", ObjectID: id,
			Details: map[string]any{"name": name}})
	})
}

// LookupAPIToken returns the live token for a bearer secret, with its
// user, or ErrNotFound when it is unknown, revoked or expired. Use is
// recorded at most once a minute.
func (s *Store) LookupAPIToken(ctx context.Context, secret string) (APIToken, error) {
	if !strings.HasPrefix(secret, apiTokenPrefix) && !strings.HasPrefix(secret, legacyAPITokenPrefix) {
		return APIToken{}, ErrNotFound
	}
	var t APIToken
	var roles []string
	err := s.db.QueryRowContext(ctx, `SELECT `+apiTokenCols+`, u.id, u.oidc_sub, u.email, u.name, COALESCE(u.last_login, 'epoch')
		FROM api_token t JOIN app_user u ON u.id = t.user_id WHERE t.hash = $1`, hashToken(secret)).
		Scan(&t.ID, &t.UserID, &t.Name, pq.Array(&roles), pq.Array(&t.IdPGroups), &t.CreatedAt, &t.LastUsed,
			&t.ExpiresAt, &t.Revoked, &t.RevokedAt, &t.User.ID, &t.User.OIDCSub, &t.User.Email, &t.User.Name, &t.User.LastLogin)
	if err != nil {
		return APIToken{}, mapErr(err)
	}
	for _, r := range roles {
		t.Roles = append(t.Roles, rbac.Role(r))
	}
	for _, at := range []*time.Time{&t.LastUsed, &t.ExpiresAt, &t.RevokedAt} {
		if at.Unix() == 0 {
			*at = time.Time{}
		}
	}
	if !t.Usable() {
		return APIToken{}, ErrNotFound
	}
	if time.Since(t.LastUsed) > time.Minute {
		now := time.Now()
		if _, err := s.db.ExecContext(ctx, `UPDATE api_token SET last_used = $2 WHERE id = $1`, t.ID, now); err != nil {
			return APIToken{}, err
		}
		t.LastUsed = now
	}
	return t, nil
}

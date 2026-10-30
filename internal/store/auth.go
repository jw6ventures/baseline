package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"time"

	"github.com/lib/pq"
)

type User struct {
	ID        string
	OIDCSub   string
	Email     string
	Name      string
	LastLogin time.Time
}

// DisplayName is the best human label available for the user.
func (u User) DisplayName() string {
	switch {
	case u.Name != "":
		return u.Name
	case u.Email != "":
		return u.Email
	}
	return u.OIDCSub
}

// UpsertUser records a login, creating the user on first sight and refreshing
// the profile claims after that.
func (s *Store) UpsertUser(ctx context.Context, sub, email, name string) (User, error) {
	u := User{OIDCSub: sub, Email: email, Name: name}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO app_user (oidc_sub, email, name, last_login) VALUES ($1, $2, $3, now())
		ON CONFLICT (oidc_sub) DO UPDATE
		SET email = EXCLUDED.email, name = EXCLUDED.name, last_login = EXCLUDED.last_login
		RETURNING id, last_login`, sub, email, name).Scan(&u.ID, &u.LastLogin)
	return u, err
}

// NewSession describes a session to create after a successful login.
type NewSession struct {
	UserID      string
	IdPGroups   []string
	OIDCBlob    []byte // sealed oidc.Session
	IP          string
	UserAgent   string
	IdleTimeout time.Duration
	MaxLifetime time.Duration
}

type Session struct {
	User        User
	IdPGroups   []string
	CreatedAt   time.Time
	LastSeen    time.Time
	ExpiresAt   time.Time
	AbsoluteExp time.Time
	idHash      []byte
}

// CreateSession stores a new session and returns its token for the cookie.
func (s *Store) CreateSession(ctx context.Context, ns NewSession) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session (id_hash, user_id, idp_groups, created_at, last_seen, expires_at,
		                     absolute_expires, oidc_blob_enc, ip, user_agent)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9)`,
		hashToken(token), ns.UserID, pq.Array(nonNil(ns.IdPGroups)), now,
		now.Add(ns.IdleTimeout), now.Add(ns.MaxLifetime), ns.OIDCBlob, ns.IP, ns.UserAgent)
	if err != nil {
		return "", err
	}
	return token, nil
}

// LookupSession returns the live session for token, or ErrNotFound if it
// doesn't exist or has expired. A session idle-expires after idle; activity
// slides that forward (written at most once a minute), never past the
// absolute expiry.
func (s *Store) LookupSession(ctx context.Context, token string, idle time.Duration) (Session, error) {
	var ss Session
	ss.idHash = hashToken(token)
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.oidc_sub, u.email, u.name, COALESCE(u.last_login, 'epoch'),
		       s.idp_groups, s.created_at, s.last_seen, s.expires_at, s.absolute_expires
		FROM session s JOIN app_user u ON u.id = s.user_id
		WHERE s.id_hash = $1 AND s.expires_at > now() AND s.absolute_expires > now()`, ss.idHash).
		Scan(&ss.User.ID, &ss.User.OIDCSub, &ss.User.Email, &ss.User.Name, &ss.User.LastLogin,
			pq.Array(&ss.IdPGroups), &ss.CreatedAt, &ss.LastSeen, &ss.ExpiresAt, &ss.AbsoluteExp)
	if err != nil {
		return ss, mapErr(err)
	}
	if time.Since(ss.LastSeen) > time.Minute {
		now := time.Now()
		exp := now.Add(idle)
		if exp.After(ss.AbsoluteExp) {
			exp = ss.AbsoluteExp
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE session SET last_seen = $2, expires_at = $3 WHERE id_hash = $1`,
			ss.idHash, now, exp); err != nil {
			return ss, err
		}
		ss.LastSeen, ss.ExpiresAt = now, exp
	}
	return ss, nil
}

// DeleteSession ends the session for token. Deleting an unknown token is not
// an error.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE id_hash = $1`, hashToken(token))
	return err
}

// PurgeSessions deletes expired sessions and returns how many it removed.
func (s *Store) PurgeSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM session WHERE expires_at <= now() OR absolute_expires <= now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// nullString maps "" to NULL, for optional foreign keys.
func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

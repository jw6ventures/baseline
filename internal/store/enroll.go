package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// ErrTokenInvalid covers unknown, revoked, expired and used-up tokens alike,
// so a caller probing tokens learns nothing.
var ErrTokenInvalid = errors.New("enrollment token is invalid, expired or used up")

type EnrollmentToken struct {
	ID            string
	Name          string
	MaxUses       int // 0 = unlimited
	Uses          int
	ExpiresAt     time.Time
	Revoked       bool
	DefaultGroups []string // host group IDs
	GroupNames    []string
	CreatedBy     string // display name
	CreatedAt     time.Time
}

// Usable reports whether the token can still enroll a host.
func (t EnrollmentToken) Usable() bool {
	return !t.Revoked && time.Now().Before(t.ExpiresAt) && (t.MaxUses == 0 || t.Uses < t.MaxUses)
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, actor Actor, userID string, t EnrollmentToken, secretHash []byte) (EnrollmentToken, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var maxUses sql.NullInt64
		if t.MaxUses > 0 {
			maxUses = sql.NullInt64{Int64: int64(t.MaxUses), Valid: true}
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO enrollment_token (name, secret_hash, max_uses, expires_at, default_groups, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
			t.Name, secretHash, maxUses, t.ExpiresAt, pq.Array(nonNil(t.DefaultGroups)), nullString(userID)).
			Scan(&t.ID, &t.CreatedAt); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "enrollment_token.create", ObjectType: "enrollment_token", ObjectID: t.ID,
			Details: map[string]any{"name": t.Name, "max_uses": t.MaxUses, "expires_at": t.ExpiresAt.UTC(), "default_groups": t.DefaultGroups},
		})
	})
	return t, err
}

func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.name, COALESCE(t.max_uses, 0), t.uses, t.expires_at, t.revoked, t.default_groups,
		       ARRAY(SELECT g.name FROM host_group g WHERE g.id = ANY(t.default_groups) ORDER BY g.name),
		       COALESCE(NULLIF(u.name, ''), u.email, ''), t.created_at
		FROM enrollment_token t LEFT JOIN app_user u ON u.id = t.created_by
		ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.Name, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.Revoked,
			pq.Array(&t.DefaultGroups), pq.Array(&t.GroupNames), &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeEnrollmentToken(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx,
			`UPDATE enrollment_token SET revoked = true WHERE id = $1 AND NOT revoked RETURNING name`, id).
			Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "enrollment_token.revoke", ObjectType: "enrollment_token", ObjectID: id,
			Details: map[string]any{"name": name},
		})
	})
}

// EnrollRequest is a validated Enroll call, minus the CSR.
type EnrollRequest struct {
	SecretHash   []byte
	MachineID    string
	DMIUUID      string
	Hostname     string
	AgentVersion string
	IP           string
}

// IssueFunc signs the agent's cert for agentID and reports its serial.
type IssueFunc func(agentID string) (serial string, notAfter time.Time, err error)

type EnrollResult struct {
	HostID  string
	AgentID string
}

// Enroll consumes one use of a token and registers a new host, flagged if
// it shares a machine-id or DMI UUID with another. It never re-binds an
// existing host: those IDs are reported by the agent itself (machine-id is
// world-readable), so matching on them would let any token holder take over
// another host's record. A host whose agent state was wiped shows up as a
// new host next to its old, offline record, which an admin revokes.
func (s *Store) Enroll(ctx context.Context, req EnrollRequest, issue IssueFunc) (EnrollResult, error) {
	var res EnrollResult
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var tokenID, tokenName string
		var groups []string
		err := tx.QueryRowContext(ctx, `
			SELECT id, name, default_groups FROM enrollment_token
			WHERE secret_hash = $1 AND NOT revoked AND expires_at > now()
			  AND (max_uses IS NULL OR uses < max_uses)
			FOR UPDATE`, req.SecretHash).Scan(&tokenID, &tokenName, pq.Array(&groups))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment_token SET uses = uses + 1 WHERE id = $1`, tokenID); err != nil {
			return err
		}

		res.AgentID = newUUID()
		serial, notAfter, err := issue(res.AgentID)
		if err != nil {
			return err
		}

		name := req.Hostname
		if name == "" {
			name = "unnamed host"
		}
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO ci (type, name, source) VALUES ('host', $1, 'agent') RETURNING id`, name).
			Scan(&res.HostID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO host (ci_id, agent_id, cert_serial, cert_not_after, machine_id, dmi_uuid,
			                  hostname, agent_version, enrollment_token_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			res.HostID, res.AgentID, serial, notAfter, req.MachineID, req.DMIUUID,
			req.Hostname, req.AgentVersion, tokenID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO host_group_member (group_id, ci_id)
			SELECT g.id, $2 FROM host_group g WHERE g.id = ANY($1::uuid[])
			ON CONFLICT DO NOTHING`, pq.Array(groups), res.HostID); err != nil {
			return err
		}
		if err := flagDuplicates(ctx, tx, res.HostID); err != nil {
			return err
		}
		return appendAudit(ctx, tx, Actor{ID: "agent:" + res.AgentID, IP: req.IP}, AuditEvent{
			Action: "host.enroll", ObjectType: "host", ObjectID: res.HostID,
			Details: map[string]any{
				"hostname": req.Hostname, "machine_id": req.MachineID, "dmi_uuid": req.DMIUUID,
				"token": tokenName, "token_id": tokenID, "cert_serial": serial,
			},
		})
	})
	return res, err
}

// flagDuplicates recomputes hostID's duplicate flag and flags every other
// host sharing its machine-id or DMI UUID. Clones of a VM template are the
// usual cause. A peer that stops matching (re-enrolled with a fresh
// machine-id) clears on its own next connect.
func flagDuplicates(ctx context.Context, tx *sql.Tx, hostID string) error {
	if err := lockIdentities(ctx, tx); err != nil {
		return err
	}
	const peers = `
		SELECT h.ci_id FROM host h, host me
		WHERE me.ci_id = $1 AND h.ci_id <> me.ci_id AND NOT h.revoked
		  AND ((me.machine_id <> '' AND h.machine_id = me.machine_id)
		    OR (me.dmi_uuid <> '' AND h.dmi_uuid = me.dmi_uuid))`
	if _, err := tx.ExecContext(ctx, `UPDATE host SET duplicate_identity = true WHERE NOT duplicate_identity AND ci_id IN (`+peers+`)`, hostID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE host SET duplicate_identity = EXISTS (`+peers+`) WHERE ci_id = $1`, hostID)
	return err
}

// identityLockKey serializes duplicate-identity checks. Clones connecting at
// the same moment would otherwise each lock their own host row and then wait
// for the other's.
const identityLockKey = 0x6a636d6469 // "jcmdi"

// lockIdentities takes the lock; callers that also lock a host row take it
// first.
func lockIdentities(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLockKey)
	return err
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

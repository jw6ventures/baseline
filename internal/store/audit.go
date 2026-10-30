package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Actor is who performed an audited action.
type Actor struct {
	ID string // user:<uuid> | agent:<uuid> | system
	IP string
}

// System is the actor for work the server does on its own.
var System = Actor{ID: "system"}

func UserActor(userID, ip string) Actor { return Actor{ID: "user:" + userID, IP: ip} }

// AuditEvent is what a caller records; the store fills in time and hashes.
type AuditEvent struct {
	Action     string // e.g. auth.login, role_binding.create
	ObjectType string
	ObjectID   string
	Details    map[string]any
}

type AuditEntry struct {
	ID         int64
	At         time.Time
	Actor      string
	ActorIP    string
	Action     string
	ObjectType string
	ObjectID   string
	Details    string // canonical JSON text
	ActorName  string // display name when the actor is a user; not hashed
	PrevHash   []byte
	Hash       []byte
}

// genesis is the prev_hash of the first audit row.
var genesis = make([]byte, sha256.Size)

// auditLockKey serializes appends so the chain has exactly one head.
const auditLockKey = 0x6a636d6462 // "jcmdb", kept through the rename to Baseline so old and new servers share the lock

// Audit appends one event in its own transaction.
func (s *Store) Audit(ctx context.Context, actor Actor, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return appendAudit(ctx, tx, actor, ev) })
}

// appendAudit appends to the chain inside tx, so an audited mutation and its
// audit row commit or roll back together.
func appendAudit(ctx context.Context, tx *sql.Tx, actor Actor, ev AuditEvent) error {
	if ev.Details == nil {
		ev.Details = map[string]any{}
	}
	raw, err := json.Marshal(ev.Details)
	if err != nil {
		return fmt.Errorf("audit details: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return err
	}

	// Hash the text Postgres will hand back on verification, not Go's
	// encoding of it: jsonb normalizes key order and whitespace.
	e := AuditEntry{
		At:         time.Now().UTC().Truncate(time.Microsecond), // timestamptz precision
		Actor:      actor.ID,
		ActorIP:    actor.IP,
		Action:     ev.Action,
		ObjectType: ev.ObjectType,
		ObjectID:   ev.ObjectID,
	}
	if err := tx.QueryRowContext(ctx, `SELECT $1::jsonb::text`, string(raw)).Scan(&e.Details); err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&e.PrevHash)
	switch {
	case err == sql.ErrNoRows:
		e.PrevHash = genesis
	case err != nil:
		return err
	}
	e.Hash = chainHash(e)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_log (at, actor, actor_ip, action, object_type, object_id, details, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
		e.At, e.Actor, e.ActorIP, e.Action, e.ObjectType, e.ObjectID, e.Details, e.PrevHash, e.Hash)
	return err
}

// chainHash is SHA-256(prev_hash || each field, length-prefixed). Length
// prefixes keep field boundaries unambiguous.
func chainHash(e AuditEntry) []byte {
	h := sha256.New()
	h.Write(e.PrevHash)
	for _, f := range []string{
		e.At.UTC().Format(time.RFC3339Nano),
		e.Actor, e.ActorIP, e.Action, e.ObjectType, e.ObjectID, e.Details,
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

const auditCols = `a.id, a.at, a.actor, a.actor_ip, a.action, a.object_type, a.object_id, a.details::text,
	COALESCE(NULLIF(u.name, ''), u.email, ''), a.prev_hash, a.hash`

// auditFrom resolves user actors to names for display.
const auditFrom = ` FROM audit_log a LEFT JOIN app_user u ON a.actor = 'user:' || u.id::text `

func scanAudit(rows *sql.Rows) (AuditEntry, error) {
	var e AuditEntry
	err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.ActorIP, &e.Action, &e.ObjectType, &e.ObjectID,
		&e.Details, &e.ActorName, &e.PrevHash, &e.Hash)
	e.At = e.At.UTC()
	return e, err
}

// ListAudit returns up to limit entries, newest first, with IDs below before
// (0 = from the newest).
func (s *Store) ListAudit(ctx context.Context, before int64, limit int) ([]AuditEntry, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+auditCols+auditFrom+`WHERE a.id < $1 ORDER BY a.id DESC LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditVerification is the result of walking the whole chain.
type AuditVerification struct {
	Checked  int64
	BrokenAt int64 // ID of the first row that doesn't chain; 0 if intact
	Reason   string
}

func (v AuditVerification) OK() bool { return v.BrokenAt == 0 }

// VerifyAudit recomputes every hash in ID order.
func (s *Store) VerifyAudit(ctx context.Context) (AuditVerification, error) {
	var v AuditVerification
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+auditFrom+`ORDER BY a.id`)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	prev := genesis
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return v, err
		}
		v.Checked++
		switch {
		case !bytes.Equal(e.PrevHash, prev):
			v.BrokenAt, v.Reason = e.ID, "prev_hash does not match the previous row (row removed or reordered)"
		case !bytes.Equal(e.Hash, chainHash(e)):
			v.BrokenAt, v.Reason = e.ID, "content does not match its hash (row altered)"
		}
		if v.BrokenAt != 0 {
			return v, nil
		}
		prev = e.Hash
	}
	return v, rows.Err()
}

// userID is the app_user ID behind a user actor, or NULL for agents and the
// system.
func (a Actor) userID() sql.NullString {
	id, ok := strings.CutPrefix(a.ID, "user:")
	return sql.NullString{String: id, Valid: ok && id != ""}
}

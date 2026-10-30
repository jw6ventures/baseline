package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
)

// Script is an entry in the script library (docs/change-management.md §6).
type Script struct {
	ID          string
	Name        string
	Description string
	Archived    bool
	CreatedAt   time.Time
	Latest      int // newest version
	LatestAt    time.Time
	Risk        string // of the newest version
	Interpreter string // of the newest version
	Runs        int    // jobs that ran any version
}

// ScriptVersion is one immutable version of a script.
type ScriptVersion struct {
	ScriptID      string
	ScriptName    string
	Version       int
	Interpreter   string
	Params        []action.ScriptParam
	Risk          string
	Body          string
	SHA256        string
	Notes         string
	CreatedBy     string // display name
	CreatedAt     time.Time
	ScriptArchive bool
}

// NewScriptVersion is what an admin saves.
type NewScriptVersion struct {
	Interpreter string
	Params      []action.ScriptParam
	Risk        action.Risk
	Body        string
	Notes       string
}

// ScriptSHA256 is the hex digest that identifies a script body.
func ScriptSHA256(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}

const scriptCols = `s.id, s.name, s.description, s.archived, s.created_at,
	COALESCE(v.version, 0), COALESCE(v.created_at, s.created_at), COALESCE(v.risk, ''), COALESCE(v.interpreter, ''),
	(SELECT count(*) FROM job j WHERE j.script_id = s.id)`

const scriptFrom = ` FROM script s LEFT JOIN LATERAL (
	SELECT version, created_at, risk, interpreter FROM script_version WHERE script_id = s.id ORDER BY version DESC LIMIT 1) v ON true `

func scanScript(row interface{ Scan(...any) error }) (Script, error) {
	var s Script
	err := row.Scan(&s.ID, &s.Name, &s.Description, &s.Archived, &s.CreatedAt, &s.Latest, &s.LatestAt, &s.Risk, &s.Interpreter, &s.Runs)
	return s, err
}

// ListScripts returns the library, archived scripts last.
func (s *Store) ListScripts(ctx context.Context) ([]Script, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scriptCols+scriptFrom+` ORDER BY s.archived, lower(s.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Script
	for rows.Next() {
		sc, err := scanScript(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) GetScript(ctx context.Context, id string) (Script, error) {
	sc, err := scanScript(s.db.QueryRowContext(ctx, `SELECT `+scriptCols+scriptFrom+` WHERE s.id = $1`, id))
	return sc, mapErr(err)
}

const versionCols = `v.script_id, s.name, v.version, v.interpreter, v.params::text, v.risk, v.body, v.sha256, v.notes,
	COALESCE(NULLIF(u.name, ''), u.email, ''), v.created_at, s.archived`

const versionFrom = ` FROM script_version v JOIN script s ON s.id = v.script_id LEFT JOIN app_user u ON u.id = v.created_by `

func scanVersion(row interface{ Scan(...any) error }) (ScriptVersion, error) {
	var v ScriptVersion
	var params string
	if err := row.Scan(&v.ScriptID, &v.ScriptName, &v.Version, &v.Interpreter, &params, &v.Risk, &v.Body, &v.SHA256,
		&v.Notes, &v.CreatedBy, &v.CreatedAt, &v.ScriptArchive); err != nil {
		return v, err
	}
	return v, json.Unmarshal([]byte(params), &v.Params)
}

// ScriptVersions lists a script's versions, newest first.
func (s *Store) ScriptVersions(ctx context.Context, scriptID string) ([]ScriptVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.script_id = $1 ORDER BY v.version DESC`, scriptID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ScriptVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetScriptVersion(ctx context.Context, scriptID string, version int) (ScriptVersion, error) {
	v, err := scanVersion(s.db.QueryRowContext(ctx,
		`SELECT `+versionCols+versionFrom+` WHERE v.script_id = $1 AND v.version = $2`, scriptID, version))
	return v, mapErr(err)
}

// CreateScript adds a script with its first version.
func (s *Store) CreateScript(ctx context.Context, actor Actor, name, description string, v NewScriptVersion) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO script (name, description, created_by) VALUES ($1, $2, $3) RETURNING id`,
			name, description, actor.userID()).Scan(&id); err != nil {
			return mapErr(err)
		}
		if err := addVersion(ctx, tx, actor, id, 1, v); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "script.create", ObjectType: "script", ObjectID: id,
			Details: map[string]any{"name": name, "version": 1, "sha256": ScriptSHA256(v.Body), "interpreter": v.Interpreter, "risk": v.Risk},
		})
	})
	return id, err
}

// AddScriptVersion saves a new version; earlier ones never change. It
// returns the new version number.
func (s *Store) AddScriptVersion(ctx context.Context, actor Actor, scriptID, description string, v NewScriptVersion) (int, error) {
	var n int
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM script WHERE id = $1 FOR UPDATE`, scriptID).Scan(&name); err != nil {
			return mapErr(err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(max(version), 0) + 1 FROM script_version WHERE script_id = $1`, scriptID).Scan(&n); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE script SET description = $2 WHERE id = $1`, scriptID, description); err != nil {
			return err
		}
		if err := addVersion(ctx, tx, actor, scriptID, n, v); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "script.version", ObjectType: "script", ObjectID: scriptID,
			Details: map[string]any{"name": name, "version": n, "sha256": ScriptSHA256(v.Body), "interpreter": v.Interpreter, "risk": v.Risk},
		})
	})
	return n, err
}

func addVersion(ctx context.Context, tx *sql.Tx, actor Actor, scriptID string, n int, v NewScriptVersion) error {
	params, err := json.Marshal(v.Params)
	if err != nil {
		return err
	}
	if v.Params == nil {
		params = []byte("[]")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO script_version (script_id, version, interpreter, params, risk, body, sha256, notes, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		scriptID, n, v.Interpreter, string(params), string(v.Risk), v.Body, ScriptSHA256(v.Body), v.Notes, actor.userID())
	return err
}

// SetScriptArchived hides a script from "Run" without losing its versions,
// which past jobs refer to.
func (s *Store) SetScriptArchived(ctx context.Context, actor Actor, scriptID string, archived bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `UPDATE script SET archived = $2 WHERE id = $1 RETURNING name`, scriptID, archived).
			Scan(&name); err != nil {
			return mapErr(err)
		}
		act := "script.archive"
		if !archived {
			act = "script.unarchive"
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: act, ObjectType: "script", ObjectID: scriptID,
			Details: map[string]any{"name": name}})
	})
}

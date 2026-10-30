package store

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// ComposeRevision is what one compose.deploy or compose.edit change writes
// to one stack (docs/change-management.md §5.1). Its ID is in the job's
// parameters; the dispatcher sends the files with the job.
type ComposeRevision struct {
	ID      string
	HostID  string
	Engine  string
	Project string
	Action  string
	// Compose is the new Compose file; HasCompose is false when an edit
	// leaves the file alone.
	Compose       string
	HasCompose    bool
	ComposeSHA256 string
	// BaseSHA256 and BaseCompose are the file an edit replaces: its hash
	// on the host, and its content as inventory showed it (secrets masked).
	BaseSHA256  string
	BaseCompose string
	// The new .env, encrypted with BASELINE_SECRET_KEY (internal/stackenv),
	// with its variable names and keyed hash; HasEnv is false when an edit
	// leaves the .env alone. EnvEnc is only read by RevisionEnv.
	HasEnv  bool
	EnvEnc  string
	EnvKeys []string
	EnvHash string
	// Read back.
	ChangeID      string
	ChangeNumber  int64
	ChangeState   string
	CreatedBy     string
	CreatedByName string
	CreatedAt     time.Time
	// JobState is the state of the revision's job; "" before the change
	// has one.
	JobState string
}

// ChangeRef is the revision's change as people see it.
func (r ComposeRevision) ChangeRef() string { return ChangeRef(r.ChangeNumber) }

// NewID returns a random UUID, for rows whose ID is needed before they are
// written (a revision's is in its job's parameters).
func NewID() string { return newUUID() }

func insertRevisions(ctx context.Context, tx *sql.Tx, changeID string, by sql.NullString, revs []ComposeRevision) error {
	for _, r := range revs {
		compose := sql.NullString{String: r.Compose, Valid: r.HasCompose}
		env := sql.NullString{String: r.EnvEnc, Valid: r.HasEnv}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO compose_revision (id, host, engine, project, action, change_id, compose, compose_sha256, base_sha256,
			       base_compose, env_enc, env_keys, env_hash, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			r.ID, r.HostID, r.Engine, r.Project, r.Action, changeID, compose, r.ComposeSHA256, r.BaseSHA256, r.BaseCompose,
			env, pq.Array(nonNil(r.EnvKeys)), r.EnvHash, by); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

const revisionCols = `r.id, r.host, r.engine, r.project, r.action, COALESCE(r.compose, ''), r.compose IS NOT NULL,
	r.compose_sha256, r.base_sha256, r.base_compose, r.env_enc IS NOT NULL, r.env_keys, r.env_hash, COALESCE(r.change_id::text, ''), COALESCE(c.number, 0), COALESCE(c.state, ''),
	COALESCE(r.created_by::text, ''), COALESCE(NULLIF(u.name, ''), u.email, ''), r.created_at,
	COALESCE((SELECT j.state FROM job j WHERE j.change_id = r.change_id AND j.params->>'revision' = r.id::text
	          ORDER BY j.seq LIMIT 1), '')`

const revisionFrom = ` FROM compose_revision r LEFT JOIN change c ON c.id = r.change_id
	LEFT JOIN app_user u ON u.id = r.created_by `

func scanRevision(row interface{ Scan(...any) error }) (ComposeRevision, error) {
	var r ComposeRevision
	err := row.Scan(&r.ID, &r.HostID, &r.Engine, &r.Project, &r.Action, &r.Compose, &r.HasCompose, &r.ComposeSHA256,
		&r.BaseSHA256, &r.BaseCompose, &r.HasEnv, pq.Array(&r.EnvKeys), &r.EnvHash,
		&r.ChangeID, &r.ChangeNumber, &r.ChangeState, &r.CreatedBy, &r.CreatedByName, &r.CreatedAt, &r.JobState)
	return r, err
}

func (s *Store) listRevisions(ctx context.Context, where string, args ...any) ([]ComposeRevision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+revisionCols+revisionFrom+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComposeRevision
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ComposeRevision reads a revision, without its .env.
func (s *Store) ComposeRevision(ctx context.Context, id string) (ComposeRevision, error) {
	r, err := scanRevision(s.db.QueryRowContext(ctx, `SELECT `+revisionCols+revisionFrom+`WHERE r.id = $1`, id))
	return r, mapErr(err)
}

// RevisionEnv is a revision's encrypted .env; "" when it has none.
func (s *Store) RevisionEnv(ctx context.Context, id string) (string, error) {
	var enc sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT env_enc FROM compose_revision WHERE id = $1`, id).Scan(&enc)
	return enc.String, mapErr(err)
}

// ChangeRevisions are a change's revisions, by stack.
func (s *Store) ChangeRevisions(ctx context.Context, changeID string) ([]ComposeRevision, error) {
	return s.listRevisions(ctx, `WHERE r.change_id = $1 ORDER BY r.project, r.id`, changeID)
}

// StackRevisions are the latest revisions of a stack, newest first.
func (s *Store) StackRevisions(ctx context.Context, hostID, engine, project string, limit int) ([]ComposeRevision, error) {
	return s.listRevisions(ctx, `WHERE r.host = $1 AND r.engine = $2 AND r.project = $3 ORDER BY r.created_at DESC LIMIT $4`,
		hostID, engine, project, limit)
}

// StackEnv is the revision that last wrote a stack's .env successfully: the
// .env the stack has now, as far as Baseline knows. ErrNotFound when Baseline
// never wrote one.
func (s *Store) StackEnv(ctx context.Context, hostID, engine, project string) (ComposeRevision, error) {
	r, err := scanRevision(s.db.QueryRowContext(ctx, `SELECT `+revisionCols+revisionFrom+`
		WHERE r.host = $1 AND r.engine = $2 AND r.project = $3 AND r.env_enc IS NOT NULL
		  AND EXISTS (SELECT 1 FROM job j WHERE j.change_id = r.change_id AND j.params->>'revision' = r.id::text
		              AND j.state = 'succeeded')
		ORDER BY r.created_at DESC LIMIT 1`, hostID, engine, project))
	return r, mapErr(err)
}

// OpenRevisions are the stack's revisions whose changes are still open:
// another deploy or edit of it waits on them.
func (s *Store) OpenRevisions(ctx context.Context, hostID, engine, project string) ([]ComposeRevision, error) {
	return s.listRevisions(ctx, `WHERE r.host = $1 AND r.engine = $2 AND r.project = $3
		AND c.state IN ('draft', 'submitted', 'approved', 'scheduled', 'in_progress') ORDER BY r.created_at`, hostID, engine, project)
}

// SetHostManageCompose turns Compose stack management on or off for a
// host: deploying stacks to it, and editing the Compose files and .env of
// the stacks on it. It reports whether that changed anything.
func (s *Store) SetHostManageCompose(ctx context.Context, actor Actor, hostID string, on bool) (bool, error) {
	changed := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var before bool
		if err := tx.QueryRowContext(ctx, `SELECT manage_compose FROM host WHERE ci_id = $1 FOR UPDATE`, hostID).
			Scan(&before); err != nil {
			return mapErr(err)
		}
		if before == on {
			return nil
		}
		changed = true
		if _, err := tx.ExecContext(ctx, `
			UPDATE host SET manage_compose = $2, manage_compose_since = CASE WHEN $2 THEN now() END WHERE ci_id = $1`,
			hostID, on); err != nil {
			return err
		}
		if err := addHistory(ctx, tx, hostID, actor.ID, "settings", map[string]any{
			"changed": []inventory.Change{{Field: "manage_compose", From: before, To: on}},
		}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host.manage_compose", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"manage_compose": on},
		})
	})
	return changed, err
}

// AddHostComposeRoot adds a directory to the end of the host's Compose
// roots. It reports whether it was new.
func (s *Store) AddHostComposeRoot(ctx context.Context, actor Actor, hostID, root string) (bool, error) {
	return s.editComposeRoots(ctx, actor, hostID, "host.compose_root_add", root, func(roots []string) []string {
		if slices.Contains(roots, root) {
			return roots
		}
		return append(slices.Clone(roots), root)
	})
}

// RemoveHostComposeRoot takes a directory off the host's Compose roots.
// Stacks already deployed under it stay where they are. It reports whether
// the host had it.
func (s *Store) RemoveHostComposeRoot(ctx context.Context, actor Actor, hostID, root string) (bool, error) {
	return s.editComposeRoots(ctx, actor, hostID, "host.compose_root_remove", root, func(roots []string) []string {
		return slices.DeleteFunc(slices.Clone(roots), func(r string) bool { return r == root })
	})
}

func (s *Store) editComposeRoots(ctx context.Context, actor Actor, hostID, auditAction, root string,
	edit func([]string) []string) (bool, error) {
	changed := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var before []string
		if err := tx.QueryRowContext(ctx, `SELECT compose_roots FROM host WHERE ci_id = $1 FOR UPDATE`, hostID).
			Scan(pq.Array(&before)); err != nil {
			return mapErr(err)
		}
		after := edit(before)
		if slices.Equal(before, after) {
			return nil
		}
		changed = true
		if after == nil {
			after = []string{}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE host SET compose_roots = $2 WHERE ci_id = $1`, hostID, pq.Array(after)); err != nil {
			return err
		}
		if err := addHistory(ctx, tx, hostID, actor.ID, "settings", map[string]any{
			"changed": []inventory.Change{{Field: "compose_roots", From: strings.Join(before, ", "), To: strings.Join(after, ", ")}},
		}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: auditAction, ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"root": root, "compose_roots": after},
		})
	})
	return changed, err
}

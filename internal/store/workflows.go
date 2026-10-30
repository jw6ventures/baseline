package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Workflows (docs/data-model.md §9) --------------------------------------------------

// Version states. A draft is edited in place; publishing freezes it, and a
// published version nobody's items use any more is retired.
const (
	VersionDraft     = "draft"
	VersionPublished = "published"
	VersionRetired   = "retired"
)

// What transitions can carry. Each is a list of {type, ...} objects in the
// transition's jsonb columns.
var (
	// ConditionTypes say who may run a transition; any one that holds lets
	// them, and none means everyone.
	ConditionTypes = []string{"role", "assignee", "reporter"}
	// ValidatorTypes say what must be true first.
	ValidatorTypes = []string{"field_required", "linked_change", "linked_ci", "children_done", "comment_required"}
	// RequirableFields are the fields field_required can name.
	RequirableFields = []string{"assignee", "description", "estimate", "due", "impact", "urgency"}
	// PostFunctionTypes say what happens after.
	PostFunctionTypes = []string{"assign", "set_priority"}
	// AssignTargets are the values of an assign post-function.
	AssignTargets = []string{"actor", "reporter", "none"}
	// ScreenFields are what a transition screen can ask for.
	ScreenFields = []string{"resolution", "assignee", "comment"}
)

var (
	// ErrNotDraft refuses to edit a published or retired version.
	ErrNotDraft = errors.New("only a draft can be edited")
	// ErrNoPublished refuses a workflow with no published version where
	// items need one.
	ErrNoPublished = errors.New("the workflow has no published version")
	// ErrStaleTransition refuses a transition that no longer applies to the
	// item: it moved on, or it is on another version.
	ErrStaleTransition = errors.New("that transition doesn't apply to the item now")
	// ErrTransitionDenied refuses a transition whose conditions fail.
	ErrTransitionDenied = errors.New("you may not run that transition")
)

// TransitionError is a validator that failed, in words for the user.
type TransitionError struct{ Msg string }

func (e *TransitionError) Error() string { return e.Msg }

// WorkflowError lists what stops a draft from being published.
type WorkflowError struct{ Problems []string }

func (e *WorkflowError) Error() string { return strings.Join(e.Problems, " ") }

// Workflow is a named set of versions.
type Workflow struct {
	ID          string
	Name        string
	Description string
	Default     bool
	CreatedAt   time.Time
	Latest      int    // the newest published version, 0 for none
	LatestID    string // its ID
	DraftID     string // the draft's ID, "" for none
	Items       int    // work items on any of its versions
	Uses        int    // project ticket types that use it
}

// WorkflowVersion is one version of a workflow. Statuses and Transitions
// are filled only by GetWorkflowVersion.
type WorkflowVersion struct {
	ID           string
	WorkflowID   string
	WorkflowName string
	Version      int
	State        string
	CreatedAt    time.Time
	CreatedBy    string
	PublishedAt  time.Time
	PublishedBy  string
	Items        int
	Statuses     []WfStatus
	Transitions  []WfTransition
}

func (v WorkflowVersion) Draft() bool { return v.State == VersionDraft }

// Status returns the version's status with the ID.
func (v WorkflowVersion) Status(id string) (WfStatus, bool) {
	i := slices.IndexFunc(v.Statuses, func(s WfStatus) bool { return s.ID == id })
	if i < 0 {
		return WfStatus{}, false
	}
	return v.Statuses[i], true
}

// WfStatus is one status of a version. Key names it across versions.
type WfStatus struct {
	ID       string
	Key      string
	Name     string
	Category string // todo | in_progress | done
	Position int
	Initial  bool     // where new items start
	X, Y     *float64 // on the diagram; nil until placed
}

// WfCondition is one rule of who may run a transition: a role (or one that
// implies it), the item's assignee or its reporter.
type WfCondition struct {
	Type string `json:"type"`
	Role string `json:"role,omitempty"`
}

// Validator is one thing that must hold before a transition runs.
type Validator struct {
	Type  string `json:"type"`
	Field string `json:"field,omitempty"` // for field_required
}

// PostFunction is one thing a transition does after moving the item.
type PostFunction struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"` // assign: actor | reporter | none; set_priority: a priority
}

// WfTransition moves an item from one status (any, when FromID is "") to
// another.
type WfTransition struct {
	ID            string
	Name          string
	FromID        string
	FromName      string
	ToID          string
	ToName        string
	ToCategory    string
	Position      int
	Conditions    []WfCondition
	Validators    []Validator
	PostFunctions []PostFunction
	Screen        []string // ScreenFields it asks for
}

// Asks reports whether the transition's screen asks for field.
func (t WfTransition) Asks(field string) bool { return slices.Contains(t.Screen, field) }

// Runner is who runs a transition: their user ID ("" for the system) and
// whether they hold a role.
type Runner struct {
	UserID  string
	HasRole func(role string) bool
}

// Allowed reports whether the runner meets the transition's conditions on
// the item. The system always may.
func (t WfTransition) Allowed(it WorkItem, r Runner) bool {
	if len(t.Conditions) == 0 || r.UserID == "" {
		return true
	}
	for _, c := range t.Conditions {
		switch c.Type {
		case "role":
			if r.HasRole != nil && r.HasRole(c.Role) {
				return true
			}
		case "assignee":
			if it.AssigneeID != "" && it.AssigneeID == r.UserID {
				return true
			}
		case "reporter":
			if it.ReporterID != "" && it.ReporterID == r.UserID {
				return true
			}
		}
	}
	return false
}

const workflowCols = `f.id, f.name, f.description, f.is_default, f.created_at,
	COALESCE((SELECT max(v.version) FROM workflow_version v WHERE v.workflow_id = f.id AND v.state = 'published'), 0),
	COALESCE((SELECT v.id::text FROM workflow_version v WHERE v.workflow_id = f.id AND v.state = 'published'
	          ORDER BY v.version DESC LIMIT 1), ''),
	COALESCE((SELECT v.id::text FROM workflow_version v WHERE v.workflow_id = f.id AND v.state = 'draft'), ''),
	(SELECT count(*) FROM work_item w JOIN workflow_version v ON v.id = w.workflow_version_id WHERE v.workflow_id = f.id),
	(SELECT count(*) FROM project_ticket_type pt WHERE pt.workflow_id = f.id)`

func scanWorkflow(row interface{ Scan(...any) error }) (Workflow, error) {
	var f Workflow
	err := row.Scan(&f.ID, &f.Name, &f.Description, &f.Default, &f.CreatedAt, &f.Latest, &f.LatestID, &f.DraftID,
		&f.Items, &f.Uses)
	return f, err
}

func (s *Store) ListWorkflows(ctx context.Context) ([]Workflow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workflowCols+` FROM workflow f ORDER BY NOT f.is_default, lower(f.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workflow
	for rows.Next() {
		f, err := scanWorkflow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetWorkflow(ctx context.Context, id string) (Workflow, error) {
	f, err := scanWorkflow(s.db.QueryRowContext(ctx, `SELECT `+workflowCols+` FROM workflow f WHERE f.id = $1`, id))
	return f, mapErr(err)
}

const wfVersionCols = `v.id, v.workflow_id, f.name, v.version, v.state, v.created_at, v.created_by,
	v.published_at, COALESCE(v.published_by, ''),
	(SELECT count(*) FROM work_item w WHERE w.workflow_version_id = v.id)`

func scanWfVersion(row interface{ Scan(...any) error }) (WorkflowVersion, error) {
	var v WorkflowVersion
	var published sql.NullTime
	err := row.Scan(&v.ID, &v.WorkflowID, &v.WorkflowName, &v.Version, &v.State, &v.CreatedAt, &v.CreatedBy,
		&published, &v.PublishedBy, &v.Items)
	v.PublishedAt = published.Time
	return v, err
}

// WorkflowVersions lists a workflow's versions, newest first.
func (s *Store) WorkflowVersions(ctx context.Context, workflowID string) ([]WorkflowVersion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+wfVersionCols+` FROM workflow_version v JOIN workflow f ON f.id = v.workflow_id
		WHERE v.workflow_id = $1 ORDER BY v.version DESC`, workflowID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []WorkflowVersion
	for rows.Next() {
		v, err := scanWfVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetWorkflowVersion fetches a version with its statuses and transitions.
func (s *Store) GetWorkflowVersion(ctx context.Context, id string) (WorkflowVersion, error) {
	return getVersion(ctx, s.db, id)
}

type rowQuerier interface {
	querier
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getVersion(ctx context.Context, q rowQuerier, id string) (WorkflowVersion, error) {
	v, err := scanWfVersion(q.QueryRowContext(ctx, `
		SELECT `+wfVersionCols+` FROM workflow_version v JOIN workflow f ON f.id = v.workflow_id WHERE v.id = $1`, id))
	if err != nil {
		return v, mapErr(err)
	}
	if v.Statuses, err = versionStatuses(ctx, q, id); err != nil {
		return v, err
	}
	v.Transitions, err = versionTransitions(ctx, q, `t.version_id = $1`, id)
	return v, err
}

func versionStatuses(ctx context.Context, q querier, versionID string) ([]WfStatus, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, key, name, category, position, initial, x, y FROM wf_status WHERE version_id = $1
		ORDER BY position, array_position(ARRAY['todo', 'in_progress', 'done'], category), lower(name)`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WfStatus
	for rows.Next() {
		var st WfStatus
		if err := rows.Scan(&st.ID, &st.Key, &st.Name, &st.Category, &st.Position, &st.Initial, &st.X, &st.Y); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func versionTransitions(ctx context.Context, q querier, where string, args ...any) ([]WfTransition, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT t.id, t.name, COALESCE(t.from_status::text, ''), COALESCE(fs.name, ''), t.to_status, ts.name, ts.category,
		       t.position, t.conditions::text, t.validators::text, t.post_functions::text, t.screen::text
		FROM wf_transition t JOIN wf_status ts ON ts.id = t.to_status LEFT JOIN wf_status fs ON fs.id = t.from_status
		WHERE `+where+` ORDER BY t.position, lower(t.name)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WfTransition
	for rows.Next() {
		var t WfTransition
		var conds, vals, posts, screen string
		if err := rows.Scan(&t.ID, &t.Name, &t.FromID, &t.FromName, &t.ToID, &t.ToName, &t.ToCategory, &t.Position,
			&conds, &vals, &posts, &screen); err != nil {
			return nil, err
		}
		for _, x := range []struct {
			raw string
			dst any
		}{{conds, &t.Conditions}, {vals, &t.Validators}, {posts, &t.PostFunctions}, {screen, &t.Screen}} {
			if err := json.Unmarshal([]byte(x.raw), x.dst); err != nil {
				return nil, fmt.Errorf("transition %s: %w", t.ID, err)
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateWorkflow creates a workflow with a draft version 1, a copy of the
// newest published version of from ("" for none: an empty draft).
func (s *Store) CreateWorkflow(ctx context.Context, actor Actor, name, description, from string) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO workflow (name, description) VALUES ($1, $2) RETURNING id`,
			name, description).Scan(&id); err != nil {
			return mapErr(err)
		}
		var src string
		if from != "" {
			if err := tx.QueryRowContext(ctx, `
				SELECT id FROM workflow_version WHERE workflow_id::text = $1 AND state = 'published'
				ORDER BY version DESC LIMIT 1`, from).Scan(&src); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNoPublished
				}
				return mapErr(err)
			}
		}
		if _, err := newDraft(ctx, tx, actor, id, 1, src); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.create", ObjectType: "workflow", ObjectID: id,
			Details: map[string]any{"name": name, "from": from},
		})
	})
	return id, err
}

// newDraft creates a draft version of a workflow, copying the statuses and
// transitions of version src unless src is "".
func newDraft(ctx context.Context, tx *sql.Tx, actor Actor, workflowID string, version int, src string) (string, error) {
	var id string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO workflow_version (workflow_id, version, created_by) VALUES ($1, $2, $3) RETURNING id`,
		workflowID, version, actor.ID).Scan(&id); err != nil {
		return "", mapErr(err)
	}
	if src == "" {
		return id, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO wf_status (version_id, key, name, category, position, initial, x, y)
		SELECT $1, key, name, category, position, initial, x, y FROM wf_status WHERE version_id = $2`, id, src); err != nil {
		return "", err
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO wf_transition (version_id, name, from_status, to_status, position, conditions, validators, post_functions, screen)
		SELECT $1, t.name, nf.id, nt.id, t.position, t.conditions, t.validators, t.post_functions, t.screen
		FROM wf_transition t
		JOIN wf_status ot ON ot.id = t.to_status JOIN wf_status nt ON nt.version_id = $1 AND nt.key = ot.key
		LEFT JOIN wf_status fo ON fo.id = t.from_status LEFT JOIN wf_status nf ON nf.version_id = $1 AND nf.key = fo.key
		WHERE t.version_id = $2`, id, src)
	return id, err
}

// UpdateWorkflow renames a workflow or makes it the default, which new
// project ticket types get unless told otherwise.
func (s *Store) UpdateWorkflow(ctx context.Context, actor Actor, id, name, description string, def bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var oldName, oldDesc string
		var oldDef bool
		if err := tx.QueryRowContext(ctx, `SELECT name, description, is_default FROM workflow WHERE id = $1 FOR UPDATE`, id).
			Scan(&oldName, &oldDesc, &oldDef); err != nil {
			return mapErr(err)
		}
		if oldDef && !def {
			def = true // there is always a default: make another one the default instead
		}
		if def && !oldDef {
			var published bool
			if err := tx.QueryRowContext(ctx, `
				SELECT EXISTS (SELECT 1 FROM workflow_version WHERE workflow_id = $1 AND state = 'published')`, id).
				Scan(&published); err != nil {
				return err
			}
			if !published {
				return ErrNoPublished
			}
			if _, err := tx.ExecContext(ctx, `UPDATE workflow SET is_default = false WHERE is_default`); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE workflow SET name = $2, description = $3, is_default = $4 WHERE id = $1`,
			id, name, description, def); err != nil {
			return mapErr(err)
		}
		if name == oldName && description == oldDesc && def == oldDef {
			return nil
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.update", ObjectType: "workflow", ObjectID: id,
			Details: map[string]any{"name": name, "description": description, "default": def},
		})
	})
}

// DeleteWorkflow deletes a workflow no project ticket type uses and no item
// is on.
func (s *Store) DeleteWorkflow(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		var def, used bool
		if err := tx.QueryRowContext(ctx, `
			SELECT name, is_default,
			       EXISTS (SELECT 1 FROM project_ticket_type WHERE workflow_id = f.id)
			       OR EXISTS (SELECT 1 FROM work_item w JOIN workflow_version v ON v.id = w.workflow_version_id WHERE v.workflow_id = f.id)
			FROM workflow f WHERE id = $1 FOR UPDATE`, id).Scan(&name, &def, &used); err != nil {
			return mapErr(err)
		}
		if def || used {
			return ErrInUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM workflow WHERE id = $1`, id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.delete", ObjectType: "workflow", ObjectID: id, Details: map[string]any{"name": name},
		})
	})
}

// EditWorkflow returns the workflow's draft, creating one from its newest
// published version when there is none.
func (s *Store) EditWorkflow(ctx context.Context, actor Actor, workflowID string) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM workflow WHERE id = $1 FOR UPDATE`, workflowID).Scan(&name); err != nil {
			return mapErr(err)
		}
		var next int
		var src string
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE((SELECT id::text FROM workflow_version WHERE workflow_id = $1 AND state = 'draft'), ''),
			       COALESCE((SELECT max(version) FROM workflow_version WHERE workflow_id = $1), 0) + 1,
			       COALESCE((SELECT id::text FROM workflow_version WHERE workflow_id = $1 AND state = 'published'
			                 ORDER BY version DESC LIMIT 1), '')`, workflowID).Scan(&id, &next, &src); err != nil {
			return err
		}
		if id != "" {
			return nil
		}
		var err error
		if id, err = newDraft(ctx, tx, actor, workflowID, next, src); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.draft", ObjectType: "workflow", ObjectID: workflowID,
			Details: map[string]any{"name": name, "version": next},
		})
	})
	return id, err
}

// draftTx runs fn on a draft version, locked; anything else is refused. It
// returns the workflow ID and the version number for the audit entry.
func (s *Store) draftTx(ctx context.Context, versionID string, fn func(tx *sql.Tx, workflowID string, version int) error) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var workflowID, state string
		var version int
		if err := tx.QueryRowContext(ctx, `SELECT workflow_id, version, state FROM workflow_version WHERE id = $1 FOR UPDATE`,
			versionID).Scan(&workflowID, &version, &state); err != nil {
			return mapErr(err)
		}
		if state != VersionDraft {
			return ErrNotDraft
		}
		return fn(tx, workflowID, version)
	})
}

// DiscardDraft deletes a draft version.
func (s *Store) DiscardDraft(ctx context.Context, actor Actor, versionID string) error {
	return s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM workflow_version WHERE id = $1`, versionID); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.discard", ObjectType: "workflow", ObjectID: workflowID, Details: map[string]any{"version": version},
		})
	})
}

func editAudit(ctx context.Context, tx *sql.Tx, actor Actor, workflowID string, version int, what string, details map[string]any) error {
	details["version"], details["edit"] = version, what
	return appendAudit(ctx, tx, actor, AuditEvent{Action: "workflow.edit", ObjectType: "workflow", ObjectID: workflowID, Details: details})
}

// SaveStatus adds a status to a draft when id is "", else changes it. A
// status marked initial takes over from the old one. The key is fixed once
// created, since migrations match statuses by it.
func (s *Store) SaveStatus(ctx context.Context, actor Actor, versionID, id string, in WfStatus) (string, error) {
	err := s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		if in.Initial {
			if _, err := tx.ExecContext(ctx, `UPDATE wf_status SET initial = false WHERE version_id = $1 AND initial AND id::text <> $2`,
				versionID, id); err != nil {
				return err
			}
		}
		what := "status.update"
		if id == "" {
			what = "status.create"
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO wf_status (version_id, key, name, category, position, initial, x, y) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				RETURNING id`, versionID, in.Key, in.Name, in.Category, in.Position, in.Initial, in.X, in.Y).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else if err := tx.QueryRowContext(ctx, `
			UPDATE wf_status SET name = $3, category = $4, position = $5, initial = $6 WHERE id = $1 AND version_id = $2
			RETURNING key`, id, versionID, in.Name, in.Category, in.Position, in.Initial).Scan(&in.Key); err != nil {
			return mapErr(err)
		}
		return editAudit(ctx, tx, actor, workflowID, version, what,
			map[string]any{"key": in.Key, "name": in.Name, "category": in.Category, "initial": in.Initial})
	})
	return id, err
}

// StatusPoint is where a status sits on the diagram.
type StatusPoint struct{ X, Y float64 }

// PlaceStatuses moves statuses of a draft on its diagram. Statuses of other
// versions are ignored.
func (s *Store) PlaceStatuses(ctx context.Context, versionID string, at map[string]StatusPoint) error {
	return s.draftTx(ctx, versionID, func(tx *sql.Tx, _ string, _ int) error {
		for id, p := range at {
			if _, err := tx.ExecContext(ctx, `UPDATE wf_status SET x = $3, y = $4 WHERE id::text = $1 AND version_id = $2`,
				id, versionID, p.X, p.Y); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteStatus removes a status from a draft, with the transitions to and
// from it.
func (s *Store) DeleteStatus(ctx context.Context, actor Actor, versionID, id string) error {
	return s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		var key string
		if err := tx.QueryRowContext(ctx, `DELETE FROM wf_status WHERE id = $1 AND version_id = $2 RETURNING key`, id, versionID).
			Scan(&key); err != nil {
			return mapErr(err)
		}
		return editAudit(ctx, tx, actor, workflowID, version, "status.delete", map[string]any{"key": key})
	})
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	if string(b) == "null" {
		return "[]"
	}
	return string(b)
}

// SaveTransition adds a transition to a draft when id is "", else changes
// it.
func (s *Store) SaveTransition(ctx context.Context, actor Actor, versionID, id string, in WfTransition) (string, error) {
	err := s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		what := "transition.update"
		args := []any{versionID, in.Name, in.FromID, in.ToID, in.Position, toJSON(in.Conditions), toJSON(in.Validators),
			toJSON(in.PostFunctions), toJSON(in.Screen)}
		if id == "" {
			what = "transition.create"
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO wf_transition (version_id, name, from_status, to_status, position, conditions, validators, post_functions, screen)
				VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8, $9) RETURNING id`, args...).Scan(&id); err != nil {
				return mapTransitionErr(err)
			}
		} else {
			res, err := tx.ExecContext(ctx, `
				UPDATE wf_transition SET name = $2, from_status = NULLIF($3, '')::uuid, to_status = $4, position = $5,
				       conditions = $6, validators = $7, post_functions = $8, screen = $9
				WHERE id = $10 AND version_id = $1`, append(args, id)...)
			if err != nil {
				return mapTransitionErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return editAudit(ctx, tx, actor, workflowID, version, what, map[string]any{"transition": id, "name": in.Name})
	})
	return id, err
}

// mapTransitionErr turns "from and to are the same status" into
// ErrConflict.
func mapTransitionErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "wf_transition_check") {
		return ErrConflict
	}
	return mapErr(err)
}

func (s *Store) DeleteTransition(ctx context.Context, actor Actor, versionID, id string) error {
	return s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM wf_transition WHERE id = $1 AND version_id = $2 RETURNING name`, id, versionID).
			Scan(&name); err != nil {
			return mapErr(err)
		}
		return editAudit(ctx, tx, actor, workflowID, version, "transition.delete", map[string]any{"transition": id, "name": name})
	})
}

// CheckVersion lists what stops a version from being published: no
// statuses, no initial status, statuses no item can reach from it.
func CheckVersion(v WorkflowVersion) []string {
	var out []string
	if len(v.Statuses) == 0 {
		return []string{"Add at least one status."}
	}
	initial := slices.IndexFunc(v.Statuses, func(s WfStatus) bool { return s.Initial })
	if initial < 0 {
		return []string{"Mark one status as initial: new items start there."}
	}
	reached := map[string]bool{v.Statuses[initial].ID: true}
	queue := []string{v.Statuses[initial].ID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, t := range v.Transitions {
			if (t.FromID == "" || t.FromID == cur) && !reached[t.ToID] {
				reached[t.ToID] = true
				queue = append(queue, t.ToID)
			}
		}
	}
	var lost []string
	for _, st := range v.Statuses {
		if !reached[st.ID] {
			lost = append(lost, st.Name)
		}
	}
	if len(lost) > 0 {
		out = append(out, "No transitions lead from "+v.Statuses[initial].Name+" to "+strings.Join(lost, ", ")+".")
	}
	return out
}

// PublishDraft freezes a draft as the version new items start on. Older
// published versions no item is on any more are retired; items on the
// others stay there until they are migrated.
func (s *Store) PublishDraft(ctx context.Context, actor Actor, versionID string) error {
	return s.draftTx(ctx, versionID, func(tx *sql.Tx, workflowID string, version int) error {
		v, err := getVersion(ctx, tx, versionID)
		if err != nil {
			return err
		}
		if problems := CheckVersion(v); len(problems) > 0 {
			return &WorkflowError{Problems: problems}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE workflow_version SET state = 'published', published_at = now(), published_by = $2 WHERE id = $1`,
			versionID, actor.ID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			UPDATE workflow_version v SET state = 'retired'
			WHERE v.workflow_id = $1 AND v.state = 'published' AND v.id <> $2
			  AND NOT EXISTS (SELECT 1 FROM work_item w WHERE w.workflow_version_id = v.id)
			RETURNING v.version`, workflowID, versionID)
		if err != nil {
			return err
		}
		var retired []int
		for rows.Next() {
			var n int
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return err
			}
			retired = append(retired, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "workflow.publish", ObjectType: "workflow", ObjectID: workflowID,
			Details: map[string]any{"version": version, "retired": retired},
		})
	})
}

// latestVersion is the newest published version of a workflow and its
// initial status.
func latestVersion(ctx context.Context, tx *sql.Tx, workflowID string) (version, initial string, err error) {
	err = tx.QueryRowContext(ctx, `
		SELECT v.id, s.id FROM workflow_version v JOIN wf_status s ON s.version_id = v.id AND s.initial
		WHERE v.workflow_id = $1 AND v.state = 'published' ORDER BY v.version DESC LIMIT 1`, workflowID).Scan(&version, &initial)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNoPublished
	}
	return version, initial, err
}

// Transitions on work items ---------------------------------------------------------

// ItemTransitions lists the transitions out of an item's status on its
// version, whoever may run them.
func (s *Store) ItemTransitions(ctx context.Context, it WorkItem) ([]WfTransition, error) {
	return versionTransitions(ctx, s.db, `t.version_id = $1 AND (t.from_status IS NULL OR t.from_status = $2) AND t.to_status <> $2`,
		it.WorkflowVersionID, it.StatusID)
}

// TransitionInput is what a transition's screen collected. Fields the
// screen doesn't ask for are ignored.
type TransitionInput struct {
	Resolution string // for a done status; "" means Done
	AssigneeID string // "" for nobody
	Comment    string
}

// TransitionWorkItem runs a transition on an item: it checks the
// conditions and validators, applies the screen's input, moves the item,
// runs the post-functions and records it all in the item's history.
func (s *Store) TransitionWorkItem(ctx context.Context, actor Actor, r Runner, itemID, transitionID string, in TransitionInput) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		ref, err := lockItem(ctx, tx, itemID)
		if err != nil {
			return err
		}
		before, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, itemID))
		if err != nil {
			return mapErr(err)
		}
		ts, err := versionTransitions(ctx, tx, `t.id::text = $1`, transitionID)
		if err != nil {
			return err
		}
		if len(ts) == 0 {
			return ErrStaleTransition
		}
		t := ts[0]
		var version string
		if err := tx.QueryRowContext(ctx, `SELECT version_id FROM wf_transition WHERE id = $1`, t.ID).Scan(&version); err != nil {
			return err
		}
		if version != before.WorkflowVersionID || (t.FromID != "" && t.FromID != before.StatusID) || t.ToID == before.StatusID {
			return ErrStaleTransition
		}
		if !t.Allowed(before, r) {
			return ErrTransitionDenied
		}

		after := before
		after.StatusID, after.StatusName, after.Status = t.ToID, t.ToName, t.ToCategory
		after.Resolution = ""
		if t.ToCategory == StatusDone {
			after.Resolution = "Done"
			if t.Asks("resolution") && in.Resolution != "" {
				if !slices.Contains(Resolutions, in.Resolution) {
					return &TransitionError{"Pick a resolution."}
				}
				after.Resolution = in.Resolution
			}
		}
		if t.Asks("assignee") {
			after.AssigneeID = in.AssigneeID
		}
		comment := ""
		if t.Asks("comment") {
			comment = strings.TrimSpace(in.Comment)
		}
		if err := validate(ctx, tx, t, after, comment); err != nil {
			return err
		}
		for _, p := range t.PostFunctions {
			switch p.Type {
			case "assign":
				switch p.Value {
				case "actor":
					after.AssigneeID = r.UserID
				case "reporter":
					after.AssigneeID = before.ReporterID
				case "none":
					after.AssigneeID = ""
				}
			case "set_priority":
				if slices.Contains(Priorities, p.Value) {
					after.Priority = p.Value
				}
			}
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE work_item SET status_id = $2, resolution = NULLIF($3, ''), assignee = NULLIF($4, '')::uuid, priority = $5,
			       updated_at = now(),
			       resolved_at = CASE WHEN $6 <> 'done' THEN NULL WHEN status_category = 'done' THEN resolved_at ELSE now() END
			WHERE id = $1`, itemID, after.StatusID, after.Resolution, after.AssigneeID, after.Priority, t.ToCategory); err != nil {
			return mapErr(err)
		}
		moved, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, itemID))
		if err != nil {
			return err
		}
		changes := statusChanges(before, moved)
		changes = append(changes, itemChanges(before, moved)...)
		if moved.AssigneeID != before.AssigneeID {
			if err := addWatcher(ctx, tx, itemID, moved.AssigneeID); err != nil {
				return err
			}
		}
		if err := addItemHistory(ctx, tx, itemID, actor.ID, map[string]any{"changed": changes, "transition": t.Name}); err != nil {
			return err
		}
		if comment != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO comment (work_item_id, author, body) VALUES ($1, NULLIF($2, '')::uuid, $3)`,
				itemID, r.UserID, comment); err != nil {
				return mapErr(err)
			}
			if err := addWatcher(ctx, tx, itemID, r.UserID); err != nil {
				return err
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "work_item.transition", ObjectType: "work_item", ObjectID: itemID,
			Details: map[string]any{"ref": ref, "transition": t.Name, "from": before.StatusName, "to": moved.StatusName,
				"resolution": moved.Resolution},
		})
	})
}

// validate runs a transition's validators against the item as it will be.
func validate(ctx context.Context, tx *sql.Tx, t WfTransition, it WorkItem, comment string) error {
	for _, v := range t.Validators {
		var ok bool
		var msg string
		switch v.Type {
		case "field_required":
			switch v.Field {
			case "assignee":
				ok, msg = it.AssigneeID != "", "Assign the item first."
			case "description":
				ok, msg = strings.TrimSpace(it.Description) != "", "Describe the item first."
			case "estimate":
				ok, msg = it.Estimate != nil, "Estimate the item first."
			case "due":
				ok, msg = !it.DueAt.IsZero(), "Set a due date first."
			case "impact":
				ok, msg = it.Impact != "", "Set the impact first."
			case "urgency":
				ok, msg = it.Urgency != "", "Set the urgency first."
			default:
				ok = true
			}
		case "linked_change":
			msg = "Link a change first."
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM work_item_change WHERE work_item_id = $1)`, it.ID).
				Scan(&ok); err != nil {
				return err
			}
		case "linked_ci":
			msg = "Link a CI first."
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM work_item_ci WHERE work_item_id = $1)`, it.ID).
				Scan(&ok); err != nil {
				return err
			}
		case "children_done":
			msg = "Finish the child items first."
			if err := tx.QueryRowContext(ctx, `
				SELECT NOT EXISTS (SELECT 1 FROM work_item WHERE parent_id = $1 AND status_category <> 'done')`, it.ID).
				Scan(&ok); err != nil {
				return err
			}
		case "comment_required":
			ok, msg = comment != "", "Add a comment."
		default:
			ok = true
		}
		if !ok {
			return &TransitionError{msg}
		}
	}
	return nil
}

// statusChanges names a move between statuses, and the resolution, in
// history terms.
func statusChanges(a, b WorkItem) []inventory.Change {
	var out []inventory.Change
	if a.StatusID != b.StatusID {
		out = append(out, inventory.Change{Field: "status", From: a.StatusName, To: b.StatusName})
	}
	if a.Resolution != b.Resolution {
		out = append(out, inventory.Change{Field: "resolution", From: a.Resolution, To: b.Resolution})
	}
	return out
}

// TransitionName is a transition name used in a published version, and
// whether any transition by that name leads to a done status.
type TransitionName struct {
	Name   string
	ToDone bool
}

// TransitionNames lists the names of the transitions items can run now,
// for bulk actions.
func (s *Store) TransitionNames(ctx context.Context) ([]TransitionName, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.name, bool_or(ts.category = 'done') FROM wf_transition t
		JOIN workflow_version v ON v.id = t.version_id JOIN wf_status ts ON ts.id = t.to_status
		WHERE v.state = 'published' GROUP BY t.name ORDER BY min(t.position), t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TransitionName
	for rows.Next() {
		var n TransitionName
		if err := rows.Scan(&n.Name, &n.ToDone); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// StatusNames lists the names of the statuses of published versions, for
// filters.
func (s *Store) StatusNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.name FROM wf_status s JOIN workflow_version v ON v.id = s.version_id
		WHERE v.state <> 'draft' GROUP BY s.name
		ORDER BY min(array_position(ARRAY['todo', 'in_progress', 'done'], s.category)), min(s.position), s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
)

// Change model states: a model is pre-approved once by an approver; editing
// it puts it back to pending (docs/change-management.md §1).
const (
	ModelPending  = "pending"
	ModelApproved = "approved"
	ModelRetired  = "retired"
)

// ChangeModel is a Standard change model: an action and its parameters,
// approved once, so each change made from it is approved automatically.
// The targets are chosen per change; for compose.* the stack is too.
type ChangeModel struct {
	ID              string
	Name            string
	Description     string
	Action          string
	Params          json.RawMessage
	ScriptID        string
	ScriptVersion   int
	Risk            string
	State           string
	RequestedBy     string
	RequestedByName string
	ApprovedByName  string
	ApprovedAt      time.Time
	SelfApproved    bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Changes         int // made from it
	PatchGroups     int // that run under it
	Stacks          int // whose updates run under it
}

// Summary describes what a change from the model does.
func (m ChangeModel) Summary() string {
	switch m.Action {
	case action.ComposeUpdate, action.ComposePull:
		var p action.ComposeParams
		json.Unmarshal(m.Params, &p)
		s := action.MustGet(m.Action).Label
		if p.HealthTimeout > 0 {
			s += ", " + (time.Duration(p.HealthTimeout) * time.Second).String() + " to come up healthy"
		}
		return s
	}
	return action.Describe(m.Action, m.Params)
}

// Approved reports whether changes can be made from the model.
func (m ChangeModel) Approved() bool { return m.State == ModelApproved }

const modelCols = `m.id, m.name, m.description, m.action, m.params::text, COALESCE(m.script_id::text, ''),
	COALESCE(m.script_version, 0), m.risk, m.state, COALESCE(m.requested_by::text, ''),
	COALESCE(NULLIF(u.name, ''), u.email, ''), COALESCE(NULLIF(a.name, ''), a.email, ''), COALESCE(m.approved_at, 'epoch'),
	m.self_approved, m.created_at, m.updated_at,
	(SELECT count(*) FROM change c WHERE c.model_id = m.id),
	(SELECT count(*) FROM patch_group g WHERE g.change_model_id = m.id),
	(SELECT count(*) FROM compose_stack s WHERE s.change_model_id = m.id)
	FROM change_model m LEFT JOIN app_user u ON u.id = m.requested_by LEFT JOIN app_user a ON a.id = m.approved_by `

func scanModel(row interface{ Scan(...any) error }) (ChangeModel, error) {
	var m ChangeModel
	var params string
	err := row.Scan(&m.ID, &m.Name, &m.Description, &m.Action, &params, &m.ScriptID, &m.ScriptVersion, &m.Risk, &m.State,
		&m.RequestedBy, &m.RequestedByName, &m.ApprovedByName, &m.ApprovedAt, &m.SelfApproved, &m.CreatedAt, &m.UpdatedAt,
		&m.Changes, &m.PatchGroups, &m.Stacks)
	m.Params = json.RawMessage(params)
	if m.ApprovedAt.Unix() == 0 {
		m.ApprovedAt = time.Time{}
	}
	return m, err
}

// ListChangeModels lists models, of one action when act isn't "".
func (s *Store) ListChangeModels(ctx context.Context, act string) ([]ChangeModel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+modelCols+`WHERE $1 = '' OR m.action = $1
		ORDER BY m.state = 'retired', lower(m.name)`, act)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeModel
	for rows.Next() {
		m, err := scanModel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) GetChangeModel(ctx context.Context, id string) (ChangeModel, error) {
	m, err := scanModel(s.db.QueryRowContext(ctx, `SELECT `+modelCols+`WHERE m.id = $1`, id))
	return m, mapErr(err)
}

// SaveChangeModel creates a model (ID "") or edits one. Either way it is
// pending until an approver approves it: changes can't be made from it
// meanwhile. Params must be validated (internal/change.ModelParams).
func (s *Store) SaveChangeModel(ctx context.Context, actor Actor, m ChangeModel) (string, error) {
	var script sql.NullString
	var version sql.NullInt64
	if m.ScriptID != "" {
		script, version = sql.NullString{String: m.ScriptID, Valid: true}, sql.NullInt64{Int64: int64(m.ScriptVersion), Valid: true}
	}
	id := m.ID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		ev := "change_model.create"
		if id == "" {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO change_model (name, description, action, params, script_id, script_version, risk, requested_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
				m.Name, m.Description, m.Action, string(m.Params), script, version, m.Risk, actor.userID()).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			ev = "change_model.update"
			res, err := tx.ExecContext(ctx, `
				UPDATE change_model SET name = $2, description = $3, action = $4, params = $5, script_id = $6,
				       script_version = $7, risk = $8, requested_by = $9, state = 'pending', approved_by = NULL,
				       approved_at = NULL, self_approved = false, updated_at = now()
				WHERE id = $1 AND state <> 'retired'`,
				id, m.Name, m.Description, m.Action, string(m.Params), script, version, m.Risk, actor.userID())
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: ev, ObjectType: "change_model", ObjectID: id,
			Details: map[string]any{"name": m.Name, "action": m.Action, "params": m.Params, "risk": m.Risk,
				"state": ModelPending}})
	})
	return id, err
}

// ApproveChangeModel approves a pending model. Approving one's own is
// allowed and flagged, like changes.
func (s *Store) ApproveChangeModel(ctx context.Context, actor Actor, id string) error {
	if !actor.userID().Valid {
		return errors.New("only users approve change models")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		var self bool
		err := tx.QueryRowContext(ctx, `
			UPDATE change_model SET state = 'approved', approved_by = $2, approved_at = now(),
			       self_approved = COALESCE(requested_by = $2, false), updated_at = now()
			WHERE id = $1 AND state = 'pending' RETURNING name, self_approved`, id, actor.userID()).Scan(&name, &self)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "change_model.approve", ObjectType: "change_model", ObjectID: id,
			Details: map[string]any{"name": name, "self_approved": self}})
	})
}

// RetireChangeModel stops a model being used; changes made from it stay.
// Patch groups and stacks using it can't run until they get another.
func (s *Store) RetireChangeModel(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRowContext(ctx, `
			UPDATE change_model SET state = 'retired', updated_at = now() WHERE id = $1 AND state <> 'retired' RETURNING name`, id).
			Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "change_model.retire", ObjectType: "change_model", ObjectID: id,
			Details: map[string]any{"name": name}})
	})
}

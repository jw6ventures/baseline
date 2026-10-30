package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Workflow migration (docs/data-model.md §12) ----------------------------------------
//
// A migration moves work items off a workflow version (kind workflow), or to
// another project or ticket type (kind move), mapping each item's status to
// one of the target version's. An admin builds it as a draft: the target,
// the status mapping and the items, picked with the list engine. Starting
// it freezes the selection; a background runner then moves the items in
// batches, each with a history entry. Validators and post-functions don't
// run: it is an admin move, not a transition.

// Migration kinds and states.
const (
	MigrationWorkflow = "workflow"
	MigrationMove     = "move"

	MigrationDraft   = "draft"
	MigrationRunning = "running"
	MigrationDone    = "done"
	MigrationFailed  = "failed"
)

// MaxMigrationItems caps one migration's selection.
const MaxMigrationItems = 20000

var (
	// ErrSameTarget refuses a migration whose items are already where it
	// would take them.
	ErrSameTarget = errors.New("the items are already there")
	// ErrStarted refuses to change a migration that has started.
	ErrStarted = errors.New("the migration has already started")
	// ErrNothingSelected refuses to start a migration with no items.
	ErrNothingSelected = errors.New("no items are selected")
	// ErrTooMany refuses a selection over MaxMigrationItems.
	ErrTooMany = fmt.Errorf("select at most %d items at a time", MaxMigrationItems)
)

// WfMigration is a migration, as drafted or as it ran.
type WfMigration struct {
	ID   string
	Kind string
	// Kind workflow: the version items leave and the workflow whose newest
	// published version they go to.
	FromVersionID    string
	FromVersion      int
	FromWorkflowID   string
	FromWorkflowName string
	ToWorkflowID     string
	ToWorkflowName   string
	// Kind move: the project and type items leave, and where they go.
	FromProjectID  string
	FromProjectKey string
	FromTypeID     string
	FromTypeName   string
	ToProjectID    string
	ToProjectKey   string
	ToTypeID       string
	ToTypeName     string
	// The version items went to, settled when the migration started.
	ToVersionID       string
	ToVersion         int
	ToVersionWorkflow string
	// Mapping maps a source status ID to a target status key.
	Mapping    map[string]string
	Query      string   // the list engine query that picks items
	Excluded   []string // item IDs unticked from it
	State      string
	Total      int
	Done       int
	Skipped    int
	Error      string
	CreatedAt  time.Time
	CreatedBy  string
	StartedAt  time.Time
	StartedBy  string
	FinishedAt time.Time
}

func (m WfMigration) Draft() bool { return m.State == MigrationDraft }

// From and To describe where the items come from and go, in words.
func (m WfMigration) From() string {
	if m.Kind == MigrationWorkflow {
		return fmt.Sprintf("%s v%d", m.FromWorkflowName, m.FromVersion)
	}
	return m.FromProjectKey + " " + m.FromTypeName
}

func (m WfMigration) To() string {
	if m.Kind == MigrationWorkflow {
		if m.ToVersion > 0 {
			return fmt.Sprintf("%s v%d", m.ToVersionWorkflow, m.ToVersion)
		}
		return m.ToWorkflowName
	}
	return m.ToProjectKey + " " + m.ToTypeName
}

// IsExcluded reports whether an item was unticked.
func (m WfMigration) IsExcluded(id string) bool { return slices.Contains(m.Excluded, id) }

const wfMigrationCols = `m.id, m.kind,
	COALESCE(m.from_version::text, ''), COALESCE(fv.version, 0), COALESCE(fw.id::text, ''), COALESCE(fw.name, ''),
	COALESCE(m.to_workflow::text, ''), COALESCE(tw.name, ''),
	COALESCE(m.from_project::text, ''), COALESCE(fp.key, ''), COALESCE(m.from_type::text, ''), COALESCE(ft.name, ''),
	COALESCE(m.to_project::text, ''), COALESCE(tp.key, ''), COALESCE(m.to_type::text, ''), COALESCE(tt.name, ''),
	COALESCE(m.to_version::text, ''), COALESCE(tv.version, 0), COALESCE(tvw.name, ''),
	m.mapping::text, m.query, m.excluded::text[], m.state, m.items_total, m.items_done, m.items_skipped, m.error,
	m.created_at, m.created_by, m.started_at, COALESCE(m.started_by, ''), m.finished_at`

const wfMigrationFrom = ` FROM wf_migration m
	LEFT JOIN workflow_version fv ON fv.id = m.from_version LEFT JOIN workflow fw ON fw.id = fv.workflow_id
	LEFT JOIN workflow tw ON tw.id = m.to_workflow
	LEFT JOIN project fp ON fp.id = m.from_project LEFT JOIN ticket_type ft ON ft.id = m.from_type
	LEFT JOIN project tp ON tp.id = m.to_project LEFT JOIN ticket_type tt ON tt.id = m.to_type
	LEFT JOIN workflow_version tv ON tv.id = m.to_version LEFT JOIN workflow tvw ON tvw.id = tv.workflow_id `

func scanWfMigration(row interface{ Scan(...any) error }) (WfMigration, error) {
	var m WfMigration
	var mapping string
	var started, finished sql.NullTime
	err := row.Scan(&m.ID, &m.Kind,
		&m.FromVersionID, &m.FromVersion, &m.FromWorkflowID, &m.FromWorkflowName, &m.ToWorkflowID, &m.ToWorkflowName,
		&m.FromProjectID, &m.FromProjectKey, &m.FromTypeID, &m.FromTypeName,
		&m.ToProjectID, &m.ToProjectKey, &m.ToTypeID, &m.ToTypeName,
		&m.ToVersionID, &m.ToVersion, &m.ToVersionWorkflow,
		&mapping, &m.Query, pq.Array(&m.Excluded), &m.State, &m.Total, &m.Done, &m.Skipped, &m.Error,
		&m.CreatedAt, &m.CreatedBy, &started, &m.StartedBy, &finished)
	if err != nil {
		return m, err
	}
	m.StartedAt, m.FinishedAt = started.Time, finished.Time
	return m, json.Unmarshal([]byte(mapping), &m.Mapping)
}

func (s *Store) GetMigration(ctx context.Context, id string) (WfMigration, error) {
	m, err := scanWfMigration(s.db.QueryRowContext(ctx, `SELECT `+wfMigrationCols+wfMigrationFrom+` WHERE m.id = $1`, id))
	return m, mapErr(err)
}

// ListMigrations lists migrations, drafts and running ones first, then
// the newest.
func (s *Store) ListMigrations(ctx context.Context, limit int) ([]WfMigration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+wfMigrationCols+wfMigrationFrom+`
		ORDER BY m.state NOT IN ('draft', 'running'), COALESCE(m.started_at, m.created_at) DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WfMigration
	for rows.Next() {
		m, err := scanWfMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RunningMigrations lists the IDs of the migrations a runner should work
// on, oldest first.
func (s *Store) RunningMigrations(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM wf_migration WHERE state = 'running' ORDER BY started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// WfMigrationInput is a new migration: for kind workflow, FromVersionID and
// ToWorkflowID; for kind move, the project and type pairs. Query is the list
// engine query to start the selection with.
type WfMigrationInput struct {
	Kind          string
	FromVersionID string
	ToWorkflowID  string
	FromProjectID string
	FromTypeID    string
	ToProjectID   string
	ToTypeID      string
	Query         string
}

// CreateMigration drafts a migration.
func (s *Store) CreateMigration(ctx context.Context, actor Actor, in WfMigrationInput) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		details := map[string]any{"kind": in.Kind}
		switch in.Kind {
		case MigrationWorkflow:
			var state string
			if err := tx.QueryRowContext(ctx, `SELECT state FROM workflow_version WHERE id::text = $1`, in.FromVersionID).
				Scan(&state); err != nil {
				return mapErr(err)
			}
			if state == VersionDraft {
				return ErrNotFound // a draft has no items
			}
			to, err := latestPublished(ctx, tx, in.ToWorkflowID)
			if err != nil {
				return err
			}
			if to == in.FromVersionID {
				return ErrSameTarget
			}
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO wf_migration (kind, from_version, to_workflow, query, created_by) VALUES ('workflow', $1, $2, $3, $4)
				RETURNING id`, in.FromVersionID, in.ToWorkflowID, in.Query, actor.ID).Scan(&id); err != nil {
				return mapErr(err)
			}
			details["from_version"], details["to_workflow"] = in.FromVersionID, in.ToWorkflowID
		case MigrationMove:
			if in.FromProjectID == in.ToProjectID && in.FromTypeID == in.ToTypeID {
				return ErrSameTarget
			}
			if _, err := moveTarget(ctx, tx, in.ToProjectID, in.ToTypeID); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO wf_migration (kind, from_project, from_type, to_project, to_type, query, created_by)
				VALUES ('move', $1, $2, $3, $4, $5, $6) RETURNING id`,
				in.FromProjectID, in.FromTypeID, in.ToProjectID, in.ToTypeID, in.Query, actor.ID).Scan(&id); err != nil {
				return mapErr(err)
			}
			details["from_project"], details["from_type"] = in.FromProjectID, in.FromTypeID
			details["to_project"], details["to_type"] = in.ToProjectID, in.ToTypeID
		default:
			return ErrNotFound
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "migration.create", ObjectType: "wf_migration", ObjectID: id,
			Details: details})
	})
	return id, err
}

// latestPublished is the ID of a workflow's newest published version.
func latestPublished(ctx context.Context, q rowQuerier, workflowID string) (string, error) {
	var id string
	err := q.QueryRowContext(ctx, `
		SELECT id FROM workflow_version WHERE workflow_id::text = $1 AND state = 'published'
		ORDER BY version DESC LIMIT 1`, workflowID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM workflow WHERE id::text = $1)`, workflowID).
			Scan(&exists); err != nil || !exists {
			return "", ErrNotFound
		}
		return "", ErrNoPublished
	}
	return id, mapErr(err)
}

// moveTarget is the version items moved to a project and type start on:
// the newest published version of the workflow the pair uses.
func moveTarget(ctx context.Context, q rowQuerier, projectID, typeID string) (string, error) {
	var workflowID string
	var archived bool
	if err := q.QueryRowContext(ctx, `
		SELECT pt.workflow_id, p.archived FROM project_ticket_type pt JOIN project p ON p.id = pt.project_id
		WHERE pt.project_id::text = $1 AND pt.ticket_type_id::text = $2`, projectID, typeID).Scan(&workflowID, &archived); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrTypeNotOffered
		}
		return "", mapErr(err)
	}
	if archived {
		return "", ErrArchived
	}
	return latestPublished(ctx, q, workflowID)
}

// targetVersion is the version a migration's items would go to now.
func targetVersion(ctx context.Context, q rowQuerier, m WfMigration) (string, error) {
	if m.Kind == MigrationWorkflow {
		return latestPublished(ctx, q, m.ToWorkflowID)
	}
	return moveTarget(ctx, q, m.ToProjectID, m.ToTypeID)
}

// scopeSQL is the condition, over work_item w, for the items a migration
// can take, with its arguments numbered from n.
func (m WfMigration) scopeSQL(n int) (string, []any) {
	if m.Kind == MigrationWorkflow {
		return fmt.Sprintf(`w.workflow_version_id = $%d`, n), []any{m.FromVersionID}
	}
	return fmt.Sprintf(`w.project_id = $%d AND w.ticket_type_id = $%d`, n, n+1), []any{m.FromProjectID, m.FromTypeID}
}

// Mapping and preview -------------------------------------------------------------

// Mapping kinds: how a source status got its target.
const (
	MapByKey      = "key"      // a target status has the same key
	MapChosen     = "chosen"   // someone picked it
	MapByCategory = "category" // the first target status of the same category
	MapInitial    = "initial"  // nothing fits better than where new items start
)

// MappingRow is one source status, where its items go and how many of the
// selected items are on it.
type MappingRow struct {
	Status WfStatus
	Target WfStatus
	How    string
	Items  int
}

// MigrationSource is a version the items in scope are on, with a row per
// status.
type MigrationSource struct {
	Version WorkflowVersion
	Rows    []MappingRow
}

// MigrationPlan is what a migration would do if it ran now.
type MigrationPlan struct {
	Target  WorkflowVersion
	Sources []MigrationSource
	Dropped []FieldDef // custom fields a move drops
	Items   int        // selected items
}

// Mapping is the plan's mapping, by source status ID to target key.
func (p MigrationPlan) Mapping() map[string]string {
	out := map[string]string{}
	for _, src := range p.Sources {
		for _, r := range src.Rows {
			out[r.Status.ID] = r.Target.Key
		}
	}
	return out
}

// MapStatus picks the target status for a source status: the one chosen, if
// the target has it, else one with the same key, else the first of the same
// category, else the initial one. target must have statuses.
func MapStatus(src WfStatus, chosen string, target []WfStatus) (WfStatus, string) {
	byKey := func(key string) int { return slices.IndexFunc(target, func(t WfStatus) bool { return t.Key == key }) }
	if i := byKey(chosen); chosen != "" && i >= 0 {
		if chosen == src.Key {
			return target[i], MapByKey
		}
		return target[i], MapChosen
	}
	if i := byKey(src.Key); i >= 0 {
		return target[i], MapByKey
	}
	if i := slices.IndexFunc(target, func(t WfStatus) bool { return t.Category == src.Category }); i >= 0 {
		return target[i], MapByCategory
	}
	if i := slices.IndexFunc(target, func(t WfStatus) bool { return t.Initial }); i >= 0 {
		return target[i], MapInitial
	}
	return target[0], MapInitial
}

// PlanMigration works out what a migration would do now: its target
// version, the versions the items in scope are on with each status mapped,
// how many of selected are on each status, and the custom fields a move
// drops. mapping overrides the stored mapping when not nil.
func (s *Store) PlanMigration(ctx context.Context, m WfMigration, mapping map[string]string, selected []string) (MigrationPlan, error) {
	return planMigration(ctx, s.db, m, mapping, selected)
}

func planMigration(ctx context.Context, q rowQuerier, m WfMigration, mapping map[string]string, selected []string) (MigrationPlan, error) {
	var p MigrationPlan
	if mapping == nil {
		mapping = m.Mapping
	}
	to := m.ToVersionID
	if m.Draft() || to == "" {
		var err error
		if to, err = targetVersion(ctx, q, m); err != nil {
			return p, err
		}
	}
	var err error
	if p.Target, err = getVersion(ctx, q, to); err != nil {
		return p, err
	}
	if len(p.Target.Statuses) == 0 {
		return p, ErrNoPublished
	}

	var versions []string
	if m.Kind == MigrationWorkflow {
		versions = []string{m.FromVersionID}
	} else {
		scope, args := m.scopeSQL(1)
		rows, err := q.QueryContext(ctx, `
			SELECT v.id FROM workflow_version v WHERE v.id IN (SELECT DISTINCT w.workflow_version_id FROM work_item w WHERE `+scope+`)
			ORDER BY v.workflow_id, v.version`, args...)
		if err != nil {
			return p, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return p, err
			}
			versions = append(versions, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return p, err
		}
	}

	counts := map[string]int{}
	if len(selected) > 0 {
		rows, err := q.QueryContext(ctx, `
			SELECT status_id, count(*) FROM work_item WHERE id::text = ANY($1::text[]) GROUP BY status_id`, pq.Array(selected))
		if err != nil {
			return p, err
		}
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return p, err
			}
			counts[id] = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return p, err
		}
	}

	for _, id := range versions {
		v, err := getVersion(ctx, q, id)
		if err != nil {
			return p, err
		}
		src := MigrationSource{Version: v}
		for _, st := range v.Statuses {
			target, how := MapStatus(st, mapping[st.ID], p.Target.Statuses)
			src.Rows = append(src.Rows, MappingRow{Status: st, Target: target, How: how, Items: counts[st.ID]})
			p.Items += counts[st.ID]
		}
		p.Sources = append(p.Sources, src)
	}

	if m.Kind == MigrationMove {
		rows, err := q.QueryContext(ctx, `
			SELECT `+fieldDefCols+` FROM field_def f
			WHERE f.id IN (SELECT gf.field_id FROM project_ticket_type_group x JOIN field_group_field gf ON gf.group_id = x.field_group_id
			               WHERE x.project_id = $1 AND x.ticket_type_id = $2)
			  AND f.id NOT IN (SELECT gf.field_id FROM project_ticket_type_group x JOIN field_group_field gf ON gf.group_id = x.field_group_id
			                   WHERE x.project_id = $3 AND x.ticket_type_id = $4)
			ORDER BY lower(f.label), f.key`, m.FromProjectID, m.FromTypeID, m.ToProjectID, m.ToTypeID)
		if err != nil {
			return p, err
		}
		for rows.Next() {
			f, err := scanFieldDef(rows)
			if err != nil {
				rows.Close()
				return p, err
			}
			p.Dropped = append(p.Dropped, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return p, err
		}
	}
	return p, nil
}

// InScope keeps the items of ids a migration can take, in order.
func (s *Store) InScope(ctx context.Context, m WfMigration, ids []string) ([]string, error) {
	return inScope(ctx, s.db, m, ids)
}

func inScope(ctx context.Context, q querier, m WfMigration, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	scope, args := m.scopeSQL(2)
	rows, err := q.QueryContext(ctx, `
		SELECT w.id FROM work_item w JOIN unnest($1::text[]) WITH ORDINALITY x(id, n) ON x.id = w.id::text
		WHERE `+scope+` ORDER BY x.n`, append([]any{pq.Array(ids)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Editing a draft -------------------------------------------------------------------

// draftMigrationTx runs fn on a draft migration, locked.
func (s *Store) draftMigrationTx(ctx context.Context, id string, fn func(tx *sql.Tx, m WfMigration) error) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM wf_migration WHERE id = $1 FOR UPDATE`, id); err != nil {
			return mapErr(err)
		}
		m, err := scanWfMigration(tx.QueryRowContext(ctx, `SELECT `+wfMigrationCols+wfMigrationFrom+` WHERE m.id = $1`, id))
		if err != nil {
			return mapErr(err)
		}
		if !m.Draft() {
			return ErrStarted
		}
		return fn(tx, m)
	})
}

// SaveMigration stores a draft's mapping and query.
func (s *Store) SaveMigration(ctx context.Context, id string, mapping map[string]string, query string) error {
	return s.draftMigrationTx(ctx, id, func(tx *sql.Tx, m WfMigration) error {
		b, err := json.Marshal(mapping)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE wf_migration SET mapping = $2, query = $3 WHERE id = $1`, id, string(b), query)
		return err
	})
}

// ExcludeItems unticks items from a draft's selection, or ticks them again.
func (s *Store) ExcludeItems(ctx context.Context, id string, ids []string, exclude bool) error {
	ids = slices.DeleteFunc(slices.Clone(ids), func(x string) bool { return !uuidRe.MatchString(x) })
	return s.draftMigrationTx(ctx, id, func(tx *sql.Tx, m WfMigration) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE wf_migration SET excluded = CASE WHEN $3
			    THEN ARRAY(SELECT DISTINCT x FROM unnest(excluded || $2::uuid[]) x ORDER BY x)
			    ELSE ARRAY(SELECT x FROM unnest(excluded) x WHERE x <> ALL($2::uuid[])) END
			WHERE id = $1`, id, pq.Array(ids), exclude)
		return err
	})
}

// IncludeAll ticks every item of a draft again.
func (s *Store) IncludeAll(ctx context.Context, id string) error {
	return s.draftMigrationTx(ctx, id, func(tx *sql.Tx, m WfMigration) error {
		_, err := tx.ExecContext(ctx, `UPDATE wf_migration SET excluded = '{}' WHERE id = $1`, id)
		return err
	})
}

// DeleteMigration discards a draft.
func (s *Store) DeleteMigration(ctx context.Context, actor Actor, id string) error {
	return s.draftMigrationTx(ctx, id, func(tx *sql.Tx, m WfMigration) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM wf_migration WHERE id = $1`, id); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "migration.delete", ObjectType: "wf_migration", ObjectID: id,
			Details: map[string]any{"from": m.From(), "to": m.To()}})
	})
}

// StartMigration saves a draft's mapping and query, freezes its selection
// (items, less those unticked and those out of scope) and hands it to the
// runner. It returns how many items it will move.
func (s *Store) StartMigration(ctx context.Context, actor Actor, id string, mapping map[string]string, query string, items []string) (int, error) {
	var n int
	err := s.draftMigrationTx(ctx, id, func(tx *sql.Tx, m WfMigration) error {
		items = slices.DeleteFunc(slices.Clone(items), m.IsExcluded)
		items, err := inScope(ctx, tx, m, items)
		if err != nil {
			return err
		}
		switch {
		case len(items) == 0:
			return ErrNothingSelected
		case len(items) > MaxMigrationItems:
			return ErrTooMany
		}
		to, err := targetVersion(ctx, tx, m)
		if err != nil {
			return err
		}
		if m.Kind == MigrationWorkflow && to == m.FromVersionID {
			return ErrSameTarget
		}
		m.ToVersionID = to
		plan, err := planMigration(ctx, tx, m, mapping, items)
		if err != nil {
			return err
		}
		b, err := json.Marshal(plan.Mapping())
		if err != nil {
			return err
		}
		n = len(items)
		if _, err := tx.ExecContext(ctx, `
			UPDATE wf_migration SET state = 'running', mapping = $2, query = $3, items = $4::uuid[], items_total = $5,
			       to_version = $6, started_at = now(), started_by = $7
			WHERE id = $1`, id, string(b), query, pq.Array(items), n, to, actor.ID); err != nil {
			return err
		}
		var dropped []string
		for _, f := range plan.Dropped {
			dropped = append(dropped, f.Key)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "migration.start", ObjectType: "wf_migration", ObjectID: id,
			Details: map[string]any{"from": m.From(), "to": m.To(), "to_version": plan.Target.Version, "items": n,
				"mapping": plan.Mapping(), "dropped": dropped}})
	})
	return n, err
}

// Running ------------------------------------------------------------------------------

// MigrateBatch moves up to n items of a running migration in one
// transaction, and finishes the migration when none are left: versions no
// item is on any more are retired. It reports whether the migration is
// over.
func (s *Store) MigrateBatch(ctx context.Context, id string, n int) (bool, error) {
	over := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM wf_migration WHERE id = $1 FOR UPDATE`, id); err != nil {
			return mapErr(err)
		}
		m, err := scanWfMigration(tx.QueryRowContext(ctx, `SELECT `+wfMigrationCols+wfMigrationFrom+` WHERE m.id = $1`, id))
		if err != nil {
			return mapErr(err)
		}
		if m.State != MigrationRunning {
			over = true
			return nil
		}
		scope, args := m.scopeSQL(3)
		rows, err := tx.QueryContext(ctx, `
			SELECT w.id FROM work_item w JOIN wf_migration m ON w.id = ANY(m.items) WHERE m.id = $1 AND `+scope+`
			ORDER BY w.id LIMIT $2 FOR UPDATE OF w`, append([]any{id, n}, args...)...)
		if err != nil {
			return err
		}
		var batch []string
		for rows.Next() {
			var item string
			if err := rows.Scan(&item); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			over = true
			return finishMigration(ctx, tx, m)
		}
		mv, err := newMover(ctx, tx, m)
		if err != nil {
			return err
		}
		for _, item := range batch {
			if err := mv.move(ctx, tx, item); err != nil {
				return fmt.Errorf("migrate %s: %w", item, err)
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE wf_migration SET items_done = items_done + $2 WHERE id = $1`, id, len(batch))
		return err
	})
	return over, err
}

// FailMigration stops a running migration that hit an error. Items already
// moved stay moved.
func (s *Store) FailMigration(ctx context.Context, id, msg string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE wf_migration SET state = 'failed', error = $2, finished_at = now(),
		       items_skipped = items_total - items_done
		WHERE id = $1 AND state = 'running'`, id, msg)
	return err
}

func finishMigration(ctx context.Context, tx *sql.Tx, m WfMigration) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE wf_migration SET state = 'done', finished_at = now(), items_skipped = items_total - items_done WHERE id = $1`,
		m.ID); err != nil {
		return err
	}
	retired, err := retireEmptyVersions(ctx, tx)
	if err != nil {
		return err
	}
	return appendAudit(ctx, tx, System, AuditEvent{Action: "migration.finish", ObjectType: "wf_migration", ObjectID: m.ID,
		Details: map[string]any{"from": m.From(), "to": m.To(), "moved": m.Done, "skipped": m.Total - m.Done, "retired": retired}})
}

// retireEmptyVersions retires published versions no item is on, except the
// newest of each workflow, where new items start. It returns them as
// "Workflow vN".
func retireEmptyVersions(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		UPDATE workflow_version v SET state = 'retired' FROM workflow f
		WHERE f.id = v.workflow_id AND v.state = 'published'
		  AND NOT EXISTS (SELECT 1 FROM work_item w WHERE w.workflow_version_id = v.id)
		  AND EXISTS (SELECT 1 FROM workflow_version n WHERE n.workflow_id = v.workflow_id AND n.state = 'published' AND n.version > v.version)
		RETURNING f.name || ' v' || v.version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// mover moves items for one batch of a migration.
type mover struct {
	m        WfMigration
	actor    string
	target   WorkflowVersion
	statuses map[string]WfStatus // source statuses, by ID, as they are looked up
	dropped  []string            // custom field keys a move drops
}

func newMover(ctx context.Context, tx *sql.Tx, m WfMigration) (*mover, error) {
	mv := &mover{m: m, actor: m.StartedBy, statuses: map[string]WfStatus{}}
	if mv.actor == "" {
		mv.actor = System.ID
	}
	var err error
	if mv.target, err = getVersion(ctx, tx, m.ToVersionID); err != nil {
		return nil, err
	}
	if len(mv.target.Statuses) == 0 {
		return nil, ErrNoPublished
	}
	if m.Kind == MigrationMove {
		plan, err := planMigration(ctx, tx, m, nil, nil)
		if err != nil {
			return nil, err
		}
		for _, f := range plan.Dropped {
			mv.dropped = append(mv.dropped, f.Key)
		}
	}
	return mv, nil
}

func (mv *mover) status(ctx context.Context, tx *sql.Tx, id string) (WfStatus, error) {
	if st, ok := mv.statuses[id]; ok {
		return st, nil
	}
	var st WfStatus
	err := tx.QueryRowContext(ctx, `SELECT id, key, name, category, position, initial FROM wf_status WHERE id = $1`, id).
		Scan(&st.ID, &st.Key, &st.Name, &st.Category, &st.Position, &st.Initial)
	mv.statuses[id] = st
	return st, err
}

func (mv *mover) move(ctx context.Context, tx *sql.Tx, id string) error {
	m := mv.m
	before, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, id))
	if err != nil {
		return err
	}
	src, err := mv.status(ctx, tx, before.StatusID)
	if err != nil {
		return err
	}
	to, _ := MapStatus(src, m.Mapping[src.ID], mv.target.Statuses)

	project, number, typeID := before.ProjectID, before.Number, before.TypeID
	if m.Kind == MigrationMove {
		typeID = m.ToTypeID
		if m.ToProjectID != before.ProjectID {
			project = m.ToProjectID
			if err := tx.QueryRowContext(ctx, `
				UPDATE project SET next_number = next_number + 1 WHERE id = $1 RETURNING next_number - 1`, project).
				Scan(&number); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO work_item_old_ref (project_id, number, work_item_id) VALUES ($1, $2, $3)
				ON CONFLICT (project_id, number) DO UPDATE SET work_item_id = EXCLUDED.work_item_id`,
				before.ProjectID, before.Number, id); err != nil {
				return err
			}
		}
	}
	resolution := ""
	if to.Category == StatusDone {
		resolution = before.Resolution
		if resolution == "" {
			resolution = "Done"
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE work_item SET project_id = $2, number = $3, ticket_type_id = $4, workflow_version_id = $5, status_id = $6,
		       resolution = NULLIF($7, ''),
		       resolved_at = CASE WHEN $8 <> 'done' THEN NULL WHEN status_category = 'done' THEN resolved_at ELSE now() END,
		       custom = custom - COALESCE($9::text[], '{}'), updated_at = now()
		WHERE id = $1`, id, project, number, typeID, mv.target.ID, to.ID, resolution, to.Category,
		pq.Array(mv.dropped)); err != nil {
		return mapErr(err)
	}
	after, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, id))
	if err != nil {
		return err
	}
	diff := map[string]any{"migration": map[string]any{"id": m.ID, "kind": m.Kind}}
	changed := migrationChanges(before, after)
	if len(changed) > 0 {
		diff["changed"] = changed
	}
	custom, err := customChanges(ctx, tx, before.Custom, after.Custom)
	if err != nil {
		return err
	}
	var removed []inventory.Change
	for _, c := range custom {
		removed = append(removed, inventory.Change{Field: c.Field, From: c.From})
	}
	if len(removed) > 0 {
		diff["removed"] = removed
	}
	return addItemHistory(ctx, tx, id, mv.actor, diff)
}

// migrationChanges names what a migration changed about an item, in
// history terms.
func migrationChanges(a, b WorkItem) []inventory.Change {
	var out []inventory.Change
	diff := func(field, from, to string) {
		if from != to {
			out = append(out, inventory.Change{Field: field, From: from, To: to})
		}
	}
	diff("ref", a.Ref(), b.Ref())
	diff("project", a.ProjectKey, b.ProjectKey)
	diff("type", a.TypeName, b.TypeName)
	diff("workflow", fmt.Sprintf("%s v%d", a.WorkflowName, a.WorkflowVersion), fmt.Sprintf("%s v%d", b.WorkflowName, b.WorkflowVersion))
	diff("status", a.StatusName, b.StatusName)
	diff("resolution", a.Resolution, b.Resolution)
	return out
}

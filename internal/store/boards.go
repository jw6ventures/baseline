package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/list"
)

// Boards (docs/data-model.md §11) --------------------------------------------------

// BoardColumn is one column of a board: the statuses, by key, and the
// status categories whose items it shows.
type BoardColumn struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	Statuses   []string `json:"statuses"`
}

// Board shows work items in columns. Filter is in the list engine's
// condition format: groups ORed, the conditions inside each ANDed.
type Board struct {
	ID          string
	ProjectID   string // "" for every project
	ProjectKey  string
	ProjectName string
	Name        string
	Columns     []BoardColumn
	Filter      [][]list.Cond
	CreatedBy   string // a user ID, "" when gone
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// DefaultColumns are a new board's: one per status category.
func DefaultColumns() []BoardColumn {
	return []BoardColumn{
		{Name: "To do", Categories: []string{StatusTodo}},
		{Name: "In progress", Categories: []string{StatusInProgress}},
		{Name: "Done", Categories: []string{StatusDone}},
	}
}

// Column returns the index of the column an item in a status goes in: the
// first naming the status's key, else the first naming its category, else
// -1.
func (b Board) Column(statusKey, category string) int {
	if i := slices.IndexFunc(b.Columns, func(c BoardColumn) bool { return slices.Contains(c.Statuses, statusKey) }); i >= 0 {
		return i
	}
	return slices.IndexFunc(b.Columns, func(c BoardColumn) bool { return slices.Contains(c.Categories, category) })
}

const boardCols = `b.id, COALESCE(b.project_id::text, ''), COALESCE(p.key, ''), COALESCE(p.name, ''), b.name,
	b.columns::text, b.filter::text, COALESCE(b.created_by::text, ''), b.created_at, b.updated_at`

const boardFrom = ` FROM board b LEFT JOIN project p ON p.id = b.project_id `

func scanBoard(row interface{ Scan(...any) error }) (Board, error) {
	var b Board
	var cols, filter string
	if err := row.Scan(&b.ID, &b.ProjectID, &b.ProjectKey, &b.ProjectName, &b.Name, &cols, &filter, &b.CreatedBy,
		&b.CreatedAt, &b.UpdatedAt); err != nil {
		return b, err
	}
	if err := json.Unmarshal([]byte(cols), &b.Columns); err != nil {
		return b, fmt.Errorf("board %s: %w", b.ID, err)
	}
	if err := json.Unmarshal([]byte(filter), &b.Filter); err != nil {
		return b, fmt.Errorf("board %s: %w", b.ID, err)
	}
	return b, nil
}

// ListBoards lists every board, by project then name.
func (s *Store) ListBoards(ctx context.Context) ([]Board, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+boardCols+boardFrom+` ORDER BY p.key NULLS FIRST, lower(b.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Board
	for rows.Next() {
		b, err := scanBoard(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) GetBoard(ctx context.Context, id string) (Board, error) {
	b, err := scanBoard(s.db.QueryRowContext(ctx, `SELECT `+boardCols+boardFrom+` WHERE b.id = $1`, id))
	return b, mapErr(err)
}

// boardJSON encodes a board's columns and filter, never as null.
func boardJSON(b Board) (string, string) {
	cols := slices.Clone(b.Columns)
	for i := range cols {
		cols[i].Categories, cols[i].Statuses = nonNil(cols[i].Categories), nonNil(cols[i].Statuses)
	}
	c, _ := json.Marshal(nonNilSlice(cols))
	f, _ := json.Marshal(nonNilSlice(b.Filter))
	return string(c), string(f)
}

// CreateBoard stores a board made by userID. A name already taken is
// ErrConflict; a project that doesn't exist is ErrNotFound.
func (s *Store) CreateBoard(ctx context.Context, actor Actor, userID string, b Board) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cols, filter := boardJSON(b)
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO board (project_id, name, columns, filter, created_by)
			VALUES (NULLIF($1, '')::uuid, $2, $3, $4, NULLIF($5, '')::uuid) RETURNING id`,
			b.ProjectID, b.Name, cols, filter, userID).Scan(&id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "board.create", ObjectType: "board", ObjectID: id,
			Details: map[string]any{"name": b.Name, "project_id": b.ProjectID}})
	})
	return id, err
}

// UpdateBoard saves a board's name, project, columns and filter.
func (s *Store) UpdateBoard(ctx context.Context, actor Actor, id string, b Board) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cols, filter := boardJSON(b)
		res, err := tx.ExecContext(ctx, `
			UPDATE board SET project_id = NULLIF($2, '')::uuid, name = $3, columns = $4, filter = $5, updated_at = now()
			WHERE id = $1`, id, b.ProjectID, b.Name, cols, filter)
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "board.update", ObjectType: "board", ObjectID: id,
			Details: map[string]any{"name": b.Name, "project_id": b.ProjectID, "columns": len(b.Columns)}})
	})
}

func (s *Store) DeleteBoard(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM board WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "board.delete", ObjectType: "board", ObjectID: id,
			Details: map[string]any{"name": name}})
	})
}

// BoardStatus is a status a board column can name: one key, whatever
// version it is in, with the name and category of its newest use.
type BoardStatus struct {
	Key      string
	Name     string
	Category string
}

// BoardStatuses lists the statuses of the published and retired versions
// of the workflows a project's ticket types use, or of every workflow when
// projectID is "", in category order.
func (s *Store) BoardStatuses(ctx context.Context, projectID string) ([]BoardStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT ON (s.key) s.key, s.name, s.category,
		       array_position(ARRAY['todo', 'in_progress', 'done'], s.category) AS rank, s.position
		FROM wf_status s JOIN workflow_version v ON v.id = s.version_id
		WHERE v.state <> 'draft'
		  AND ($1 = '' OR v.workflow_id IN (SELECT workflow_id FROM project_ticket_type WHERE project_id::text = $1)
		       OR v.id IN (SELECT workflow_version_id FROM work_item WHERE project_id::text = $1))
		ORDER BY s.key, v.published_at DESC NULLS LAST`, projectID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	type ranked struct {
		BoardStatus
		rank, pos int
	}
	var all []ranked
	for rows.Next() {
		var x ranked
		if err := rows.Scan(&x.Key, &x.Name, &x.Category, &x.rank, &x.pos); err != nil {
			return nil, err
		}
		all = append(all, x)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(all, func(a, b ranked) int {
		if a.rank != b.rank {
			return a.rank - b.rank
		}
		return a.pos - b.pos
	})
	out := make([]BoardStatus, len(all))
	for i, x := range all {
		out[i] = x.BoardStatus
	}
	return out, nil
}

// BoardCard is a work item on a board, with its status's key.
type BoardCard struct {
	WorkItem
	StatusKey string
}

// BoardCards fetches the items with the IDs, in the order given.
func (s *Store) BoardCards(ctx context.Context, ids []string) ([]BoardCard, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ws.key, `+workItemCols+workItemFrom+` WHERE w.id::text = ANY($1)`,
		pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[string]BoardCard{}
	for rows.Next() {
		var c BoardCard
		if c.WorkItem, err = scanWorkItem(rows, &c.StatusKey); err != nil {
			return nil, err
		}
		byID[c.ID] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]BoardCard, 0, len(byID))
	for _, id := range ids {
		if c, ok := byID[id]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

// VersionStatusKeys maps the status IDs of the versions to their keys.
func (s *Store) VersionStatusKeys(ctx context.Context, versionIDs []string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, key FROM wf_status WHERE version_id::text = ANY($1)`,
		pq.Array(versionIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			return nil, err
		}
		out[id] = key
	}
	return out, rows.Err()
}

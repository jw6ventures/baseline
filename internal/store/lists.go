package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/list"
)

// ListRows runs a statement the list engine built (internal/list) and
// scans each column by its field's type.
func (s *Store) ListRows(ctx context.Context, st list.Statement) (list.Result, error) {
	var res list.Result
	// A list statement is many small correlated subqueries, which Postgres
	// overestimates; past jit_above_cost it spends seconds compiling a
	// query that runs in a millisecond. Lists are interactive, so no JIT.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL jit = off`); err != nil {
		return res, err
	}
	rows, err := tx.QueryContext(ctx, st.SQL, st.Args...)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		row := list.Row{Values: make([]any, len(st.Cols)), Links: make([]string, len(st.Cols))}
		dest := []any{&row.ID, &row.Link, &row.Dim, &row.Editable}
		cells := make([]any, len(st.Cols))
		for i, f := range st.Cols {
			cells[i] = scanTarget(f.Type)
			dest = append(dest, cells[i], &row.Links[i])
		}
		var group any
		if st.Group != nil {
			group = scanTarget(st.Group.Type)
			dest = append(dest, group)
		}
		var total, groupCount int
		dest = append(dest, &total)
		if st.Group != nil {
			dest = append(dest, &groupCount)
		}
		if err := rows.Scan(dest...); err != nil {
			return res, err
		}
		for i, c := range cells {
			row.Values[i] = scanned(c)
		}
		if group != nil {
			row.Group = scanned(group)
			row.GroupCount = groupCount
		}
		res.Total = total
		res.Rows = append(res.Rows, row)
	}
	return res, rows.Err()
}

func scanTarget(t list.Type) any {
	switch t {
	case list.Number:
		return new(sql.NullFloat64)
	case list.Bool:
		return new(sql.NullBool)
	case list.Time:
		return new(sql.NullTime)
	case list.Tags:
		return new(pq.StringArray)
	}
	return new(sql.NullString)
}

func scanned(v any) any {
	switch x := v.(type) {
	case *sql.NullString:
		return x.String
	case *sql.NullFloat64:
		if !x.Valid {
			return nil
		}
		return x.Float64
	case *sql.NullBool:
		return x.Valid && x.Bool
	case *sql.NullTime:
		if !x.Valid {
			return time.Time{}
		}
		return x.Time
	case *pq.StringArray:
		return []string(*x)
	}
	return nil
}

// SavedList is a named query over one table. Owner "" means shared.
type SavedList struct {
	ID         string
	Table      string
	Name       string
	Owner      string
	CreatedBy  string
	Columns    []string
	Conditions [][]list.Cond
	Search     string
	Sort       list.Sort
	GroupBy    string
	CreatedAt  time.Time
}

// Shared reports whether everyone sees the list.
func (l SavedList) Shared() bool { return l.Owner == "" }

// Query is the list as a list engine query.
func (l SavedList) Query() list.Query {
	return list.Query{Groups: l.Conditions, Search: l.Search, Cols: l.Columns, Sort: l.Sort, GroupBy: l.GroupBy, List: l.ID}
}

const savedListCols = `id, table_key, name, COALESCE(owner::text, ''), COALESCE(created_by::text, ''),
	columns::text, conditions::text, search, sort::text, group_by, created_at`

func scanSavedList(row interface{ Scan(...any) error }) (SavedList, error) {
	var l SavedList
	var cols, conds, sort string
	if err := row.Scan(&l.ID, &l.Table, &l.Name, &l.Owner, &l.CreatedBy, &cols, &conds, &l.Search, &sort,
		&l.GroupBy, &l.CreatedAt); err != nil {
		return l, err
	}
	for _, p := range []struct {
		src string
		dst any
	}{{cols, &l.Columns}, {conds, &l.Conditions}, {sort, &l.Sort}} {
		if err := json.Unmarshal([]byte(p.src), p.dst); err != nil {
			return l, fmt.Errorf("saved list %s: %w", l.ID, err)
		}
	}
	return l, nil
}

// SavedLists returns the shared lists of a table and the user's own,
// shared first, each by name.
func (s *Store) SavedLists(ctx context.Context, table, userID string) ([]SavedList, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+savedListCols+` FROM saved_list
		WHERE table_key = $1 AND (owner IS NULL OR owner::text = $2)
		ORDER BY owner IS NOT NULL, lower(name)`, table, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedList
	for rows.Next() {
		l, err := scanSavedList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) GetSavedList(ctx context.Context, id string) (SavedList, error) {
	l, err := scanSavedList(s.db.QueryRowContext(ctx, `SELECT `+savedListCols+` FROM saved_list WHERE id = $1`, id))
	return l, mapErr(err)
}

// CreateSavedList stores a list, made by userID; shared lists have no
// owner. A name already used by the same owner on the table is
// ErrConflict.
func (s *Store) CreateSavedList(ctx context.Context, actor Actor, userID string, l SavedList) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cols, _ := json.Marshal(nonNil(l.Columns))
		groups := l.Conditions
		if groups == nil {
			groups = [][]list.Cond{}
		}
		conds, _ := json.Marshal(groups)
		sort, _ := json.Marshal(l.Sort)
		var owner any
		if !l.Shared() {
			owner = l.Owner
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO saved_list (table_key, name, owner, created_by, columns, conditions, search, sort, group_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
			l.Table, l.Name, owner, userID, string(cols), string(conds), l.Search, string(sort), l.GroupBy).Scan(&id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "saved_list.create", ObjectType: "saved_list", ObjectID: id,
			Details: map[string]any{"table": l.Table, "name": l.Name, "shared": l.Shared()}})
	})
	return id, err
}

func (s *Store) DeleteSavedList(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var table, name string
		var shared bool
		if err := tx.QueryRowContext(ctx, `DELETE FROM saved_list WHERE id = $1 RETURNING table_key, name, owner IS NULL`, id).
			Scan(&table, &name, &shared); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "saved_list.delete", ObjectType: "saved_list", ObjectID: id,
			Details: map[string]any{"table": table, "name": name, "shared": shared}})
	})
}

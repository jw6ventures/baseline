package store

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/lib/pq"
)

// Window kinds.
const (
	WindowKindWindow = "window"
	WindowKindFreeze = "freeze"
)

// MaintenanceWindow is a maintenance window or a freeze: it opens on a cron
// schedule in a time zone and lasts Duration, for every host (no scope
// groups) or the hosts in its groups (docs/change-management.md §3). The
// schedule itself is read by internal/change.
type MaintenanceWindow struct {
	ID          string
	Name        string
	Description string
	Kind        string
	Cron        string
	Duration    time.Duration
	TZ          string
	ScopeGroups []string // host group IDs; empty: global
	ScopeNames  []string
	// ScopeGone: every group in its scope was deleted, so it applies to
	// nobody (and reads as inactive).
	ScopeGone bool
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Global reports whether the window applies to every host.
func (w MaintenanceWindow) Global() bool { return len(w.ScopeGroups) == 0 && !w.ScopeGone }

// Covers reports whether the window applies to a host in these groups.
func (w MaintenanceWindow) Covers(hostGroups []string) bool {
	return w.Global() || slices.ContainsFunc(w.ScopeGroups, func(g string) bool { return slices.Contains(hostGroups, g) })
}

// Groups that no longer exist drop out of the scope; a window scoped only
// to deleted groups applies to nobody rather than to everybody.
const windowCols = `w.id, w.name, w.description, w.kind, w.cron, w.duration_s, w.tz,
	ARRAY(SELECT g.id::text FROM host_group g WHERE g.id = ANY(w.scope_groups) ORDER BY lower(g.name)),
	ARRAY(SELECT g.name FROM host_group g WHERE g.id = ANY(w.scope_groups) ORDER BY lower(g.name)),
	cardinality(w.scope_groups) > 0, w.active, w.created_at, w.updated_at FROM maintenance_window w `

func scanWindow(row interface{ Scan(...any) error }) (MaintenanceWindow, error) {
	var w MaintenanceWindow
	var secs int
	var scoped bool
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.Kind, &w.Cron, &secs, &w.TZ, pq.Array(&w.ScopeGroups),
		pq.Array(&w.ScopeNames), &scoped, &w.Active, &w.CreatedAt, &w.UpdatedAt)
	w.Duration = time.Duration(secs) * time.Second
	if scoped && len(w.ScopeGroups) == 0 {
		w.ScopeGone, w.Active = true, false
	}
	return w, err
}

// ListWindows lists windows and freezes, windows first.
func (s *Store) ListWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+windowCols+`ORDER BY w.kind DESC, lower(w.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MaintenanceWindow
	for rows.Next() {
		w, err := scanWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) GetWindow(ctx context.Context, id string) (MaintenanceWindow, error) {
	w, err := scanWindow(s.db.QueryRowContext(ctx, `SELECT `+windowCols+`WHERE w.id = $1`, id))
	return w, mapErr(err)
}

// SaveWindow creates (ID "") or updates a window or freeze. The cron
// expression and time zone must have been checked.
func (s *Store) SaveWindow(ctx context.Context, actor Actor, w MaintenanceWindow) (string, error) {
	id := w.ID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		ev := "window.create"
		secs := int(w.Duration / time.Second)
		if id == "" {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO maintenance_window (name, description, kind, cron, duration_s, tz, scope_groups, active, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
				w.Name, w.Description, w.Kind, w.Cron, secs, w.TZ, pq.Array(nonNil(w.ScopeGroups)), w.Active, actor.userID()).
				Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			ev = "window.update"
			res, err := tx.ExecContext(ctx, `
				UPDATE maintenance_window SET name = $2, description = $3, kind = $4, cron = $5, duration_s = $6, tz = $7,
				       scope_groups = $8, active = $9, updated_at = now() WHERE id = $1`,
				id, w.Name, w.Description, w.Kind, w.Cron, secs, w.TZ, pq.Array(nonNil(w.ScopeGroups)), w.Active)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: ev, ObjectType: "maintenance_window", ObjectID: id,
			Details: map[string]any{"name": w.Name, "kind": w.Kind, "cron": w.Cron, "duration": w.Duration.String(),
				"tz": w.TZ, "scope_groups": w.ScopeGroups, "active": w.Active}})
	})
	return id, err
}

// DeleteWindow removes a window or freeze. Changes, patch groups and stacks
// that used it lose it (and run without a window).
func (s *Store) DeleteWindow(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name, kind string
		if err := tx.QueryRowContext(ctx, `DELETE FROM maintenance_window WHERE id = $1 RETURNING name, kind`, id).
			Scan(&name, &kind); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "window.delete", ObjectType: "maintenance_window", ObjectID: id,
			Details: map[string]any{"name": name, "kind": kind}})
	})
}

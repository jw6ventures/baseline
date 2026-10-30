package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/rbac"
)

type HostGroup struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

func (s *Store) ListHostGroups(ctx context.Context) ([]HostGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, created_at FROM host_group ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostGroup
	for rows.Next() {
		var g HostGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CreateHostGroup(ctx context.Context, actor Actor, name, description string) (HostGroup, error) {
	g := HostGroup{Name: name, Description: description}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO host_group (name, description) VALUES ($1, $2) RETURNING id, created_at`,
			name, description).Scan(&g.ID, &g.CreatedAt); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host_group.create", ObjectType: "host_group", ObjectID: g.ID,
			Details: map[string]any{"name": name, "description": description},
		})
	})
	return g, err
}

// DeleteHostGroup removes a group and, by cascade, the role bindings scoped
// to it. The audit row lists those bindings.
func (s *Store) DeleteHostGroup(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM host_group WHERE id = $1`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		var users []string
		if err := tx.QueryRowContext(ctx, `SELECT ARRAY(SELECT name FROM patch_group WHERE host_group_id = $1 ORDER BY name)`, id).
			Scan(pq.Array(&users)); err != nil {
			return err
		}
		if len(users) > 0 {
			return fmt.Errorf("%w: patch groups %s patch it", ErrInUse, strings.Join(users, ", "))
		}
		dropped, err := bindingsTx(ctx, tx, `WHERE b.scope_group_id = $1`, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_group WHERE id = $1`, id); err != nil {
			return err
		}
		var lost []string
		for _, b := range dropped {
			lost = append(lost, b.IdPGroup+" → "+string(b.Role))
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host_group.delete", ObjectType: "host_group", ObjectID: id,
			Details: map[string]any{"name": name, "dropped_bindings": lost},
		})
	})
}

type RoleBinding struct {
	ID             string
	IdPGroup       string
	Role           rbac.Role
	ScopeGroupID   string // "" = global
	ScopeGroupName string
	CreatedAt      time.Time
}

func (b RoleBinding) RBAC() rbac.Binding {
	return rbac.Binding{IdPGroup: b.IdPGroup, Role: b.Role, ScopeGroupID: b.ScopeGroupID}
}

func (s *Store) ListRoleBindings(ctx context.Context) ([]RoleBinding, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return bindingsTx(ctx, tx, "")
}

// RBACBindings returns the bindings in the form rbac.Resolve takes.
func (s *Store) RBACBindings(ctx context.Context) ([]rbac.Binding, error) {
	bs, err := s.ListRoleBindings(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]rbac.Binding, len(bs))
	for i, b := range bs {
		out[i] = b.RBAC()
	}
	return out, nil
}

func bindingsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) ([]RoleBinding, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT b.id, b.idp_group, b.role, COALESCE(b.scope_group_id::text, ''), COALESCE(g.name, ''), b.created_at
		FROM role_binding b LEFT JOIN host_group g ON g.id = b.scope_group_id `+where+`
		ORDER BY lower(b.idp_group), b.role, g.name NULLS FIRST`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []RoleBinding
	for rows.Next() {
		var b RoleBinding
		if err := rows.Scan(&b.ID, &b.IdPGroup, &b.Role, &b.ScopeGroupID, &b.ScopeGroupName, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CreateRoleBinding adds a binding. Admin bindings are forced global.
func (s *Store) CreateRoleBinding(ctx context.Context, actor Actor, b RoleBinding) (RoleBinding, error) {
	if b.Role == rbac.Admin {
		b.ScopeGroupID = ""
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO role_binding (idp_group, role, scope_group_id) VALUES ($1, $2, $3)
			RETURNING id, created_at`, b.IdPGroup, b.Role, nullString(b.ScopeGroupID)).
			Scan(&b.ID, &b.CreatedAt); err != nil {
			return mapErr(err)
		}
		if b.ScopeGroupID != "" {
			if err := tx.QueryRowContext(ctx, `SELECT name FROM host_group WHERE id = $1`,
				b.ScopeGroupID).Scan(&b.ScopeGroupName); err != nil {
				return mapErr(err)
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "role_binding.create", ObjectType: "role_binding", ObjectID: b.ID,
			Details: bindingDetails(b),
		})
	})
	return b, err
}

func (s *Store) DeleteRoleBinding(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		found, err := bindingsTx(ctx, tx, `WHERE b.id = $1`, id)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_binding WHERE id = $1`, id); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "role_binding.delete", ObjectType: "role_binding", ObjectID: id,
			Details: bindingDetails(found[0]),
		})
	})
}

func bindingDetails(b RoleBinding) map[string]any {
	scope := "global"
	if b.ScopeGroupID != "" {
		scope = "host_group:" + b.ScopeGroupName
	}
	return map[string]any{"idp_group": b.IdPGroup, "role": b.Role, "scope": scope}
}

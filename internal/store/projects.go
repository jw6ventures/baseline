package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Projects and ticket types (docs/data-model.md §8) ------------------------------

var (
	ProjectKinds = []string{"service_desk", "software"}
	// BaseKinds tell built-in features what a ticket type is, whatever its
	// name.
	BaseKinds = []string{"incident", "request", "problem", "epic", "story", "task", "bug", "generic"}
)

// ErrNoTypes refuses a project that offers no ticket types.
var ErrNoTypes = errors.New("a project needs at least one ticket type")

// TicketType is shared by every project that offers it.
type TicketType struct {
	ID          string
	Key         string
	Name        string
	Icon        string
	Description string
	BaseKind    string
	Projects    int // projects that offer it
}

const ticketTypeCols = `t.id, t.key, t.name, t.icon, t.description, t.base_kind,
	(SELECT count(*) FROM project_ticket_type pt WHERE pt.ticket_type_id = t.id)`

func scanTicketType(row interface{ Scan(...any) error }) (TicketType, error) {
	var t TicketType
	err := row.Scan(&t.ID, &t.Key, &t.Name, &t.Icon, &t.Description, &t.BaseKind, &t.Projects)
	return t, err
}

func (s *Store) ListTicketTypes(ctx context.Context) ([]TicketType, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ticketTypeCols+` FROM ticket_type t ORDER BY lower(t.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TicketType
	for rows.Next() {
		t, err := scanTicketType(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTicketType(ctx context.Context, id string) (TicketType, error) {
	t, err := scanTicketType(s.db.QueryRowContext(ctx, `SELECT `+ticketTypeCols+` FROM ticket_type t WHERE t.id = $1`, id))
	return t, mapErr(err)
}

// SaveTicketType creates a ticket type when id is "", else updates it. The
// key is fixed once created.
func (s *Store) SaveTicketType(ctx context.Context, actor Actor, id string, in TicketType) (string, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		action := "ticket_type.update"
		if id == "" {
			action = "ticket_type.create"
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO ticket_type (key, name, icon, description, base_kind) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
				in.Key, in.Name, in.Icon, in.Description, in.BaseKind).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else if err := tx.QueryRowContext(ctx, `
			UPDATE ticket_type SET name = $2, icon = $3, description = $4, base_kind = $5 WHERE id = $1 RETURNING key`,
			id, in.Name, in.Icon, in.Description, in.BaseKind).Scan(&in.Key); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "ticket_type", ObjectID: id,
			Details: map[string]any{"key": in.Key, "name": in.Name, "base_kind": in.BaseKind},
		})
	})
	return id, err
}

// Project groups work items, which are numbered within it: OPS-42.
type Project struct {
	ID            string
	Key           string
	Name          string
	Kind          string // service_desk | software
	Description   string
	HostGroupID   string
	HostGroupName string
	Archived      bool
	CreatedAt     time.Time
	Open          int // items not done
	Types         []ProjectType
	CategoryID    string // "" for none
	// Category and Tags are only read by GetProject.
	Category ProjectCategory
	Tags     []ProjectTag
}

// ProjectType is a ticket type as one project offers it, with the workflow
// its items follow.
type ProjectType struct {
	TicketType
	Position     int
	Default      bool
	WorkflowID   string
	WorkflowName string
}

// DefaultType is the type new items start as.
func (p Project) DefaultType() string {
	for _, t := range p.Types {
		if t.Default {
			return t.ID
		}
	}
	if len(p.Types) > 0 {
		return p.Types[0].ID
	}
	return ""
}

// Offers reports whether the project offers the ticket type.
func (p Project) Offers(typeID string) bool {
	return slices.ContainsFunc(p.Types, func(t ProjectType) bool { return t.ID == typeID })
}

const projectCols = `p.id, p.key, p.name, p.kind, p.description, COALESCE(p.host_group_id::text, ''), COALESCE(g.name, ''),
	p.archived, p.created_at,
	(SELECT count(*) FROM work_item w WHERE w.project_id = p.id AND w.status_category <> 'done'),
	COALESCE(p.category_id::text, '')`

const projectFrom = ` FROM project p LEFT JOIN host_group g ON g.id = p.host_group_id `

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Key, &p.Name, &p.Kind, &p.Description, &p.HostGroupID, &p.HostGroupName,
		&p.Archived, &p.CreatedAt, &p.Open, &p.CategoryID)
	return p, err
}

// ListProjects lists the projects, without their types; archived ones only
// when asked.
func (s *Store) ListProjects(ctx context.Context, archived bool) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+projectCols+projectFrom+` WHERE $1 OR NOT p.archived ORDER BY p.key`, archived)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProject fetches a project, with its types, by key.
func (s *Store) GetProject(ctx context.Context, key string) (Project, error) {
	p, err := scanProject(s.db.QueryRowContext(ctx, `SELECT `+projectCols+projectFrom+` WHERE p.key = $1`, strings.ToUpper(key)))
	if err != nil {
		return p, mapErr(err)
	}
	if p.Types, err = s.projectTypes(ctx, s.db, p.ID); err != nil {
		return p, err
	}
	if p.CategoryID != "" {
		cats, err := s.ListProjectCategories(ctx)
		if err != nil {
			return p, err
		}
		for _, c := range cats {
			if c.ID == p.CategoryID {
				p.Category = c
			}
		}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.name, t.color, t.description FROM project_tag_link l JOIN project_tag t ON t.id = l.tag_id
		WHERE l.project_id = $1 ORDER BY lower(t.name)`, p.ID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var t ProjectTag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Description); err != nil {
			return p, err
		}
		p.Tags = append(p.Tags, t)
	}
	return p, rows.Err()
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *Store) projectTypes(ctx context.Context, q querier, projectID string) ([]ProjectType, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT `+ticketTypeCols+`, pt.position, pt.is_default, pt.workflow_id, f.name
		FROM project_ticket_type pt JOIN ticket_type t ON t.id = pt.ticket_type_id JOIN workflow f ON f.id = pt.workflow_id
		WHERE pt.project_id = $1 ORDER BY pt.position, lower(t.name)`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectType
	for rows.Next() {
		var t ProjectType
		if err := rows.Scan(&t.ID, &t.Key, &t.Name, &t.Icon, &t.Description, &t.BaseKind, &t.Projects,
			&t.Position, &t.Default, &t.WorkflowID, &t.WorkflowName); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ProjectInput is the editable part of a project. Key is only read when
// creating one: it is in every item's reference.
type ProjectInput struct {
	Key         string
	Name        string
	Kind        string
	Description string
	HostGroupID string // "" for none
	Archived    bool
	TypeIDs     []string // in order
	DefaultType string   // one of TypeIDs; "" for the first
	// Workflows maps type IDs to the workflow their items follow; a type
	// missing from it gets the default workflow.
	Workflows  map[string]string
	CategoryID string   // "" for none
	TagIDs     []string // picked from the tag list
}

func (s *Store) CreateProject(ctx context.Context, actor Actor, in ProjectInput) (string, error) {
	if len(in.TypeIDs) == 0 {
		return "", ErrNoTypes
	}
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO project (key, name, kind, description, host_group_id) VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid)
			RETURNING id`, in.Key, in.Name, in.Kind, in.Description, in.HostGroupID).Scan(&id); err != nil {
			return mapErr(err)
		}
		types, err := setProjectTypes(ctx, tx, id, in)
		if err != nil {
			return err
		}
		if err := setProjectLabels(ctx, tx, id, in); err != nil {
			return err
		}
		category, tags, err := projectLabels(ctx, tx, id)
		if err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "project.create", ObjectType: "project", ObjectID: id,
			Details: map[string]any{"key": in.Key, "name": in.Name, "kind": in.Kind, "types": types,
				"category": category, "tags": tags},
		})
	})
	return id, err
}

func (s *Store) UpdateProject(ctx context.Context, actor Actor, id string, in ProjectInput) error {
	if len(in.TypeIDs) == 0 {
		return ErrNoTypes
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var key, name, kind, desc, group string
		var archived bool
		if err := tx.QueryRowContext(ctx, `
			SELECT p.key, p.name, p.kind, p.description, COALESCE(g.name, ''), p.archived`+projectFrom+`
			WHERE p.id = $1 FOR UPDATE OF p`, id).Scan(&key, &name, &kind, &desc, &group, &archived); err != nil {
			return mapErr(err)
		}
		before, err := s.projectTypes(ctx, tx, id)
		if err != nil {
			return err
		}
		category, tags, err := projectLabels(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE project SET name = $2, kind = $3, description = $4, host_group_id = NULLIF($5, '')::uuid, archived = $6
			WHERE id = $1`, id, in.Name, in.Kind, in.Description, in.HostGroupID, in.Archived); err != nil {
			return mapErr(err)
		}
		// Types the project keeps keep their field groups and layouts.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM project_ticket_type WHERE project_id = $1 AND NOT ticket_type_id::text = ANY($2::text[])`,
			id, pq.Array(in.TypeIDs)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM form_layout WHERE project_id = $1 AND NOT ticket_type_id::text = ANY($2::text[])`,
			id, pq.Array(in.TypeIDs)); err != nil {
			return err
		}
		after, err := setProjectTypes(ctx, tx, id, in)
		if err != nil {
			return err
		}
		if err := setProjectLabels(ctx, tx, id, in); err != nil {
			return err
		}
		newCategory, newTags, err := projectLabels(ctx, tx, id)
		if err != nil {
			return err
		}
		var newGroup string
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT name FROM host_group WHERE id::text = $1), '')`,
			in.HostGroupID).Scan(&newGroup); err != nil {
			return err
		}
		var beforeTypes []string
		for _, t := range before {
			beforeTypes = append(beforeTypes, t.Key+" ("+t.WorkflowName+")")
		}
		var changes []inventory.Change
		diff := func(field string, from, to any) {
			if from != to {
				changes = append(changes, inventory.Change{Field: field, From: from, To: to})
			}
		}
		diff("name", name, in.Name)
		diff("kind", kind, in.Kind)
		diff("description", desc, in.Description)
		diff("host_group", group, newGroup)
		diff("archived", archived, in.Archived)
		diff("category", category, newCategory)
		diff("tags", tags, newTags)
		diff("types", strings.Join(beforeTypes, ", "), strings.Join(after, ", "))
		if len(changes) == 0 {
			return nil
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "project.update", ObjectType: "project", ObjectID: id,
			Details: map[string]any{"key": key, "changed": changes},
		})
	})
}

// setProjectTypes inserts the project's types and returns their keys, with
// their workflows, the default first. A workflow needs a published version
// for items to start on.
func setProjectTypes(ctx context.Context, tx *sql.Tx, projectID string, in ProjectInput) ([]string, error) {
	def := in.DefaultType
	if !slices.Contains(in.TypeIDs, def) {
		def = in.TypeIDs[0]
	}
	// Clear the old default first: one default per project is a unique index.
	if _, err := tx.ExecContext(ctx, `UPDATE project_ticket_type SET is_default = false WHERE project_id = $1`, projectID); err != nil {
		return nil, err
	}
	var keys []string
	for i, t := range in.TypeIDs {
		var key, workflow string
		var published bool
		if err := tx.QueryRowContext(ctx, `
			SELECT t.key, f.name, EXISTS (SELECT 1 FROM workflow_version v WHERE v.workflow_id = f.id AND v.state = 'published')
			FROM ticket_type t, workflow f
			WHERE t.id = $1 AND CASE WHEN $2 = '' THEN f.is_default ELSE f.id::text = $2 END`, t, in.Workflows[t]).
			Scan(&key, &workflow, &published); err != nil {
			return nil, mapErr(err)
		}
		if !published {
			return nil, ErrNoPublished
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO project_ticket_type (project_id, ticket_type_id, position, is_default, workflow_id)
			VALUES ($1, $2, $3, $4, CASE WHEN $5 = '' THEN (SELECT id FROM workflow WHERE is_default) ELSE $5::uuid END)
			ON CONFLICT (project_id, ticket_type_id) DO UPDATE
			SET position = EXCLUDED.position, is_default = EXCLUDED.is_default, workflow_id = EXCLUDED.workflow_id`,
			projectID, t, i, t == def, in.Workflows[t]); err != nil {
			return nil, mapErr(err)
		}
		key += " (" + workflow + ")"
		if t == def {
			keys = append([]string{key}, keys...)
		} else {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// ListUsers lists everyone who has signed in, for assignee pickers.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, oidc_sub, email, name, COALESCE(last_login, 'epoch') FROM app_user
		ORDER BY lower(COALESCE(NULLIF(name, ''), NULLIF(email, ''), oidc_sub))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OIDCSub, &u.Email, &u.Name, &u.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

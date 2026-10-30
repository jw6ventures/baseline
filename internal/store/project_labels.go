package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

// Project categories and tags (docs/data-model.md §16) ----------------------------

// ColorRe is a category's or tag's color: #rrggbb in lower case, or "".
var ColorRe = regexp.MustCompile(`^(#[0-9a-f]{6})?$`)

// ErrCategoryCycle refuses to file a category under itself or one of its
// subcategories.
var ErrCategoryCycle = errors.New("a category can't sit under itself")

// CategorySep joins a category's path: Infrastructure / Network.
const CategorySep = " / "

// ProjectCategory is one node of the category tree.
type ProjectCategory struct {
	ID          string
	ParentID    string // "" at the top
	Name        string
	Color       string // its own; "" for none
	Description string
	Path        string // names from the top, joined by CategorySep
	Depth       int    // 0 at the top
	// ShownColor is Color, or the nearest ancestor's when it has none.
	ShownColor string
	Projects   int // projects filed directly under it
	Children   int
}

// categoryTree walks the tree from the top, so each category follows its
// parent and siblings sort by name.
const categoryTree = `WITH RECURSIVE tree AS (
		SELECT c.id, c.parent_id, c.name, c.color, c.description, c.name AS path, 0 AS depth, c.color AS shown,
			ARRAY[lower(c.name)] AS sort
		FROM project_category c WHERE c.parent_id IS NULL
		UNION ALL
		SELECT c.id, c.parent_id, c.name, c.color, c.description, t.path || ' / ' || c.name, t.depth + 1,
			CASE WHEN c.color <> '' THEN c.color ELSE t.shown END, t.sort || lower(c.name)
		FROM project_category c JOIN tree t ON c.parent_id = t.id)`

// ListProjectCategories lists the whole tree, parents before children.
func (s *Store) ListProjectCategories(ctx context.Context) ([]ProjectCategory, error) {
	rows, err := s.db.QueryContext(ctx, categoryTree+`
		SELECT t.id, COALESCE(t.parent_id::text, ''), t.name, t.color, t.description, t.path, t.depth, t.shown,
			(SELECT count(*) FROM project p WHERE p.category_id = t.id),
			(SELECT count(*) FROM project_category k WHERE k.parent_id = t.id)
		FROM tree t ORDER BY t.sort`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectCategory
	for rows.Next() {
		var c ProjectCategory
		if err := rows.Scan(&c.ID, &c.ParentID, &c.Name, &c.Color, &c.Description, &c.Path, &c.Depth, &c.ShownColor,
			&c.Projects, &c.Children); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveProjectCategory creates a category when id is "", else updates it,
// moving it under ParentID ("" for the top).
func (s *Store) SaveProjectCategory(ctx context.Context, actor Actor, id string, in ProjectCategory) (string, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		action := "project_category.update"
		if id == "" {
			action = "project_category.create"
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO project_category (parent_id, name, color, description) VALUES (NULLIF($1, '')::uuid, $2, $3, $4)
				RETURNING id`, in.ParentID, in.Name, in.Color, in.Description).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			if in.ParentID != "" {
				// The new parent can't be the category or under it.
				var cycle bool
				if err := tx.QueryRowContext(ctx, `
					WITH RECURSIVE up AS (
						SELECT id, parent_id FROM project_category WHERE id = $2::uuid
						UNION ALL
						SELECT c.id, c.parent_id FROM project_category c JOIN up ON c.id = up.parent_id)
					SELECT EXISTS (SELECT 1 FROM up WHERE id = $1::uuid)`, id, in.ParentID).Scan(&cycle); err != nil {
					return mapErr(err)
				}
				if cycle {
					return ErrCategoryCycle
				}
			}
			res, err := tx.ExecContext(ctx, `
				UPDATE project_category SET parent_id = NULLIF($2, '')::uuid, name = $3, color = $4, description = $5
				WHERE id = $1`, id, in.ParentID, in.Name, in.Color, in.Description)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "project_category", ObjectID: id,
			Details: map[string]any{"name": in.Name, "parent_id": in.ParentID, "color": in.Color},
		})
	})
	return id, err
}

// DeleteProjectCategory deletes a category with no subcategories; its
// projects are left uncategorized. ErrInUse while it has subcategories.
func (s *Store) DeleteProjectCategory(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		var children bool
		if err := tx.QueryRowContext(ctx, `
			SELECT name, EXISTS (SELECT 1 FROM project_category k WHERE k.parent_id = c.id)
			FROM project_category c WHERE id = $1 FOR UPDATE`, id).Scan(&name, &children); err != nil {
			return mapErr(err)
		}
		if children {
			return ErrInUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM project_category WHERE id = $1`, id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "project_category.delete", ObjectType: "project_category", ObjectID: id,
			Details: map[string]any{"name": name},
		})
	})
}

// ProjectTag is one tag projects can carry.
type ProjectTag struct {
	ID          string
	Name        string
	Color       string // "" for none
	Description string
	Projects    int
}

// ListProjectTags lists the tags by name.
func (s *Store) ListProjectTags(ctx context.Context) ([]ProjectTag, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.name, t.color, t.description, (SELECT count(*) FROM project_tag_link l WHERE l.tag_id = t.id)
		FROM project_tag t ORDER BY lower(t.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectTag
	for rows.Next() {
		var t ProjectTag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Description, &t.Projects); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveProjectTag creates a tag when id is "", else updates it.
func (s *Store) SaveProjectTag(ctx context.Context, actor Actor, id string, in ProjectTag) (string, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		action := "project_tag.update"
		if id == "" {
			action = "project_tag.create"
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO project_tag (name, color, description) VALUES ($1, $2, $3) RETURNING id`,
				in.Name, in.Color, in.Description).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			res, err := tx.ExecContext(ctx, `UPDATE project_tag SET name = $2, color = $3, description = $4 WHERE id = $1`,
				id, in.Name, in.Color, in.Description)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "project_tag", ObjectID: id,
			Details: map[string]any{"name": in.Name, "color": in.Color},
		})
	})
	return id, err
}

// DeleteProjectTag deletes a tag, taking it off every project.
func (s *Store) DeleteProjectTag(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM project_tag WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "project_tag.delete", ObjectType: "project_tag", ObjectID: id,
			Details: map[string]any{"name": name},
		})
	})
}

// projectLabels reads a project's category path and tags, for the audit
// log's before and after.
func projectLabels(ctx context.Context, tx *sql.Tx, id string) (category, tags string, err error) {
	err = tx.QueryRowContext(ctx, categoryTree+`
		SELECT COALESCE((SELECT t.path FROM tree t JOIN project p ON p.category_id = t.id WHERE p.id = $1), ''),
			COALESCE((SELECT string_agg(g.name, ', ' ORDER BY lower(g.name)) FROM project_tag_link l
				JOIN project_tag g ON g.id = l.tag_id WHERE l.project_id = $1), '')`, id).Scan(&category, &tags)
	return
}

// setProjectLabels files the project under its category and sets its tags.
func setProjectLabels(ctx context.Context, tx *sql.Tx, id string, in ProjectInput) error {
	if _, err := tx.ExecContext(ctx, `UPDATE project SET category_id = NULLIF($2, '')::uuid WHERE id = $1`,
		id, in.CategoryID); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM project_tag_link WHERE project_id = $1`, id); err != nil {
		return err
	}
	for _, t := range in.TagIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_tag_link (project_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			id, t); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

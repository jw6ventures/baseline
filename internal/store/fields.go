package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Custom fields, field groups and form layouts (docs/data-model.md §10) ----------

// Field types.
const (
	FieldText        = "text"
	FieldTextarea    = "textarea"
	FieldNumber      = "number"
	FieldDate        = "date"
	FieldDatetime    = "datetime"
	FieldBool        = "bool"
	FieldSelect      = "select"
	FieldMultiselect = "multiselect"
	FieldUser        = "user"
	FieldCI          = "ci_ref"
	FieldItem        = "item_ref"
	FieldURL         = "url"
)

var (
	FieldTypes = []string{FieldText, FieldTextarea, FieldNumber, FieldDate, FieldDatetime, FieldBool,
		FieldSelect, FieldMultiselect, FieldUser, FieldCI, FieldItem, FieldURL}
	// FieldKeyRe is what a field key may be. The list engine puts keys in
	// SQL text, so nothing else may reach the table.
	FieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// CoreFields are the work item fields a layout can place, in the order
	// they show when a layout leaves them out.
	CoreFields = []string{"title", "description", "priority", "impact", "urgency", "assignee", "parent", "estimate", "due"}
	// Screens a layout can be for. Transition screens come with the
	// workflow engine.
	Screens = []string{ScreenCreate, ScreenView}
)

const (
	ScreenCreate = "create"
	ScreenView   = "view"
)

// ErrNoOptions refuses a select field with nothing to pick.
var ErrNoOptions = errors.New("a select field needs options")

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// FieldDef is a custom field, defined once and used through groups.
type FieldDef struct {
	ID          string
	Key         string
	Label       string
	Type        string
	Options     []string // select and multiselect
	Description string
	CreatedAt   time.Time
	Groups      int // groups that hold it
}

// HasOptions reports whether the type picks from Options.
func (f FieldDef) HasOptions() bool { return f.Type == FieldSelect || f.Type == FieldMultiselect }

// ErrFieldValue is a value that doesn't fit its field. Its text is shown
// to people.
type ErrFieldValue struct {
	Label string
	Msg   string
}

func (e ErrFieldValue) Error() string { return e.Label + ": " + e.Msg }

// Parse reads a field's value from a form: one string, or several for a
// multiselect. It returns nil for no value. loc is the zone a datetime is
// typed in. Users, CIs and items are IDs; callers check they exist and may
// be used.
func (f FieldDef) Parse(raw []string, loc *time.Location) (any, error) {
	bad := func(msg string) error { return ErrFieldValue{Label: f.Label, Msg: msg} }
	var vals []string
	for _, r := range raw {
		if r = strings.TrimSpace(r); r != "" {
			vals = append(vals, r)
		}
	}
	if len(vals) == 0 {
		return nil, nil
	}
	v := vals[0]
	switch f.Type {
	case FieldText, FieldTextarea:
		return v, nil
	case FieldURL:
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, bad("enter a link starting with http:// or https://")
		}
		return v, nil
	case FieldNumber:
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, bad("enter a number")
		}
		return n, nil
	case FieldDate:
		t, err := time.Parse(time.DateOnly, v)
		if err != nil {
			return nil, bad("enter a date like 2026-10-01")
		}
		return t.Format(time.DateOnly), nil
	case FieldDatetime:
		if loc == nil {
			loc = time.UTC
		}
		for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", time.RFC3339} {
			if t, err := time.ParseInLocation(layout, v, loc); err == nil {
				return t.UTC().Format(time.RFC3339), nil
			}
		}
		return nil, bad("enter a date and time like 2026-10-01T15:04")
	case FieldBool:
		switch strings.ToLower(v) {
		case "1", "true", "on", "yes":
			return true, nil
		case "0", "false", "off", "no":
			return false, nil
		}
		return nil, bad("pick yes or no")
	case FieldSelect:
		if !slices.Contains(f.Options, v) {
			return nil, bad("pick one of the options")
		}
		return v, nil
	case FieldMultiselect:
		var out []any
		for _, x := range vals {
			if !slices.Contains(f.Options, x) {
				return nil, bad("pick from the options")
			}
			if !slices.Contains(out, any(x)) {
				out = append(out, x)
			}
		}
		return out, nil
	case FieldUser, FieldCI, FieldItem:
		if !uuidRe.MatchString(v) {
			return nil, bad("pick one")
		}
		return strings.ToLower(v), nil
	}
	return nil, bad("has an unknown type")
}

// Text is a stored value as plain text: dates as typed, numbers without
// trailing zeros, multiselects joined. Users, CIs and items stay IDs.
func (f FieldDef) Text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case []any:
		var parts []string
		for _, p := range x {
			parts = append(parts, fmt.Sprint(p))
		}
		return strings.Join(parts, ", ")
	}
	b, _ := json.Marshal(v)
	return string(b)
}

const fieldDefCols = `f.id, f.key, f.label, f.type, f.options::text, f.description, f.created_at,
	(SELECT count(*) FROM field_group_field gf WHERE gf.field_id = f.id)`

func scanFieldDef(row interface{ Scan(...any) error }, extra ...any) (FieldDef, error) {
	var f FieldDef
	var options string
	if err := row.Scan(append([]any{&f.ID, &f.Key, &f.Label, &f.Type, &options, &f.Description, &f.CreatedAt, &f.Groups}, extra...)...); err != nil {
		return f, err
	}
	return f, json.Unmarshal([]byte(options), &f.Options)
}

func (s *Store) ListFieldDefs(ctx context.Context) ([]FieldDef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+fieldDefCols+` FROM field_def f ORDER BY lower(f.label), f.key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FieldDef
	for rows.Next() {
		f, err := scanFieldDef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFieldDef(ctx context.Context, id string) (FieldDef, error) {
	f, err := scanFieldDef(s.db.QueryRowContext(ctx, `SELECT `+fieldDefCols+` FROM field_def f WHERE f.id = $1`, id))
	return f, mapErr(err)
}

// SaveFieldDef creates a field when id is "", else updates it. The key and
// type are fixed once created: stored values depend on them.
func (s *Store) SaveFieldDef(ctx context.Context, actor Actor, id string, in FieldDef) (string, error) {
	if in.Options == nil {
		in.Options = []string{}
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		action := "field.update"
		if id == "" {
			action = "field.create"
			if (in.Type == FieldSelect || in.Type == FieldMultiselect) && len(in.Options) == 0 {
				return ErrNoOptions
			}
			opts, _ := json.Marshal(in.Options)
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO field_def (key, label, type, options, description) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
				in.Key, in.Label, in.Type, string(opts), in.Description).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			if err := tx.QueryRowContext(ctx, `SELECT key, type FROM field_def WHERE id = $1 FOR UPDATE`, id).
				Scan(&in.Key, &in.Type); err != nil {
				return mapErr(err)
			}
			if !(in.Type == FieldSelect || in.Type == FieldMultiselect) {
				in.Options = []string{}
			} else if len(in.Options) == 0 {
				return ErrNoOptions
			}
			opts, _ := json.Marshal(in.Options)
			if _, err := tx.ExecContext(ctx, `UPDATE field_def SET label = $2, options = $3, description = $4 WHERE id = $1`,
				id, in.Label, string(opts), in.Description); err != nil {
				return mapErr(err)
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "field_def", ObjectID: id,
			Details: map[string]any{"key": in.Key, "label": in.Label, "type": in.Type, "options": in.Options},
		})
	})
	return id, err
}

// DeleteFieldDef removes a field no group holds. Values already stored on
// items stay in their custom column but no longer show.
func (s *Store) DeleteFieldDef(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var key string
		var groups int
		if err := tx.QueryRowContext(ctx, `
			SELECT key, (SELECT count(*) FROM field_group_field WHERE field_id = f.id) FROM field_def f WHERE id = $1 FOR UPDATE`,
			id).Scan(&key, &groups); err != nil {
			return mapErr(err)
		}
		if groups > 0 {
			return ErrInUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM field_def WHERE id = $1`, id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "field.delete", ObjectType: "field_def", ObjectID: id, Details: map[string]any{"key": key},
		})
	})
}

// GroupField is a field as one group holds it.
type GroupField struct {
	FieldDef
	Position int
	Required bool
	Default  any // nil for none
}

// FieldGroup bundles fields for projects to apply to their ticket types.
type FieldGroup struct {
	ID          string
	Name        string
	Description string
	Fields      []GroupField
	Uses        int // project ticket types that apply it
}

// Holds reports whether the group holds the field.
func (g FieldGroup) Holds(fieldID string) bool {
	return slices.ContainsFunc(g.Fields, func(f GroupField) bool { return f.ID == fieldID })
}

// Field returns the group's entry for a field.
func (g FieldGroup) Field(fieldID string) (GroupField, bool) {
	for _, f := range g.Fields {
		if f.ID == fieldID {
			return f, true
		}
	}
	return GroupField{}, false
}

// loadGroups fetches groups and their fields. where filters field_group g
// and is trusted SQL; order is how the groups come back.
func (s *Store) loadGroups(ctx context.Context, q querier, from, where, order string, args ...any) ([]FieldGroup, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT g.id, g.name, g.description,
		       (SELECT count(*) FROM project_ticket_type_group x WHERE x.field_group_id = g.id)
		FROM field_group g `+from+` WHERE `+where+` ORDER BY `+order, args...)
	if err != nil {
		return nil, err
	}
	var out []FieldGroup
	index := map[string]int{}
	for rows.Next() {
		var g FieldGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Uses); err != nil {
			rows.Close()
			return nil, err
		}
		index[g.ID] = len(out)
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	ids := make([]string, len(out))
	for i, g := range out {
		ids[i] = g.ID
	}
	rows, err = q.QueryContext(ctx, `
		SELECT `+fieldDefCols+`, gf.group_id, gf.position, gf.required, COALESCE(gf.default_value::text, 'null')
		FROM field_group_field gf JOIN field_def f ON f.id = gf.field_id
		WHERE gf.group_id::text = ANY($1::text[]) ORDER BY gf.position, lower(f.label)`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var gf GroupField
		var group, def string
		f, err := scanFieldDef(rows, &group, &gf.Position, &gf.Required, &def)
		if err != nil {
			return nil, err
		}
		gf.FieldDef = f
		if err := json.Unmarshal([]byte(def), &gf.Default); err != nil {
			return nil, err
		}
		i := index[group]
		out[i].Fields = append(out[i].Fields, gf)
	}
	return out, rows.Err()
}

func (s *Store) ListFieldGroups(ctx context.Context) ([]FieldGroup, error) {
	return s.loadGroups(ctx, s.db, "", "true", "lower(g.name)")
}

func (s *Store) GetFieldGroup(ctx context.Context, id string) (FieldGroup, error) {
	if !uuidRe.MatchString(id) {
		return FieldGroup{}, ErrNotFound
	}
	gs, err := s.loadGroups(ctx, s.db, "", "g.id = $1", "g.name", id)
	if err != nil {
		return FieldGroup{}, err
	}
	if len(gs) == 0 {
		return FieldGroup{}, ErrNotFound
	}
	return gs[0], nil
}

// GroupFieldInput is one field of a group being saved.
type GroupFieldInput struct {
	FieldID  string
	Required bool
	Default  any // a value Parse returned, or nil
}

// FieldGroupInput is the editable part of a group. Fields are in order.
type FieldGroupInput struct {
	Name        string
	Description string
	Fields      []GroupFieldInput
}

// SaveFieldGroup creates a group when id is "", else updates it, replacing
// its fields.
func (s *Store) SaveFieldGroup(ctx context.Context, actor Actor, id string, in FieldGroupInput) (string, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		action := "field_group.update"
		if id == "" {
			action = "field_group.create"
			if err := tx.QueryRowContext(ctx, `INSERT INTO field_group (name, description) VALUES ($1, $2) RETURNING id`,
				in.Name, in.Description).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			res, err := tx.ExecContext(ctx, `UPDATE field_group SET name = $2, description = $3 WHERE id = $1`, id, in.Name, in.Description)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM field_group_field WHERE group_id = $1`, id); err != nil {
				return err
			}
		}
		var keys []string
		for i, f := range in.Fields {
			def := sql.NullString{}
			if f.Default != nil {
				b, err := json.Marshal(f.Default)
				if err != nil {
					return err
				}
				def = sql.NullString{String: string(b), Valid: true}
			}
			var key string
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO field_group_field (group_id, field_id, position, required, default_value) VALUES ($1, $2, $3, $4, $5::jsonb)
				RETURNING (SELECT key FROM field_def WHERE id = $2)`, id, f.FieldID, i, f.Required, def).Scan(&key); err != nil {
				return mapErr(err)
			}
			keys = append(keys, key)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "field_group", ObjectID: id,
			Details: map[string]any{"name": in.Name, "fields": keys},
		})
	})
	return id, err
}

// DeleteFieldGroup removes a group, and with it every project's use of it.
// Layouts that place it skip it.
func (s *Store) DeleteFieldGroup(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM field_group WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "field_group.delete", ObjectType: "field_group", ObjectID: id, Details: map[string]any{"name": name},
		})
	})
}

// ProjectTypeGroups lists the groups a project applies to a ticket type, in
// order.
func (s *Store) ProjectTypeGroups(ctx context.Context, projectID, typeID string) ([]FieldGroup, error) {
	return s.projectTypeGroups(ctx, s.db, projectID, typeID)
}

func (s *Store) projectTypeGroups(ctx context.Context, q querier, projectID, typeID string) ([]FieldGroup, error) {
	return s.loadGroups(ctx, q, `JOIN project_ticket_type_group x ON x.field_group_id = g.id`,
		`x.project_id = $1 AND x.ticket_type_id = $2`, `x.position, lower(g.name)`, projectID, typeID)
}

// SetProjectTypeGroups sets the groups, in order, a project applies to one
// of its ticket types.
func (s *Store) SetProjectTypeGroups(ctx context.Context, actor Actor, projectID, typeID string, groupIDs []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var key, typeKey string
		if err := tx.QueryRowContext(ctx, `
			SELECT p.key, t.key FROM project_ticket_type pt JOIN project p ON p.id = pt.project_id
			JOIN ticket_type t ON t.id = pt.ticket_type_id
			WHERE pt.project_id = $1 AND pt.ticket_type_id = $2 FOR UPDATE OF pt`, projectID, typeID).Scan(&key, &typeKey); err != nil {
			if errors.Is(mapErr(err), ErrNotFound) {
				return ErrTypeNotOffered
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM project_ticket_type_group WHERE project_id = $1 AND ticket_type_id = $2`, projectID, typeID); err != nil {
			return err
		}
		var names []string
		for i, g := range groupIDs {
			var name string
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO project_ticket_type_group (project_id, ticket_type_id, field_group_id, position) VALUES ($1, $2, $3, $4)
				RETURNING (SELECT name FROM field_group WHERE id = $3)`, projectID, typeID, g, i).Scan(&name); err != nil {
				return mapErr(err)
			}
			names = append(names, name)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "project.field_groups", ObjectType: "project", ObjectID: projectID,
			Details: map[string]any{"key": key, "type": typeKey, "groups": names},
		})
	})
}

// LayoutItem places a core field, a whole group or one field.
type LayoutItem struct {
	Kind    string `json:"kind"`               // core | group | field
	Field   string `json:"field,omitempty"`    // core: one of CoreFields
	GroupID string `json:"group_id,omitempty"` // group
	FieldID string `json:"field_id,omitempty"` // field
}

// LayoutSection is a titled part of a screen.
type LayoutSection struct {
	Title     string       `json:"title"`
	Columns   int          `json:"columns"` // 1 or 2
	Collapsed bool         `json:"collapsed"`
	Items     []LayoutItem `json:"items"`
}

// Layout orders a screen. ProjectID "" is the ticket type's default.
type Layout struct {
	ID             string
	ProjectID      string
	TypeID         string
	Screen         string
	ViewUsesCreate bool
	Sections       []LayoutSection
	UpdatedAt      time.Time
}

// CleanSections drops what a layout can't hold: unknown kinds and core
// fields, malformed IDs, empty sections without a title. Columns are 1 or 2.
func CleanSections(in []LayoutSection) []LayoutSection {
	out := []LayoutSection{}
	for _, sec := range in {
		sec.Title = strings.TrimSpace(sec.Title)
		if sec.Columns != 2 {
			sec.Columns = 1
		}
		items := []LayoutItem{}
		for _, it := range sec.Items {
			switch {
			case it.Kind == "core" && slices.Contains(CoreFields, it.Field):
				items = append(items, LayoutItem{Kind: "core", Field: it.Field})
			case it.Kind == "group" && uuidRe.MatchString(it.GroupID):
				items = append(items, LayoutItem{Kind: "group", GroupID: strings.ToLower(it.GroupID)})
			case it.Kind == "field" && uuidRe.MatchString(it.FieldID):
				items = append(items, LayoutItem{Kind: "field", FieldID: strings.ToLower(it.FieldID)})
			}
		}
		sec.Items = items
		if len(items) > 0 || sec.Title != "" {
			out = append(out, sec)
		}
	}
	return out
}

// GetLayout fetches the layout stored for exactly this project (or the
// type's default when projectID is "") and screen.
func (s *Store) GetLayout(ctx context.Context, projectID, typeID, screen string) (Layout, error) {
	l := Layout{ProjectID: projectID, TypeID: typeID, Screen: screen}
	var sections string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, view_uses_create, sections::text, updated_at FROM form_layout
		WHERE project_id IS NOT DISTINCT FROM NULLIF($1, '')::uuid AND ticket_type_id::text = $2 AND screen = $3
		  AND transition_id IS NULL`, projectID, typeID, screen).Scan(&l.ID, &l.ViewUsesCreate, &sections, &l.UpdatedAt)
	if err != nil {
		return l, mapErr(err)
	}
	return l, json.Unmarshal([]byte(sections), &l.Sections)
}

// SaveLayout stores a layout, replacing the one for the same project, type
// and screen.
func (s *Store) SaveLayout(ctx context.Context, actor Actor, l Layout) error {
	if !slices.Contains(Screens, l.Screen) {
		return fmt.Errorf("layout: unknown screen %q", l.Screen)
	}
	l.Sections = CleanSections(l.Sections)
	if l.Screen != ScreenCreate {
		l.ViewUsesCreate = false
	}
	b, err := json.Marshal(l.Sections)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM form_layout WHERE project_id IS NOT DISTINCT FROM NULLIF($1, '')::uuid AND ticket_type_id = $2
			AND screen = $3 AND transition_id IS NULL`, l.ProjectID, l.TypeID, l.Screen); err != nil {
			return mapErr(err)
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO form_layout (project_id, ticket_type_id, screen, view_uses_create, sections)
			VALUES (NULLIF($1, '')::uuid, $2, $3, $4, $5) RETURNING id`,
			l.ProjectID, l.TypeID, l.Screen, l.ViewUsesCreate, string(b)).Scan(&id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "layout.save", ObjectType: "form_layout", ObjectID: id,
			Details: map[string]any{"project_id": l.ProjectID, "ticket_type_id": l.TypeID, "screen": l.Screen,
				"view_uses_create": l.ViewUsesCreate, "sections": len(l.Sections)},
		})
	})
}

// DeleteLayout removes a stored layout, so the screen inherits again.
func (s *Store) DeleteLayout(ctx context.Context, actor Actor, projectID, typeID, screen string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, `
			DELETE FROM form_layout WHERE project_id IS NOT DISTINCT FROM NULLIF($1, '')::uuid AND ticket_type_id::text = $2
			AND screen = $3 AND transition_id IS NULL RETURNING id`, projectID, typeID, screen).Scan(&id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "layout.delete", ObjectType: "form_layout", ObjectID: id,
			Details: map[string]any{"project_id": projectID, "ticket_type_id": typeID, "screen": screen},
		})
	})
}

// FormField is a custom field as a screen shows it: once, however many
// applied groups hold it.
type FormField struct {
	FieldDef
	Required bool // if any applied group requires it
	Default  any  // the first applied group's default
}

// FormItem is a core field (Core set) or a custom field.
type FormItem struct {
	Core  string
	Field *FormField
}

// FormSection is a section of a resolved screen.
type FormSection struct {
	Title     string
	Columns   int
	Collapsed bool
	Items     []FormItem
}

// Form is a screen resolved for one project and ticket type.
type Form struct {
	// Layout is the stored layout used, or the zero Layout when none
	// applies and the groups' own order is used.
	Layout   Layout
	Sections []FormSection
	// Fields are every applied custom field, in the order they show.
	Fields []*FormField
}

// Field returns the form's custom field with the key, or nil.
func (f Form) Field(key string) *FormField {
	for _, x := range f.Fields {
		if x.Key == key {
			return x
		}
	}
	return nil
}

// ResolveForm builds a screen for a project's ticket type: its effective
// layout applied to the groups the project applies.
func (s *Store) ResolveForm(ctx context.Context, projectID, typeID, screen string) (Form, error) {
	groups, err := s.ProjectTypeGroups(ctx, projectID, typeID)
	if err != nil {
		return Form{}, err
	}
	layout, err := s.EffectiveLayout(ctx, projectID, typeID, screen)
	if err != nil {
		return Form{}, err
	}
	return BuildForm(layout, groups), nil
}

// EffectiveLayout is the layout a screen uses: the project's own, else the
// ticket type's default (projectID "" asks for the default alone). For the
// view screen a create layout marked "use for view too" counts at each
// level. It returns nil when no layout applies.
func (s *Store) EffectiveLayout(ctx context.Context, projectID, typeID, screen string) (*Layout, error) {
	levels := []string{""}
	if projectID != "" {
		levels = []string{projectID, ""}
	}
	for _, level := range levels {
		l, err := s.GetLayout(ctx, level, typeID, screen)
		if err == nil {
			return &l, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if screen != ScreenView {
			continue
		}
		l, err = s.GetLayout(ctx, level, typeID, ScreenCreate)
		if err == nil && l.ViewUsesCreate {
			return &l, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	return nil, nil
}

// DefaultSections is the layout of a screen nobody has laid out: the core
// fields, then a section per group.
func DefaultSections(groups []FieldGroup) []LayoutSection {
	lead := LayoutSection{Columns: 1, Items: []LayoutItem{}}
	for _, c := range CoreFields {
		lead.Items = append(lead.Items, LayoutItem{Kind: "core", Field: c})
	}
	out := []LayoutSection{lead}
	for _, g := range groups {
		out = append(out, LayoutSection{Title: g.Name, Columns: 1, Items: []LayoutItem{{Kind: "group", GroupID: g.ID}}})
	}
	return out
}

// BuildForm places applied groups' fields by a layout, or by the groups'
// own order when layout is nil. A field in several groups shows once and is
// required if any of them requires it. Core fields the layout leaves out
// lead in an untitled section, so a screen can't lose its title; custom
// fields it leaves out trail in "Other", so applying a group never hides
// its fields.
func BuildForm(layout *Layout, groups []FieldGroup) Form {
	applied := map[string]*FormField{}
	var order []*FormField
	for _, g := range groups {
		for _, gf := range g.Fields {
			if f, ok := applied[gf.ID]; ok {
				f.Required = f.Required || gf.Required
				if f.Default == nil {
					f.Default = gf.Default
				}
				continue
			}
			f := &FormField{FieldDef: gf.FieldDef, Required: gf.Required, Default: gf.Default}
			applied[gf.ID] = f
			order = append(order, f)
		}
	}
	byGroup := map[string]FieldGroup{}
	for _, g := range groups {
		byGroup[g.ID] = g
	}

	var form Form
	var sections []LayoutSection
	if layout != nil {
		form.Layout = *layout
		sections = layout.Sections
	} else {
		sections = DefaultSections(groups)
	}

	placedCore := map[string]bool{}
	placed := map[string]bool{}
	place := func(sec *FormSection, id string) {
		if f, ok := applied[id]; ok && !placed[id] {
			placed[id] = true
			sec.Items = append(sec.Items, FormItem{Field: f})
			form.Fields = append(form.Fields, f)
		}
	}
	for _, ls := range sections {
		sec := FormSection{Title: ls.Title, Columns: ls.Columns, Collapsed: ls.Collapsed}
		if sec.Columns != 2 {
			sec.Columns = 1
		}
		for _, it := range ls.Items {
			switch it.Kind {
			case "core":
				if slices.Contains(CoreFields, it.Field) && !placedCore[it.Field] {
					placedCore[it.Field] = true
					sec.Items = append(sec.Items, FormItem{Core: it.Field})
				}
			case "group":
				for _, gf := range byGroup[it.GroupID].Fields {
					place(&sec, gf.ID)
				}
			case "field":
				place(&sec, it.FieldID)
			}
		}
		if len(sec.Items) > 0 {
			form.Sections = append(form.Sections, sec)
		}
	}
	var missing []FormItem
	for _, c := range CoreFields {
		if !placedCore[c] {
			missing = append(missing, FormItem{Core: c})
		}
	}
	if len(missing) > 0 {
		form.Sections = append([]FormSection{{Columns: 1, Items: missing}}, form.Sections...)
	}
	other := FormSection{Title: "Other", Columns: 1}
	for _, f := range order {
		place(&other, f.ID)
	}
	if len(other.Items) > 0 {
		form.Sections = append(form.Sections, other)
	}
	return form
}

// customChanges lists the custom values that differ between two items'
// Custom maps, named by field label. Users show by name and items by
// reference; CIs stay IDs, since history is shown to people who may not
// see the CI.
func customChanges(ctx context.Context, tx *sql.Tx, a, b map[string]any) ([]inventory.Change, error) {
	var keys []string
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var changed []string
	for _, k := range keys {
		x, _ := json.Marshal(a[k])
		y, _ := json.Marshal(b[k])
		if string(x) != string(y) {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		return nil, nil
	}
	defs := map[string]FieldDef{}
	rows, err := tx.QueryContext(ctx, `SELECT `+fieldDefCols+` FROM field_def f WHERE f.key = ANY($1::text[])`, pq.Array(changed))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		f, err := scanFieldDef(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		defs[f.Key] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	text := func(f FieldDef, v any) (string, error) {
		id, _ := v.(string)
		var out string
		var err error
		switch {
		case id == "":
			return f.Text(v), nil
		case f.Type == FieldUser:
			err = tx.QueryRowContext(ctx, `SELECT `+userName("u")+` FROM app_user u WHERE u.id::text = $1`, id).Scan(&out)
		case f.Type == FieldItem:
			err = tx.QueryRowContext(ctx, `
				SELECT p.key || '-' || w.number FROM work_item w JOIN project p ON p.id = w.project_id WHERE w.id::text = $1`, id).Scan(&out)
		default:
			return f.Text(v), nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			return id, nil
		}
		return out, err
	}
	var out []inventory.Change
	for _, k := range changed {
		f, ok := defs[k]
		if !ok {
			f = FieldDef{Key: k, Label: k}
		}
		from, err := text(f, a[k])
		if err != nil {
			return nil, err
		}
		to, err := text(f, b[k])
		if err != nil {
			return nil, err
		}
		out = append(out, inventory.Change{Field: f.Label, From: from, To: to})
	}
	return out, nil
}

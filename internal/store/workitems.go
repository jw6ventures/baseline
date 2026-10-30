package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Work items (docs/data-model.md §8) -----------------------------------------------

// Status categories. Every workflow status belongs to one, and boards, SLAs
// and reports key off it.
const (
	StatusTodo       = "todo"
	StatusInProgress = "in_progress"
	StatusDone       = "done"
)

var (
	StatusCategories = []string{StatusTodo, StatusInProgress, StatusDone}
	Priorities       = []string{"critical", "high", "medium", "low"}
	// Levels are the values of impact and urgency.
	Levels      = []string{"high", "medium", "low"}
	Resolutions = []string{"Done", "Fixed", "Won't do", "Duplicate", "Cannot reproduce"}
	// ItemCIRoles say how a CI takes part in a work item.
	ItemCIRoles = []string{"affected", "caused_by", "target"}
	// ItemChangeKinds say how a change relates to a work item.
	ItemChangeKinds = []string{"fixes", "implements", "caused"}
	// ItemLinkKinds read "from <kind> to": OPS-1 blocks OPS-2.
	ItemLinkKinds = []string{"blocks", "relates", "duplicates", "caused_by"}
)

var (
	// ErrTypeNotOffered refuses an item of a type its project doesn't offer.
	ErrTypeNotOffered = errors.New("the project doesn't offer that ticket type")
	// ErrArchived refuses new items in an archived project.
	ErrArchived = errors.New("the project is archived")
	// ErrParentCycle refuses a parent that is the item itself or below it.
	ErrParentCycle = errors.New("an item can't be its own parent or ancestor")
)

var refRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]{1,9})-([1-9][0-9]{0,9})$`)

// ParseRef splits a work item reference, OPS-42, into project key and number.
func ParseRef(ref string) (key string, number int, ok bool) {
	m := refRe.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return strings.ToUpper(m[1]), n, true
}

// WorkItem is one ticket: an incident, a request, a story, a bug.
type WorkItem struct {
	ID          string
	ProjectID   string
	ProjectKey  string
	ProjectName string
	Number      int
	TypeID      string
	TypeKey     string
	TypeName    string
	BaseKind    string
	Status      string // the status category: todo | in_progress | done
	Resolution  string // set when done
	// The item's place in its workflow: the version it is on and its
	// status there.
	WorkflowID        string
	WorkflowName      string
	WorkflowVersionID string
	WorkflowVersion   int
	StatusID          string
	StatusName        string
	Title             string
	Description       string
	Priority          string
	Impact            string // "" when unset
	Urgency           string
	ReporterID        string // "" when the system opened it
	Reporter          string // display name
	AssigneeID        string
	Assignee          string
	ParentID          string
	ParentRef         string
	ParentTitle       string
	Estimate          *float64
	DueAt             time.Time // zero when unset
	Source            string    // user | alert | unplanned_change | email | api
	SourceRef         string
	Custom            map[string]any
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ResolvedAt        time.Time // zero while open
}

// Ref is the item's reference, OPS-42.
func (w WorkItem) Ref() string { return fmt.Sprintf("%s-%d", w.ProjectKey, w.Number) }

func (w WorkItem) Done() bool { return w.Status == StatusDone }

// userName is a user's display name in SQL, as User.DisplayName has it.
func userName(alias string) string {
	return fmt.Sprintf("COALESCE(NULLIF(%[1]s.name, ''), NULLIF(%[1]s.email, ''), %[1]s.oidc_sub, '')", alias)
}

var workItemCols = `w.id, w.project_id, p.key, p.name, w.number, w.ticket_type_id, t.key, t.name, t.base_kind,
	w.status_category, COALESCE(w.resolution, ''), w.title, w.description, w.priority,
	COALESCE(w.impact, ''), COALESCE(w.urgency, ''),
	COALESCE(w.reporter::text, ''), ` + userName("ru") + `, COALESCE(w.assignee::text, ''), ` + userName("au") + `,
	COALESCE(w.parent_id::text, ''), COALESCE(pp.key || '-' || pw.number, ''), COALESCE(pw.title, ''),
	w.estimate, w.due_at, w.source, w.source_ref, w.custom::text, w.created_at, w.updated_at, w.resolved_at,
	wf.id, wf.name, w.workflow_version_id, wv.version, w.status_id, ws.name`

const workItemFrom = ` FROM work_item w JOIN project p ON p.id = w.project_id JOIN ticket_type t ON t.id = w.ticket_type_id
	LEFT JOIN app_user ru ON ru.id = w.reporter LEFT JOIN app_user au ON au.id = w.assignee
	LEFT JOIN work_item pw ON pw.id = w.parent_id LEFT JOIN project pp ON pp.id = pw.project_id
	JOIN wf_status ws ON ws.id = w.status_id JOIN workflow_version wv ON wv.id = w.workflow_version_id
	JOIN workflow wf ON wf.id = wv.workflow_id `

func scanWorkItem(row interface{ Scan(...any) error }, extra ...any) (WorkItem, error) {
	var w WorkItem
	var estimate sql.NullFloat64
	var due, resolved sql.NullTime
	var custom string
	dest := []any{&w.ID, &w.ProjectID, &w.ProjectKey, &w.ProjectName, &w.Number, &w.TypeID, &w.TypeKey, &w.TypeName, &w.BaseKind,
		&w.Status, &w.Resolution, &w.Title, &w.Description, &w.Priority, &w.Impact, &w.Urgency,
		&w.ReporterID, &w.Reporter, &w.AssigneeID, &w.Assignee, &w.ParentID, &w.ParentRef, &w.ParentTitle,
		&estimate, &due, &w.Source, &w.SourceRef, &custom, &w.CreatedAt, &w.UpdatedAt, &resolved,
		&w.WorkflowID, &w.WorkflowName, &w.WorkflowVersionID, &w.WorkflowVersion, &w.StatusID, &w.StatusName}
	if err := row.Scan(append(extra, dest...)...); err != nil {
		return w, err
	}
	if estimate.Valid {
		w.Estimate = &estimate.Float64
	}
	w.DueAt, w.ResolvedAt = due.Time, resolved.Time
	return w, json.Unmarshal([]byte(custom), &w.Custom)
}

func (s *Store) GetWorkItem(ctx context.Context, id string) (WorkItem, error) {
	w, err := scanWorkItem(s.db.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, id))
	return w, mapErr(err)
}

// GetWorkItemByRef fetches an item by its reference, OPS-42, or by one it
// had before it moved to another project.
func (s *Store) GetWorkItemByRef(ctx context.Context, ref string) (WorkItem, error) {
	key, n, ok := ParseRef(ref)
	if !ok {
		return WorkItem{}, ErrNotFound
	}
	w, err := scanWorkItem(s.db.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE p.key = $1 AND w.number = $2`, key, n))
	if errors.Is(err, sql.ErrNoRows) {
		w, err = scanWorkItem(s.db.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+`
			WHERE w.id = (SELECT o.work_item_id FROM work_item_old_ref o JOIN project op ON op.id = o.project_id
			              WHERE op.key = $1 AND o.number = $2)`, key, n))
	}
	return w, mapErr(err)
}

// WorkItemFilter narrows ListWorkItems.
type WorkItemFilter struct {
	ProjectID string
	TypeID    string
	Status    string // "" = not done, "all", or a category
	Assignee  string // "" = anyone, "none" = unassigned, or a user ID
	ParentID  string
	Query     string // matches the reference, title and description
	Limit     int
}

func (s *Store) ListWorkItems(ctx context.Context, f WorkItemFilter) ([]WorkItem, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+workItemCols+workItemFrom+`
		WHERE ($1 = '' OR w.project_id::text = $1)
		  AND ($2 = '' OR w.ticket_type_id::text = $2)
		  AND (CASE WHEN $3 = '' THEN w.status_category <> 'done' WHEN $3 = 'all' THEN true ELSE w.status_category = $3 END)
		  AND (CASE WHEN $4 = '' THEN true WHEN $4 = 'none' THEN w.assignee IS NULL ELSE w.assignee::text = $4 END)
		  AND ($5 = '' OR w.parent_id::text = $5)
		  AND ($6 = '' OR strpos(lower(p.key || '-' || w.number || ' ' || w.title || ' ' || w.description), lower($6)) > 0)
		ORDER BY w.status_category = 'done', array_position(ARRAY['critical', 'high', 'medium', 'low'], w.priority),
		         w.updated_at DESC
		LIMIT $7`, f.ProjectID, f.TypeID, f.Status, f.Assignee, f.ParentID, strings.TrimSpace(f.Query), f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkItem
	for rows.Next() {
		w, err := scanWorkItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WorkItemInput is the editable part of a work item. Its project and type
// are fixed once it exists: moving an item or changing its type maps its
// status and fields, which the workflow migration screen does.
type WorkItemInput struct {
	ProjectID   string
	TypeID      string
	Title       string
	Description string
	Priority    string
	Impact      string // "" for unset
	Urgency     string
	AssigneeID  string // "" for nobody
	ParentID    string // "" for none
	Estimate    *float64
	DueAt       time.Time // zero for none
	Source      string    // "" for user
	SourceRef   string
	// Custom sets custom field values by key; a nil value clears one. A nil
	// map leaves them all as they are.
	Custom map[string]any
}

// customJSON splits Custom into the values to set, as JSON, and the keys
// to clear.
func (in WorkItemInput) customJSON() (string, []string, error) {
	set := map[string]any{}
	clear := []string{}
	for k, v := range in.Custom {
		if v == nil {
			clear = append(clear, k)
		} else {
			set[k] = v
		}
	}
	b, err := json.Marshal(set)
	return string(b), clear, err
}

func nullFloat(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}

// CreateWorkItem opens an item, numbered next in its project, and returns
// its ID and reference. It starts at the initial status of the newest
// published version of the workflow its project sets for its type.
// reporter is a user ID, or "" for the system. The reporter and the
// assignee watch it.
func (s *Store) CreateWorkItem(ctx context.Context, actor Actor, reporter string, in WorkItemInput) (string, string, error) {
	if in.Source == "" {
		in.Source = "user"
	}
	var id, ref string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var key string
		var archived bool
		if err := tx.QueryRowContext(ctx, `SELECT key, archived FROM project WHERE id = $1 FOR UPDATE`, in.ProjectID).
			Scan(&key, &archived); err != nil {
			return mapErr(err)
		}
		if archived {
			return ErrArchived
		}
		var workflowID string
		if err := tx.QueryRowContext(ctx, `
			SELECT workflow_id FROM project_ticket_type WHERE project_id = $1 AND ticket_type_id::text = $2`,
			in.ProjectID, in.TypeID).Scan(&workflowID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrTypeNotOffered
			}
			return err
		}
		version, status, err := latestVersion(ctx, tx, workflowID)
		if err != nil {
			return err
		}
		var number int
		if err := tx.QueryRowContext(ctx, `
			UPDATE project SET next_number = next_number + 1 WHERE id = $1 RETURNING next_number - 1`, in.ProjectID).
			Scan(&number); err != nil {
			return err
		}
		ref = fmt.Sprintf("%s-%d", key, number)
		custom, _, err := in.customJSON()
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO work_item (project_id, number, ticket_type_id, title, description, priority, impact, urgency,
			                       reporter, assignee, parent_id, estimate, due_at, source, source_ref,
			                       workflow_version_id, status_id, custom)
			VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, '')::uuid, NULLIF($10, '')::uuid,
			        NULLIF($11, '')::uuid, $12, $13, $14, $15, $16, $17, $18)
			RETURNING id`,
			in.ProjectID, number, in.TypeID, in.Title, in.Description, in.Priority, in.Impact, in.Urgency,
			reporter, in.AssigneeID, in.ParentID, nullFloat(in.Estimate), nullTime(in.DueAt), in.Source, in.SourceRef,
			version, status, custom).
			Scan(&id); err != nil {
			return mapErr(err)
		}
		for _, u := range []string{reporter, in.AssigneeID} {
			if err := addWatcher(ctx, tx, id, u); err != nil {
				return err
			}
		}
		if err := addItemHistory(ctx, tx, id, actor.ID, map[string]any{"initial": true}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "work_item.create", ObjectType: "work_item", ObjectID: id,
			Details: map[string]any{"ref": ref, "title": in.Title, "source": in.Source},
		})
	})
	return id, ref, err
}

func addItemHistory(ctx context.Context, tx *sql.Tx, itemID, actor string, diff any) error {
	b, err := json.Marshal(diff)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO work_item_history (work_item_id, actor, diff) VALUES ($1, $2, $3)`,
		itemID, actor, string(b))
	return err
}

func addWatcher(ctx context.Context, tx *sql.Tx, itemID, userID string) error {
	if userID == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO watcher (work_item_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		itemID, userID)
	return mapErr(err)
}

// lockItem locks an item for a change and returns its reference.
func lockItem(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var ref string
	err := tx.QueryRowContext(ctx, `
		SELECT p.key || '-' || w.number FROM work_item w JOIN project p ON p.id = w.project_id
		WHERE w.id = $1 FOR UPDATE OF w`, id).Scan(&ref)
	return ref, mapErr(err)
}

// checkParent refuses a parent that is the item or one of its descendants.
func checkParent(ctx context.Context, tx *sql.Tx, id, parent string) error {
	if parent == "" {
		return nil
	}
	if parent == id {
		return ErrParentCycle
	}
	var cycle bool
	if err := tx.QueryRowContext(ctx, `
		WITH RECURSIVE up(id) AS (
		    SELECT parent_id FROM work_item WHERE id = $1
		    UNION
		    SELECT w.parent_id FROM work_item w JOIN up ON w.id = up.id WHERE w.parent_id IS NOT NULL)
		SELECT EXISTS (SELECT 1 FROM up WHERE id = $2)`, parent, id).Scan(&cycle); err != nil {
		return mapErr(err)
	}
	if cycle {
		return ErrParentCycle
	}
	return nil
}

// UpdateWorkItem edits an item's fields, recording what changed in its
// history. The project, type and status don't change here: the status moves
// by TransitionWorkItem.
func (s *Store) UpdateWorkItem(ctx context.Context, actor Actor, id string, in WorkItemInput) error {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		ref, err := lockItem(ctx, tx, id)
		if err != nil {
			return err
		}
		before, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, id))
		if err != nil {
			return mapErr(err)
		}
		if err := checkParent(ctx, tx, id, in.ParentID); err != nil {
			return err
		}
		set, clear, err := in.customJSON()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE work_item SET title = $2, description = $3, priority = $4, impact = NULLIF($5, ''), urgency = NULLIF($6, ''),
			       assignee = NULLIF($7, '')::uuid, parent_id = NULLIF($8, '')::uuid, estimate = $9, due_at = $10,
			       custom = (custom - $11::text[]) || $12::jsonb, updated_at = now()
			WHERE id = $1`, id, in.Title, in.Description, in.Priority, in.Impact, in.Urgency,
			in.AssigneeID, in.ParentID, nullFloat(in.Estimate), nullTime(in.DueAt), pq.Array(clear), set); err != nil {
			return mapErr(err)
		}
		after, err := scanWorkItem(tx.QueryRowContext(ctx, `SELECT `+workItemCols+workItemFrom+` WHERE w.id = $1`, id))
		if err != nil {
			return err
		}
		changes := itemChanges(before, after)
		custom, err := customChanges(ctx, tx, before.Custom, after.Custom)
		if err != nil {
			return err
		}
		changes = append(changes, custom...)
		if len(changes) == 0 {
			return errNoChange // rolls back the updated_at bump
		}
		if after.AssigneeID != before.AssigneeID {
			if err := addWatcher(ctx, tx, id, after.AssigneeID); err != nil {
				return err
			}
		}
		if err := addItemHistory(ctx, tx, id, actor.ID, map[string]any{"changed": changes}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "work_item.update", ObjectType: "work_item", ObjectID: id,
			Details: map[string]any{"ref": ref, "changed": changes},
		})
	})
	if errors.Is(err, errNoChange) {
		return nil
	}
	return err
}

// errNoChange rolls back an update that changed nothing; callers don't see it.
var errNoChange = errors.New("no change")

func estimateText(f *float64) string {
	if f == nil {
		return ""
	}
	return strconv.FormatFloat(*f, 'f', -1, 64)
}

func dateText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}

func itemChanges(a, b WorkItem) []inventory.Change {
	var out []inventory.Change
	diff := func(field, from, to string) {
		if from != to {
			out = append(out, inventory.Change{Field: field, From: from, To: to})
		}
	}
	diff("title", a.Title, b.Title)
	diff("description", a.Description, b.Description)
	diff("priority", a.Priority, b.Priority)
	diff("impact", a.Impact, b.Impact)
	diff("urgency", a.Urgency, b.Urgency)
	if a.AssigneeID != b.AssigneeID {
		out = append(out, inventory.Change{Field: "assignee", From: a.Assignee, To: b.Assignee})
	}
	diff("parent", a.ParentRef, b.ParentRef)
	diff("estimate", estimateText(a.Estimate), estimateText(b.Estimate))
	diff("due", dateText(a.DueAt), dateText(b.DueAt))
	return out
}

// itemLinkChange records a link added to or removed from an item, in its
// history and the audit log. about names what the link points at in the
// history entry ({"ci_id": ...}, {"change_id": ...}), so the entry can be
// hidden from people who may not see it.
func itemLinkChange(ctx context.Context, tx *sql.Tx, actor Actor, id, action string, added bool, field, label string,
	about, details map[string]any) error {
	ref, err := lockItem(ctx, tx, id)
	if err != nil {
		return err
	}
	var diff map[string]any
	if added {
		diff = map[string]any{"added": []inventory.Change{{Field: field, To: label}}}
	} else {
		diff = map[string]any{"removed": []inventory.Change{{Field: field, From: label}}}
	}
	for k, v := range about {
		diff[k] = v
	}
	if err := addItemHistory(ctx, tx, id, actor.ID, diff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE work_item SET updated_at = now() WHERE id = $1`, id); err != nil {
		return err
	}
	details["ref"] = ref
	return appendAudit(ctx, tx, actor, AuditEvent{Action: action, ObjectType: "work_item", ObjectID: id, Details: details})
}

// CIs ------------------------------------------------------------------------------

// ItemCI is a CI linked to a work item.
type ItemCI struct {
	Role string // affected | caused_by | target
	CI   CI
}

func (s *Store) WorkItemCIs(ctx context.Context, itemID string) ([]ItemCI, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.role, `+ciCols+` FROM work_item_ci l JOIN ci ON ci.id = l.ci_id JOIN ci_type t ON t.key = ci.type
		WHERE l.work_item_id = $1 ORDER BY array_position(ARRAY['affected', 'caused_by', 'target'], l.role), lower(ci.name)`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ItemCI
	for rows.Next() {
		var l ItemCI
		var attrs string
		c := &l.CI
		if err := rows.Scan(&l.Role, &c.ID, &c.Type, &c.TypeLabel, &c.Name, &c.Status, &c.Source, &c.Owner, &c.Description,
			pq.Array(&c.Tags), &attrs, &c.FirstSeen, &c.LastSeen, &c.UpdatedAt, &c.HostID, &c.Relation); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(attrs), &c.Attrs)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) LinkWorkItemCI(ctx context.Context, actor Actor, itemID, ciID, role string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM ci WHERE id = $1`, ciID).Scan(&name); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO work_item_ci (work_item_id, ci_id, role) VALUES ($1, $2, $3)`,
			itemID, ciID, role); err != nil {
			return mapErr(err)
		}
		return itemLinkChange(ctx, tx, actor, itemID, "work_item.link_ci", true, "ci."+role, name,
			map[string]any{"ci_id": ciID}, map[string]any{"ci": ciID, "role": role})
	})
}

func (s *Store) UnlinkWorkItemCI(ctx context.Context, actor Actor, itemID, ciID, role string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `
			WITH d AS (DELETE FROM work_item_ci WHERE work_item_id = $1 AND ci_id::text = $2 AND role = $3 RETURNING ci_id)
			SELECT ci.name FROM d JOIN ci ON ci.id = d.ci_id`, itemID, ciID, role).Scan(&name); err != nil {
			return mapErr(err)
		}
		return itemLinkChange(ctx, tx, actor, itemID, "work_item.unlink_ci", false, "ci."+role, name,
			map[string]any{"ci_id": ciID}, map[string]any{"ci": ciID, "role": role})
	})
}

// CIWorkItem is a work item a CI is linked to.
type CIWorkItem struct {
	Role string
	Item WorkItem
}

// CIWorkItems lists the work items a CI is linked to, open ones first.
func (s *Store) CIWorkItems(ctx context.Context, ciID string) ([]CIWorkItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.role, `+workItemCols+workItemFrom+` JOIN work_item_ci l ON l.work_item_id = w.id
		WHERE l.ci_id = $1 ORDER BY w.status_category = 'done', w.updated_at DESC LIMIT 200`, ciID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []CIWorkItem
	for rows.Next() {
		var l CIWorkItem
		if l.Item, err = scanWorkItem(rows, &l.Role); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Changes --------------------------------------------------------------------------

// ItemChange is a change linked to a work item.
type ItemChange struct {
	Kind   string // fixes | implements | caused
	Change Change
}

func (s *Store) WorkItemChanges(ctx context.Context, itemID string) ([]ItemChange, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.kind, `+changeCols+changeFrom+` JOIN work_item_change l ON l.change_id = c.id
		WHERE l.work_item_id = $1 ORDER BY c.number`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ItemChange
	for rows.Next() {
		var l ItemChange
		if l.Change, err = scanChange(prefixScanner{rows, []any{&l.Kind}}); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// prefixScanner scans leading columns into extra before handing the rest on.
type prefixScanner struct {
	row   interface{ Scan(...any) error }
	extra []any
}

func (p prefixScanner) Scan(dest ...any) error { return p.row.Scan(append(p.extra, dest...)...) }

// ChangeIDByNumber finds a change by its number, CHG-000123's 123.
func (s *Store) ChangeIDByNumber(ctx context.Context, number int64) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM change WHERE number = $1`, number).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) LinkWorkItemChange(ctx context.Context, actor Actor, itemID, changeID, kind string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var number int64
		if err := tx.QueryRowContext(ctx, `SELECT number FROM change WHERE id = $1`, changeID).Scan(&number); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO work_item_change (work_item_id, change_id, kind) VALUES ($1, $2, $3)`,
			itemID, changeID, kind); err != nil {
			return mapErr(err)
		}
		return itemLinkChange(ctx, tx, actor, itemID, "work_item.link_change", true, "change."+kind, ChangeRef(number),
			map[string]any{"change_id": changeID}, map[string]any{"change": ChangeRef(number), "kind": kind})
	})
}

func (s *Store) UnlinkWorkItemChange(ctx context.Context, actor Actor, itemID, changeID, kind string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var number int64
		if err := tx.QueryRowContext(ctx, `
			WITH d AS (DELETE FROM work_item_change WHERE work_item_id = $1 AND change_id::text = $2 AND kind = $3 RETURNING change_id)
			SELECT c.number FROM d JOIN change c ON c.id = d.change_id`, itemID, changeID, kind).Scan(&number); err != nil {
			return mapErr(err)
		}
		return itemLinkChange(ctx, tx, actor, itemID, "work_item.unlink_change", false, "change."+kind, ChangeRef(number),
			map[string]any{"change_id": changeID}, map[string]any{"change": ChangeRef(number), "kind": kind})
	})
}

// ChangeWorkItem is a work item a change is linked to.
type ChangeWorkItem struct {
	Kind string
	Item WorkItem
}

func (s *Store) ChangeWorkItems(ctx context.Context, changeID string) ([]ChangeWorkItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.kind, `+workItemCols+workItemFrom+` JOIN work_item_change l ON l.work_item_id = w.id
		WHERE l.change_id = $1 ORDER BY p.key, w.number`, changeID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ChangeWorkItem
	for rows.Next() {
		var l ChangeWorkItem
		if l.Item, err = scanWorkItem(rows, &l.Kind); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Links between items ----------------------------------------------------------------

// ItemLink is a link between two items, seen from one of them.
type ItemLink struct {
	Kind string
	// Outgoing is true when the item asked about is the "from" side.
	Outgoing bool
	Other    WorkItem
}

func (s *Store) WorkItemLinks(ctx context.Context, itemID string) ([]ItemLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.kind, l.from_id = $1, `+workItemCols+workItemFrom+`
		JOIN work_item_link l ON w.id = CASE WHEN l.from_id = $1 THEN l.to_id ELSE l.from_id END
		WHERE l.from_id = $1 OR l.to_id = $1
		ORDER BY l.from_id <> $1, l.kind, p.key, w.number`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ItemLink
	for rows.Next() {
		var l ItemLink
		if l.Other, err = scanWorkItem(rows, &l.Kind, &l.Outgoing); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LinkWorkItems records "from <kind> to", in both items' history.
func (s *Store) LinkWorkItems(ctx context.Context, actor Actor, from, to, kind string) error {
	if from == to {
		return ErrConflict
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO work_item_link (from_id, to_id, kind) VALUES ($1, $2, $3)`,
			from, to, kind); err != nil {
			return mapErr(err)
		}
		return linkHistory(ctx, tx, actor, from, to, kind, true)
	})
}

func (s *Store) UnlinkWorkItems(ctx context.Context, actor Actor, from, to, kind string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM work_item_link WHERE from_id::text = $1 AND to_id::text = $2 AND kind = $3`,
			from, to, kind)
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return linkHistory(ctx, tx, actor, from, to, kind, false)
	})
}

func linkHistory(ctx context.Context, tx *sql.Tx, actor Actor, from, to, kind string, added bool) error {
	var fromRef, toRef string
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT p.key || '-' || w.number FROM work_item w JOIN project p ON p.id = w.project_id WHERE w.id = $1),
		       (SELECT p.key || '-' || w.number FROM work_item w JOIN project p ON p.id = w.project_id WHERE w.id = $2)`,
		from, to).Scan(&fromRef, &toRef); err != nil {
		return mapErr(err)
	}
	label := fromRef + " " + kind + " " + toRef
	action := "work_item.link"
	if !added {
		action = "work_item.unlink"
	}
	if err := itemLinkChange(ctx, tx, actor, from, action, added, "link", label, nil,
		map[string]any{"to": toRef, "kind": kind}); err != nil {
		return err
	}
	if _, err := lockItem(ctx, tx, to); err != nil {
		return err
	}
	var diff map[string]any
	if added {
		diff = map[string]any{"added": []inventory.Change{{Field: "link", To: label}}}
	} else {
		diff = map[string]any{"removed": []inventory.Change{{Field: "link", From: label}}}
	}
	if err := addItemHistory(ctx, tx, to, actor.ID, diff); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE work_item SET updated_at = now() WHERE id = $1`, to)
	return err
}

// Comments, watchers, history --------------------------------------------------------

// Comment is a reply or, when Internal, a work note.
type Comment struct {
	ID       string
	AuthorID string
	Author   string // display name
	Body     string
	Internal bool
	At       time.Time
}

func (s *Store) WorkItemComments(ctx context.Context, itemID string) ([]Comment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, COALESCE(c.author::text, ''), `+userName("u")+`, c.body, c.internal, c.at
		FROM comment c LEFT JOIN app_user u ON u.id = c.author WHERE c.work_item_id = $1 ORDER BY c.at, c.id`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.AuthorID, &c.Author, &c.Body, &c.Internal, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddComment adds a comment by author, who then watches the item.
func (s *Store) AddComment(ctx context.Context, actor Actor, author, itemID, body string, internal bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		ref, err := lockItem(ctx, tx, itemID)
		if err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO comment (work_item_id, author, body, internal) VALUES ($1, NULLIF($2, '')::uuid, $3, $4) RETURNING id`,
			itemID, author, body, internal).Scan(&id); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE work_item SET updated_at = now() WHERE id = $1`, itemID); err != nil {
			return err
		}
		if err := addWatcher(ctx, tx, itemID, author); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "work_item.comment", ObjectType: "work_item", ObjectID: itemID,
			Details: map[string]any{"ref": ref, "comment": id, "internal": internal},
		})
	})
}

func (s *Store) WorkItemWatchers(ctx context.Context, itemID string) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.oidc_sub, u.email, u.name FROM watcher x JOIN app_user u ON u.id = x.user_id
		WHERE x.work_item_id = $1 ORDER BY lower(`+userName("u")+`)`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OIDCSub, &u.Email, &u.Name); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetWatching starts or stops user watching an item.
func (s *Store) SetWatching(ctx context.Context, actor Actor, itemID, userID string, on bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		ref, err := lockItem(ctx, tx, itemID)
		if err != nil {
			return err
		}
		var res sql.Result
		action := "work_item.watch"
		if on {
			res, err = tx.ExecContext(ctx, `INSERT INTO watcher (work_item_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				itemID, userID)
		} else {
			action = "work_item.unwatch"
			res, err = tx.ExecContext(ctx, `DELETE FROM watcher WHERE work_item_id = $1 AND user_id = $2`, itemID, userID)
		}
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "work_item", ObjectID: itemID, Details: map[string]any{"ref": ref, "user": userID},
		})
	})
}

// ItemEvent is one entry of a work item's history.
type ItemEvent struct {
	At        time.Time
	Actor     string
	ActorName string // when the actor is a user
	Initial   bool
	Diff      inventory.Diff
	Summary   string // "changed priority, assignee"
	// Transition names the workflow transition that made the entry, and
	// Migration the kind of admin move (workflow, type or project).
	Transition string
	Migration  string
	// CIID or ChangeID is what a link entry points at.
	CIID     string
	ChangeID string
}

// itemSummary names the fields a history entry touches.
func itemSummary(d inventory.Diff) string {
	var parts []string
	for _, x := range []struct {
		verb    string
		changes []inventory.Change
	}{{"changed", d.Changed}, {"added", d.Added}, {"removed", d.Removed}} {
		if len(x.changes) == 0 {
			continue
		}
		var fields []string
		for _, c := range x.changes {
			fields = append(fields, c.Field)
		}
		parts = append(parts, x.verb+" "+strings.Join(fields, ", "))
	}
	return strings.Join(parts, "; ")
}

func (s *Store) WorkItemHistory(ctx context.Context, itemID string, limit int) ([]ItemEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.at, h.actor, COALESCE(`+userName("u")+`, ''), h.diff::text FROM work_item_history h
		LEFT JOIN app_user u ON h.actor = 'user:' || u.id::text
		WHERE h.work_item_id = $1 ORDER BY h.at DESC, h.id DESC LIMIT $2`, itemID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []ItemEvent
	for rows.Next() {
		var e ItemEvent
		var diff string
		if err := rows.Scan(&e.At, &e.Actor, &e.ActorName, &diff); err != nil {
			return nil, err
		}
		var raw struct {
			Initial    bool   `json:"initial"`
			CIID       string `json:"ci_id"`
			ChangeID   string `json:"change_id"`
			Transition string `json:"transition"`
			Migration  struct {
				Kind string `json:"kind"`
			} `json:"migration"`
			inventory.Diff
		}
		if json.Unmarshal([]byte(diff), &raw) == nil {
			e.Initial, e.Diff, e.Summary = raw.Initial, raw.Diff, itemSummary(raw.Diff)
			e.CIID, e.ChangeID = raw.CIID, raw.ChangeID
			e.Transition, e.Migration = raw.Transition, raw.Migration.Kind
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

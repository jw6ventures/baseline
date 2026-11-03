package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/action"
)

// Change states (docs/change-management.md §2).
const (
	ChangeDraft       = "draft"
	ChangeSubmitted   = "submitted"
	ChangeApproved    = "approved"
	ChangeScheduled   = "scheduled"
	ChangeInProgress  = "in_progress"
	ChangeImplemented = "implemented"
	ChangeFailed      = "failed"
	ChangeRolledBack  = "rolled_back"
	ChangeReview      = "review"
	ChangeClosed      = "closed"
	ChangeRejected    = "rejected"
	ChangeCancelled   = "cancelled"
)

// Change kinds (ITIL).
const (
	KindStandard  = "standard"
	KindNormal    = "normal"
	KindEmergency = "emergency"
)

// ChangeKinds lists the kinds in the order the UI shows them.
var ChangeKinds = []string{KindNormal, KindEmergency, KindStandard}

// What happens to the hosts left when a change's window closes.
const (
	WindowCarryOver = "carry_over"
	WindowFail      = "fail"
)

// MaxApprovals bounds a change's required approvals.
const MaxApprovals = 5

var (
	// ErrState rejects a transition the change's state doesn't allow.
	ErrState = errors.New("the change is not in a state that allows this")
	// ErrModel rejects a Standard change whose model isn't approved.
	ErrModel = errors.New("the change model isn't approved")
)

// Change is a change record.
type Change struct {
	ID                string
	Number            int64
	Kind              string
	Title             string
	Description       string
	Justification     string
	Risk              string
	Impact            string
	BackoutPlan       string
	TestPlan          string
	State             string
	Outcome           string
	RequestedBy       string // user ID; "" for the scheduler
	RequestedByName   string
	RequiredApprovals int
	Concurrency       int
	StopOnFailure     bool
	Plan              []PlanStep
	CreatedAt         time.Time
	SubmittedAt       time.Time
	ApprovedAt        time.Time
	PlannedStart      time.Time
	PlannedEnd        time.Time
	ActualStart       time.Time
	ActualEnd         time.Time
	ClosedAt          time.Time
	HostIDs           []string // affected hosts
	HostNames         []string
	SelfApproved      bool
	Approvals         int // approvals so far

	ModelID      string
	ModelName    string
	WindowID     string
	WindowName   string
	WindowEndsAt time.Time // while in progress inside a window
	OnWindowEnd  string
	ScheduleNote string
	ReviewNotes  string
	ReviewedBy   string // name

	Jobs, JobsOK, JobsFailed, JobsOpen, JobsQueued int
}

// Ref is the change's human reference, CHG-000123.
func (c Change) Ref() string { return ChangeRef(c.Number) }

func ChangeRef(n int64) string { return fmt.Sprintf("CHG-%06d", n) }

// Open reports whether the change hasn't run its course: it can still be
// cancelled.
func (c Change) Open() bool {
	switch c.State {
	case ChangeDraft, ChangeSubmitted, ChangeApproved, ChangeScheduled, ChangeInProgress:
		return true
	}
	return false
}

// Closable reports whether the change has ended and waits to be closed.
func (c Change) Closable() bool {
	switch c.State {
	case ChangeImplemented, ChangeFailed, ChangeRolledBack, ChangeReview:
		return true
	}
	return false
}

// NeedsReview reports whether closing the change needs a
// post-implementation review: Emergency changes, and every change that
// failed or was rolled back.
func (c Change) NeedsReview() bool {
	return c.Closable() && c.State != ChangeImplemented
}

// PlanStep is one line of a change's implementation plan: an action on
// some hosts. Its jobs are the expansion.
type PlanStep struct {
	Action        string          `json:"action"`
	Summary       string          `json:"summary"`
	Params        json.RawMessage `json:"params"`
	HostIDs       []string        `json:"hosts"`
	ScriptID      string          `json:"script_id,omitempty"`
	ScriptVersion int             `json:"script_version,omitempty"`
}

// NewChange is a change to create, with the jobs that implement it.
type NewChange struct {
	Kind          string // "" is normal
	ModelID       string // standard: the approved model it is an instance of
	Title         string
	Description   string
	Justification string
	Risk          action.Risk
	Impact        action.Risk // "" is low
	BackoutPlan   string
	TestPlan      string
	// RequiredApprovals is for Normal changes (default 1); Emergency ones
	// need one, Standard ones none.
	RequiredApprovals int
	Concurrency       int
	StopOnFailure     bool
	// WindowID runs the change only inside that maintenance window.
	WindowID string
	// PlannedStart, when set, holds the change until then.
	PlannedStart time.Time
	OnWindowEnd  string     // "" is carry_over
	Steps        []PlanStep // Params already validated (action.Validate)
	// CIs are affected CIs beside the hosts, e.g. a Compose stack.
	CIs []string
	// Draft saves the change without submitting it.
	Draft bool
	// SelfApprove approves the change on creation, as its requester, who
	// must hold approver on every affected host. It's flagged as such.
	SelfApprove bool
	// Revisions are the files of compose.deploy and compose.edit steps,
	// stored with the change.
	Revisions []ComposeRevision
	// Manifests are the manifests of k8s.deploy and k8s.edit steps.
	Manifests []Manifest
}

const changeCols = `c.id, c.number, c.kind, c.title, c.description, c.justification, c.risk, c.impact, c.backout_plan,
	c.test_plan, c.state, COALESCE(c.outcome, ''),
	COALESCE(c.requested_by::text, ''), COALESCE(NULLIF(u.name, ''), u.email, ''), c.required_approvals, c.concurrency,
	c.stop_on_failure, c.implementation_plan::text, c.created_at, COALESCE(c.submitted_at, 'epoch'),
	COALESCE(c.approved_at, 'epoch'), COALESCE(c.planned_start, 'epoch'), COALESCE(c.planned_end, 'epoch'),
	COALESCE(c.actual_start, 'epoch'), COALESCE(c.actual_end, 'epoch'), COALESCE(c.closed_at, 'epoch'),
	ARRAY(SELECT cc.ci_id::text FROM change_ci cc JOIN host h ON h.ci_id = cc.ci_id WHERE cc.change_id = c.id ORDER BY h.hostname),
	ARRAY(SELECT h.hostname FROM change_ci cc JOIN host h ON h.ci_id = cc.ci_id WHERE cc.change_id = c.id ORDER BY h.hostname),
	EXISTS (SELECT 1 FROM change_approval a WHERE a.change_id = c.id AND a.self_approved AND a.decision = 'approve'),
	(SELECT count(*) FROM change_approval a WHERE a.change_id = c.id AND a.decision = 'approve'),
	COALESCE(c.model_id::text, ''), COALESCE(m.name, ''), COALESCE(c.window_id::text, ''), COALESCE(w.name, ''),
	COALESCE(c.window_ends_at, 'epoch'), c.on_window_end, c.schedule_note, c.review_notes,
	COALESCE(NULLIF(r.name, ''), r.email, ''),
	(SELECT count(*) FROM job j WHERE j.change_id = c.id),
	(SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state = 'succeeded'),
	(SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state IN ('failed', 'timed_out', 'rejected', 'rolled_back')),
	(SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state IN ('queued', 'dispatched', 'running')),
	(SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state = 'queued')`

const changeFrom = ` FROM change c LEFT JOIN app_user u ON u.id = c.requested_by LEFT JOIN change_model m ON m.id = c.model_id
	LEFT JOIN maintenance_window w ON w.id = c.window_id LEFT JOIN app_user r ON r.id = c.reviewed_by `

func scanChange(row interface{ Scan(...any) error }) (Change, error) {
	var c Change
	var plan string
	err := row.Scan(&c.ID, &c.Number, &c.Kind, &c.Title, &c.Description, &c.Justification, &c.Risk, &c.Impact, &c.BackoutPlan,
		&c.TestPlan, &c.State, &c.Outcome,
		&c.RequestedBy, &c.RequestedByName, &c.RequiredApprovals, &c.Concurrency, &c.StopOnFailure, &plan,
		&c.CreatedAt, &c.SubmittedAt, &c.ApprovedAt, &c.PlannedStart, &c.PlannedEnd, &c.ActualStart, &c.ActualEnd, &c.ClosedAt,
		pq.Array(&c.HostIDs), pq.Array(&c.HostNames), &c.SelfApproved, &c.Approvals,
		&c.ModelID, &c.ModelName, &c.WindowID, &c.WindowName, &c.WindowEndsAt, &c.OnWindowEnd, &c.ScheduleNote,
		&c.ReviewNotes, &c.ReviewedBy,
		&c.Jobs, &c.JobsOK, &c.JobsFailed, &c.JobsOpen, &c.JobsQueued)
	if err != nil {
		return c, err
	}
	for _, t := range []*time.Time{&c.SubmittedAt, &c.ApprovedAt, &c.PlannedStart, &c.PlannedEnd, &c.ActualStart,
		&c.ActualEnd, &c.ClosedAt, &c.WindowEndsAt} {
		if t.Unix() == 0 {
			*t = time.Time{}
		}
	}
	if c.RequestedBy == "" && c.RequestedByName == "" {
		c.RequestedByName = "the scheduler"
	}
	return c, json.Unmarshal([]byte(plan), &c.Plan)
}

// ChangeFilter narrows ListChanges.
type ChangeFilter struct {
	States  []string // empty: any
	HostID  string   // only changes affecting this host
	CIID    string   // only changes affecting this CI (a stack)
	ModelID string   // only changes made from this model
	// PlannedFrom and PlannedTo keep changes planned to start in
	// [PlannedFrom, PlannedTo), for the calendar.
	PlannedFrom, PlannedTo time.Time
	Limit                  int
}

// ListChanges returns changes, newest first. Callers filter by what the
// user may see (HostIDs).
func (s *Store) ListChanges(ctx context.Context, f ChangeFilter) ([]Change, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	var from, to any
	if !f.PlannedFrom.IsZero() {
		from, to = f.PlannedFrom, f.PlannedTo
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+changeCols+changeFrom+`
		WHERE (cardinality($1::text[]) = 0 OR c.state = ANY($1))
		  AND ($2 = '' OR EXISTS (SELECT 1 FROM change_ci cc WHERE cc.change_id = c.id AND cc.ci_id::text = $2))
		  AND ($4 = '' OR EXISTS (SELECT 1 FROM change_ci cc WHERE cc.change_id = c.id AND cc.ci_id::text = $4))
		  AND ($5::timestamptz IS NULL OR (c.planned_start >= $5 AND c.planned_start < $6))
		  AND ($7 = '' OR c.model_id::text = $7)
		ORDER BY c.number DESC LIMIT $3`, pq.Array(nonNil(f.States)), f.HostID, f.Limit, f.CIID, from, to, f.ModelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		c, err := scanChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetChange(ctx context.Context, id string) (Change, error) {
	c, err := scanChange(s.db.QueryRowContext(ctx, `SELECT `+changeCols+changeFrom+` WHERE c.id = $1`, id))
	return c, mapErr(err)
}

// Approval is one approver's decision.
type Approval struct {
	Approver     string
	ApproverName string
	Decision     string
	Comment      string
	SelfApproved bool
	At           time.Time
}

func (s *Store) ChangeApprovals(ctx context.Context, changeID string) ([]Approval, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.approver, COALESCE(NULLIF(u.name, ''), u.email, ''), a.decision, a.comment, a.self_approved, a.at
		FROM change_approval a JOIN app_user u ON u.id = a.approver WHERE a.change_id = $1 ORDER BY a.at`, changeID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.Approver, &a.ApproverName, &a.Decision, &a.Comment, &a.SelfApproved, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func nullTime(t time.Time) sql.NullTime { return sql.NullTime{Time: t, Valid: !t.IsZero()} }

// CreateChange records a change and queues its jobs, one per step and
// host. The jobs wait until the change is in progress. A Standard change is
// approved at once by its model; only those may be requested by the system
// (patch groups, Compose auto-updates).
func (s *Store) CreateChange(ctx context.Context, actor Actor, nc NewChange) (Change, error) {
	userID := actor.userID()
	if nc.Kind == "" {
		nc.Kind = KindNormal
	}
	if !slices.Contains(ChangeKinds, nc.Kind) {
		return Change{}, fmt.Errorf("unknown change kind %q", nc.Kind)
	}
	if !userID.Valid && nc.Kind != KindStandard {
		return Change{}, errors.New("only Standard changes are requested by the system")
	}
	if (nc.Kind == KindStandard) != (nc.ModelID != "") {
		return Change{}, errors.New("a Standard change, and only one, comes from a change model")
	}
	if len(nc.Steps) == 0 {
		return Change{}, errors.New("a change needs at least one action")
	}
	if nc.Concurrency < 1 {
		nc.Concurrency = 1
	}
	if nc.Impact == "" {
		nc.Impact = action.Low
	}
	if nc.OnWindowEnd == "" {
		nc.OnWindowEnd = WindowCarryOver
	}
	switch nc.Kind {
	case KindNormal:
		nc.RequiredApprovals = min(max(nc.RequiredApprovals, 1), MaxApprovals)
	default:
		nc.RequiredApprovals = 1
	}
	state := ChangeSubmitted
	switch {
	case nc.Kind == KindStandard:
		state = ChangeApproved
	case nc.Draft:
		state = ChangeDraft
	}
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var modelName string
		if nc.ModelID != "" {
			var mstate string
			if err := tx.QueryRowContext(ctx, `SELECT name, state FROM change_model WHERE id = $1 FOR SHARE`, nc.ModelID).
				Scan(&modelName, &mstate); err != nil {
				return mapErr(err)
			}
			if mstate != ModelApproved {
				return ErrModel
			}
		}
		plan, err := json.Marshal(nc.Steps)
		if err != nil {
			return err
		}
		var number int64
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO change (kind, model_id, title, description, justification, risk, impact, backout_plan, test_plan,
			                    implementation_plan, state, requested_by, required_approvals, concurrency, stop_on_failure,
			                    window_id, planned_start, on_window_end, submitted_at, approved_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			        CASE WHEN $11 <> 'draft' THEN now() END, CASE WHEN $11 = 'approved' THEN now() END)
			RETURNING id, number`,
			nc.Kind, nullString(nc.ModelID), nc.Title, nc.Description, nc.Justification, string(nc.Risk), string(nc.Impact),
			nc.BackoutPlan, nc.TestPlan, string(plan), state, userID, nc.RequiredApprovals, nc.Concurrency, nc.StopOnFailure,
			nullString(nc.WindowID), nullTime(nc.PlannedStart), nc.OnWindowEnd).
			Scan(&id, &number); err != nil {
			return mapErr(err)
		}
		var hosts []string
		seq := 0
		for _, st := range nc.Steps {
			for _, h := range st.HostIDs {
				seq++
				var script sql.NullString
				var version sql.NullInt64
				if st.ScriptID != "" {
					script = sql.NullString{String: st.ScriptID, Valid: true}
					version = sql.NullInt64{Int64: int64(st.ScriptVersion), Valid: true}
				}
				timeout := action.Timeout(st.Action, st.Params)
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO job (change_id, seq, host, action, params, script_id, script_version, timeout_s, requested_by)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
					id, seq, h, st.Action, string(st.Params), script, version, int(timeout.Seconds()), userID); err != nil {
					return mapErr(err)
				}
				if !slices.Contains(hosts, h) {
					hosts = append(hosts, h)
				}
			}
		}
		if err := insertRevisions(ctx, tx, id, userID, nc.Revisions); err != nil {
			return err
		}
		if err := insertManifests(ctx, tx, id, userID, nc.Manifests); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO change_ci (change_id, ci_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
			id, pq.Array(append(slices.Clone(hosts), nc.CIs...))); err != nil {
			return mapErr(err)
		}
		var summary []string
		for _, st := range nc.Steps {
			summary = append(summary, st.Summary)
		}
		details := map[string]any{"number": ChangeRef(number), "kind": nc.Kind, "title": nc.Title, "risk": nc.Risk,
			"hosts": hosts, "actions": summary, "jobs": seq, "state": state}
		if modelName != "" {
			details["model"] = modelName
		}
		if nc.WindowID != "" {
			details["window"] = nc.WindowID
		}
		if !nc.PlannedStart.IsZero() {
			details["planned_start"] = nc.PlannedStart.UTC().Format(time.RFC3339)
		}
		if err := appendAudit(ctx, tx, actor, AuditEvent{
			Action: "change.create", ObjectType: "change", ObjectID: id, Details: details,
		}); err != nil {
			return err
		}
		if state == ChangeApproved {
			return appendAudit(ctx, tx, actor, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id,
				Details: map[string]any{"number": ChangeRef(number), "from": "", "to": ChangeApproved,
					"reason": "pre-approved by change model " + modelName}})
		}
		if nc.SelfApprove && state == ChangeSubmitted {
			return decide(ctx, tx, actor, id, "approve", "")
		}
		return nil
	})
	if err != nil {
		return Change{}, err
	}
	return s.GetChange(ctx, id)
}

// SubmitChange submits a draft for approval; only its requester does.
func (s *Store) SubmitChange(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var number int64
		err := tx.QueryRowContext(ctx, `
			UPDATE change SET state = 'submitted', submitted_at = now(), updated_at = now()
			WHERE id = $1 AND state = 'draft' AND requested_by::text = $2 RETURNING number`, id, actor.userID().String).
			Scan(&number)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id,
			Details: map[string]any{"number": ChangeRef(number), "from": ChangeDraft, "to": ChangeSubmitted}})
	})
}

// ApproveChange records an approval; the change is approved once it has
// enough, and starts when its window and freezes allow (internal/change).
// Self-approval is allowed and flagged.
func (s *Store) ApproveChange(ctx context.Context, actor Actor, id, comment string) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return decide(ctx, tx, actor, id, "approve", comment) })
}

// RejectChange rejects a submitted change; its jobs never run.
func (s *Store) RejectChange(ctx context.Context, actor Actor, id, comment string) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return decide(ctx, tx, actor, id, "reject", comment) })
}

func decide(ctx context.Context, tx *sql.Tx, actor Actor, id, decision, comment string) error {
	userID := actor.userID()
	if !userID.Valid {
		return errors.New("only users approve changes")
	}
	var state, requester string
	var number int64
	var required int
	if err := tx.QueryRowContext(ctx, `
		SELECT state, COALESCE(requested_by::text, ''), number, required_approvals FROM change WHERE id = $1 FOR UPDATE`, id).
		Scan(&state, &requester, &number, &required); err != nil {
		return mapErr(err)
	}
	if state != ChangeSubmitted {
		return ErrState
	}
	self := requester == userID.String
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO change_approval (change_id, approver, decision, comment, self_approved) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (change_id, approver) DO UPDATE SET decision = EXCLUDED.decision, comment = EXCLUDED.comment, at = now()`,
		id, userID, decision, comment, self); err != nil {
		return err
	}
	details := map[string]any{"number": ChangeRef(number), "self_approved": self}
	if comment != "" {
		details["comment"] = comment
	}
	if decision == "reject" {
		if err := appendAudit(ctx, tx, actor, AuditEvent{Action: "change.reject", ObjectType: "change", ObjectID: id, Details: details}); err != nil {
			return err
		}
		return endChange(ctx, tx, id, ChangeRejected, "", "the change was rejected")
	}
	if err := appendAudit(ctx, tx, actor, AuditEvent{Action: "change.approve", ObjectType: "change", ObjectID: id, Details: details}); err != nil {
		return err
	}
	var approvals int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM change_approval WHERE change_id = $1 AND decision = 'approve'`, id).Scan(&approvals); err != nil {
		return err
	}
	if approvals < required {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE change SET state = 'approved', approved_at = now(), updated_at = now() WHERE id = $1`, id); err != nil {
		return err
	}
	return appendAudit(ctx, tx, actor, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id,
		Details: map[string]any{"number": ChangeRef(number), "from": state, "to": ChangeApproved}})
}

// CancelChange stops a change that hasn't finished. Queued jobs are
// cancelled; it returns the jobs already sent to agents, which the caller
// asks to stop.
func (s *Store) CancelChange(ctx context.Context, actor Actor, id, reason string) ([]JobRef, error) {
	var running []JobRef
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var state string
		var number int64
		if err := tx.QueryRowContext(ctx, `SELECT state, number FROM change WHERE id = $1 FOR UPDATE`, id).
			Scan(&state, &number); err != nil {
			return mapErr(err)
		}
		if !(Change{State: state}).Open() {
			return ErrState
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT j.id, j.host, h.agent_id FROM job j JOIN host h ON h.ci_id = j.host
			WHERE j.change_id = $1 AND j.state IN ('dispatched', 'running')`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r JobRef
			if err := rows.Scan(&r.ID, &r.HostID, &r.AgentID); err != nil {
				rows.Close()
				return err
			}
			running = append(running, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		details := map[string]any{"number": ChangeRef(number), "from": state, "to": ChangeCancelled}
		if reason != "" {
			details["reason"] = reason
		}
		if err := appendAudit(ctx, tx, actor, AuditEvent{Action: "change.cancel", ObjectType: "change", ObjectID: id, Details: details}); err != nil {
			return err
		}
		msg := "the change was cancelled"
		if reason != "" {
			msg += ": " + reason
		}
		return endChange(ctx, tx, id, ChangeCancelled, "cancelled", msg)
	})
	return running, err
}

// endChange moves a change to a final state and cancels its queued jobs.
func endChange(ctx context.Context, tx *sql.Tx, id, state, outcome, why string) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE change SET state = $2, outcome = NULLIF($3, ''), actual_end = CASE WHEN actual_start IS NULL THEN NULL ELSE now() END,
		       window_ends_at = NULL, closed_at = now(), updated_at = now() WHERE id = $1`, id, state, outcome); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE job SET state = 'cancelled', finished_at = now(), error = $2 WHERE change_id = $1 AND state = 'queued'`, id, why)
	return err
}

// CloseChange closes a change that has run its course. Closing one that
// needs a review (Emergency, failed, rolled back) needs the review's notes.
func (s *Store) CloseChange(ctx context.Context, actor Actor, id, notes string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var c Change
		if err := tx.QueryRowContext(ctx, `SELECT state, number FROM change WHERE id = $1 FOR UPDATE`, id).
			Scan(&c.State, &c.Number); err != nil {
			return mapErr(err)
		}
		if !c.Closable() {
			return ErrState
		}
		if c.NeedsReview() && strings.TrimSpace(notes) == "" {
			return errors.New("this change needs a post-implementation review before it closes")
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET state = 'closed', review_notes = $2, reviewed_by = CASE WHEN $2 <> '' THEN $3::uuid END,
			       closed_at = now(), updated_at = now() WHERE id = $1`, id, notes, actor.userID()); err != nil {
			return err
		}
		details := map[string]any{"number": c.Ref(), "from": c.State, "to": ChangeClosed}
		if notes != "" {
			details["review"] = notes
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "change.close", ObjectType: "change", ObjectID: id, Details: details})
	})
}

// Scheduling (internal/change) -------------------------------------------------

// ScheduleChange holds an approved change until start, inside the window
// opening that ends at end (zero without a window). note says why it waits.
func (s *Store) ScheduleChange(ctx context.Context, id string, start, end time.Time, note string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var state, prevNote string
		var number int64
		var prev sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT state, number, planned_start, schedule_note FROM change WHERE id = $1 FOR UPDATE`, id).
			Scan(&state, &number, &prev, &prevNote); err != nil {
			return mapErr(err)
		}
		if state != ChangeApproved && state != ChangeScheduled {
			return ErrState
		}
		if state == ChangeScheduled && prev.Valid && prev.Time.Equal(start) && prevNote == note {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET state = 'scheduled', planned_start = $2, planned_end = $3, schedule_note = $4, updated_at = now()
			WHERE id = $1`, id, start, nullTime(end), note); err != nil {
			return err
		}
		details := map[string]any{"number": ChangeRef(number), "from": state, "to": ChangeScheduled,
			"planned_start": start.UTC().Format(time.RFC3339)}
		if note != "" {
			details["reason"] = note
		}
		return appendAudit(ctx, tx, System, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id, Details: details})
	})
}

// NoteSchedule records why an approved change can't be scheduled at all
// (its window never opens), leaving it approved.
func (s *Store) NoteSchedule(ctx context.Context, id, note string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE change SET schedule_note = $2 WHERE id = $1 AND schedule_note <> $2`, id, note)
	return err
}

// StartChange puts an approved or scheduled change in progress, so its jobs
// are dispatched; windowEnd is the end of the window opening it runs in
// (zero without one).
func (s *Store) StartChange(ctx context.Context, id string, windowEnd time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var state string
		var number int64
		if err := tx.QueryRowContext(ctx, `SELECT state, number FROM change WHERE id = $1 FOR UPDATE`, id).
			Scan(&state, &number); err != nil {
			return mapErr(err)
		}
		if state != ChangeApproved && state != ChangeScheduled {
			return ErrState
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET state = 'in_progress', actual_start = COALESCE(actual_start, now()), window_ends_at = $2,
			       schedule_note = '', updated_at = now() WHERE id = $1`, id, nullTime(windowEnd)); err != nil {
			return err
		}
		details := map[string]any{"number": ChangeRef(number), "from": state, "to": ChangeInProgress}
		if !windowEnd.IsZero() {
			details["window_ends_at"] = windowEnd.UTC().Format(time.RFC3339)
		}
		if err := appendAudit(ctx, tx, System, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id, Details: details}); err != nil {
			return err
		}
		// A change whose every job was already settled (nothing to do)
		// finishes here.
		return completeChange(ctx, tx, id)
	})
}

// WindowClosed handles a change in progress whose window opening has
// ended and that has no job running: the hosts left wait for next (a
// carried-over change) or, when next is zero, are failed.
func (s *Store) WindowClosed(ctx context.Context, id string, next, nextEnd time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var state string
		var number int64
		var open, queued int
		if err := tx.QueryRowContext(ctx, `
			SELECT c.state, c.number,
			       (SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state IN ('dispatched', 'running')),
			       (SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state = 'queued')
			FROM change c WHERE c.id = $1 FOR UPDATE`, id).Scan(&state, &number, &open, &queued); err != nil {
			return mapErr(err)
		}
		if state != ChangeInProgress || open > 0 {
			return nil
		}
		if queued == 0 {
			return completeChange(ctx, tx, id)
		}
		if next.IsZero() {
			if _, err := tx.ExecContext(ctx, `
				UPDATE job SET state = 'cancelled', finished_at = now(), error = 'the maintenance window closed before the job could start'
				WHERE change_id = $1 AND state = 'queued'`, id); err != nil {
				return err
			}
			if err := appendAudit(ctx, tx, System, AuditEvent{Action: "change.window_closed", ObjectType: "change", ObjectID: id,
				Details: map[string]any{"number": ChangeRef(number), "skipped_jobs": queued}}); err != nil {
				return err
			}
			return completeChange(ctx, tx, id)
		}
		note := plural(queued, "job") + " carried over: the window closed before they could start"
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET state = 'scheduled', planned_start = $2, planned_end = $3, window_ends_at = NULL,
			       schedule_note = $4, updated_at = now() WHERE id = $1`, id, next, nullTime(nextEnd), note); err != nil {
			return err
		}
		return appendAudit(ctx, tx, System, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: id,
			Details: map[string]any{"number": ChangeRef(number), "from": state, "to": ChangeScheduled,
				"planned_start": next.UTC().Format(time.RFC3339), "reason": note}})
	})
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// ChangeCounts is the dashboard's change summary.
type ChangeCounts struct {
	AwaitingApproval int
	Scheduled        int
	InProgress       int
	AwaitingReview   int
}

func (s *Store) ChangeCounts(ctx context.Context, hostIDs []string) (ChangeCounts, error) {
	var c ChangeCounts
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE state = 'submitted'), count(*) FILTER (WHERE state IN ('approved', 'scheduled')),
		       count(*) FILTER (WHERE state = 'in_progress'), count(*) FILTER (WHERE state IN ('review', 'failed', 'rolled_back'))
		FROM change c WHERE NOT EXISTS (
		    SELECT 1 FROM change_ci cc JOIN host h ON h.ci_id = cc.ci_id
		    WHERE cc.change_id = c.id AND NOT cc.ci_id::text = ANY($1))`,
		pq.Array(nonNil(hostIDs))).Scan(&c.AwaitingApproval, &c.Scheduled, &c.InProgress, &c.AwaitingReview)
	return c, err
}

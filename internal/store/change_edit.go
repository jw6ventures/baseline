package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
)

// Editable reports whether the change can still be edited: it hasn't
// started. What it runs (its plan and targets) is fixed when it is made.
func (c Change) Editable() bool {
	switch c.State {
	case ChangeDraft, ChangeSubmitted, ChangeApproved, ChangeScheduled:
		return true
	}
	return false
}

// Escalatable reports whether the change can become an Emergency change:
// it isn't one, and it hasn't ended.
func (c Change) Escalatable() bool {
	return c.Kind != KindEmergency && c.Open()
}

// ChangeEdit is an edit of a change: the fields that are set change, the
// others stay as they are.
type ChangeEdit struct {
	Title, Description, Justification, BackoutPlan, TestPlan *string

	Risk, Impact *action.Risk
	// RequiredApprovals is for Normal changes; others ignore it.
	RequiredApprovals *int
	Concurrency       *int
	StopOnFailure     *bool
	// WindowID "" runs the change without a window.
	WindowID *string
	// NotBefore zero starts the change as soon as it can.
	NotBefore   *time.Time
	OnWindowEnd *string

	// Approve is set when the editor holds approver on every host the
	// change affects (and edits from the UI): an edit that withdraws the
	// approvals counts as their approval of the edited change.
	Approve bool
}

// EditResult says what an edit did.
type EditResult struct {
	Change Change
	// Fields are the fields that changed; none means the edit changed
	// nothing and wasn't recorded.
	Fields []string
	// Withdrawn approvals no longer count: the edit changed what was
	// approved.
	Withdrawn int
	// From is the state before the edit, when the edit changed it.
	From string
}

// editField is one field an edit may change, as the audit log names it.
type editField struct {
	name string
	// reapprove fields change what approvers approved (its risk, how and
	// when it runs): changing them withdraws the approvals given.
	reapprove bool
	// schedule fields change when it runs: an approved or scheduled
	// change is planned again.
	schedule bool
}

func auditTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// EditChange edits a change that hasn't started. Every edit is recorded
// (change.edit) with each field's old and new value. An edit of its risk,
// impact, schedule or rollout withdraws the approvals given so far (but a
// Standard change's, which its model approved): the change needs approval
// again, unless e.Approve, when the editor's approval stands for the
// edited change. An approved or scheduled change whose schedule changed is
// planned again from its new start.
func (s *Store) EditChange(ctx context.Context, actor Actor, id string, e ChangeEdit) (EditResult, error) {
	var res EditResult
	err := s.tx(ctx, func(tx *sql.Tx) error {
		c, err := scanChange(tx.QueryRowContext(ctx, `SELECT `+changeCols+changeFrom+` WHERE c.id = $1 FOR UPDATE OF c`, id))
		if err != nil {
			return mapErr(err)
		}
		if !c.Editable() {
			return ErrState
		}
		n := c
		changes := map[string]any{}
		var reapprove, reschedule bool
		set := func(f editField, from, to any) {
			changes[f.name] = map[string]any{"from": from, "to": to}
			res.Fields = append(res.Fields, f.name)
			reapprove = reapprove || f.reapprove
			reschedule = reschedule || f.schedule
		}
		text := func(name string, field *string, v *string) {
			if v == nil {
				return
			}
			nv := strings.TrimSpace(*v)
			if nv != *field {
				set(editField{name: name}, *field, nv)
				*field = nv
			}
		}
		if e.Title != nil && strings.TrimSpace(*e.Title) == "" {
			return EditError("a change needs a title")
		}
		if e.Title != nil && len(strings.TrimSpace(*e.Title)) > 200 {
			return EditError("the title is longer than 200 characters")
		}
		text("title", &n.Title, e.Title)
		text("description", &n.Description, e.Description)
		text("justification", &n.Justification, e.Justification)
		text("backout_plan", &n.BackoutPlan, e.BackoutPlan)
		text("test_plan", &n.TestPlan, e.TestPlan)
		if e.Risk != nil && string(*e.Risk) != n.Risk {
			set(editField{name: "risk", reapprove: true}, n.Risk, string(*e.Risk))
			n.Risk = string(*e.Risk)
		}
		if e.Impact != nil && string(*e.Impact) != n.Impact {
			set(editField{name: "impact", reapprove: true}, n.Impact, string(*e.Impact))
			n.Impact = string(*e.Impact)
		}
		if e.RequiredApprovals != nil && n.Kind == KindNormal {
			v := min(max(*e.RequiredApprovals, 1), MaxApprovals)
			if v != n.RequiredApprovals {
				// More or fewer approvers don't change what they approve;
				// the count is checked again below.
				set(editField{name: "required_approvals"}, n.RequiredApprovals, v)
				n.RequiredApprovals = v
			}
		}
		if e.Concurrency != nil {
			v := max(*e.Concurrency, 1)
			if v != n.Concurrency {
				set(editField{name: "concurrency", reapprove: true}, n.Concurrency, v)
				n.Concurrency = v
			}
		}
		if e.StopOnFailure != nil && *e.StopOnFailure != n.StopOnFailure {
			set(editField{name: "stop_on_failure", reapprove: true}, n.StopOnFailure, *e.StopOnFailure)
			n.StopOnFailure = *e.StopOnFailure
		}
		if e.WindowID != nil && *e.WindowID != n.WindowID {
			from := n.WindowName
			to := ""
			if *e.WindowID != "" {
				if err := tx.QueryRowContext(ctx, `SELECT name FROM maintenance_window WHERE id::text = $1 AND kind = 'window'`,
					*e.WindowID).Scan(&to); err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return EditError("no such maintenance window")
					}
					return err
				}
			}
			set(editField{name: "window", reapprove: true, schedule: true}, from, to)
			n.WindowID, n.WindowName = *e.WindowID, to
		}
		if e.NotBefore != nil && !e.NotBefore.Equal(n.NotBefore) {
			set(editField{name: "not_before", reapprove: true, schedule: true}, auditTime(n.NotBefore), auditTime(*e.NotBefore))
			n.NotBefore = *e.NotBefore
		}
		if e.OnWindowEnd != nil && *e.OnWindowEnd != n.OnWindowEnd {
			if *e.OnWindowEnd != WindowCarryOver && *e.OnWindowEnd != WindowFail {
				return EditError("on_window_end is carry_over or fail")
			}
			set(editField{name: "on_window_end", reapprove: true}, n.OnWindowEnd, *e.OnWindowEnd)
			n.OnWindowEnd = *e.OnWindowEnd
		}
		if len(res.Fields) == 0 {
			res.Change = c
			return nil
		}

		state := c.State
		planned := sql.NullTime{Time: c.PlannedStart, Valid: !c.PlannedStart.IsZero()}
		plannedEnd := sql.NullTime{Time: c.PlannedEnd, Valid: !c.PlannedEnd.IsZero()}
		note := c.ScheduleNote
		if reschedule || state == ChangeDraft || state == ChangeSubmitted {
			// Until it's approved, its planned start is the one asked for.
			planned, plannedEnd, note = nullTime(n.NotBefore), sql.NullTime{}, ""
		}
		if reschedule && state == ChangeScheduled {
			state = ChangeApproved // the scheduler plans it again
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET title = $2, description = $3, justification = $4, backout_plan = $5, test_plan = $6,
			       risk = $7, impact = $8, required_approvals = $9, concurrency = $10, stop_on_failure = $11,
			       window_id = $12, not_before = $13, on_window_end = $14, planned_start = $15, planned_end = $16,
			       schedule_note = $17, state = $18, updated_at = now()
			WHERE id = $1`,
			id, n.Title, n.Description, n.Justification, n.BackoutPlan, n.TestPlan, n.Risk, n.Impact, n.RequiredApprovals,
			n.Concurrency, n.StopOnFailure, nullString(n.WindowID), nullTime(n.NotBefore), n.OnWindowEnd, planned,
			plannedEnd, note, state); err != nil {
			return mapErr(err)
		}
		details := map[string]any{"number": c.Ref(), "state": c.State, "changes": changes}

		// Approvals: a Standard change's model approved it; a draft has
		// none yet.
		if n.Kind != KindStandard && c.State != ChangeDraft {
			if reapprove {
				r, err := tx.ExecContext(ctx, `
					UPDATE change_approval SET withdrawn = true WHERE change_id = $1 AND decision = 'approve' AND NOT withdrawn`, id)
				if err != nil {
					return err
				}
				w, _ := r.RowsAffected()
				res.Withdrawn = int(w)
				if w > 0 {
					details["approvals_withdrawn"] = w
				}
			}
			if reapprove && e.Approve {
				if err := approveAs(ctx, tx, actor, id, c.RequestedBy, "approved with an edit"); err != nil {
					return err
				}
				details["approved_by_editor"] = true
			}
			to, err := settleApprovals(ctx, tx, id, state, n.RequiredApprovals)
			if err != nil {
				return err
			}
			if to != c.State {
				res.From = c.State
				details["to"] = to
			}
		} else if state != c.State {
			res.From = c.State
			details["to"] = state
		}
		if err := appendAudit(ctx, tx, actor, AuditEvent{Action: "change.edit", ObjectType: "change", ObjectID: id,
			Details: details}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	if res.Change.ID == "" {
		res.Change, err = s.GetChange(ctx, id)
	}
	return res, err
}

// approveAs records actor's approval of the change, flagged as
// self-approval when they requested it.
func approveAs(ctx context.Context, tx *sql.Tx, actor Actor, id, requester, comment string) error {
	userID := actor.userID()
	if !userID.Valid {
		return errors.New("only users approve changes")
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO change_approval (change_id, approver, decision, comment, self_approved) VALUES ($1, $2, 'approve', $3, $4)
		ON CONFLICT (change_id, approver) DO UPDATE SET decision = 'approve', comment = EXCLUDED.comment,
		    self_approved = EXCLUDED.self_approved, withdrawn = false, at = now()`,
		id, userID, comment, requester == userID.String)
	return err
}

// settleApprovals moves a submitted, approved or scheduled change to
// approved when it has the approvals it needs, and back to submitted when
// it doesn't. It returns the state the change is in.
func settleApprovals(ctx context.Context, tx *sql.Tx, id, state string, required int) (string, error) {
	switch state {
	case ChangeSubmitted, ChangeApproved, ChangeScheduled:
	default:
		return state, nil
	}
	var have int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM change_approval WHERE change_id = $1 AND decision = 'approve' AND NOT withdrawn`, id).
		Scan(&have); err != nil {
		return state, err
	}
	switch {
	case have >= required && state == ChangeSubmitted:
		_, err := tx.ExecContext(ctx, `UPDATE change SET state = 'approved', approved_at = now(), updated_at = now() WHERE id = $1`, id)
		return ChangeApproved, err
	case have < required && state != ChangeSubmitted:
		_, err := tx.ExecContext(ctx, `
			UPDATE change SET state = 'submitted', approved_at = NULL, planned_start = not_before, planned_end = NULL,
			       schedule_note = '', updated_at = now() WHERE id = $1`, id)
		return ChangeSubmitted, err
	}
	return state, nil
}

// EscalateResult says what an escalation did.
type EscalateResult struct {
	Change    Change
	Withdrawn int    // approvals withdrawn
	From      string // the state before, when it changed
}

// EscalateChange makes an open change an Emergency change: it needs one
// approver, ignores freezes, drops its maintenance window and requested
// start so it runs as soon as it is approved, and needs a
// post-implementation review once it has run. The reason is required and
// recorded (change.escalate).
//
// With approve (the escalator holds approver on every host the change
// affects, from the UI), the escalation is their approval: a change that
// hasn't started is approved and starts now, and a change in progress
// stops waiting for its window. Without it, the approvals given so far are
// withdrawn and the change waits for an approver (a draft stays a draft);
// a change in progress can only be escalated with approve.
func (s *Store) EscalateChange(ctx context.Context, actor Actor, id, reason string, approve bool) (EscalateResult, error) {
	var res EscalateResult
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return res, EditError("an escalation needs a reason")
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		c, err := scanChange(tx.QueryRowContext(ctx, `SELECT `+changeCols+changeFrom+` WHERE c.id = $1 FOR UPDATE OF c`, id))
		if err != nil {
			return mapErr(err)
		}
		if !c.Escalatable() {
			return ErrState
		}
		if c.State == ChangeInProgress && !approve {
			return ErrNeedsApprover
		}
		state := c.State
		if state == ChangeScheduled {
			state = ChangeApproved // the scheduler plans it again, at once
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE change SET kind = 'emergency', required_approvals = 1, window_id = NULL, window_ends_at = NULL,
			       not_before = NULL, planned_start = CASE WHEN state = 'in_progress' THEN planned_start END,
			       planned_end = CASE WHEN state = 'in_progress' THEN planned_end END,
			       schedule_note = '', state = $2, updated_at = now()
			WHERE id = $1`, id, state); err != nil {
			return mapErr(err)
		}
		details := map[string]any{"number": c.Ref(), "from_kind": c.Kind, "to_kind": KindEmergency, "reason": reason,
			"state": c.State}
		if c.WindowName != "" {
			details["window_removed"] = c.WindowName
		}
		if !c.NotBefore.IsZero() {
			details["not_before_removed"] = auditTime(c.NotBefore)
		}
		if c.State != ChangeDraft {
			if !approve || c.Kind == KindStandard {
				// What was approved (or pre-approved by a model) wasn't an
				// Emergency change.
				r, err := tx.ExecContext(ctx, `
					UPDATE change_approval SET withdrawn = true WHERE change_id = $1 AND decision = 'approve' AND NOT withdrawn`, id)
				if err != nil {
					return err
				}
				w, _ := r.RowsAffected()
				res.Withdrawn = int(w)
				if w > 0 {
					details["approvals_withdrawn"] = w
				}
			}
			if approve {
				if err := approveAs(ctx, tx, actor, id, c.RequestedBy, "escalated to Emergency: "+reason); err != nil {
					return err
				}
				details["approved_by_escalator"] = true
			}
			if state != ChangeInProgress {
				if state, err = settleApprovals(ctx, tx, id, state, 1); err != nil {
					return err
				}
			}
		} else if approve {
			// An approver escalating a draft submits and approves it.
			if _, err := tx.ExecContext(ctx, `
				UPDATE change SET state = 'approved', submitted_at = now(), approved_at = now() WHERE id = $1`, id); err != nil {
				return err
			}
			if err := approveAs(ctx, tx, actor, id, c.RequestedBy, "escalated to Emergency: "+reason); err != nil {
				return err
			}
			details["approved_by_escalator"] = true
			state = ChangeApproved
		}
		if state != c.State {
			res.From = c.State
			details["to"] = state
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "change.escalate", ObjectType: "change", ObjectID: id,
			Details: details})
	})
	if err != nil {
		return res, err
	}
	res.Change, err = s.GetChange(ctx, id)
	return res, err
}

// EditError refuses an edit for what it asks, not for the server's sake.
type EditError string

func (e EditError) Error() string { return string(e) }

// ErrNeedsApprover refuses an escalation of a running change by someone
// who can't approve it.
var ErrNeedsApprover = errors.New("escalating a change in progress needs the approver role on every host it affects")

// ChangeHistory is the change's audit trail, oldest first.
func (s *Store) ChangeHistory(ctx context.Context, id string) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+auditCols+auditFrom+`WHERE a.object_type = 'change' AND a.object_id = $1 ORDER BY a.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

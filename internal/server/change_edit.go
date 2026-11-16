package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Editing a change and escalating it to Emergency
// (docs/change-management.md §2.1).

type changeEditView struct {
	Change  store.Change
	Form    url.Values
	Windows []store.MaintenanceWindow
	Risks   []action.Risk
	TZ      string
	Error   string
	// CanApprove: the editor approves every host, so an edit that needs
	// approval again is approved by them.
	CanApprove bool
}

// editForm is the edit form filled from the change.
func (s *Server) editForm(c store.Change) url.Values {
	f := url.Values{}
	f.Set("title", c.Title)
	f.Set("description", c.Description)
	f.Set("justification", c.Justification)
	f.Set("backout_plan", c.BackoutPlan)
	f.Set("test_plan", c.TestPlan)
	f.Set("risk", c.Risk)
	f.Set("impact", c.Impact)
	f.Set("approvals", strconv.Itoa(c.RequiredApprovals))
	f.Set("concurrency", strconv.Itoa(c.Concurrency))
	if c.StopOnFailure {
		f.Set("stop_on_failure", "1")
	}
	f.Set("window", c.WindowID)
	f.Set("on_window_end", c.OnWindowEnd)
	if !c.NotBefore.IsZero() {
		f.Set("not_before", c.NotBefore.In(s.cfg.Location).Format("2006-01-02T15:04"))
	}
	return f
}

func (s *Server) renderChangeEdit(w http.ResponseWriter, r *http.Request, c store.Change, hosts map[string]store.Host,
	status int, f url.Values, errMsg string) {
	ws, err := s.store.ListWindows(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := changeEditView{Change: c, Form: f, Risks: action.Risks, TZ: s.cfg.Location.String(), Error: errMsg,
		CanApprove: canOnAll(principal(r).Grants, rbac.Approver, c.HostIDs, hosts)}
	for _, w := range ws {
		if w.Kind == store.WindowKindWindow && (w.Active || w.ID == c.WindowID) {
			v.Windows = append(v.Windows, w)
		}
	}
	s.pages.render(w, status, "change_edit", s.data(r, "Edit "+c.Ref(), v))
}

// loadManaged loads the change in the path for an edit or an escalation:
// the user must be allowed to manage it.
func (s *Server) loadManaged(w http.ResponseWriter, r *http.Request) (store.Change, map[string]store.Host, bool) {
	c, hosts, ok := s.loadChange(w, r)
	if !ok {
		return c, hosts, false
	}
	if !s.mayManage(r, c, hosts) {
		s.errorPage(w, r, http.StatusForbidden, "Only the requester, an approver of every host it affects or an admin can change this change.")
		return c, hosts, false
	}
	return c, hosts, true
}

func (s *Server) changeEditPage(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	if !c.Editable() {
		s.backToChange(w, r, c.ID, "error", "This change has started, so it can't be edited any more.")
		return
	}
	s.renderChangeEdit(w, r, c, hosts, http.StatusOK, s.editForm(c), "")
}

// formEdit reads the edit form into an edit of c.
func (s *Server) formEdit(f url.Values, c store.Change) (store.ChangeEdit, error) {
	str := func(k string) *string { v := f.Get(k); return &v }
	e := store.ChangeEdit{Title: str("title"), Description: str("description"), Justification: str("justification"),
		BackoutPlan: str("backout_plan"), TestPlan: str("test_plan")}
	if c.Kind != store.KindStandard {
		// A Standard change's risk is its model's.
		risk, err := action.ParseRisk(f.Get("risk"))
		if err != nil {
			return e, errors.New("pick a risk")
		}
		impact, err := action.ParseRisk(f.Get("impact"))
		if err != nil {
			return e, errors.New("pick an impact")
		}
		e.Risk, e.Impact = &risk, &impact
	}
	if c.Kind == store.KindNormal {
		n, err := strconv.Atoi(f.Get("approvals"))
		if err != nil || n < 1 || n > store.MaxApprovals {
			return e, errors.New("approvals needed is a number from 1 to 5")
		}
		e.RequiredApprovals = &n
	}
	n, err := strconv.Atoi(f.Get("concurrency"))
	if err != nil || n < 1 || n > 100 {
		return e, errors.New("how many at a time is a number from 1 to 100")
	}
	e.Concurrency = &n
	stop := f.Get("stop_on_failure") != ""
	e.StopOnFailure = &stop
	e.WindowID = str("window")
	end := store.WindowCarryOver
	if f.Get("on_window_end") == store.WindowFail {
		end = store.WindowFail
	}
	e.OnWindowEnd = &end
	var nb time.Time
	if v := strings.TrimSpace(f.Get("not_before")); v != "" {
		if nb, err = time.ParseInLocation("2006-01-02T15:04", v, s.cfg.Location); err != nil {
			return e, errors.New("the planned start isn't a date and time")
		}
	}
	e.NotBefore = &nb
	return e, nil
}

// checkEdit refuses an edit's schedule the way a new change's is refused:
// a start in the past (when it changed), a freeze, a window that doesn't
// cover the hosts.
func (s *Server) checkEdit(r *http.Request, c store.Change, e store.ChangeEdit) error {
	nb, win := c.NotBefore, c.WindowID
	if e.NotBefore != nil {
		nb = *e.NotBefore
	}
	if e.WindowID != nil {
		win = *e.WindowID
	}
	if nb.Equal(c.NotBefore) && win == c.WindowID {
		return nil
	}
	if !nb.Equal(c.NotBefore) && !nb.IsZero() && nb.Before(time.Now().Add(-time.Minute)) {
		return errors.New("the planned start is in the past; leave it empty to start once approved")
	}
	return s.changes.CheckStart(r.Context(), store.Change{Kind: c.Kind, PlannedStart: nb, WindowID: win, HostIDs: c.HostIDs},
		time.Now())
}

func (s *Server) changeEdit(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	fail := func(msg string) { s.renderChangeEdit(w, r, c, hosts, http.StatusUnprocessableEntity, r.Form, msg) }
	if !c.Editable() {
		s.backToChange(w, r, c.ID, "error", "This change has started, so it can't be edited any more.")
		return
	}
	e, err := s.formEdit(r.Form, c)
	if err == nil {
		err = s.checkEdit(r, c, e)
	}
	if err != nil {
		fail(sentence(err))
		return
	}
	e.Approve = canOnAll(principal(r).Grants, rbac.Approver, c.HostIDs, hosts)
	res, err := s.store.EditChange(r.Context(), s.actor(r), c.ID, e)
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "This change has started, so it can't be edited any more.")
		return
	case errors.As(err, new(store.EditError)):
		fail(sentence(err))
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.nudgeJobs()
	s.backToChange(w, r, c.ID, "notice", editNotice(res))
}

func editNotice(res store.EditResult) string {
	if len(res.Fields) == 0 {
		return "Nothing changed."
	}
	msg := "Change edited."
	c := res.Change
	switch {
	case res.From != "" && c.State == store.ChangeSubmitted:
		msg += " Its approval was withdrawn, so it waits for " + plural(c.RequiredApprovals-c.Approvals, "approval", "approvals") + " again."
	case res.From == store.ChangeSubmitted && c.State == store.ChangeApproved:
		msg += " It has the approvals it needs now."
	case res.Withdrawn > 0 && c.State == store.ChangeApproved:
		msg += " You approved the edited change; it stays approved."
	case res.Withdrawn > 0:
		msg += " " + plural(res.Withdrawn, "approval was", "approvals were") + " withdrawn: approvers approve the edited change."
	}
	return msg
}

func (s *Server) changeEscalate(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		s.backToChange(w, r, c.ID, "error", "Say why this change is an emergency.")
		return
	}
	approve := canOnAll(principal(r).Grants, rbac.Approver, c.HostIDs, hosts)
	res, err := s.store.EscalateChange(r.Context(), s.actor(r), c.ID, reason, approve)
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "This change can't be escalated: it has ended, or it is an Emergency change already.")
		return
	case errors.Is(err, store.ErrNeedsApprover):
		s.backToChange(w, r, c.ID, "error", "This change is running; only an approver of every host it affects can escalate it.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.nudgeJobs()
	s.backToChange(w, r, c.ID, "notice", escalateNotice(res))
}

func escalateNotice(res store.EscalateResult) string {
	msg := "Escalated to Emergency."
	switch res.Change.State {
	case store.ChangeDraft:
		msg += " It's still a draft: submit it, and one approver approves it."
	case store.ChangeSubmitted:
		msg += " It runs, ignoring windows and freezes, once one approver approves it."
	case store.ChangeApproved, store.ChangeScheduled:
		msg += " You approved it; it starts now, ignoring windows and freezes."
	case store.ChangeInProgress:
		msg += " Its jobs no longer wait for a window or a freeze."
	}
	return msg
}

// changeEvent is a line of a change's history, from its audit trail.
type changeEvent struct {
	At      time.Time
	Who     string
	What    string
	Details []string
}

var editLabels = map[string]string{
	"title": "Title", "description": "Description", "justification": "Why", "backout_plan": "Back-out plan",
	"test_plan": "Test plan", "risk": "Risk", "impact": "Impact", "required_approvals": "Approvals needed",
	"concurrency": "At a time", "stop_on_failure": "Stop at the first failure", "window": "Maintenance window",
	"not_before": "Not before", "on_window_end": "When the window closes",
}

// editOrder is the order edited fields are listed in.
var editOrder = []string{"title", "description", "justification", "backout_plan", "test_plan", "risk", "impact",
	"required_approvals", "concurrency", "stop_on_failure", "window", "not_before", "on_window_end"}

var stateLabels = map[string]string{
	store.ChangeDraft: "draft", store.ChangeSubmitted: "submitted", store.ChangeApproved: "approved",
	store.ChangeScheduled: "scheduled", store.ChangeInProgress: "in progress", store.ChangeImplemented: "implemented",
	store.ChangeFailed: "failed", store.ChangeRolledBack: "rolled back", store.ChangeReview: "in review",
	store.ChangeClosed: "closed", store.ChangeRejected: "rejected", store.ChangeCancelled: "cancelled",
}

func (s *Server) editValue(field string, v any) string {
	switch x := v.(type) {
	case nil:
		return "none"
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		switch {
		case x == "" && field == "window":
			return "none"
		case x == "" && field == "not_before":
			return "as soon as it can"
		case x == "":
			return "empty"
		case field == "not_before":
			if t, err := time.Parse(time.RFC3339, x); err == nil {
				return t.In(s.cfg.Location).Format("2006-01-02 15:04 MST")
			}
		case field == "on_window_end" && x == store.WindowFail:
			return "hosts left are skipped"
		case field == "on_window_end":
			return "hosts left wait for the next opening"
		}
		if len(x) > 120 {
			return x[:117] + "…"
		}
		return x
	}
	return "?"
}

// changeEvents turns a change's audit trail into its history.
func (s *Server) changeEvents(entries []store.AuditEntry) []changeEvent {
	var out []changeEvent
	for _, e := range entries {
		var d map[string]any
		_ = json.Unmarshal([]byte(e.Details), &d)
		str := func(k string) string { v, _ := d[k].(string); return v }
		ev := changeEvent{At: e.At, Who: e.ActorName}
		if ev.Who == "" {
			ev.Who = "the scheduler"
		}
		switch e.Action {
		case "change.create":
			ev.What = "Created"
		case "change.state":
			ev.What = "Now " + stateLabels[str("to")]
			if why := str("reason"); why != "" {
				ev.What += ": " + why
			}
		case "change.approve":
			ev.What = "Approved"
			if self, _ := d["self_approved"].(bool); self {
				ev.What += " (self-approval)"
			}
		case "change.reject":
			ev.What = "Rejected"
		case "change.cancel":
			ev.What = "Cancelled"
		case "change.close":
			ev.What = "Closed"
		case "change.window_closed":
			ev.What = "The window closed with jobs left; they were skipped"
		case "change.edit":
			ev.What = "Edited"
			changes, _ := d["changes"].(map[string]any)
			for _, f := range editOrder {
				c, ok := changes[f].(map[string]any)
				if !ok {
					continue
				}
				ev.Details = append(ev.Details, editLabels[f]+": "+s.editValue(f, c["from"])+" → "+s.editValue(f, c["to"]))
			}
			if n, _ := d["approvals_withdrawn"].(float64); n > 0 {
				ev.Details = append(ev.Details, plural(int(n), "approval", "approvals")+" withdrawn")
			}
			if ok, _ := d["approved_by_editor"].(bool); ok {
				ev.Details = append(ev.Details, "approved by the editor")
			}
			if to := str("to"); to != "" {
				ev.Details = append(ev.Details, "now "+stateLabels[to])
			}
		case "change.escalate":
			ev.What = "Escalated from " + str("from_kind") + " to Emergency: " + str("reason")
			if w := str("window_removed"); w != "" {
				ev.Details = append(ev.Details, "maintenance window "+w+" removed")
			}
			if nb := str("not_before_removed"); nb != "" {
				ev.Details = append(ev.Details, "planned start "+s.editValue("not_before", nb)+" removed")
			}
			if n, _ := d["approvals_withdrawn"].(float64); n > 0 {
				ev.Details = append(ev.Details, plural(int(n), "approval", "approvals")+" withdrawn")
			}
			if ok, _ := d["approved_by_escalator"].(bool); ok {
				ev.Details = append(ev.Details, "approved by the escalator")
			}
			if to := str("to"); to != "" {
				ev.Details = append(ev.Details, "now "+stateLabels[to])
			}
		default:
			ev.What = e.Action
		}
		out = append(out, ev)
	}
	return out
}

// changeEditRequest is the body of PATCH /api/v1/changes/{id}: the fields
// to change. Like the rest of the API, an edit never approves: one that
// withdraws approvals leaves the change waiting for approvers.
type changeEditRequest struct {
	Title             *string `json:"title"`
	Description       *string `json:"description"`
	Justification     *string `json:"justification"`
	BackoutPlan       *string `json:"backout_plan"`
	TestPlan          *string `json:"test_plan"`
	Risk              *string `json:"risk"`
	Impact            *string `json:"impact"`
	RequiredApprovals *int    `json:"required_approvals"`
	Concurrency       *int    `json:"concurrency"`
	StopOnFailure     *bool   `json:"stop_on_failure"`
	Window            *string `json:"window"` // "" for none
	// NotBefore holds the change until then; null starts it as soon as it
	// can. Leave it out to keep it.
	NotBefore   json.RawMessage `json:"not_before"`
	OnWindowEnd *string         `json:"on_window_end"`
}

func (s *Server) apiChangeEdit(w http.ResponseWriter, r *http.Request) {
	c, hosts, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req changeEditRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if !s.mayManage(r, c, hosts) {
		apiError(w, http.StatusForbidden, "only the requester, an approver on its hosts or an admin edits a change")
		return
	}
	if !c.Editable() {
		apiError(w, http.StatusConflict, "only a change that hasn't started can be edited; this one is "+c.State)
		return
	}
	e := store.ChangeEdit{Title: req.Title, Description: req.Description, Justification: req.Justification,
		BackoutPlan: req.BackoutPlan, TestPlan: req.TestPlan, Concurrency: req.Concurrency,
		StopOnFailure: req.StopOnFailure, WindowID: req.Window, OnWindowEnd: req.OnWindowEnd}
	for _, x := range []struct {
		name string
		in   *string
		out  **action.Risk
	}{{"risk", req.Risk, &e.Risk}, {"impact", req.Impact, &e.Impact}} {
		if x.in == nil {
			continue
		}
		if c.Kind == store.KindStandard {
			s.respond(w, r, nil, bad("a Standard change's %s is its model's", x.name))
			return
		}
		rk, err := action.ParseRisk(*x.in)
		if err != nil {
			s.respond(w, r, nil, bad("%s must be low, medium or high", x.name))
			return
		}
		*x.out = &rk
	}
	if n := req.RequiredApprovals; n != nil {
		if c.Kind != store.KindNormal {
			s.respond(w, r, nil, bad("only a Normal change sets required_approvals"))
			return
		}
		if *n < 1 || *n > store.MaxApprovals {
			s.respond(w, r, nil, bad("required_approvals must be 1 to %d", store.MaxApprovals))
			return
		}
	}
	e.RequiredApprovals = req.RequiredApprovals
	if n := req.Concurrency; n != nil && (*n < 1 || *n > 100) {
		s.respond(w, r, nil, bad("concurrency must be 1 to 100"))
		return
	}
	if len(req.NotBefore) > 0 {
		var t *time.Time
		if err := json.Unmarshal(req.NotBefore, &t); err != nil {
			s.respond(w, r, nil, bad("not_before must be an RFC 3339 time or null"))
			return
		}
		nb := time.Time{}
		if t != nil {
			nb = *t
		}
		e.NotBefore = &nb
	}
	if err := s.checkEdit(r, c, e); err != nil {
		s.respond(w, r, nil, bad("%s", err.Error()))
		return
	}
	_, err = s.store.EditChange(r.Context(), s.actor(r), c.ID, e)
	switch {
	case errors.Is(err, store.ErrState):
		apiError(w, http.StatusConflict, "only a change that hasn't started can be edited")
	case errors.As(err, new(store.EditError)):
		s.respond(w, r, nil, bad("%s", err.Error()))
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.nudgeJobs()
		s.respondChange(w, r, c.ID)
	}
}

// apiChangeEscalate makes a change an Emergency change. The API never
// approves, so the approvals given so far are withdrawn and the change waits
// for one approver; a change in progress is escalated from the UI.
func (s *Server) apiChangeEscalate(w http.ResponseWriter, r *http.Request) {
	c, hosts, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if !s.mayManage(r, c, hosts) {
		apiError(w, http.StatusForbidden, "only the requester, an approver on its hosts or an admin escalates a change")
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		s.respond(w, r, nil, bad("reason: say why the change is an emergency"))
		return
	}
	_, err = s.store.EscalateChange(r.Context(), s.actor(r), c.ID, req.Reason, false)
	switch {
	case errors.Is(err, store.ErrState):
		apiError(w, http.StatusConflict, "this change can't be escalated: it has ended or is an Emergency change already")
	case errors.Is(err, store.ErrNeedsApprover):
		apiError(w, http.StatusConflict, "a change in progress is escalated from the UI, by an approver of every host it affects")
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.nudgeJobs()
		s.respondChange(w, r, c.ID)
	}
}

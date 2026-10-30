package server

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Workflows (docs/data-model.md §9), under Settings. Admins edit a draft of
// a workflow and publish it as a new version; items stay on the version they
// started on.

var statusKeyRe = typeKeyRe

type workflowsView struct {
	Workflows []store.Workflow
	Name      string // the new workflow form, as typed
	From      string
	Notice    string
	Error     string
}

func (s *Server) workflowsPage(w http.ResponseWriter, r *http.Request, v workflowsView, status int) {
	var err error
	if v.Workflows, err = s.store.ListWorkflows(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.From == "" {
		for _, f := range v.Workflows {
			if f.Default {
				v.From = f.ID
			}
		}
	}
	s.pages.render(w, status, "workflows", s.data(r, "Workflows", v))
}

func (s *Server) workflows(w http.ResponseWriter, r *http.Request) {
	s.workflowsPage(w, r, workflowsView{Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}, http.StatusOK)
}

func (s *Server) workflowURL(id string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u := "/settings/workflows/" + id
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return s.url(u)
}

func (s *Server) workflowCreate(w http.ResponseWriter, r *http.Request) {
	name, from := strings.TrimSpace(r.FormValue("name")), r.FormValue("from")
	v := workflowsView{Name: name, From: from}
	if name == "" {
		v.Error = "Enter a name."
		s.workflowsPage(w, r, v, http.StatusBadRequest)
		return
	}
	id, err := s.store.CreateWorkflow(r.Context(), s.actor(r), name, strings.TrimSpace(r.FormValue("description")), from)
	switch {
	case errors.Is(err, store.ErrConflict):
		v.Error = "A workflow called " + name + " already exists."
	case errors.Is(err, store.ErrNoPublished), errors.Is(err, store.ErrNotFound):
		v.Error = "Copy a workflow that has a published version, or start empty."
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	if v.Error != "" {
		s.workflowsPage(w, r, v, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.workflowURL(id, "notice", "Created a draft. Publish it when it's ready."), http.StatusSeeOther)
}

// loadWorkflow fetches the workflow named in the path.
func (s *Server) loadWorkflow(w http.ResponseWriter, r *http.Request) (store.Workflow, bool) {
	f, err := s.store.GetWorkflow(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such workflow.")
		return f, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return f, false
	}
	return f, true
}

type workflowView struct {
	Workflow    store.Workflow
	Versions    []store.WorkflowVersion
	Version     store.WorkflowVersion // the one shown
	Problems    []string              // what stops the draft from being published
	Categories  []string
	Projects    []workflowUse
	NextVersion int
	Diagram     wfDiagram
	Notice      string
	Error       string
}

// workflowUse is a project ticket type that uses a workflow.
type workflowUse struct {
	ProjectKey string
	TypeName   string
}

func (s *Server) workflowPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	v := workflowView{Workflow: f, Categories: store.StatusCategories, Notice: q.Get("notice"), Error: q.Get("error")}
	var err error
	if v.Versions, err = s.store.WorkflowVersions(ctx, f.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, x := range v.Versions {
		v.NextVersion = max(v.NextVersion, x.Version+1)
	}
	show := q.Get("v")
	if !slices.ContainsFunc(v.Versions, func(x store.WorkflowVersion) bool { return x.ID == show }) {
		show = f.DraftID
		if show == "" {
			show = f.LatestID
		}
		if show == "" && len(v.Versions) > 0 {
			show = v.Versions[0].ID
		}
	}
	if show != "" {
		if v.Version, err = s.store.GetWorkflowVersion(ctx, show); err != nil {
			s.serverError(w, r, err)
			return
		}
		if v.Version.Draft() {
			v.Problems = store.CheckVersion(v.Version)
		}
		v.Diagram = diagramOf(v.Version)
	}
	projects, err := s.store.ListProjects(ctx, true)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, p := range projects {
		full, err := s.store.GetProject(ctx, p.Key)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, t := range full.Types {
			if t.WorkflowID == f.ID {
				v.Projects = append(v.Projects, workflowUse{ProjectKey: p.Key, TypeName: t.Name})
			}
		}
	}
	s.pages.render(w, http.StatusOK, "workflow", s.data(r, "Workflow "+f.Name, v))
}

func (s *Server) workflowUpdate(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, s.workflowURL(f.ID, "error", "Enter a name."), http.StatusSeeOther)
		return
	}
	err := s.store.UpdateWorkflow(r.Context(), s.actor(r), f.ID, name, strings.TrimSpace(r.FormValue("description")),
		r.FormValue("default") == "1")
	switch {
	case errors.Is(err, store.ErrConflict):
		http.Redirect(w, r, s.workflowURL(f.ID, "error", "A workflow called "+name+" already exists."), http.StatusSeeOther)
	case errors.Is(err, store.ErrNoPublished):
		http.Redirect(w, r, s.workflowURL(f.ID, "error", "Publish a version before making this the default."), http.StatusSeeOther)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.workflowURL(f.ID, "notice", "Saved."), http.StatusSeeOther)
	}
}

func (s *Server) workflowDelete(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	err := s.store.DeleteWorkflow(r.Context(), s.actor(r), f.ID)
	switch {
	case errors.Is(err, store.ErrInUse):
		http.Redirect(w, r, s.workflowURL(f.ID, "error",
			"Only a workflow that isn't the default, that no project uses and that no item is on can be deleted."), http.StatusSeeOther)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/workflows?notice="+url.QueryEscape("Deleted "+f.Name+".")), http.StatusSeeOther)
	}
}

// workflowEdit opens the workflow's draft, creating it from the newest
// published version.
func (s *Server) workflowEdit(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	id, err := s.store.EditWorkflow(r.Context(), s.actor(r), f.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.workflowURL(f.ID, "v", id), http.StatusSeeOther)
}

// draftOp runs fn on the workflow's draft and goes back to it with fn's
// message, or with what went wrong.
func (s *Server) draftOp(fn func(r *http.Request, draft string) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, ok := s.loadWorkflow(w, r)
		if !ok {
			return
		}
		back := func(kind, msg string) {
			http.Redirect(w, r, s.workflowURL(f.ID, kind, msg)+backAnchor(r), http.StatusSeeOther)
		}
		if f.DraftID == "" {
			back("error", "There's no draft to change: edit the workflow first.")
			return
		}
		msg, err := fn(r, f.DraftID)
		var bad errBadInput
		var wfErr *store.WorkflowError
		switch {
		case errors.As(err, &bad):
			back("error", string(bad))
		case errors.As(err, &wfErr):
			back("error", wfErr.Error())
		case errors.Is(err, store.ErrNotDraft):
			back("error", "That version is published: edit the workflow to get a draft.")
		case errors.Is(err, store.ErrConflict):
			back("error", "That already exists in this draft.")
		case errors.Is(err, store.ErrNotFound):
			back("error", "That's no longer in this draft.")
		case err != nil:
			s.serverError(w, r, err)
		default:
			back("notice", msg)
		}
	}
}

func (s *Server) workflowPublish(r *http.Request, draft string) (string, error) {
	return "Published. New items start on this version.", s.store.PublishDraft(r.Context(), s.actor(r), draft)
}

func (s *Server) workflowDiscard(r *http.Request, draft string) (string, error) {
	return "Discarded the draft.", s.store.DiscardDraft(r.Context(), s.actor(r), draft)
}

// statusSave adds a status to the draft, or changes the one in the path.
func (s *Server) statusSave(r *http.Request, draft string) (string, error) {
	in := store.WfStatus{Key: strings.TrimSpace(r.FormValue("key")), Name: strings.TrimSpace(r.FormValue("name")),
		Category: r.FormValue("category"), Initial: r.FormValue("initial") == "1"}
	in.Position, _ = strconv.Atoi(r.FormValue("position"))
	x, errX := strconv.ParseFloat(r.FormValue("x"), 64)
	y, errY := strconv.ParseFloat(r.FormValue("y"), 64)
	if errX == nil && errY == nil && !math.IsInf(x+y, 0) && !math.IsNaN(x+y) {
		in.X, in.Y = &x, &y
	}
	id := r.PathValue("sid")
	switch {
	case id == "" && !statusKeyRe.MatchString(in.Key):
		return "", errBadInput("A status key is lower-case letters, digits and underscores, starting with a letter, e.g. in_review.")
	case in.Name == "":
		return "", errBadInput("Enter a status name.")
	case !slices.Contains(store.StatusCategories, in.Category):
		return "", errBadInput("Pick a category.")
	case in.Initial && in.Category == store.StatusDone:
		return "", errBadInput("New items can't start in a Done status.")
	}
	_, err := s.store.SaveStatus(r.Context(), s.actor(r), draft, id, in)
	return "Saved " + in.Name + ".", err
}

func (s *Server) statusDelete(r *http.Request, draft string) (string, error) {
	return "Deleted the status and its transitions.", s.store.DeleteStatus(r.Context(), s.actor(r), draft, r.PathValue("sid"))
}

func (s *Server) transitionDelete(r *http.Request, draft string) (string, error) {
	return "Deleted the transition.", s.store.DeleteTransition(r.Context(), s.actor(r), draft, r.PathValue("tid"))
}

type transitionFormView struct {
	Workflow     store.Workflow
	Version      store.WorkflowVersion
	Transition   store.WfTransition
	New          bool
	Roles        []rbac.Role
	Fields       []string // what field_required can name
	Validators   []string
	AssignValues []string
	Priorities   []string
	ScreenFields []string
	Error        string
}

func (v transitionFormView) HasCondition(typ, role string) bool {
	return slices.Contains(v.Transition.Conditions, store.WfCondition{Type: typ, Role: role})
}

func (v transitionFormView) HasValidator(typ, field string) bool {
	return slices.Contains(v.Transition.Validators, store.Validator{Type: typ, Field: field})
}

// PostValue is the value of the transition's post-function of a type, or "".
func (v transitionFormView) PostValue(typ string) string {
	for _, p := range v.Transition.PostFunctions {
		if p.Type == typ {
			return p.Value
		}
	}
	return ""
}

func (s *Server) transitionForm(w http.ResponseWriter, r *http.Request, f store.Workflow, v transitionFormView, status int) {
	var err error
	if v.Version, err = s.store.GetWorkflowVersion(r.Context(), f.DraftID); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Workflow, v.Roles = f, rbac.Roles
	v.Fields, v.AssignValues, v.Priorities, v.ScreenFields = store.RequirableFields, store.AssignTargets, store.Priorities, store.ScreenFields
	v.Validators = []string{"linked_change", "linked_ci", "children_done", "comment_required"}
	title := "New transition"
	if !v.New {
		title = "Edit transition " + v.Transition.Name
	}
	s.pages.render(w, status, "workflow_transition", s.data(r, title, v))
}

// transitionPage shows the form for a new transition or one in the draft.
func (s *Server) transitionPage(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	if f.DraftID == "" {
		http.Redirect(w, r, s.workflowURL(f.ID, "error", "There's no draft to change: edit the workflow first."), http.StatusSeeOther)
		return
	}
	v := transitionFormView{New: r.PathValue("tid") == ""}
	if !v.New {
		draft, err := s.store.GetWorkflowVersion(r.Context(), f.DraftID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		i := slices.IndexFunc(draft.Transitions, func(t store.WfTransition) bool { return t.ID == r.PathValue("tid") })
		if i < 0 {
			s.errorPage(w, r, http.StatusNotFound, "No such transition in the draft.")
			return
		}
		v.Transition = draft.Transitions[i]
	} else {
		v.Transition.FromID, v.Transition.ToID = r.URL.Query().Get("from"), r.URL.Query().Get("to")
	}
	s.transitionForm(w, r, f, v, http.StatusOK)
}

// transitionInput reads the transition form.
func transitionInput(r *http.Request) (store.WfTransition, error) {
	r.ParseForm()
	t := store.WfTransition{Name: strings.TrimSpace(r.FormValue("name")), FromID: r.FormValue("from"), ToID: r.FormValue("to")}
	t.Position, _ = strconv.Atoi(r.FormValue("position"))
	for _, role := range r.Form["role"] {
		if _, err := rbac.ParseRole(role); err == nil {
			t.Conditions = append(t.Conditions, store.WfCondition{Type: "role", Role: role})
		}
	}
	for _, c := range []string{"assignee", "reporter"} {
		if r.FormValue("cond_"+c) == "1" {
			t.Conditions = append(t.Conditions, store.WfCondition{Type: c})
		}
	}
	for _, field := range r.Form["required"] {
		if slices.Contains(store.RequirableFields, field) {
			t.Validators = append(t.Validators, store.Validator{Type: "field_required", Field: field})
		}
	}
	for _, v := range r.Form["validator"] {
		if slices.Contains(store.ValidatorTypes, v) && v != "field_required" {
			t.Validators = append(t.Validators, store.Validator{Type: v})
		}
	}
	if a := r.FormValue("assign"); slices.Contains(store.AssignTargets, a) {
		t.PostFunctions = append(t.PostFunctions, store.PostFunction{Type: "assign", Value: a})
	}
	if p := r.FormValue("set_priority"); slices.Contains(store.Priorities, p) {
		t.PostFunctions = append(t.PostFunctions, store.PostFunction{Type: "set_priority", Value: p})
	}
	for _, field := range r.Form["screen"] {
		if slices.Contains(store.ScreenFields, field) {
			t.Screen = append(t.Screen, field)
		}
	}
	switch {
	case t.Name == "":
		return t, errBadInput("Enter a name, e.g. Start progress.")
	case t.ToID == "":
		return t, errBadInput("Pick the status it leads to.")
	case t.FromID == t.ToID:
		return t, errBadInput("A transition leads to another status.")
	}
	return t, nil
}

func (s *Server) transitionSave(w http.ResponseWriter, r *http.Request) {
	f, ok := s.loadWorkflow(w, r)
	if !ok {
		return
	}
	if f.DraftID == "" {
		http.Redirect(w, r, s.workflowURL(f.ID, "error", "There's no draft to change: edit the workflow first."), http.StatusSeeOther)
		return
	}
	id := r.PathValue("tid")
	t, err := transitionInput(r)
	if err == nil {
		_, err = s.store.SaveTransition(r.Context(), s.actor(r), f.DraftID, id, t)
		switch {
		case errors.Is(err, store.ErrNotFound):
			err = errBadInput("Pick statuses of this draft.")
		case errors.Is(err, store.ErrConflict):
			err = errBadInput("A transition leads to another status.")
		case errors.Is(err, store.ErrNotDraft):
			err = errBadInput("The draft was just published: edit the workflow again.")
		}
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		t.ID = id
		s.transitionForm(w, r, f, transitionFormView{Transition: t, New: id == "", Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.workflowURL(f.ID, "notice", "Saved "+t.Name+".")+backAnchor(r), http.StatusSeeOther)
}

// backAnchor brings a change made on the diagram back to the diagram.
func backAnchor(r *http.Request) string {
	if r.FormValue("back") == "diagram" {
		return "#diagram"
	}
	return ""
}

// Words for a transition's rules, in the editor.

func conditionText(c store.WfCondition) string {
	switch c.Type {
	case "role":
		return "role " + c.Role
	case "assignee":
		return "the assignee"
	case "reporter":
		return "the reporter"
	}
	return c.Type
}

func validatorText(v store.Validator) string {
	switch v.Type {
	case "field_required":
		return v.Field + " set"
	case "linked_change":
		return "a linked change"
	case "linked_ci":
		return "a linked CI"
	case "children_done":
		return "child items done"
	case "comment_required":
		return "a comment"
	}
	return v.Type
}

func postFunctionText(p store.PostFunction) string {
	switch {
	case p.Type == "assign" && p.Value == "actor":
		return "assign to whoever runs it"
	case p.Type == "assign" && p.Value == "reporter":
		return "assign to the reporter"
	case p.Type == "assign":
		return "unassign"
	case p.Type == "set_priority":
		return "priority " + p.Value
	}
	return p.Type
}

// ruleTexts describes a transition's conditions, validators or
// post-functions, joined.
func ruleTexts(rules any) string {
	var out []string
	switch x := rules.(type) {
	case []store.WfCondition:
		for _, c := range x {
			out = append(out, conditionText(c))
		}
	case []store.Validator:
		for _, v := range x {
			out = append(out, validatorText(v))
		}
	case []store.PostFunction:
		for _, p := range x {
			out = append(out, postFunctionText(p))
		}
	case []string:
		out = x
	}
	return strings.Join(out, ", ")
}

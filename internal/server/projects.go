package server

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Projects and ticket types (docs/data-model.md §8). Everyone with a role
// sees projects; admins set them up.

var (
	projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)
	typeKeyRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

type projectListView struct {
	CanEdit bool
	Notice  string
	List    *listView
}

func (s *Server) projectList(w http.ResponseWriter, r *http.Request) {
	l, ok := s.buildList(w, r, "project")
	if !ok {
		return
	}
	v := projectListView{CanEdit: principal(r).Grants.Has(rbac.Admin), Notice: r.URL.Query().Get("notice"), List: l}
	s.renderList(w, r, "projects", "Projects", v, l)
}

// loadProject fetches the project named in the path.
func (s *Server) loadProject(w http.ResponseWriter, r *http.Request) (store.Project, bool) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("key"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such project.")
		return p, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return p, false
	}
	return p, true
}

type projectView struct {
	Project store.Project
	Items   []store.WorkItem
	CanEdit bool
	Notice  string
}

func (s *Server) projectPage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProject(w, r)
	if !ok {
		return
	}
	v := projectView{Project: p, CanEdit: principal(r).Grants.Has(rbac.Admin), Notice: r.URL.Query().Get("notice")}
	var err error
	if v.Items, err = s.store.ListWorkItems(r.Context(), store.WorkItemFilter{ProjectID: p.ID, Limit: 50}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "project", s.data(r, p.Key+" "+p.Name, v))
}

type projectFormView struct {
	Project   store.Project
	New       bool
	Types     []store.TicketType
	Workflows []store.Workflow // those with a published version
	Labels    projectLabels
	Groups    []store.HostGroup
	Kinds     []string
	Error     string
}

func (s *Server) projectForm(w http.ResponseWriter, r *http.Request, v projectFormView, status int) {
	var err error
	if v.Types, err = s.store.ListTicketTypes(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Groups, err = s.store.ListHostGroups(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	workflows, err := s.store.ListWorkflows(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, f := range workflows {
		if f.Latest > 0 {
			v.Workflows = append(v.Workflows, f)
		}
	}
	if v.Labels, err = s.projectLabels(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Kinds = store.ProjectKinds
	title := "New project"
	if !v.New {
		title = "Edit " + v.Project.Key
	}
	s.pages.render(w, status, "project_form", s.data(r, title, v))
}

func (s *Server) projectNew(w http.ResponseWriter, r *http.Request) {
	s.projectForm(w, r, projectFormView{New: true, Project: store.Project{Kind: "service_desk"}}, http.StatusOK)
}

func (s *Server) projectEdit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProject(w, r)
	if !ok {
		return
	}
	s.projectForm(w, r, projectFormView{Project: p}, http.StatusOK)
}

// projectInput reads the project form. echo is the form as typed, for
// showing it again.
func projectInput(r *http.Request) (store.ProjectInput, store.Project, error) {
	in := store.ProjectInput{
		Key: strings.ToUpper(strings.TrimSpace(r.FormValue("key"))), Name: strings.TrimSpace(r.FormValue("name")),
		Kind: r.FormValue("kind"), Description: strings.TrimSpace(r.FormValue("description")),
		HostGroupID: r.FormValue("host_group"), Archived: r.FormValue("archived") == "1",
		DefaultType: r.FormValue("default_type"), Workflows: map[string]string{},
		CategoryID: r.FormValue("category"),
	}
	for _, t := range r.Form["tags"] {
		if t != "" && !slices.Contains(in.TagIDs, t) {
			in.TagIDs = append(in.TagIDs, t)
		}
	}
	for _, t := range r.Form["types"] {
		if t != "" && !slices.Contains(in.TypeIDs, t) {
			in.TypeIDs = append(in.TypeIDs, t)
			if f := r.FormValue("workflow_" + t); f != "" {
				in.Workflows[t] = f
			}
		}
	}
	echo := store.Project{Key: in.Key, Name: in.Name, Kind: in.Kind, Description: in.Description,
		HostGroupID: in.HostGroupID, Archived: in.Archived, CategoryID: in.CategoryID}
	for _, t := range in.TagIDs {
		echo.Tags = append(echo.Tags, store.ProjectTag{ID: t})
	}
	for _, t := range in.TypeIDs {
		echo.Types = append(echo.Types, store.ProjectType{TicketType: store.TicketType{ID: t}, Default: t == in.DefaultType,
			WorkflowID: in.Workflows[t]})
	}
	switch {
	case in.Name == "":
		return in, echo, errBadInput("Enter a name.")
	case !slices.Contains(store.ProjectKinds, in.Kind):
		return in, echo, errBadInput("Pick a kind.")
	case len(in.TypeIDs) == 0:
		return in, echo, errBadInput("Pick at least one ticket type.")
	}
	return in, echo, nil
}

func (s *Server) projectCreate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	in, echo, err := projectInput(r)
	if err == nil && !projectKeyRe.MatchString(in.Key) {
		err = errBadInput("The key is 2 to 10 capital letters or digits, starting with a letter, e.g. OPS.")
	}
	if err == nil {
		_, err = s.store.CreateProject(r.Context(), s.actor(r), in)
		if errors.Is(err, store.ErrConflict) {
			err = errBadInput("A project with key " + in.Key + " already exists.")
		}
		err = projectErr(err)
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		s.projectForm(w, r, projectFormView{New: true, Project: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/projects/"+in.Key+"?notice="+url.QueryEscape("Created.")), http.StatusSeeOther)
}

// projectErr words the store's refusals of a project form.
func projectErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errBadInput("That host group, ticket type, workflow, category or tag no longer exists.")
	case errors.Is(err, store.ErrNoPublished):
		return errBadInput("Pick workflows that have a published version.")
	}
	return err
}

func (s *Server) projectUpdate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadProject(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	in, echo, err := projectInput(r)
	echo.ID, echo.Key = p.ID, p.Key
	if err == nil {
		err = projectErr(s.store.UpdateProject(r.Context(), s.actor(r), p.ID, in))
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		s.projectForm(w, r, projectFormView{Project: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/projects/"+p.Key+"?notice="+url.QueryEscape("Saved.")), http.StatusSeeOther)
}

// Ticket types (Settings) -------------------------------------------------------------

type ticketTypesView struct {
	Types     []store.TicketType
	Edit      store.TicketType // the form: empty ID for a new type
	BaseKinds []string
	Notice    string
	Error     string
}

func (s *Server) ticketTypesPage(w http.ResponseWriter, r *http.Request, v ticketTypesView, status int) {
	var err error
	if v.Types, err = s.store.ListTicketTypes(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.BaseKinds = store.BaseKinds
	s.pages.render(w, status, "ticket_types", s.data(r, "Ticket types", v))
}

func (s *Server) ticketTypes(w http.ResponseWriter, r *http.Request) {
	v := ticketTypesView{Edit: store.TicketType{BaseKind: "generic"}, Notice: r.URL.Query().Get("notice")}
	if id := r.URL.Query().Get("edit"); id != "" {
		t, err := s.store.GetTicketType(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		if err == nil {
			v.Edit = t
		}
	}
	s.ticketTypesPage(w, r, v, http.StatusOK)
}

func (s *Server) ticketTypeSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in := store.TicketType{ID: id, Key: strings.TrimSpace(r.FormValue("key")), Name: strings.TrimSpace(r.FormValue("name")),
		Icon: strings.TrimSpace(r.FormValue("icon")), Description: strings.TrimSpace(r.FormValue("description")),
		BaseKind: r.FormValue("base_kind")}
	var msg string
	switch {
	case id == "" && !typeKeyRe.MatchString(in.Key):
		msg = "The key is lower-case letters, digits and underscores, starting with a letter, e.g. change_request."
	case in.Name == "":
		msg = "Enter a name."
	case !slices.Contains(store.BaseKinds, in.BaseKind):
		msg = "Pick what kind of ticket it is."
	}
	if msg == "" {
		_, err := s.store.SaveTicketType(r.Context(), s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrConflict):
			msg = "A ticket type with key " + in.Key + " already exists."
		case errors.Is(err, store.ErrNotFound):
			s.errorPage(w, r, http.StatusNotFound, "No such ticket type.")
			return
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		s.ticketTypesPage(w, r, ticketTypesView{Edit: in, Error: msg}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/ticket-types?notice="+url.QueryEscape("Saved "+in.Name+".")), http.StatusSeeOther)
}

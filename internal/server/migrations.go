package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/store"
)

// Workflow migration (docs/data-model.md §12), under Settings: moving work
// items off a workflow version, or to another project or ticket type. An
// admin drafts a migration, maps statuses, picks items in the list engine
// and runs it; a background runner moves the items.

func (s *Server) migrationRoutes(mux *http.ServeMux) {
	mux.Handle("GET /settings/migrations", s.page(adminOnly, s.migrations))
	mux.Handle("POST /settings/migrations", s.page(adminOnly, s.migrationCreate))
	mux.Handle("GET /settings/migrations/{id}", s.page(adminOnly, s.migrationPage))
	mux.Handle("POST /settings/migrations/{id}", s.page(adminOnly, s.migrationSave))
	mux.Handle("POST /settings/migrations/{id}/select", s.page(adminOnly, s.migrationSelect))
	mux.Handle("POST /settings/migrations/{id}/select-all", s.page(adminOnly, s.migrationSelectAll))
	mux.Handle("POST /settings/migrations/{id}/start", s.page(adminOnly, s.migrationStart))
	mux.Handle("POST /settings/migrations/{id}/delete", s.page(adminOnly, s.migrationDelete))
}

// migrationBatch is how many items the runner moves per transaction.
const migrationBatch = 100

// RunMigrations starts the runner that moves the items of started
// migrations, in the background until ctx ends. It picks up migrations a
// restart interrupted. Without it (tests), starting a migration runs it to
// the end before the request returns.
func (s *Server) RunMigrations(ctx context.Context) {
	s.migrate = make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			s.runMigrations(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-s.migrate:
			}
		}
	}()
}

func (s *Server) runMigrations(ctx context.Context) {
	ids, err := s.store.RunningMigrations(ctx)
	if err != nil {
		s.log.Log("Server", "migrations", jw6_utils.Error, err.Error())
		return
	}
	for _, id := range ids {
		if err := s.runMigration(ctx, id); err != nil {
			s.log.Log("Server", "migrations", jw6_utils.Error, err.Error())
		}
	}
}

// runMigration moves a migration's items batch by batch until it is over,
// and marks it failed if a batch fails.
func (s *Server) runMigration(ctx context.Context, id string) error {
	for ctx.Err() == nil {
		over, err := s.store.MigrateBatch(ctx, id, migrationBatch)
		if err != nil {
			if ctx.Err() != nil {
				return nil // the next start picks it up
			}
			if ferr := s.store.FailMigration(ctx, id, err.Error()); ferr != nil {
				return ferr
			}
			return fmt.Errorf("migration %s: %w", id, err)
		}
		if over {
			return nil
		}
	}
	return nil
}

// The list of migrations, and the forms that start one ---------------------------

type migrationsView struct {
	Migrations []store.WfMigration
	Sources    []sourceVersion // versions items can be moved off
	Workflows  []store.Workflow
	Projects   []store.Project
	Types      []store.TicketType
	// The forms, as typed or as a link filled them in.
	FromVersion string
	ToWorkflow  string
	FromProject string
	FromType    string
	ToProject   string
	ToType      string
	Ref         string // one item to move, from its page
	Notice      string
	Error       string
}

// sourceVersion is a published version with items on it.
type sourceVersion struct {
	ID       string
	Workflow store.Workflow
	Version  int
	Items    int
}

func (v migrationsView) Label(id string) string {
	for _, x := range v.Sources {
		if x.ID == id {
			return fmt.Sprintf("%s v%d", x.Workflow.Name, x.Version)
		}
	}
	return ""
}

func (s *Server) migrationsPage(w http.ResponseWriter, r *http.Request, v migrationsView, status int) {
	ctx := r.Context()
	var err error
	if v.Migrations, err = s.store.ListMigrations(ctx, 100); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Workflows, err = s.store.ListWorkflows(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, f := range v.Workflows {
		versions, err := s.store.WorkflowVersions(ctx, f.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, x := range versions {
			if x.State == store.VersionPublished && x.Items > 0 {
				v.Sources = append(v.Sources, sourceVersion{ID: x.ID, Workflow: f, Version: x.Version, Items: x.Items})
			}
		}
	}
	if v.Projects, err = s.store.ListProjects(ctx, false); err != nil {
		s.serverError(w, r, err)
		return
	}
	for i, p := range v.Projects {
		if v.Projects[i], err = s.store.GetProject(ctx, p.Key); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if v.Types, err = s.store.ListTicketTypes(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	// A version link suggests its own workflow as the target.
	if v.ToWorkflow == "" {
		for _, x := range v.Sources {
			if x.ID == v.FromVersion {
				v.ToWorkflow = x.Workflow.ID
			}
		}
	}
	s.pages.render(w, status, "migrations", s.data(r, "Migrations", v))
}

func (s *Server) migrations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.migrationsPage(w, r, migrationsView{FromVersion: q.Get("from_version"), FromProject: q.Get("project"),
		FromType: q.Get("type"), ToProject: q.Get("project"), Ref: q.Get("ref"),
		Notice: q.Get("notice"), Error: q.Get("error")}, http.StatusOK)
}

func (s *Server) migrationCreate(w http.ResponseWriter, r *http.Request) {
	in := store.WfMigrationInput{Kind: r.FormValue("kind"), FromVersionID: r.FormValue("from_version"),
		ToWorkflowID: r.FormValue("to_workflow"), FromProjectID: r.FormValue("from_project"), FromTypeID: r.FormValue("from_type"),
		ToProjectID: r.FormValue("to_project"), ToTypeID: r.FormValue("to_type")}
	v := migrationsView{FromVersion: in.FromVersionID, ToWorkflow: in.ToWorkflowID, FromProject: in.FromProjectID,
		FromType: in.FromTypeID, ToProject: in.ToProjectID, ToType: in.ToTypeID, Ref: strings.TrimSpace(r.FormValue("ref"))}
	if v.Ref != "" {
		// From an item's page: the selection starts as that item.
		in.Query = list.Query{Groups: [][]list.Cond{{cond("ref", list.Eq, strings.ToUpper(v.Ref))}}}.Encode()
	}
	id, err := s.store.CreateMigration(r.Context(), s.actor(r), in)
	switch {
	case errors.Is(err, store.ErrSameTarget):
		v.Error = "Those items are already there: pick another target."
	case errors.Is(err, store.ErrNoPublished):
		v.Error = "The target workflow has no published version yet."
	case errors.Is(err, store.ErrTypeNotOffered):
		v.Error = "The target project doesn't offer that ticket type."
	case errors.Is(err, store.ErrArchived):
		v.Error = "The target project is archived."
	case errors.Is(err, store.ErrNotFound):
		v.Error = "Pick where the items come from and where they go."
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	if v.Error != "" {
		s.migrationsPage(w, r, v, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/migrations/"+id), http.StatusSeeOther)
}

// The migration screen -------------------------------------------------------------

type migrationView struct {
	M        store.WfMigration
	Plan     store.MigrationPlan
	List     *listView
	Selected int      // items that would move
	Targets  []string // "3 to Review", per target status
	TooMany  bool
	Problem  string // why the plan can't be worked out now
	Base     string
	Notice   string
	Error    string
}

// Percent is how far a running migration has got.
func (v migrationView) Percent() int {
	if v.M.Total == 0 {
		return 0
	}
	return v.M.Done * 100 / v.M.Total
}

func (s *Server) loadMigration(w http.ResponseWriter, r *http.Request) (store.WfMigration, bool) {
	m, err := s.store.GetMigration(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such migration.")
		return m, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return m, false
	}
	return m, true
}

func (s *Server) migrationPath(m store.WfMigration) string { return "/settings/migrations/" + m.ID }

// migrationTable is the work items table limited to the items a migration
// can take, all of them by default.
func migrationTable(base *list.Table, m store.WfMigration) *list.Table {
	t := *base
	t.Scope = func(a *list.Args, v list.Viewer) string {
		if m.Kind == store.MigrationWorkflow {
			return "w.workflow_version_id::text = " + a.Add(m.FromVersionID)
		}
		return "w.project_id::text = " + a.Add(m.FromProjectID) + " AND w.ticket_type_id::text = " + a.Add(m.FromTypeID)
	}
	for _, view := range t.Views {
		if view.Key == "all" {
			t.Default = view.Query
		}
	}
	return &t
}

// migrationItems returns the IDs of the items a query picks, before
// unticking, at most one more than store.MaxMigrationItems.
func (s *Server) migrationItems(r *http.Request, t *list.Table, q list.Query) ([]string, error) {
	viewer, err := s.listViewer(r)
	if err != nil {
		return nil, err
	}
	st, err := list.Build(t, list.Query{Cols: []string{"ref"}, Groups: q.Groups, Search: q.Search, Sort: t.Default.Sort},
		list.Options{Viewer: viewer, Now: time.Now(), Loc: s.cfg.Location, Limit: store.MaxMigrationItems + 1})
	if err != nil {
		return nil, err
	}
	res, err := s.store.ListRows(r.Context(), st)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(res.Rows))
	for i, row := range res.Rows {
		ids[i] = row.ID
	}
	return ids, nil
}

func (s *Server) migrationPage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMigration(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	path := s.migrationPath(m)
	q := r.URL.Query()
	v := migrationView{M: m, Base: s.cfg.PublicURL.Path, Notice: q.Get("notice"), Error: q.Get("error")}
	if !m.Draft() {
		var err error
		if v.Plan, err = s.store.PlanMigration(ctx, m, nil, nil); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		s.pages.render(w, http.StatusOK, "migration", s.data(r, "Migration", v))
		return
	}
	base, _, err := s.listTable(ctx, "work")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	t := migrationTable(base, m)
	// The saved selection, until someone filters it again.
	if list.IsBare(q) && m.Query != "" {
		saved, _ := url.ParseQuery(m.Query)
		sq, _ := list.Parse(t, saved)
		target := sq.Values()
		for _, k := range []string{"notice", "error"} {
			if q.Has(k) {
				target.Set(k, q.Get(k))
			}
		}
		http.Redirect(w, r, s.url(path+"?"+target.Encode()), http.StatusSeeOther)
		return
	}
	excluded := map[string]bool{}
	for _, id := range m.Excluded {
		excluded[id] = true
	}
	lv, ok := s.buildTableList(w, r, t, path, listSelect{URL: path + "/select", Excluded: excluded, Form: "migration-form"})
	if !ok {
		return
	}
	v.List = lv
	ids, err := s.migrationItems(r, t, lv.Query)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { return excluded[id] })
	v.Selected, v.TooMany = len(ids), len(ids) > store.MaxMigrationItems
	v.Plan, err = s.store.PlanMigration(ctx, m, nil, ids)
	switch {
	case errors.Is(err, store.ErrNoPublished):
		v.Problem = "The target workflow has no published version."
	case errors.Is(err, store.ErrTypeNotOffered):
		v.Problem = "The target project no longer offers " + m.ToTypeName + "."
	case errors.Is(err, store.ErrArchived):
		v.Problem = "The target project is archived."
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	counts := map[string]int{}
	var order []store.WfStatus
	for _, src := range v.Plan.Sources {
		for _, row := range src.Rows {
			if row.Items == 0 {
				continue
			}
			if _, ok := counts[row.Target.Key]; !ok {
				order = append(order, row.Target)
			}
			counts[row.Target.Key] += row.Items
		}
	}
	for _, st := range order {
		v.Targets = append(v.Targets, fmt.Sprintf("%d to %s", counts[st.Key], st.Name))
	}
	s.renderList(w, r, "migration", "Migration", v, lv)
}

// mappingInput reads the mapping selects: map.<source status ID> = target key.
func mappingInput(r *http.Request) map[string]string {
	r.ParseForm()
	out := map[string]string{}
	for k, vs := range r.PostForm {
		if id, ok := strings.CutPrefix(k, "map."); ok && len(vs) > 0 && statusKeyRe.MatchString(vs[0]) {
			out[id] = vs[0]
		}
	}
	return out
}

// queryInput reads the list query the migration form carries, checked
// against the table.
func queryInput(r *http.Request, t *list.Table) list.Query {
	values, _ := url.ParseQuery(r.FormValue("query"))
	q, _ := list.Parse(t, values)
	q.Page, q.List = 0, ""
	return q
}

func (s *Server) backToMigration(w http.ResponseWriter, r *http.Request, m store.WfMigration, query, kind, msg string) {
	target := s.migrationPath(m)
	v, _ := url.ParseQuery(query)
	if kind != "" {
		v.Set(kind, msg)
	}
	if len(v) > 0 {
		target += "?" + v.Encode()
	}
	http.Redirect(w, r, s.url(target), http.StatusSeeOther)
}

// migrationSave stores the mapping and the list query.
func (s *Server) migrationSave(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMigration(w, r)
	if !ok {
		return
	}
	base, _, err := s.listTable(r.Context(), "work")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	query := queryInput(r, migrationTable(base, m)).Encode()
	err = s.store.SaveMigration(r.Context(), m.ID, mappingInput(r), query)
	switch {
	case errors.Is(err, store.ErrStarted):
		s.backToMigration(w, r, m, "", "error", "The migration has already started.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToMigration(w, r, m, query, "notice", "Saved the mapping.")
	}
}

// migrationSelect ticks or unticks one row (id) or every row of a page
// (page, with row for each), as the list's checkboxes change.
func (s *Server) migrationSelect(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ids := []string{r.FormValue("id")}
	if r.FormValue("page") != "" {
		ids = r.Form["row"]
	}
	err := s.store.ExcludeItems(r.Context(), r.PathValue("id"), ids, r.FormValue("keep") == "")
	switch {
	case errors.Is(err, store.ErrStarted):
		http.Error(w, "The migration has already started.", http.StatusConflict)
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "No such migration.", http.StatusNotFound)
	case err != nil:
		s.serverError(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) migrationSelectAll(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMigration(w, r)
	if !ok {
		return
	}
	err := s.store.IncludeAll(r.Context(), m.ID)
	switch {
	case errors.Is(err, store.ErrStarted):
		s.backToMigration(w, r, m, "", "error", "The migration has already started.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToMigration(w, r, m, r.FormValue("query"), "notice", "Ticked every item again.")
	}
}

// migrationStart saves the form and starts the migration on the items the
// list picks, less the unticked ones.
func (s *Server) migrationStart(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMigration(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	base, _, err := s.listTable(ctx, "work")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	t := migrationTable(base, m)
	q := queryInput(r, t)
	query := q.Encode()
	ids, err := s.migrationItems(r, t, q)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	n, err := s.store.StartMigration(ctx, s.actor(r), m.ID, mappingInput(r), query, ids)
	back := func(msg string) { s.backToMigration(w, r, m, query, "error", msg) }
	switch {
	case errors.Is(err, store.ErrStarted):
		back("The migration has already started.")
	case errors.Is(err, store.ErrNothingSelected):
		back("No items are selected.")
	case errors.Is(err, store.ErrTooMany):
		back(fmt.Sprintf("Select at most %d items at a time: filter the list down and run the rest after.", store.MaxMigrationItems))
	case errors.Is(err, store.ErrSameTarget):
		back("Those items are already on the target version.")
	case errors.Is(err, store.ErrNoPublished):
		back("The target workflow has no published version.")
	case errors.Is(err, store.ErrTypeNotOffered):
		back("The target project no longer offers " + m.ToTypeName + ".")
	case errors.Is(err, store.ErrArchived):
		back("The target project is archived.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		msg := fmt.Sprintf("Started: moving %s.", plural(n, "item"))
		if s.migrate != nil {
			select {
			case s.migrate <- struct{}{}:
			default:
			}
		} else if err := s.runMigration(ctx, m.ID); err != nil {
			msg = err.Error()
		}
		s.backToMigration(w, r, m, "", "notice", msg)
	}
}

func (s *Server) migrationDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMigration(w, r)
	if !ok {
		return
	}
	err := s.store.DeleteMigration(r.Context(), s.actor(r), m.ID)
	switch {
	case errors.Is(err, store.ErrStarted):
		s.backToMigration(w, r, m, "", "error", "A migration that has started stays on record.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/migrations?notice="+url.QueryEscape("Discarded the draft.")), http.StatusSeeOther)
	}
}

// Words for the screen.

func mapHowText(how string) string {
	switch how {
	case store.MapByKey:
		return "same key"
	case store.MapChosen:
		return "chosen"
	case store.MapByCategory:
		return "guessed by category"
	}
	return "guessed: where new items start"
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Boards (docs/data-model.md §11): work items in columns, each a set of
// status categories and statuses. Dropping a card on a column runs a real
// transition; board.js splits a column into one drop zone per transition
// that leads into it. Anyone with a role may make a board; its maker and
// admins change it.

// boardLimit caps the cards a board shows.
const boardLimit = 500

// boardMaxColumns caps a board's columns.
const boardMaxColumns = 12

func (s *Server) boardRoutes(mux *http.ServeMux) {
	mux.Handle("GET /boards", s.page(anyRole, s.boards))
	mux.Handle("POST /boards", s.page(anyRole, s.boardCreate))
	mux.Handle("GET /boards/{id}", s.page(anyRole, s.boardPage))
	mux.Handle("GET /boards/{id}/edit", s.page(anyRole, s.boardEdit))
	mux.Handle("POST /boards/{id}", s.page(anyRole, s.boardSave))
	mux.Handle("POST /boards/{id}/delete", s.page(anyRole, s.boardDelete))
	mux.Handle("POST /boards/{id}/move", s.page(anyRole, s.boardMove))
}

func canEditBoard(p *Principal, b store.Board) bool {
	return (b.CreatedBy != "" && b.CreatedBy == p.User.ID) || p.Grants.Has(rbac.Admin)
}

func (s *Server) boardURL(id string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u := "/boards/" + id
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return s.url(u)
}

// defaultBoardFilter is a new board's filter: items not done, or done in
// the last two weeks, so the Done column doesn't grow forever.
func defaultBoardFilter() [][]list.Cond {
	return [][]list.Cond{
		{cond("status", list.Ne, store.StatusDone)},
		{cond("resolved_at", list.Within, "14d")},
	}
}

type boardsView struct {
	Boards   []boardLink
	Projects []store.Project // open ones, for a new board
	Name     string          // the new board form, as typed
	Project  string
	Notice   string
	Error    string
}

type boardLink struct {
	store.Board
	CanEdit bool
}

func (s *Server) boardsPage(w http.ResponseWriter, r *http.Request, v boardsView, status int) {
	ctx := r.Context()
	boards, err := s.store.ListBoards(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, b := range boards {
		v.Boards = append(v.Boards, boardLink{Board: b, CanEdit: canEditBoard(principal(r), b)})
	}
	if v.Projects, err = s.store.ListProjects(ctx, false); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, status, "boards", s.data(r, "Boards", v))
}

func (s *Server) boards(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.boardsPage(w, r, boardsView{Project: strings.ToUpper(q.Get("project")), Notice: q.Get("notice"), Error: q.Get("error")},
		http.StatusOK)
}

// boardCreate makes a board with a column per status category and the
// default filter, then opens it.
func (s *Server) boardCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := boardsView{Name: strings.TrimSpace(r.FormValue("name")), Project: strings.ToUpper(r.FormValue("project"))}
	b := store.Board{Name: v.Name, Columns: store.DefaultColumns(), Filter: defaultBoardFilter()}
	switch {
	case b.Name == "":
		v.Error = "Enter a name."
	case len(b.Name) > 80:
		v.Error = "A board's name is at most 80 characters."
	}
	if v.Error == "" && v.Project != "" {
		p, err := s.store.GetProject(ctx, v.Project)
		switch {
		case errors.Is(err, store.ErrNotFound):
			v.Error = "Pick a project."
		case err != nil:
			s.serverError(w, r, err)
			return
		}
		b.ProjectID = p.ID
	}
	if v.Error == "" {
		id, err := s.store.CreateBoard(ctx, s.actor(r), principal(r).User.ID, b)
		switch {
		case errors.Is(err, store.ErrConflict):
			v.Error = "A board called " + b.Name + " already exists."
		case err != nil:
			s.serverError(w, r, err)
			return
		default:
			http.Redirect(w, r, s.boardURL(id, "notice", "Created. Edit it to change its columns and filter."), http.StatusSeeOther)
			return
		}
	}
	s.boardsPage(w, r, v, http.StatusBadRequest)
}

// loadBoard fetches the board named in the path.
func (s *Server) loadBoard(w http.ResponseWriter, r *http.Request) (store.Board, bool) {
	b, err := s.store.GetBoard(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such board.")
		return b, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return b, false
	}
	return b, true
}

// The board ----------------------------------------------------------------------

type boardView struct {
	Board    store.Board
	Columns  []boardColumnView
	Filter   []string // each OR group in words
	Problems []string // filter conditions the list engine no longer allows
	Shown    int
	Total    int
	Unplaced int // matching items whose status no column takes
	CanEdit  bool
	// For the transition screen.
	Resolutions []string
	Users       []store.User
	Notice      string
	Error       string
}

type boardColumnView struct {
	Index int
	Name  string
	Cards []boardCard
}

type boardCard struct {
	store.BoardCard
	Targets []boardTarget
}

// TargetsJSON is the card's transitions for board.js.
func (c boardCard) TargetsJSON() string {
	b, _ := json.Marshal(nonNilTargets(c.Targets))
	return string(b)
}

func nonNilTargets(t []boardTarget) []boardTarget {
	if t == nil {
		return []boardTarget{}
	}
	return t
}

// boardTarget is a transition out of a card's status: the column it leads
// into (-1 for none), whether the user may run it and what its screen asks
// for.
type boardTarget struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	To      string   `json:"to"`
	Column  int      `json:"col"`
	Allowed bool     `json:"ok"`
	Screen  []string `json:"screen"`
}

// boardQuery is the list engine query for a board's cards: its filter,
// limited to its project, by priority.
func boardQuery(b store.Board) list.Query {
	q := list.Query{Groups: b.Filter, Cols: []string{"ref"}, Sort: list.Sort{Field: "priority"}}
	if b.ProjectKey != "" {
		q = q.With(cond("project", list.Eq, b.ProjectKey))
	}
	return q
}

func (s *Server) boardPage(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBoard(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	v, asksAssignee, err := s.boardData(r, b)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Resolutions, v.Notice, v.Error = store.Resolutions, q.Get("notice"), q.Get("error")
	if asksAssignee {
		if v.Users, err = s.store.ListUsers(r.Context()); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.pages.render(w, http.StatusOK, "board", s.data(r, b.Name, v))
}

// boardData fills a board's columns with the cards its filter matches, for
// the page and the API, and reports whether a transition the user may run
// asks for an assignee.
func (s *Server) boardData(r *http.Request, b store.Board) (boardView, bool, error) {
	ctx := r.Context()
	v := boardView{Board: b, CanEdit: canEditBoard(principal(r), b)}
	t, _, err := s.listTable(ctx, "work")
	if err != nil {
		return v, false, err
	}
	query, problems := list.Parse(t, boardQuery(b).Values())
	v.Problems = problems
	for _, g := range b.Filter {
		var words []string
		for _, c := range g {
			words = append(words, condLabel(t, c))
		}
		if len(words) > 0 {
			v.Filter = append(v.Filter, strings.Join(words, " and "))
		}
	}
	viewer, err := s.listViewer(r)
	if err != nil {
		return v, false, err
	}
	st, err := list.Build(t, query, list.Options{Viewer: viewer, Now: time.Now(), Loc: s.cfg.Location, Limit: boardLimit})
	if err != nil {
		return v, false, err
	}
	res, err := s.store.ListRows(ctx, st)
	if err != nil {
		return v, false, err
	}
	v.Total = res.Total
	ids := make([]string, len(res.Rows))
	for i, row := range res.Rows {
		ids[i] = row.ID
	}
	cards, err := s.store.BoardCards(ctx, ids)
	if err != nil {
		return v, false, err
	}
	v.Shown = len(cards)

	for i, c := range b.Columns {
		v.Columns = append(v.Columns, boardColumnView{Index: i, Name: c.Name})
	}
	targets, asksAssignee, err := s.boardTargets(r, b, cards)
	if err != nil {
		return v, false, err
	}
	for i, c := range cards {
		col := b.Column(c.StatusKey, c.Status)
		if col < 0 {
			v.Unplaced++
			continue
		}
		v.Columns[col].Cards = append(v.Columns[col].Cards, boardCard{BoardCard: c, Targets: targets[i]})
	}
	return v, asksAssignee, nil
}

// boardTargets works out each card's transitions, the column each leads
// into and whether the user may run it, and whether any the user may run
// asks for an assignee.
func (s *Server) boardTargets(r *http.Request, b store.Board, cards []store.BoardCard) ([][]boardTarget, bool, error) {
	ctx := r.Context()
	var versions []string
	for _, c := range cards {
		if !slices.Contains(versions, c.WorkflowVersionID) {
			versions = append(versions, c.WorkflowVersionID)
		}
	}
	keys, err := s.store.VersionStatusKeys(ctx, versions)
	if err != nil {
		return nil, false, err
	}
	// Items on one version in one status share their transitions.
	byStatus := map[string][]store.WfTransition{}
	run := runner(r)
	asksAssignee := false
	out := make([][]boardTarget, len(cards))
	for i, c := range cards {
		k := c.WorkflowVersionID + "|" + c.StatusID
		ts, ok := byStatus[k]
		if !ok {
			if ts, err = s.store.ItemTransitions(ctx, c.WorkItem); err != nil {
				return nil, false, err
			}
			byStatus[k] = ts
		}
		for _, t := range ts {
			bt := boardTarget{ID: t.ID, Name: t.Name, To: t.ToName, Column: b.Column(keys[t.ToID], t.ToCategory),
				Allowed: t.Allowed(c.WorkItem, run), Screen: []string{}}
			for _, f := range t.Screen {
				if f == "resolution" && t.ToCategory != store.StatusDone {
					continue
				}
				bt.Screen = append(bt.Screen, f)
			}
			if bt.Allowed && t.Asks("assignee") {
				asksAssignee = true
			}
			out[i] = append(out[i], bt)
		}
	}
	return out, asksAssignee, nil
}

// boardMove runs a transition on an item from the board, from a drop or
// the card's menu, and goes back to the board. Items are named by ID: a
// reference changes when an item moves project.
func (s *Server) boardMove(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBoard(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	back := func(kind, msg string) { http.Redirect(w, r, s.boardURL(b.ID, kind, msg), http.StatusSeeOther) }
	it, err := s.store.GetWorkItem(ctx, r.FormValue("item"))
	if errors.Is(err, store.ErrNotFound) {
		back("error", "That work item no longer exists.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	in := store.TransitionInput{Resolution: r.FormValue("resolution"), AssigneeID: r.FormValue("assignee"),
		Comment: r.FormValue("comment")}
	err = s.store.TransitionWorkItem(ctx, s.actor(r), runner(r), it.ID, r.FormValue("transition"), in)
	var bad *store.TransitionError
	switch {
	case errors.As(err, &bad):
		back("error", it.Ref()+": "+bad.Msg)
	case errors.Is(err, store.ErrStaleTransition):
		back("error", it.Ref()+" has moved on: that transition doesn't apply any more.")
	case errors.Is(err, store.ErrTransitionDenied):
		back("error", "You may not run that transition on "+it.Ref()+".")
	case errors.Is(err, store.ErrNotFound):
		back("error", "That assignee no longer exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		moved, err := s.store.GetWorkItem(ctx, it.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		back("notice", moved.Ref()+" is now "+moved.StatusName+".")
	}
}

// Configuring a board ------------------------------------------------------------

type boardFormView struct {
	Board      store.Board
	Projects   []store.Project
	ProjectKey string
	Statuses   []store.BoardStatus
	Categories []string
	Columns    []boardColumnForm // the board's, then blank ones to add
	// The filter's condition builder (list_parts.html).
	Builder  [][]builderRow
	NewGroup builderRow
	Fields   []*list.Field
	AllOps   []list.Op
	Error    string
}

type boardColumnForm struct {
	Index int
	store.BoardColumn
}

func (s *Server) boardForm(w http.ResponseWriter, r *http.Request, v boardFormView, status int) {
	ctx := r.Context()
	var err error
	if v.Projects, err = s.store.ListProjects(ctx, true); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Statuses, err = s.store.BoardStatuses(ctx, v.Board.ProjectID); err != nil {
		s.serverError(w, r, err)
		return
	}
	t, _, err := s.listTable(ctx, "work")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Categories = store.StatusCategories
	for i, c := range v.Board.Columns {
		v.Columns = append(v.Columns, boardColumnForm{Index: i, BoardColumn: c})
	}
	for n := len(v.Columns); len(v.Columns) < min(n+2, boardMaxColumns); {
		v.Columns = append(v.Columns, boardColumnForm{Index: len(v.Columns)})
	}
	for g, conds := range v.Board.Filter {
		var rows []builderRow
		for _, c := range conds {
			rows = append(rows, builderRow{Group: g, Field: t.Field(c.Field), Op: c.Op, Value: c.Value})
		}
		v.Builder = append(v.Builder, append(rows, builderRow{Group: g}))
	}
	v.NewGroup = builderRow{Group: len(v.Board.Filter)}
	for i := range t.Fields {
		if f := &t.Fields[i]; f.Filterable() {
			v.Fields = append(v.Fields, f)
		}
	}
	v.AllOps = list.AllOps()
	s.pages.render(w, status, "board_form", s.data(r, "Edit board "+v.Board.Name, v))
}

func (s *Server) boardEdit(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBoard(w, r)
	if !ok {
		return
	}
	if !canEditBoard(principal(r), b) {
		s.errorPage(w, r, http.StatusForbidden, "Only the board's maker and admins change it.")
		return
	}
	s.boardForm(w, r, boardFormView{Board: b, ProjectKey: b.ProjectKey}, http.StatusOK)
}

// boardInput reads the board form into b. Columns arrive as rows: col is
// each row's index, and name_<i>, pos_<i>, cat_<i> and status_<i> its
// fields; a row with no name and nothing ticked is dropped.
func (s *Server) boardInput(r *http.Request, b store.Board) (store.Board, error) {
	r.ParseForm()
	b.Name = strings.TrimSpace(r.FormValue("name"))
	b.ProjectKey = strings.ToUpper(r.FormValue("project"))
	type row struct {
		pos int
		col store.BoardColumn
	}
	var rows []row
	for _, i := range r.Form["col"] {
		if _, err := strconv.Atoi(i); err != nil {
			continue
		}
		c := store.BoardColumn{Name: strings.TrimSpace(r.FormValue("name_" + i))}
		for _, cat := range r.Form["cat_"+i] {
			if slices.Contains(store.StatusCategories, cat) && !slices.Contains(c.Categories, cat) {
				c.Categories = append(c.Categories, cat)
			}
		}
		for _, key := range r.Form["status_"+i] {
			if statusKeyRe.MatchString(key) && !slices.Contains(c.Statuses, key) {
				c.Statuses = append(c.Statuses, key)
			}
		}
		if c.Name == "" && len(c.Categories) == 0 && len(c.Statuses) == 0 {
			continue
		}
		pos, err := strconv.Atoi(strings.TrimSpace(r.FormValue("pos_" + i)))
		if err != nil {
			pos = len(rows) + 1
		}
		rows = append(rows, row{pos, c})
	}
	slices.SortStableFunc(rows, func(a, b row) int { return a.pos - b.pos })
	b.Columns = nil
	for _, x := range rows {
		b.Columns = append(b.Columns, x.col)
	}

	t, _, err := s.listTable(r.Context(), "work")
	if err != nil {
		return b, err
	}
	b.Filter = nil
	if slices.ContainsFunc(r.Form["cf"], func(f string) bool { return strings.TrimSpace(f) != "" }) {
		q, problems := list.Parse(t, url.Values{"cf": r.Form["cf"], "co": r.Form["co"], "cv": r.Form["cv"], "cg": r.Form["cg"]})
		b.Filter = q.Groups
		if len(problems) > 0 {
			return b, errBadInput(strings.Join(problems, " "))
		}
	}

	switch {
	case b.Name == "":
		return b, errBadInput("Enter a name.")
	case len(b.Name) > 80:
		return b, errBadInput("A board's name is at most 80 characters.")
	case len(b.Columns) == 0:
		return b, errBadInput("A board needs at least one column.")
	case len(b.Columns) > boardMaxColumns:
		return b, errBadInput(fmt.Sprintf("A board has at most %d columns.", boardMaxColumns))
	}
	for _, c := range b.Columns {
		switch {
		case c.Name == "":
			return b, errBadInput("Name every column.")
		case len(c.Categories) == 0 && len(c.Statuses) == 0:
			return b, errBadInput("Tick a category or a status for column " + c.Name + ".")
		}
	}
	b.ProjectID = ""
	if b.ProjectKey != "" {
		p, err := s.store.GetProject(r.Context(), b.ProjectKey)
		if errors.Is(err, store.ErrNotFound) {
			b.ProjectKey = ""
			return b, errBadInput("Pick a project.")
		}
		if err != nil {
			return b, err
		}
		b.ProjectID = p.ID
	}
	return b, nil
}

func (s *Server) boardSave(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBoard(w, r)
	if !ok {
		return
	}
	if !canEditBoard(principal(r), b) {
		s.errorPage(w, r, http.StatusForbidden, "Only the board's maker and admins change it.")
		return
	}
	in, err := s.boardInput(r, b)
	if err == nil {
		err = s.store.UpdateBoard(r.Context(), s.actor(r), b.ID, in)
		if errors.Is(err, store.ErrConflict) {
			err = errBadInput("A board called " + in.Name + " already exists.")
		}
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		s.boardForm(w, r, boardFormView{Board: in, ProjectKey: in.ProjectKey, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.boardURL(b.ID, "notice", "Saved."), http.StatusSeeOther)
}

func (s *Server) boardDelete(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBoard(w, r)
	if !ok {
		return
	}
	if !canEditBoard(principal(r), b) {
		s.errorPage(w, r, http.StatusForbidden, "Only the board's maker and admins change it.")
		return
	}
	if err := s.store.DeleteBoard(r.Context(), s.actor(r), b.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/boards?notice="+url.QueryEscape("Deleted "+b.Name+".")), http.StatusSeeOther)
}

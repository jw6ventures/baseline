package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// The list engine's pages (docs/lists.md): every list's saved lists,
// inline edits and bulk actions.

func (s *Server) listRoutes(mux *http.ServeMux) {
	mux.Handle("POST /lists/{table}/saved", s.page(anyRole, s.listSave))
	mux.Handle("POST /lists/{table}/saved/{id}/delete", s.page(anyRole, s.listDeleteSaved))
	mux.Handle("POST /lists/{table}/bulk", s.page(anyRole, s.listBulk))
	mux.Handle("GET /lists/{table}/rows/{id}/{field}", s.page(anyRole, s.listCell))
	mux.Handle("GET /lists/{table}/rows/{id}/{field}/edit", s.page(anyRole, s.listCellEdit))
	mux.Handle("POST /lists/{table}/rows/{id}/{field}", s.page(anyRole, s.listCellSave))
}

// listTable returns a table and the path of its page.
func (s *Server) listTable(ctx context.Context, key string) (*list.Table, string, error) {
	switch key {
	case "host":
		return hostTable, "/hosts", nil
	case "ci":
		types, err := s.store.CITypes(ctx)
		return ciTable(types), "/cis", err
	case "change":
		return changeTable, "/changes", nil
	case "job":
		return jobTable, "/jobs", nil
	case "container":
		advice, err := s.containerAdvice(ctx)
		return containerTable(advice), "/containers", err
	case "stack":
		return stackTable, "/stacks", nil
	case "update":
		return updateHostTable, "/updates", nil
	case "package":
		return packageTable, "/updates/packages", nil
	case "vm":
		return vmTable, "/vms", nil
	case "window":
		facts, err := s.windowFactsOf(ctx)
		p, _ := ctx.Value(ctxKey{}).(*Principal)
		return windowTable(facts, p != nil && p.Grants.Has(rbac.Admin)), "/windows", err
	case "model":
		summaries, err := s.modelSummaries(ctx)
		return modelTable(summaries), "/change-models", err
	case "alert":
		return alertTable, "/alerts", nil
	case "project":
		l, err := s.projectLabels(ctx)
		return projectTable(l), "/projects", err
	case "audit":
		return auditTable, "/audit", nil
	case "work":
		projects, err := s.store.ListProjects(ctx, true)
		if err != nil {
			return nil, "", err
		}
		types, err := s.store.ListTicketTypes(ctx)
		if err != nil {
			return nil, "", err
		}
		statuses, err := s.store.StatusNames(ctx)
		if err != nil {
			return nil, "", err
		}
		workflows, err := s.store.ListWorkflows(ctx)
		if err != nil {
			return nil, "", err
		}
		fields, err := s.store.ListFieldDefs(ctx)
		if err != nil {
			return nil, "", err
		}
		l, err := s.projectLabels(ctx)
		return workTable(projects, types, statuses, workflows, fields, l), "/work", err
	}
	return nil, "", store.ErrNotFound
}

func (s *Server) listViewer(r *http.Request) (list.Viewer, error) {
	ids, err := s.visibleHostIDs(r)
	p := principal(r)
	v := list.Viewer{HostIDs: ids, Global: p.Grants.Has(rbac.Viewer), UserID: p.User.ID}
	for g := range p.Grants.Scoped() {
		if p.Grants.HasOn(rbac.Viewer, []string{g}) {
			v.GroupIDs = append(v.GroupIDs, g)
		}
	}
	return v, err
}

// legacyParams are the filters lists had before the list engine.
var legacyParams = []string{"q", "show", "type", "status", "project", "assignee", "platform", "updates", "security",
	"view", "env", "category", "visibility", "before", "archived"}

// legacyValues turns the filters the lists had before the list engine
// (?show=open, ?type=nas&status=all, ?updates=1, ?q=) into list
// parameters, so old links and bookmarks still open what they did.
func legacyValues(t *list.Table, v url.Values) url.Values {
	for _, k := range []string{"cf", "cols", "sort", "group", "page", "list"} {
		if v.Has(k) {
			return v
		}
	}
	if !slices.ContainsFunc(legacyParams, v.Has) {
		return v
	}
	q := t.Default
	show := v.Get("show")
	if t.Key == "alert" && v.Get("view") == "history" {
		show = "resolved"
	}
	if t.Key == "project" && v.Get("archived") == "1" {
		show = "all"
	}
	if show != "" {
		if i := slices.IndexFunc(t.Views, func(w list.View) bool { return w.Key == show }); i >= 0 {
			q = t.Views[i].Query
		}
	}
	if t.Key == "work" {
		switch st := v.Get("status"); st {
		case "":
		case "all":
			q.Groups = nil
		default:
			q.Groups = [][]list.Cond{{cond("status", list.Eq, st)}}
		}
		if p := strings.ToUpper(v.Get("project")); p != "" {
			q = q.With(cond("project", list.Eq, p))
		}
		switch v.Get("assignee") {
		case "me":
			q = q.With(cond("assigned_to_me", list.IsTrue, ""))
		case "none":
			q = q.With(cond("assignee", list.Empty, ""))
		}
	}
	if t.Key == "ci" {
		switch st := v.Get("status"); st {
		case "":
		case "all":
			q.Groups = nil
		default:
			q.Groups = [][]list.Cond{{cond("status", list.Eq, st)}}
		}
		if typ := v.Get("type"); typ != "" {
			q = q.With(cond("type", list.Eq, typ))
		}
	}
	on := func(param string) bool { return v.Get(param) == "1" }
	switch t.Key {
	case "vm":
		if p := v.Get("platform"); p != "" {
			q = q.With(cond("platform", list.Eq, p))
		}
	case "container":
		if on("updates") {
			q = q.With(cond("has_update", list.IsTrue, ""))
		}
	case "stack":
		if on("updates") {
			q = q.With(cond("drift", list.Gt, "0"))
		}
		for _, f := range [][2]string{{"env", "environment"}, {"category", "category"}, {"visibility", "visibility"}} {
			switch val := v.Get(f[0]); val {
			case "":
			case noClass:
				q = q.With(cond(f[1], list.Empty, ""))
			default:
				q = q.With(cond(f[1], list.Eq, val))
			}
		}
	case "update":
		if on("security") {
			q = q.With(cond("security", list.Gt, "0"))
		}
	case "package":
		if on("security") {
			q = q.With(cond("security", list.IsTrue, ""))
		}
	case "audit":
		if before := v.Get("before"); before != "" {
			q = q.With(cond("id", list.Lt, before))
		}
	}
	q.Search = strings.TrimSpace(v.Get("q"))
	out := q.Values()
	for _, k := range []string{"notice", "error"} {
		if n := v.Get(k); n != "" {
			out.Set(k, n)
		}
	}
	return out
}

// listView is everything the shared list template shows.
type listView struct {
	Base     string
	Path     string // the page: /hosts
	Table    *list.Table
	Query    list.Query
	Encoded  string // the query without page or saved list, for forms and the cell menu
	Problems []string
	Notice   string
	Error    string

	Header     []headerCell
	Colspan    int
	GroupField *list.Field
	Rows       []rowView
	Total      int
	From       int
	To         int
	Prev       string
	Next       string
	Crumbs     [][]crumb // per group
	ClearURL   string

	Views []viewLink
	Saved []savedLink

	Builder     [][]builderRow // per group, each ending with a blank row
	NewGroup    builderRow     // the blank row that starts an OR group
	Fields      []*list.Field  // filterable, for the builder
	GroupFields []*list.Field
	Columns     []colChoice
	AllOps      []list.Op

	CanShare  bool
	Actions   []bulkAction
	Selection bool // rows have checkboxes
	// SelectURL, when set, saves ticks as they change, and SelectForm gets
	// the query (see listSelect); rows start ticked unless Excluded.
	// AllTicked: no row on the page is excluded.
	SelectURL  string
	SelectForm string
	Excluded   map[string]bool
	AllTicked  bool
}

type headerCell struct {
	Label  string
	URL    string // sorts by it; "" when it can't
	Sorted bool
	Desc   bool
	Class  string
}

type rowView struct {
	ID         string
	Link       string
	Dim        bool
	Cells      []cellView
	GroupStart bool
	Group      cellView
	GroupCount int
}

// cellView is one cell. Match and Exclude are the operators "show
// matching" and "filter out" add for Value; empty when the cell offers
// neither.
type cellView struct {
	Field   *list.Field
	Text    string
	Raw     string // the stored value, for badges
	Tags    []string
	Link    string
	Title   string
	Match   list.Op
	Exclude list.Op
	Value   string
	Edit    string // inline edit URL
	EditTag string // the htmx target id
}

type crumb struct {
	Label  string
	Remove string
}

type viewLink struct {
	Label   string
	URL     string
	Current bool
}

type savedLink struct {
	ID        string
	Name      string
	URL       string
	Shared    bool
	Current   bool
	CanDelete bool
}

type builderRow struct {
	Group  int
	Field  *list.Field // nil for a blank row
	Op     list.Op
	Value  string
	Remove string // the list without it
}

type colChoice struct {
	Key   string
	Label string
	On    bool
}

// buildList parses the request's query and runs it.
func (s *Server) buildList(w http.ResponseWriter, r *http.Request, key string) (*listView, bool) {
	t, path, err := s.listTable(r.Context(), key)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	return s.buildTableList(w, r, t, path, listSelect{})
}

// listSelect makes a list a selection that is saved as it changes, as the
// migration screen's is, rather than one for bulk actions: every row is
// ticked unless Excluded, and ticking posts to URL. Form names the form
// that gets the list's query, as "query", when it is submitted.
type listSelect struct {
	URL      string
	Excluded map[string]bool
	Form     string
}

// buildTableList runs the request's query on t, a list page at path.
func (s *Server) buildTableList(w http.ResponseWriter, r *http.Request, t *list.Table, path string, sel listSelect) (*listView, bool) {
	ctx := r.Context()
	viewer, err := s.listViewer(r)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	values := legacyValues(t, r.URL.Query())
	q, problems := list.Parse(t, values)
	// The builder's GET form sends blank rows and one cols value per
	// checkbox, and old links use old parameters: answer with the
	// canonical URL, so what people copy and share is short and stable.
	if !list.IsBare(values) && len(problems) == 0 {
		canon := q.Values()
		got := url.Values{}
		for k, vs := range r.URL.Query() {
			if k != "notice" && k != "error" {
				got[k] = vs
			}
		}
		if canon.Encode() != got.Encode() {
			for _, k := range []string{"notice", "error"} {
				if values.Has(k) {
					canon.Set(k, values.Get(k))
				}
			}
			target := s.url(path + "?" + canon.Encode())
			if r.Header.Get("HX-Request") != "true" {
				http.Redirect(w, r, target, http.StatusSeeOther)
				return nil, false
			}
			w.Header().Set("HX-Push-Url", target)
		}
	}
	st, err := list.Build(t, q, list.Options{Viewer: viewer, Now: time.Now(), Loc: s.cfg.Location})
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	res, err := s.store.ListRows(ctx, st)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	p := principal(r)
	v := &listView{Base: s.cfg.PublicURL.Path, Path: path, Table: t, Query: q, Problems: problems,
		Notice: values.Get("notice"), Error: values.Get("error"), Total: res.Total,
		CanShare: p.Grants.HasAnywhere(rbac.Operator), AllOps: list.AllOps()}
	plain := q
	plain.Page, plain.List = 0, ""
	v.Encoded = plain.Encode()
	if sel.URL != "" {
		v.SelectURL, v.SelectForm, v.Excluded, v.Selection, v.AllTicked = sel.URL, sel.Form, sel.Excluded, true, true
	} else {
		v.Actions = s.bulkActions(ctx, t, p.Grants)
		v.Selection = len(v.Actions) > 0
	}

	editors := listEditors[t.Key]
	for _, f := range st.Cols {
		h := headerCell{Label: f.Label, Class: f.Class}
		if f.Sortable() {
			h.URL = path + "?" + q.SortedBy(f.Key).Encode()
			h.Sorted = q.Sort.Field == f.Key
			h.Desc = h.Sorted && q.Sort.Desc
		}
		v.Header = append(v.Header, h)
	}
	v.Colspan = len(st.Cols)
	if v.Selection {
		v.Colspan++
	}
	v.GroupField = st.Group
	var prevGroup string
	for i, row := range res.Rows {
		rv := rowView{ID: row.ID, Link: row.Link, Dim: row.Dim}
		if sel.Excluded[row.ID] {
			v.AllTicked = false
		}
		for j, f := range st.Cols {
			c := s.cell(f, row.Values[j], row.Links[j])
			if ed, ok := editors[f.Key]; ok && row.Editable && ed.allow(p.Grants) {
				c.Edit = fmt.Sprintf("/lists/%s/rows/%s/%s", t.Key, row.ID, f.Key)
				c.EditTag = fmt.Sprintf("cell-%s-%s", row.ID, f.Key)
			}
			rv.Cells = append(rv.Cells, c)
		}
		if st.Group != nil {
			rv.Group = s.cell(st.Group, row.Group, "")
			key := rv.Group.Raw + "\x00" + strings.Join(rv.Group.Tags, "\x00")
			if i == 0 || key != prevGroup {
				rv.GroupStart, rv.GroupCount = true, row.GroupCount
			}
			prevGroup = key
		}
		v.Rows = append(v.Rows, rv)
	}
	if n := len(res.Rows); n > 0 {
		v.From = (max(q.Page, 1)-1)*list.PageSize + 1
		v.To = v.From + n - 1
	}
	if q.Page > 1 {
		v.Prev = path + "?" + q.OnPage(q.Page-1).Encode()
	}
	if v.To < v.Total {
		v.Next = path + "?" + q.OnPage(max(q.Page, 1)+1).Encode()
	}

	for g, conds := range q.Groups {
		var cs []crumb
		for i, c := range conds {
			cs = append(cs, crumb{Label: condLabel(t, c), Remove: path + "?" + q.Without(g, i).Encode()})
		}
		v.Crumbs = append(v.Crumbs, cs)
	}
	clear := plain
	clear.Groups = nil
	v.ClearURL = path + "?" + clear.Encode()

	for _, view := range t.Views {
		v.Views = append(v.Views, viewLink{Label: view.Label, URL: path + "?" + view.Query.Encode(),
			Current: q.List == "" && view.Query.Conditions() == q.Conditions()})
	}
	saved, err := s.store.SavedLists(ctx, t.Key, p.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	for _, l := range saved {
		v.Saved = append(v.Saved, savedLink{ID: l.ID, Name: l.Name, URL: path + "?" + l.Query().Encode(),
			Shared: l.Shared(), Current: q.List == l.ID, CanDelete: canDeleteSaved(p, l)})
	}

	for g, conds := range q.Groups {
		var rows []builderRow
		for i, c := range conds {
			rows = append(rows, builderRow{Group: g, Field: t.Field(c.Field), Op: c.Op, Value: c.Value,
				Remove: path + "?" + q.Without(g, i).Encode()})
		}
		v.Builder = append(v.Builder, append(rows, builderRow{Group: g}))
	}
	v.NewGroup = builderRow{Group: len(q.Groups)}
	for i := range t.Fields {
		f := &t.Fields[i]
		if f.Filterable() {
			v.Fields = append(v.Fields, f)
		}
		if f.Groupable() {
			v.GroupFields = append(v.GroupFields, f)
		}
	}
	for _, key := range q.Cols {
		v.Columns = append(v.Columns, colChoice{Key: key, Label: t.Field(key).Label, On: true})
	}
	for _, f := range t.Fields {
		if !slices.Contains(q.Cols, f.Key) {
			v.Columns = append(v.Columns, colChoice{Key: f.Key, Label: f.Label})
		}
	}
	return v, true
}

// isHTMX reports whether htmx asks for the list alone, so a page can skip
// what only its full render shows.
func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// renderList renders a list page, or only the list when htmx asks for it.
func (s *Server) renderList(w http.ResponseWriter, r *http.Request, page, title string, body any, v *listView) {
	if isHTMX(r) {
		s.pages.partial(w, http.StatusOK, page, "list", v)
		return
	}
	s.pages.render(w, http.StatusOK, page, s.data(r, title, body))
}

// cell formats one value for display and for the cell menu.
func (s *Server) cell(f *list.Field, val any, link string) cellView {
	c := cellView{Field: f, Link: link}
	empty := func() {
		c.Match, c.Exclude = list.Empty, list.NotEmpty
	}
	switch x := val.(type) {
	case string:
		c.Raw, c.Value = x, x
		c.Text = x
		if f.Type == list.Enum {
			c.Text = f.OptionLabel(x)
		}
		if x == "" {
			empty()
		} else {
			c.Match, c.Exclude = list.Eq, list.Ne
		}
	case float64:
		c.Text = strconv.FormatFloat(x, 'f', -1, 64)
		c.Raw, c.Value = c.Text, c.Text
		c.Match, c.Exclude = list.Eq, list.Ne
	case nil:
		if f.Type == list.Number {
			empty()
		}
	case bool:
		if x {
			c.Text, c.Raw = "yes", "true"
			c.Match, c.Exclude = list.IsTrue, list.IsFalse
		} else {
			c.Raw = "false"
			c.Match, c.Exclude = list.IsFalse, list.IsTrue
		}
	case time.Time:
		if !x.IsZero() {
			c.Text = x.In(s.cfg.Location).Format("2006-01-02 15:04")
			c.Title = ago(time.Since(x))
		}
	case []string:
		c.Tags = x
		if len(x) == 0 {
			empty()
		} else {
			c.Match, c.Exclude = list.Has, list.Lacks
		}
	}
	if !f.Filterable() {
		c.Match, c.Exclude = "", ""
	}
	return c
}

// condLabel is a condition in words, for breadcrumbs.
func condLabel(t *list.Table, c list.Cond) string {
	f := t.Field(c.Field)
	if f == nil {
		return c.Field
	}
	if !c.Op.NeedsValue() {
		return f.Label + " " + c.Op.Label()
	}
	val := c.Value
	switch {
	case f.Type == list.Enum:
		val = f.OptionLabel(val)
	case c.Op == list.Older:
		return f.Label + " more than " + val + " ago"
	}
	return f.Label + " " + c.Op.Label() + " " + val
}

// Saved lists -------------------------------------------------------------------

func canDeleteSaved(p *Principal, l store.SavedList) bool {
	if !l.Shared() {
		return l.Owner == p.User.ID
	}
	return l.CreatedBy == p.User.ID || p.Grants.Has(rbac.Admin)
}

func (s *Server) listSave(w http.ResponseWriter, r *http.Request) {
	t, path, err := s.listTable(r.Context(), r.PathValue("table"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such list.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	path = listBack(t.Key, path, r.FormValue("path"))
	values, _ := url.ParseQuery(r.FormValue("query"))
	q, _ := list.Parse(t, values)
	q.Page, q.List = 0, ""
	back := func(param, msg string) {
		v := q.Values()
		v.Set(param, msg)
		http.Redirect(w, r, s.url(path+"?"+v.Encode()), http.StatusSeeOther)
	}
	p := principal(r)
	name := strings.TrimSpace(r.FormValue("name"))
	shared := r.FormValue("shared") == "1"
	switch {
	case name == "":
		back("error", "Give the list a name.")
		return
	case len(name) > 80:
		back("error", "Keep the name under 80 characters.")
		return
	case shared && !p.Grants.HasAnywhere(rbac.Operator):
		back("error", "Only operators can share lists.")
		return
	}
	l := store.SavedList{Table: t.Key, Name: name, Columns: q.Cols, Conditions: q.Groups, Search: q.Search,
		Sort: q.Sort, GroupBy: q.GroupBy}
	if !shared {
		l.Owner = p.User.ID
	}
	id, err := s.store.CreateSavedList(r.Context(), s.actor(r), p.User.ID, l)
	if errors.Is(err, store.ErrConflict) {
		back("error", "There is already a list called "+name+".")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q.List = id
	v := q.Values()
	v.Set("notice", "Saved as "+name+".")
	http.Redirect(w, r, s.url(path+"?"+v.Encode()), http.StatusSeeOther)
}

func (s *Server) listDeleteSaved(w http.ResponseWriter, r *http.Request) {
	t, path, err := s.listTable(r.Context(), r.PathValue("table"))
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "No such list.")
		return
	}
	path = listBack(t.Key, path, r.FormValue("path"))
	l, err := s.store.GetSavedList(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (l.Table != r.PathValue("table") ||
		(!l.Shared() && l.Owner != principal(r).User.ID))) {
		s.errorPage(w, r, http.StatusNotFound, "No such saved list.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !canDeleteSaved(principal(r), l) {
		s.errorPage(w, r, http.StatusForbidden, "Only whoever shared this list, or an admin, can delete it.")
		return
	}
	if err := s.store.DeleteSavedList(r.Context(), s.actor(r), l.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	v, _ := url.ParseQuery(r.FormValue("back")) // empty: the table's default
	v.Del("list")
	v.Set("notice", "Deleted "+l.Name+".")
	http.Redirect(w, r, s.url(path+"?"+v.Encode()), http.StatusSeeOther)
}

// Rows the user may act on ------------------------------------------------------

// allowedRows returns which of ids the viewer may see in the table, and
// whether each may be edited in place.
func (s *Server) allowedRows(r *http.Request, t *list.Table, ids []string, cols ...string) ([]list.Row, []*list.Field, error) {
	viewer, err := s.listViewer(r)
	if err != nil {
		return nil, nil, err
	}
	if len(cols) == 0 {
		cols = t.Default.Cols[:1]
	}
	q := list.Query{Cols: cols, Sort: t.Default.Sort}
	st, err := list.Build(t, q, list.Options{Viewer: viewer, IDs: ids, Limit: max(len(ids), 1)})
	if err != nil {
		return nil, nil, err
	}
	res, err := s.store.ListRows(r.Context(), st)
	return res.Rows, st.Cols, err
}

// Inline edit -------------------------------------------------------------------

// cellEditor edits one field of a row in place.
type cellEditor struct {
	Input   string // text | select | tags
	Options func() []list.Option
	Allow   access // who may edit (agentless CIs need a global operator)
	Save    func(s *Server, r *http.Request, id, value string) error
}

func (e cellEditor) allow(g rbac.Grants) bool { return e.Allow(g) }

// listEditors are the fields each table edits in place. Only rows the
// table's EditExpr allows offer them.
var listEditors = map[string]map[string]cellEditor{
	"ci": {
		"owner":  {Input: "text", Allow: globalOperator, Save: saveCIField("owner")},
		"status": {Input: "select", Allow: globalOperator, Save: saveCIField("status"), Options: func() []list.Option { return opts(ciStatuses...) }},
		"tags":   {Input: "tags", Allow: globalOperator, Save: saveCIField("tags")},
	},
	// Anyone who can open a work item edits it, as on its page.
	"work": {
		"title":    {Input: "text", Allow: anyRole, Save: saveItemField("title")},
		"priority": {Input: "select", Allow: anyRole, Save: saveItemField("priority"), Options: func() []list.Option { return opts(store.Priorities...) }},
	},
}

var errBadValue = errors.New("bad value")

// saveCIField changes one field of a manual CI through UpdateCI, so it
// keeps its history and audit entry.
func saveCIField(field string) func(s *Server, r *http.Request, id, value string) error {
	return func(s *Server, r *http.Request, id, value string) error {
		c, err := s.store.GetCI(r.Context(), id)
		if err != nil {
			return err
		}
		in := store.CIInput{Type: c.Type, Name: c.Name, Status: c.Status, Owner: c.Owner, Description: c.Description,
			Tags: c.Tags, Attrs: map[string]string{}}
		for k := range c.Attrs {
			in.Attrs[k] = c.Attr(k)
		}
		value = strings.TrimSpace(value)
		switch field {
		case "owner":
			in.Owner = value
		case "status":
			if !slices.Contains(ciStatuses, value) {
				return errBadValue
			}
			in.Status = value
		case "tags":
			in.Tags = nil
			for _, t := range strings.FieldsFunc(value, func(c rune) bool { return c == ',' || c == ' ' }) {
				if !slices.Contains(in.Tags, t) {
					in.Tags = append(in.Tags, t)
				}
			}
		}
		return s.store.UpdateCI(r.Context(), s.actor(r), id, in)
	}
}

// saveItemField changes one field of a work item through UpdateWorkItem,
// so it keeps its history.
func saveItemField(field string) func(s *Server, r *http.Request, id, value string) error {
	return func(s *Server, r *http.Request, id, value string) error {
		it, err := s.store.GetWorkItem(r.Context(), id)
		if err != nil {
			return err
		}
		in := itemInput(it)
		value = strings.TrimSpace(value)
		switch field {
		case "title":
			if value == "" {
				return errBadValue
			}
			in.Title = value
		case "priority":
			if !slices.Contains(store.Priorities, value) {
				return errBadValue
			}
			in.Priority = value
		}
		return s.store.UpdateWorkItem(r.Context(), s.actor(r), id, in)
	}
}

// resolutionSep joins a transition's name and the resolution to close with
// in a bulk transition's value.
const resolutionSep = "::"

// bulkTransition runs the transition named in value, out of each item's own
// status. An item with no such transition, or one the user may not run or
// whose validators fail, is skipped.
func bulkTransition(s *Server, r *http.Request, id, value string) error {
	name, resolution := value, ""
	if i := strings.LastIndex(value, resolutionSep); i >= 0 {
		name, resolution = value[:i], value[i+len(resolutionSep):]
	}
	it, err := s.store.GetWorkItem(r.Context(), id)
	if err != nil {
		return err
	}
	ts, err := s.transitionsFor(r, it)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ts, func(t itemTransition) bool { return t.Name == name && t.Allowed })
	if i < 0 {
		return store.ErrNotFound
	}
	err = s.store.TransitionWorkItem(r.Context(), s.actor(r), runner(r), id, ts[i].ID,
		store.TransitionInput{Resolution: resolution, AssigneeID: it.AssigneeID})
	var bad *store.TransitionError
	if errors.As(err, &bad) || errors.Is(err, store.ErrStaleTransition) || errors.Is(err, store.ErrTransitionDenied) {
		return store.ErrNotFound
	}
	return err
}

// itemInput is an item's editable fields as they stand.
func itemInput(it store.WorkItem) store.WorkItemInput {
	return store.WorkItemInput{ProjectID: it.ProjectID, TypeID: it.TypeID, Title: it.Title, Description: it.Description,
		Priority: it.Priority, Impact: it.Impact, Urgency: it.Urgency, AssigneeID: it.AssigneeID, ParentID: it.ParentID,
		Estimate: it.Estimate, DueAt: it.DueAt, Source: it.Source, SourceRef: it.SourceRef}
}

type cellEditView struct {
	Base    string
	Cell    cellView
	Table   string
	ID      string
	Editor  cellEditor
	Value   string
	Options []list.Option
	Error   string
	Tag     string // the cell's element id
}

// editTarget checks the table, row, field and role of an inline edit.
func (s *Server) editTarget(w http.ResponseWriter, r *http.Request) (*list.Table, list.Row, *list.Field, cellEditor, bool) {
	t, _, err := s.listTable(r.Context(), r.PathValue("table"))
	if err != nil {
		http.Error(w, "No such list.", http.StatusNotFound)
		return nil, list.Row{}, nil, cellEditor{}, false
	}
	key := r.PathValue("field")
	ed, editable := listEditors[t.Key][key]
	f := t.Field(key)
	if f == nil {
		http.Error(w, "No such field.", http.StatusNotFound)
		return nil, list.Row{}, nil, cellEditor{}, false
	}
	rows, _, err := s.allowedRows(r, t, []string{r.PathValue("id")}, key)
	if err != nil {
		s.serverError(w, r, err)
		return nil, list.Row{}, nil, cellEditor{}, false
	}
	if len(rows) == 0 {
		http.Error(w, "No such row.", http.StatusNotFound)
		return nil, list.Row{}, nil, cellEditor{}, false
	}
	if r.Method == http.MethodGet && !strings.HasSuffix(r.URL.Path, "/edit") {
		return t, rows[0], f, ed, true // showing the cell needs no edit rights
	}
	if !editable || !rows[0].Editable || !ed.allow(principal(r).Grants) {
		http.Error(w, "This can't be edited here.", http.StatusForbidden)
		return nil, list.Row{}, nil, cellEditor{}, false
	}
	return t, rows[0], f, ed, true
}

func (s *Server) cellEdit(t *list.Table, row list.Row, f *list.Field, ed cellEditor, g rbac.Grants) cellView {
	c := s.cell(f, row.Values[0], row.Links[0])
	if row.Editable && ed.Save != nil && ed.allow(g) {
		c.Edit = fmt.Sprintf("/lists/%s/rows/%s/%s", t.Key, row.ID, f.Key)
		c.EditTag = fmt.Sprintf("cell-%s-%s", row.ID, f.Key)
	}
	return c
}

func (s *Server) listCell(w http.ResponseWriter, r *http.Request) {
	t, row, f, ed, ok := s.editTarget(w, r)
	if !ok {
		return
	}
	s.pages.partial(w, http.StatusOK, "", "list-cell", map[string]any{"Base": s.cfg.PublicURL.Path,
		"Cell": s.cellEdit(t, row, f, ed, principal(r).Grants)})
}

func (s *Server) listCellEdit(w http.ResponseWriter, r *http.Request) {
	t, row, f, ed, ok := s.editTarget(w, r)
	if !ok {
		return
	}
	s.renderCellEdit(w, http.StatusOK, t, row, f, ed, "")
}

func (s *Server) renderCellEdit(w http.ResponseWriter, status int, t *list.Table, row list.Row, f *list.Field, ed cellEditor, msg string) {
	c := s.cell(f, row.Values[0], row.Links[0])
	v := cellEditView{Base: s.cfg.PublicURL.Path, Cell: c, Table: t.Key, ID: row.ID, Editor: ed, Value: c.Raw, Error: msg,
		Tag: fmt.Sprintf("cell-%s-%s", row.ID, f.Key)}
	if c.Tags != nil {
		v.Value = strings.Join(c.Tags, ", ")
	}
	if ed.Options != nil {
		v.Options = ed.Options()
	}
	s.pages.partial(w, status, "", "list-cell-edit", v)
}

func (s *Server) listCellSave(w http.ResponseWriter, r *http.Request) {
	t, row, f, ed, ok := s.editTarget(w, r)
	if !ok {
		return
	}
	err := ed.Save(s, r, row.ID, r.FormValue("value"))
	switch {
	case errors.Is(err, errBadValue):
		s.renderCellEdit(w, http.StatusUnprocessableEntity, t, row, f, ed, "That value isn't allowed.")
		return
	case errors.Is(err, store.ErrNotManual):
		s.renderCellEdit(w, http.StatusUnprocessableEntity, t, row, f, ed, "Discovery maintains this CI.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	rows, _, err := s.allowedRows(r, t, []string{row.ID}, f.Key)
	if err != nil || len(rows) == 0 {
		s.serverError(w, r, fmt.Errorf("reload %s %s: %v", t.Key, row.ID, err))
		return
	}
	s.pages.partial(w, http.StatusOK, "", "list-cell", map[string]any{"Base": s.cfg.PublicURL.Path,
		"Cell": s.cellEdit(t, rows[0], f, ed, principal(r).Grants)})
}

// Bulk actions ------------------------------------------------------------------

// bulkAction runs on the selected rows, or with Go, opens the page Go
// returns for them (a change's form, which asks before anything runs).
// Options, if any, are the values to pick from.
type bulkAction struct {
	Key      string
	Label    string
	Options  []list.Option
	Editable bool // only rows the table's EditExpr allows
	Run      func(s *Server, r *http.Request, id, value string) error
	Go       func(ids []string) string
}

// changeFor is a bulk action's Go that opens the new-change form for the
// action with the rows picked as param.
func changeFor(name, param string) func(ids []string) string {
	return func(ids []string) string {
		v := url.Values{"action": {name}, param: ids}
		return "/changes/new?" + v.Encode()
	}
}

func (s *Server) bulkActions(ctx context.Context, t *list.Table, g rbac.Grants) []bulkAction {
	switch t.Key {
	case "ci":
		if g.Has(rbac.Operator) {
			return []bulkAction{{Key: "status", Label: "Set status of agentless CIs", Options: opts(ciStatuses...),
				Editable: true, Run: func(s *Server, r *http.Request, id, value string) error {
					return saveCIField("status")(s, r, id, value)
				}}}
		}
	case "work":
		names, err := s.store.TransitionNames(ctx)
		if err != nil {
			return nil
		}
		var transitions []list.Option
		for _, n := range names {
			if !n.ToDone {
				transitions = append(transitions, list.Option{Value: n.Name, Label: n.Name})
				continue
			}
			for _, res := range store.Resolutions {
				transitions = append(transitions, list.Option{Value: n.Name + resolutionSep + res, Label: n.Name + ": " + res})
			}
		}
		return []bulkAction{
			{Key: "transition", Label: "Transition", Options: transitions, Run: bulkTransition},
			{Key: "priority", Label: "Set priority", Options: opts(store.Priorities...), Run: func(s *Server, r *http.Request, id, value string) error {
				return saveItemField("priority")(s, r, id, value)
			}},
		}
	case "container":
		if !g.HasAnywhere(rbac.Operator) {
			return nil
		}
		return []bulkAction{{Key: "restart", Label: "Restart…", Go: changeFor(action.ContainerRestart, "container")}}
	case "stack":
		if !g.HasAnywhere(rbac.Operator) {
			return nil
		}
		return []bulkAction{
			{Key: "pull", Label: "Pull images…", Go: changeFor(action.ComposePull, "stack")},
			{Key: "update", Label: "Update…", Go: changeFor(action.ComposeUpdate, "stack")},
			{Key: "start", Label: "Start…", Go: changeFor(action.ComposeStart, "stack")},
			{Key: "archive", Label: "Archive…", Go: changeFor(action.ComposeArchive, "stack")},
			{Key: "move", Label: "Move…", Go: changeFor(action.ComposeMove, "stack")},
		}
	case "alert":
		if !g.HasAnywhere(rbac.Operator) {
			return nil
		}
		return []bulkAction{
			{Key: "ack", Label: "Acknowledge", Run: bulkAck},
			{Key: "close", Label: "Close", Run: bulkClose},
			{Key: "silence", Label: "Silence for", Options: opts(silenceSpans...), Run: bulkSilence},
		}
	case "host":
		if !g.Has(rbac.Admin) {
			return nil
		}
		groups, err := s.store.ListHostGroups(ctx)
		if err != nil || len(groups) == 0 {
			return nil
		}
		var o []list.Option
		for _, hg := range groups {
			o = append(o, list.Option{Value: hg.ID, Label: hg.Name})
		}
		edit := func(add bool) func(s *Server, r *http.Request, id, value string) error {
			return func(s *Server, r *http.Request, id, value string) error {
				h, err := s.store.GetHost(r.Context(), id)
				if err != nil {
					return err
				}
				ids := slices.DeleteFunc(slices.Clone(h.GroupIDs), func(g string) bool { return g == value })
				if add {
					ids = append(ids, value)
				}
				if slices.Equal(ids, h.GroupIDs) {
					return nil
				}
				return s.store.SetHostGroups(r.Context(), s.actor(r), id, ids)
			}
		}
		return []bulkAction{
			{Key: "add_group", Label: "Add to host group", Options: o, Run: edit(true)},
			{Key: "remove_group", Label: "Remove from host group", Options: o, Run: edit(false)},
		}
	}
	return nil
}

func (s *Server) listBulk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, path, err := s.listTable(ctx, r.PathValue("table"))
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "No such list.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	path = listBack(t.Key, path, r.FormValue("path"))
	back, _ := url.ParseQuery(r.FormValue("back"))
	if !back.Has("sort") {
		back.Set("sort", t.Default.Sort.Field)
	}
	done := func(param, msg string) {
		back.Set(param, msg)
		http.Redirect(w, r, s.url(path+"?"+back.Encode()), http.StatusSeeOther)
	}
	actions := s.bulkActions(ctx, t, principal(r).Grants)
	i := slices.IndexFunc(actions, func(a bulkAction) bool { return a.Key == r.FormValue("action") })
	if i < 0 {
		done("error", "Pick an action.")
		return
	}
	a := actions[i]
	value := r.FormValue("value")
	if a.Options != nil && !slices.ContainsFunc(a.Options, func(o list.Option) bool { return o.Value == value }) {
		done("error", "Pick a value for "+strings.ToLower(a.Label)+".")
		return
	}
	ids := r.Form["id"]
	if len(ids) == 0 {
		done("error", "Select some rows first.")
		return
	}
	if len(ids) > 1000 {
		done("error", "Select at most 1000 rows at a time.")
		return
	}
	rows, _, err := s.allowedRows(r, t, ids)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if a.Go != nil {
		picked := make([]string, 0, len(rows))
		for _, row := range rows {
			picked = append(picked, row.ID)
		}
		if len(picked) == 0 {
			done("error", "None of those can be changed here.")
			return
		}
		http.Redirect(w, r, s.url(a.Go(picked)), http.StatusSeeOther)
		return
	}
	n, skipped := 0, len(ids)-len(rows)
	for _, row := range rows {
		if a.Editable && !row.Editable {
			skipped++
			continue
		}
		if err := a.Run(s, r, row.ID, value); err != nil {
			if errors.Is(err, store.ErrNotManual) || errors.Is(err, store.ErrNotFound) {
				skipped++
				continue
			}
			s.serverError(w, r, err)
			return
		}
		n++
	}
	msg := fmt.Sprintf("%s: %s.", a.Label, plural(n, t.Noun))
	if skipped > 0 {
		msg += fmt.Sprintf(" Skipped %d that can't be changed here.", skipped)
	}
	done("notice", msg)
}

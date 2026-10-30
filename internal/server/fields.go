package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/store"
)

// Custom fields, field groups and form layouts (docs/data-model.md §10).
// Admins define fields and groups under Settings, apply groups to a
// project's ticket types on the project, and lay out each screen per
// ticket type, with a project overriding the type's default when it needs
// to.

var coreFieldLabels = map[string]string{
	"title": "Title", "description": "Description", "priority": "Priority", "impact": "Impact", "urgency": "Urgency",
	"assignee": "Assignee", "parent": "Parent", "estimate": "Estimate", "due": "Due",
}

var fieldTypeLabels = map[string]string{
	store.FieldText: "Text", store.FieldTextarea: "Long text", store.FieldNumber: "Number", store.FieldDate: "Date",
	store.FieldDatetime: "Date and time", store.FieldBool: "Yes or no", store.FieldSelect: "Pick one",
	store.FieldMultiselect: "Pick several", store.FieldUser: "User", store.FieldCI: "CI", store.FieldItem: "Work item",
	store.FieldURL: "Link",
}

func fieldTypeLabel(t string) string {
	if l, ok := fieldTypeLabels[t]; ok {
		return l
	}
	return t
}

// hasDefault reports whether a field type takes a default in a group:
// users, CIs and items differ per item.
func hasDefault(t string) bool {
	return t != store.FieldUser && t != store.FieldCI && t != store.FieldItem
}

// Fields (Settings) -------------------------------------------------------------------

type fieldsView struct {
	Fields []store.FieldDef
	Edit   store.FieldDef // the form: empty ID for a new field
	Types  []string
	Notice string
	Error  string
}

func (s *Server) fieldsPage(w http.ResponseWriter, r *http.Request, v fieldsView, status int) {
	var err error
	if v.Fields, err = s.store.ListFieldDefs(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Types = store.FieldTypes
	s.pages.render(w, status, "fields", s.data(r, "Custom fields", v))
}

func (s *Server) fields(w http.ResponseWriter, r *http.Request) {
	v := fieldsView{Edit: store.FieldDef{Type: store.FieldText}, Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	if id := r.URL.Query().Get("edit"); id != "" {
		f, err := s.store.GetFieldDef(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		if err == nil {
			v.Edit = f
		}
	}
	s.fieldsPage(w, r, v, http.StatusOK)
}

// splitOptions reads options typed one per line, dropping blanks and
// repeats.
func splitOptions(s string) []string {
	var out []string
	for _, o := range strings.Split(s, "\n") {
		if o = strings.TrimSpace(o); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

func (s *Server) fieldSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in := store.FieldDef{ID: id, Key: strings.TrimSpace(r.FormValue("key")), Label: strings.TrimSpace(r.FormValue("label")),
		Type: r.FormValue("type"), Options: splitOptions(r.FormValue("options")),
		Description: strings.TrimSpace(r.FormValue("description"))}
	if id != "" {
		cur, err := s.store.GetFieldDef(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			s.errorPage(w, r, http.StatusNotFound, "No such field.")
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		in.Key, in.Type = cur.Key, cur.Type
	}
	var msg string
	switch {
	case id == "" && !store.FieldKeyRe.MatchString(in.Key):
		msg = "The key is lower-case letters, digits and underscores, starting with a letter, e.g. os_version."
	case in.Label == "":
		msg = "Enter a label."
	case !slices.Contains(store.FieldTypes, in.Type):
		msg = "Pick a type."
	case in.HasOptions() && len(in.Options) == 0:
		msg = "List the options, one per line."
	}
	if msg == "" {
		_, err := s.store.SaveFieldDef(r.Context(), s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrConflict):
			msg = "A field with key " + in.Key + " already exists."
		case errors.Is(err, store.ErrNotFound):
			s.errorPage(w, r, http.StatusNotFound, "No such field.")
			return
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		s.fieldsPage(w, r, fieldsView{Edit: in, Error: msg}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/fields?notice="+url.QueryEscape("Saved "+in.Label+".")), http.StatusSeeOther)
}

func (s *Server) fieldDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteFieldDef(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrInUse):
		http.Redirect(w, r, s.url("/settings/fields?error="+url.QueryEscape("Take the field out of its groups first.")), http.StatusSeeOther)
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such field.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/fields?notice="+url.QueryEscape("Deleted.")), http.StatusSeeOther)
	}
}

// Field groups (Settings) -------------------------------------------------------------

type fieldGroupsView struct {
	Groups []store.FieldGroup
	Notice string
}

func (s *Server) fieldGroups(w http.ResponseWriter, r *http.Request) {
	v := fieldGroupsView{Notice: r.URL.Query().Get("notice")}
	var err error
	if v.Groups, err = s.store.ListFieldGroups(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "field_groups", s.data(r, "Field groups", v))
}

// groupFieldRow is one field on the group form.
type groupFieldRow struct {
	Field    store.FieldDef
	On       bool
	Position int
	Required bool
	Default  string
}

type fieldGroupView struct {
	Group store.FieldGroup
	New   bool
	Rows  []groupFieldRow
	Error string
}

// fieldGroupForm shows the group form. rows, when set, are the form as
// typed; otherwise they come from the group.
func (s *Server) fieldGroupForm(w http.ResponseWriter, r *http.Request, v fieldGroupView, status int) {
	if v.Rows == nil {
		defs, err := s.store.ListFieldDefs(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, f := range defs {
			row := groupFieldRow{Field: f, Position: len(v.Group.Fields) + len(v.Rows) + 1}
			if gf, ok := v.Group.Field(f.ID); ok {
				row.On, row.Position, row.Required = true, gf.Position+1, gf.Required
				row.Default = s.inputText(f, gf.Default)
			}
			v.Rows = append(v.Rows, row)
		}
		sort.SliceStable(v.Rows, func(i, j int) bool {
			if v.Rows[i].On != v.Rows[j].On {
				return v.Rows[i].On
			}
			return v.Rows[i].On && v.Rows[i].Position < v.Rows[j].Position
		})
	}
	title := "New field group"
	if !v.New {
		title = "Edit " + v.Group.Name
	}
	s.pages.render(w, status, "field_group", s.data(r, title, v))
}

func (s *Server) fieldGroupNew(w http.ResponseWriter, r *http.Request) {
	s.fieldGroupForm(w, r, fieldGroupView{New: true}, http.StatusOK)
}

func (s *Server) fieldGroupEdit(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetFieldGroup(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such field group.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.fieldGroupForm(w, r, fieldGroupView{Group: g}, http.StatusOK)
}

func (s *Server) fieldGroupSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()
	id := r.PathValue("id")
	in := store.FieldGroupInput{Name: strings.TrimSpace(r.FormValue("name")), Description: strings.TrimSpace(r.FormValue("description"))}
	v := fieldGroupView{New: id == "", Group: store.FieldGroup{ID: id, Name: in.Name, Description: in.Description}}
	defs, err := s.store.ListFieldDefs(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var msg string
	type picked struct {
		pos int
		in  store.GroupFieldInput
	}
	var chosen []picked
	for i, f := range defs {
		row := groupFieldRow{Field: f, On: slices.Contains(r.Form["field"], f.ID), Required: r.FormValue("req_"+f.ID) == "1",
			Default: strings.TrimSpace(r.FormValue("def_" + f.ID))}
		row.Position, err = strconv.Atoi(r.FormValue("pos_" + f.ID))
		if err != nil {
			row.Position = 1000 + i
		}
		v.Rows = append(v.Rows, row)
		if !row.On {
			continue
		}
		gf := store.GroupFieldInput{FieldID: f.ID, Required: row.Required}
		if row.Default != "" && hasDefault(f.Type) {
			raw := []string{row.Default}
			if f.Type == store.FieldMultiselect {
				raw = strings.Split(row.Default, ",")
			}
			gf.Default, err = f.Parse(raw, s.cfg.Location)
			var bad store.ErrFieldValue
			if errors.As(err, &bad) && msg == "" {
				msg = "The default for " + bad.Error()
			}
		}
		chosen = append(chosen, picked{row.Position, gf})
	}
	sort.SliceStable(chosen, func(i, j int) bool { return chosen[i].pos < chosen[j].pos })
	for _, c := range chosen {
		in.Fields = append(in.Fields, c.in)
	}
	if in.Name == "" && msg == "" {
		msg = "Enter a name."
	}
	if msg == "" {
		_, err = s.store.SaveFieldGroup(ctx, s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrConflict):
			msg = "A field group called " + in.Name + " already exists."
		case errors.Is(err, store.ErrNotFound):
			msg = "That group or one of its fields no longer exists."
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		v.Error = msg
		s.fieldGroupForm(w, r, v, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/field-groups?notice="+url.QueryEscape("Saved "+in.Name+".")), http.StatusSeeOther)
}

func (s *Server) fieldGroupDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteFieldGroup(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such field group.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/field-groups?notice="+url.QueryEscape("Deleted.")), http.StatusSeeOther)
	}
}

// A project's ticket type: groups and layouts -----------------------------------------

// layoutState says where a screen's layout comes from.
type layoutState struct {
	Screen string
	Own    bool // the project overrides the type's default
	Shared bool // the create layout serves view too
}

type projectTypeView struct {
	Project store.Project
	Type    store.ProjectType
	Groups  []store.FieldGroup // every group, the applied ones first
	Applied map[string]int     // group ID: position, from 1
	Layouts []layoutState
	Notice  string
	Error   string
}

// loadProjectType fetches the project and one of its ticket types, by key.
func (s *Server) loadProjectType(w http.ResponseWriter, r *http.Request) (store.Project, store.ProjectType, bool) {
	p, ok := s.loadProject(w, r)
	if !ok {
		return p, store.ProjectType{}, false
	}
	for _, t := range p.Types {
		if t.Key == r.PathValue("type") {
			return p, t, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "The project doesn't offer that ticket type.")
	return p, store.ProjectType{}, false
}

func (s *Server) projectTypePage(w http.ResponseWriter, r *http.Request) {
	p, t, ok := s.loadProjectType(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	v := projectTypeView{Project: p, Type: t, Applied: map[string]int{}, Notice: r.URL.Query().Get("notice"),
		Error: r.URL.Query().Get("error")}
	applied, err := s.store.ProjectTypeGroups(ctx, p.ID, t.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	all, err := s.store.ListFieldGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for i, g := range applied {
		v.Applied[g.ID] = i + 1
		v.Groups = append(v.Groups, g)
	}
	for _, g := range all {
		if _, ok := v.Applied[g.ID]; !ok {
			v.Groups = append(v.Groups, g)
		}
	}
	for _, screen := range store.Screens {
		st := layoutState{Screen: screen}
		l, err := s.store.GetLayout(ctx, p.ID, t.ID, screen)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		st.Own, st.Shared = err == nil, err == nil && l.ViewUsesCreate
		v.Layouts = append(v.Layouts, st)
	}
	s.pages.render(w, http.StatusOK, "project_type", s.data(r, p.Key+" "+t.Name, v))
}

func (s *Server) projectTypeGroups(w http.ResponseWriter, r *http.Request) {
	p, t, ok := s.loadProjectType(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	type picked struct {
		id  string
		pos int
	}
	var chosen []picked
	for i, id := range r.Form["group"] {
		pos, err := strconv.Atoi(r.FormValue("gpos_" + id))
		if err != nil {
			pos = 1000 + i
		}
		chosen = append(chosen, picked{id, pos})
	}
	sort.SliceStable(chosen, func(i, j int) bool { return chosen[i].pos < chosen[j].pos })
	var ids []string
	for _, c := range chosen {
		if !slices.Contains(ids, c.id) {
			ids = append(ids, c.id)
		}
	}
	back := "/projects/" + p.Key + "/types/" + t.Key
	err := s.store.SetProjectTypeGroups(r.Context(), s.actor(r), p.ID, t.ID, ids)
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, s.url(back+"?error="+url.QueryEscape("That field group no longer exists.")), http.StatusSeeOther)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url(back+"?notice="+url.QueryEscape("Saved the field groups.")), http.StatusSeeOther)
	}
}

// Layout editor -----------------------------------------------------------------------

type layoutEditView struct {
	Heading  string
	Screen   string
	Action   string // where the form posts, under the public URL
	Back     string
	Reset    string // posts to drop the stored layout; "" when none is stored
	ResetMsg string
	// Source says where the layout shown comes from when nothing is
	// stored at this level.
	Source         string
	Sections       string // JSON
	Palette        []paletteItem
	ViewUsesCreate bool
	Notice         string
	Error          string
}

type paletteItem struct {
	Kind    string `json:"kind"`
	Field   string `json:"field,omitempty"`
	GroupID string `json:"group_id,omitempty"`
	FieldID string `json:"field_id,omitempty"`
	Label   string `json:"label"`
	Note    string `json:"note,omitempty"`
}

// palette lists what a layout can place. applied, when not nil, marks the
// groups and fields that apply.
func (s *Server) palette(r *http.Request, applied []store.FieldGroup) ([]paletteItem, error) {
	groups, err := s.store.ListFieldGroups(r.Context())
	if err != nil {
		return nil, err
	}
	defs, err := s.store.ListFieldDefs(r.Context())
	if err != nil {
		return nil, err
	}
	var items []paletteItem
	for _, c := range store.CoreFields {
		items = append(items, paletteItem{Kind: "core", Field: c, Label: coreFieldLabels[c]})
	}
	isApplied := func(fn func(store.FieldGroup) bool) bool {
		return applied == nil || slices.ContainsFunc(applied, fn)
	}
	for _, g := range groups {
		var names []string
		for _, f := range g.Fields {
			names = append(names, f.Label)
		}
		note := strings.Join(names, ", ")
		if !isApplied(func(a store.FieldGroup) bool { return a.ID == g.ID }) {
			note = "not applied here: " + note
		}
		items = append(items, paletteItem{Kind: "group", GroupID: g.ID, Label: g.Name, Note: note})
	}
	for _, f := range defs {
		note := fieldTypeLabel(f.Type)
		if !isApplied(func(a store.FieldGroup) bool { return a.Holds(f.ID) }) {
			note += ", not applied here"
		}
		items = append(items, paletteItem{Kind: "field", FieldID: f.ID, Label: f.Label, Note: note})
	}
	return items, nil
}

func sectionsJSON(sections []store.LayoutSection) string {
	if sections == nil {
		sections = []store.LayoutSection{}
	}
	b, _ := json.Marshal(sections)
	return string(b)
}

func screenOK(screen string) bool { return slices.Contains(store.Screens, screen) }

// typeLayoutTarget fetches the ticket type of a default layout.
func (s *Server) typeLayoutTarget(w http.ResponseWriter, r *http.Request) (store.TicketType, string, bool) {
	t, err := s.store.GetTicketType(r.Context(), r.PathValue("id"))
	screen := r.PathValue("screen")
	if errors.Is(err, store.ErrNotFound) || (err == nil && !screenOK(screen)) {
		s.errorPage(w, r, http.StatusNotFound, "No such layout.")
		return t, screen, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return t, screen, false
	}
	return t, screen, true
}

// typeLayout edits a ticket type's default layout for a screen.
func (s *Server) typeLayout(w http.ResponseWriter, r *http.Request) {
	t, screen, ok := s.typeLayoutTarget(w, r)
	if !ok {
		return
	}
	path := "/settings/ticket-types/" + t.ID + "/layouts/" + screen
	v := layoutEditView{Heading: t.Name + ": default " + screen + " screen", Screen: screen, Action: path,
		Back: "/settings/ticket-types", Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	if err := s.fillLayoutEdit(r, &v, "", t.ID, screen, nil); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Reset != "" {
		v.ResetMsg = "Remove the default: screens use the core fields, then each applied group."
	}
	s.pages.render(w, http.StatusOK, "layout", s.data(r, v.Heading, v))
}

// fillLayoutEdit fills the editor with the layout stored for the level, or
// what the level inherits.
func (s *Server) fillLayoutEdit(r *http.Request, v *layoutEditView, projectID, typeID, screen string, applied []store.FieldGroup) error {
	ctx := r.Context()
	var err error
	if v.Palette, err = s.palette(r, applied); err != nil {
		return err
	}
	l, err := s.store.GetLayout(ctx, projectID, typeID, screen)
	if err == nil {
		v.Sections, v.ViewUsesCreate, v.Reset = sectionsJSON(l.Sections), l.ViewUsesCreate, v.Action+"/delete"
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	var inherited *store.Layout
	if projectID != "" {
		if inherited, err = s.store.EffectiveLayout(ctx, "", typeID, screen); err != nil {
			return err
		}
	} else if screen == store.ScreenView {
		if c, err := s.store.GetLayout(ctx, "", typeID, store.ScreenCreate); err == nil && c.ViewUsesCreate {
			inherited = &c
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	switch {
	case inherited != nil && inherited.ProjectID == "" && projectID != "":
		v.Source = "This project uses the ticket type's default " + inherited.Screen + " layout. Saving here overrides it for this project."
		v.Sections = sectionsJSON(inherited.Sections)
	case inherited != nil:
		v.Source = "The create layout serves this screen too. Saving a view layout here replaces that."
		v.Sections = sectionsJSON(inherited.Sections)
	default:
		v.Source = "Nothing is laid out yet: the screen shows the core fields, then each applied group."
		v.Sections = sectionsJSON(store.DefaultSections(applied))
	}
	return nil
}

// layoutInput reads the editor's form.
func layoutInput(r *http.Request) ([]store.LayoutSection, bool, error) {
	var sections []store.LayoutSection
	if err := json.Unmarshal([]byte(r.FormValue("sections")), &sections); err != nil {
		return nil, false, errBadInput("The layout isn't valid JSON: " + err.Error())
	}
	return store.CleanSections(sections), r.FormValue("view_uses_create") == "1", nil
}

func (s *Server) typeLayoutSave(w http.ResponseWriter, r *http.Request) {
	t, screen, ok := s.typeLayoutTarget(w, r)
	if !ok {
		return
	}
	path := "/settings/ticket-types/" + t.ID + "/layouts/" + screen
	s.saveLayout(w, r, store.Layout{TypeID: t.ID, Screen: screen}, path)
}

func (s *Server) saveLayout(w http.ResponseWriter, r *http.Request, l store.Layout, path string) {
	var err error
	l.Sections, l.ViewUsesCreate, err = layoutInput(r)
	var bad errBadInput
	if errors.As(err, &bad) {
		http.Redirect(w, r, s.url(path+"?error="+url.QueryEscape(string(bad))), http.StatusSeeOther)
		return
	}
	if err == nil {
		err = s.store.SaveLayout(r.Context(), s.actor(r), l)
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url(path+"?notice="+url.QueryEscape("Saved.")), http.StatusSeeOther)
}

func (s *Server) typeLayoutDelete(w http.ResponseWriter, r *http.Request) {
	t, screen, ok := s.typeLayoutTarget(w, r)
	if !ok {
		return
	}
	path := "/settings/ticket-types/" + t.ID + "/layouts/" + screen
	s.deleteLayout(w, r, "", t.ID, screen, path)
}

func (s *Server) deleteLayout(w http.ResponseWriter, r *http.Request, projectID, typeID, screen, path string) {
	err := s.store.DeleteLayout(r.Context(), s.actor(r), projectID, typeID, screen)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url(path+"?notice="+url.QueryEscape("Removed.")), http.StatusSeeOther)
}

// projectLayoutTarget fetches the project, ticket type and screen of a
// project's layout.
func (s *Server) projectLayoutTarget(w http.ResponseWriter, r *http.Request) (store.Project, store.ProjectType, string, bool) {
	p, t, ok := s.loadProjectType(w, r)
	screen := r.PathValue("screen")
	if ok && !screenOK(screen) {
		s.errorPage(w, r, http.StatusNotFound, "No such layout.")
		return p, t, screen, false
	}
	return p, t, screen, ok
}

func (s *Server) projectLayout(w http.ResponseWriter, r *http.Request) {
	p, t, screen, ok := s.projectLayoutTarget(w, r)
	if !ok {
		return
	}
	applied, err := s.store.ProjectTypeGroups(r.Context(), p.ID, t.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if applied == nil {
		applied = []store.FieldGroup{}
	}
	back := "/projects/" + p.Key + "/types/" + t.Key
	v := layoutEditView{Heading: p.Key + " " + t.Name + ": " + screen + " screen", Screen: screen,
		Action: back + "/layouts/" + screen, Back: back, Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	if err := s.fillLayoutEdit(r, &v, p.ID, t.ID, screen, applied); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Reset != "" {
		v.ResetMsg = "Use the ticket type's default layout again."
	}
	s.pages.render(w, http.StatusOK, "layout", s.data(r, v.Heading, v))
}

func (s *Server) projectLayoutSave(w http.ResponseWriter, r *http.Request) {
	p, t, screen, ok := s.projectLayoutTarget(w, r)
	if !ok {
		return
	}
	s.saveLayout(w, r, store.Layout{ProjectID: p.ID, TypeID: t.ID, Screen: screen},
		"/projects/"+p.Key+"/types/"+t.Key+"/layouts/"+screen)
}

func (s *Server) projectLayoutDelete(w http.ResponseWriter, r *http.Request) {
	p, t, screen, ok := s.projectLayoutTarget(w, r)
	if !ok {
		return
	}
	s.deleteLayout(w, r, p.ID, t.ID, screen, "/projects/"+p.Key+"/types/"+t.Key+"/layouts/"+screen)
}

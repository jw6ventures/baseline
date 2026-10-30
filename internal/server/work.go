package server

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Work items (docs/data-model.md §8). Anyone with a role can open, edit and
// comment on them: they track work rather than change hosts. What links to
// them follows the usual rules: a CI or change shows only to whoever may
// see it.

var statusLabels = map[string]string{store.StatusTodo: "To do", store.StatusInProgress: "In progress", store.StatusDone: "Done"}

func itemStatusLabel(s string) string {
	if l, ok := statusLabels[s]; ok {
		return l
	}
	return s
}

type workListView struct {
	CanCreate bool // there is an open project to file into
	List      *listView
}

func (s *Server) workList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "work")
	if !ok {
		return
	}
	projects, err := s.store.ListProjects(r.Context(), false)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderList(w, r, "work_items", "Work items", workListView{CanCreate: len(projects) > 0, List: v}, v)
}

// loadItem fetches the work item named in the path, OPS-42.
func (s *Server) loadItem(w http.ResponseWriter, r *http.Request) (store.WorkItem, bool) {
	it, err := s.store.GetWorkItemByRef(r.Context(), r.PathValue("ref"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such work item.")
		return it, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return it, false
	}
	// An old reference, from before a move to another project: go to the
	// item's own.
	if old := r.PathValue("ref"); r.Method == http.MethodGet && !strings.EqualFold(old, it.Ref()) {
		target := "/work/" + it.Ref() + strings.TrimPrefix(r.URL.Path, "/work/"+old)
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, s.url(target), http.StatusMovedPermanently)
		return it, false
	}
	return it, true
}

// backToItem shows the item again with a notice or error, keeping the
// related list the form was posted from open.
func (s *Server) backToItem(w http.ResponseWriter, r *http.Request, ref, kind, msg string) {
	u := "/work/" + ref + "?" + kind + "=" + url.QueryEscape(msg)
	if rel := r.FormValue("rel"); slices.Contains(relTabKeys, rel) {
		u += "&rel=" + rel
	}
	http.Redirect(w, r, s.url(u), http.StatusSeeOther)
}

// linkedItem is a work item linked to a CI or change, and how.
type linkedItem struct {
	Rel  string
	Item store.WorkItem
}

type itemCIView struct {
	store.ItemCI
	Link string
}

type workItemView struct {
	Item        store.WorkItem
	CIs         []itemCIView
	Changes     []store.ItemChange
	Links       []store.ItemLink
	Children    []store.WorkItem
	SLAs        []slaClockView
	Watchers    []store.User
	Watching    bool
	RelTabs     []relTab
	Rel         string // the open related list
	Activities  []activityEntry
	Filters     []activityFilter
	Activity    string     // the activity filter
	Targets     []store.CI // CIs the user may link
	Transitions []itemTransition
	Users       []store.User // for transition screens that ask for an assignee
	Sections    []formSection
	Resolutions []string
	CIRoles     []string
	ChangeKinds []string
	LinkKinds   []string
	CanMove     bool // admins move items and change their type, by migration
	Notice      string
	Error       string
}

func (s *Server) workPage(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	v := workItemView{Item: it, Resolutions: store.Resolutions,
		CIRoles: store.ItemCIRoles, ChangeKinds: store.ItemChangeKinds, LinkKinds: store.ItemLinkKinds,
		CanMove: adminOnly(principal(r).Grants),
		Notice:  r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	ids, err := s.ciHostIDs(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	cis, err := s.store.WorkItemCIs(ctx, it.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, c := range cis {
		if canSeeCI(c.CI, ids) {
			v.CIs = append(v.CIs, itemCIView{ItemCI: c, Link: ciLink(c.CI)})
		}
	}
	changes, err := s.store.WorkItemChanges(ctx, it.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(changes) > 0 {
		hosts, err := s.hostIndex(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, c := range changes {
			if canOnAll(principal(r).Grants, rbac.Viewer, c.Change.HostIDs, hosts) {
				v.Changes = append(v.Changes, c)
			}
		}
	}
	if v.Links, err = s.store.WorkItemLinks(ctx, it.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Children, err = s.store.ListWorkItems(ctx, store.WorkItemFilter{ParentID: it.ID, Status: "all"}); err != nil {
		s.serverError(w, r, err)
		return
	}
	slas, err := s.store.WorkItemSLAs(ctx, it.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v.SLAs = slaClockViews(slas, time.Now())
	comments, err := s.store.WorkItemComments(ctx, it.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Watchers, err = s.store.WorkItemWatchers(ctx, it.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	me := principal(r).User.ID
	v.Watching = slices.ContainsFunc(v.Watchers, func(u store.User) bool { return u.ID == me })
	history, err := s.store.WorkItemHistory(ctx, it.ID, 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if history, err = s.visibleHistory(r, history, ids); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Activities, v.Filters, v.Activity = activityStream(comments, history, r.URL.Query().Get("activity"))
	relTabs(&v, r.URL.Query().Get("rel"))
	if v.Targets, err = s.store.ListCIs(ctx, store.CIFilter{HostIDs: ids, Limit: 1000}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Transitions, err = s.transitionsFor(r, it); err != nil {
		s.serverError(w, r, err)
		return
	}
	if slices.ContainsFunc(v.Transitions, func(t itemTransition) bool { return t.Asks("assignee") }) {
		if v.Users, err = s.store.ListUsers(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	form, err := s.store.ResolveForm(ctx, it.ProjectID, it.TypeID, store.ScreenView)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Sections, err = s.screenSections(r, form, it); err != nil {
		s.serverError(w, r, err)
		return
	}
	dropHeaderFields(v.Sections)
	s.pages.render(w, http.StatusOK, "work_item", s.data(r, it.Ref()+" "+it.Title, v))
}

// itemTransition is a transition out of an item's status, and whether the
// user may run it.
type itemTransition struct {
	store.WfTransition
	Allowed bool
}

// runner is the user running a transition.
func runner(r *http.Request) store.Runner {
	g := principal(r).Grants
	return store.Runner{UserID: principal(r).User.ID, HasRole: func(role string) bool { return g.Has(rbac.Role(role)) }}
}

// transitionsFor lists the transitions out of an item's status, and which
// the user may run.
func (s *Server) transitionsFor(r *http.Request, it store.WorkItem) ([]itemTransition, error) {
	ts, err := s.store.ItemTransitions(r.Context(), it)
	if err != nil {
		return nil, err
	}
	run := runner(r)
	var out []itemTransition
	for _, t := range ts {
		out = append(out, itemTransition{WfTransition: t, Allowed: t.Allowed(it, run)})
	}
	return out, nil
}

// visibleHistory drops the entries about CIs and changes the user may not
// see, or that no longer exist.
func (s *Server) visibleHistory(r *http.Request, events []store.ItemEvent, hostIDs []string) ([]store.ItemEvent, error) {
	var hosts map[string]store.Host
	seen := map[string]bool{}
	var out []store.ItemEvent
	for _, e := range events {
		key := e.CIID + "|" + e.ChangeID
		ok, done := seen[key]
		switch {
		case done:
		case e.CIID != "":
			c, err := s.store.GetCI(r.Context(), e.CIID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			ok = err == nil && canSeeCI(c, hostIDs)
		case e.ChangeID != "":
			c, err := s.store.GetChange(r.Context(), e.ChangeID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			if err == nil && hosts == nil {
				if hosts, err = s.hostIndex(r); err != nil {
					return nil, err
				}
			}
			ok = err == nil && canOnAll(principal(r).Grants, rbac.Viewer, c.HostIDs, hosts)
		default:
			ok = true
		}
		seen[key] = ok
		if ok {
			out = append(out, e)
		}
	}
	return out, nil
}

type workFormView struct {
	Item       store.WorkItem
	New        bool
	Projects   []store.Project // open projects, for a new item
	Project    store.Project
	Users      []store.User
	Targets    []store.CI // CIs the user may pick for a CI field
	Sections   []formSection
	Priorities []string
	Levels     []string
	Error      string
}

func (s *Server) workForm(w http.ResponseWriter, r *http.Request, v workFormView, status int) {
	ctx := r.Context()
	var err error
	if v.New {
		if v.Projects, err = s.store.ListProjects(ctx, false); err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(v.Projects) == 0 {
			s.errorPage(w, r, http.StatusConflict, "There are no open projects to file work items in. An admin creates them under Projects.")
			return
		}
		if !slices.ContainsFunc(v.Projects, func(p store.Project) bool { return p.Key == v.Item.ProjectKey }) {
			v.Item.ProjectKey, v.Item.TypeID = v.Projects[0].Key, ""
		}
	}
	if v.Project, err = s.store.GetProject(ctx, v.Item.ProjectKey); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.errorPage(w, r, http.StatusNotFound, "No such project.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if v.New && !v.Project.Offers(v.Item.TypeID) {
		v.Item.TypeID = v.Project.DefaultType()
	}
	if v.Users, err = s.store.ListUsers(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	form, err := s.store.ResolveForm(ctx, v.Project.ID, v.Item.TypeID, store.ScreenCreate)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Item.Custom == nil {
		v.Item.Custom = customDefaults(form)
	}
	if v.Sections, err = s.screenSections(r, form, v.Item); err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(form.Fields) > 0 {
		ids, err := s.ciHostIDs(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if v.Targets, err = s.store.ListCIs(ctx, store.CIFilter{HostIDs: ids, Limit: 1000}); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	v.Priorities, v.Levels = store.Priorities, store.Levels
	title := "New work item"
	if !v.New {
		title = "Edit " + v.Item.Ref()
	}
	s.pages.render(w, status, "work_item_form", s.data(r, title, v))
}

// workNew shows the form for a new item. Picking the project reloads it with
// that project's ticket types.
func (s *Server) workNew(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	it := store.WorkItem{ProjectKey: strings.ToUpper(q.Get("project")), TypeID: q.Get("type"), Priority: "medium",
		Title: q.Get("title")}
	if parent := q.Get("parent"); parent != "" {
		it.ParentRef = strings.ToUpper(parent)
	}
	s.workForm(w, r, workFormView{New: true, Item: it}, http.StatusOK)
}

func (s *Server) workEdit(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	s.workForm(w, r, workFormView{Item: it}, http.StatusOK)
}

// workInput reads the work item form. echo is the form as typed.
func (s *Server) workInput(r *http.Request, echo store.WorkItem) (store.WorkItemInput, store.WorkItem, error) {
	in := store.WorkItemInput{
		Title: strings.TrimSpace(r.FormValue("title")), Description: strings.TrimSpace(r.FormValue("description")),
		Priority: r.FormValue("priority"), Impact: r.FormValue("impact"), Urgency: r.FormValue("urgency"),
		AssigneeID: r.FormValue("assignee"),
	}
	echo.Title, echo.Description, echo.Priority, echo.Impact, echo.Urgency = in.Title, in.Description, in.Priority, in.Impact, in.Urgency
	echo.AssigneeID = in.AssigneeID
	echo.ParentRef = strings.ToUpper(strings.TrimSpace(r.FormValue("parent")))
	switch {
	case in.Title == "":
		return in, echo, errBadInput("Enter a title.")
	case !slices.Contains(store.Priorities, in.Priority):
		return in, echo, errBadInput("Pick a priority.")
	case in.Impact != "" && !slices.Contains(store.Levels, in.Impact):
		return in, echo, errBadInput("Pick an impact.")
	case in.Urgency != "" && !slices.Contains(store.Levels, in.Urgency):
		return in, echo, errBadInput("Pick an urgency.")
	}
	if e := strings.TrimSpace(r.FormValue("estimate")); e != "" {
		f, err := strconv.ParseFloat(e, 64)
		if err != nil || f < 0 {
			return in, echo, errBadInput("The estimate is a number, 0 or more.")
		}
		in.Estimate, echo.Estimate = &f, &f
	}
	if d := strings.TrimSpace(r.FormValue("due")); d != "" {
		t, err := time.Parse(time.DateOnly, d)
		if err != nil {
			return in, echo, errBadInput("The due date is YYYY-MM-DD.")
		}
		in.DueAt, echo.DueAt = t, t
	}
	if echo.ParentRef != "" {
		parent, err := s.store.GetWorkItemByRef(r.Context(), echo.ParentRef)
		if errors.Is(err, store.ErrNotFound) {
			return in, echo, errBadInput("There's no work item " + echo.ParentRef + " to be the parent.")
		}
		if err != nil {
			return in, echo, err
		}
		in.ParentID = parent.ID
	}
	return in, echo, nil
}

// readCustom reads the create screen's custom fields into in, and into
// echo for showing the form again.
func (s *Server) readCustom(r *http.Request, in *store.WorkItemInput, echo *store.WorkItem, projectID, typeID string, current map[string]any) error {
	form, err := s.store.ResolveForm(r.Context(), projectID, typeID, store.ScreenCreate)
	if err != nil {
		return err
	}
	values, err := s.customInput(r, form, current)
	echo.Custom = withCustom(current, values)
	in.Custom = values
	return err
}

func (s *Server) workCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	echo := store.WorkItem{ProjectKey: strings.ToUpper(r.FormValue("project")), TypeID: r.FormValue("type")}
	in, echo, err := s.workInput(r, echo)
	var ref string
	if err == nil {
		var p store.Project
		p, err = s.store.GetProject(ctx, echo.ProjectKey)
		if errors.Is(err, store.ErrNotFound) {
			err, echo.ProjectKey = errBadInput("Pick a project."), ""
		}
		in.ProjectID, in.TypeID = p.ID, echo.TypeID
		if err == nil && !p.Offers(in.TypeID) {
			err = store.ErrTypeNotOffered
		}
		if err == nil {
			err = s.readCustom(r, &in, &echo, p.ID, in.TypeID, nil)
		}
		if err == nil {
			_, ref, err = s.store.CreateWorkItem(ctx, s.actor(r), principal(r).User.ID, in)
		}
		switch {
		case errors.Is(err, store.ErrTypeNotOffered):
			err = errBadInput("Pick one of the project's ticket types.")
		case errors.Is(err, store.ErrArchived):
			err = errBadInput("The project is archived.")
		case errors.Is(err, store.ErrNotFound):
			err = errBadInput("That assignee no longer exists.")
		}
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		s.workForm(w, r, workFormView{New: true, Item: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.backToItem(w, r, ref, "notice", "Created.")
}

func (s *Server) workUpdate(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	in, echo, err := s.workInput(r, it)
	if err == nil {
		err = s.readCustom(r, &in, &echo, it.ProjectID, it.TypeID, it.Custom)
	}
	if err == nil {
		err = s.store.UpdateWorkItem(r.Context(), s.actor(r), it.ID, in)
		switch {
		case errors.Is(err, store.ErrParentCycle):
			err = errBadInput("The parent can't be this item or one below it.")
		case errors.Is(err, store.ErrNotFound):
			err = errBadInput("That assignee or parent no longer exists.")
		}
	}
	var bad errBadInput
	if errors.As(err, &bad) {
		s.workForm(w, r, workFormView{Item: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.backToItem(w, r, it.Ref(), "notice", "Saved.")
}

// workTransition runs one of the transitions out of the item's status.
func (s *Server) workTransition(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	in := store.TransitionInput{Resolution: r.FormValue("resolution"), AssigneeID: r.FormValue("assignee"),
		Comment: r.FormValue("comment")}
	err := s.store.TransitionWorkItem(r.Context(), s.actor(r), runner(r), it.ID, r.FormValue("transition"), in)
	var bad *store.TransitionError
	switch {
	case errors.As(err, &bad):
		s.backToItem(w, r, it.Ref(), "error", bad.Msg)
	case errors.Is(err, store.ErrStaleTransition):
		s.backToItem(w, r, it.Ref(), "error", "That transition doesn't apply any more: the item has moved on.")
	case errors.Is(err, store.ErrTransitionDenied):
		s.backToItem(w, r, it.Ref(), "error", "You may not run that transition.")
	case errors.Is(err, store.ErrNotFound):
		s.backToItem(w, r, it.Ref(), "error", "That assignee no longer exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		it, err = s.store.GetWorkItem(r.Context(), it.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		s.backToItem(w, r, it.Ref(), "notice", "Now "+it.StatusName+".")
	}
}

func (s *Server) workComment(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	body := strings.TrimSpace(r.FormValue("body"))
	if body == "" {
		s.backToItem(w, r, it.Ref(), "error", "Write something first.")
		return
	}
	internal := r.FormValue("internal") == "1"
	if err := s.store.AddComment(r.Context(), s.actor(r), principal(r).User.ID, it.ID, body, internal); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "Comment added."
	if internal {
		msg = "Work note added."
	}
	s.backToItem(w, r, it.Ref(), "notice", msg)
}

func (s *Server) workWatch(w http.ResponseWriter, r *http.Request) {
	it, ok := s.loadItem(w, r)
	if !ok {
		return
	}
	on := r.FormValue("on") == "1"
	if err := s.store.SetWatching(r.Context(), s.actor(r), it.ID, principal(r).User.ID, on); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "You stopped watching this."
	if on {
		msg = "You're watching this."
	}
	s.backToItem(w, r, it.Ref(), "notice", msg)
}

// workCI links or unlinks a CI the user may see.
func (s *Server) workCI(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, ok := s.loadItem(w, r)
		if !ok {
			return
		}
		role := r.FormValue("role")
		if !slices.Contains(store.ItemCIRoles, role) {
			s.backToItem(w, r, it.Ref(), "error", "Pick a role.")
			return
		}
		c, err := s.store.GetCI(r.Context(), r.FormValue("ci"))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		ids, ierr := s.ciHostIDs(r)
		if ierr != nil {
			s.serverError(w, r, ierr)
			return
		}
		if err != nil || !canSeeCI(c, ids) {
			s.backToItem(w, r, it.Ref(), "error", "Pick a CI.")
			return
		}
		msg := "Linked " + c.Name + "."
		if link {
			err = s.store.LinkWorkItemCI(r.Context(), s.actor(r), it.ID, c.ID, role)
		} else {
			err = s.store.UnlinkWorkItemCI(r.Context(), s.actor(r), it.ID, c.ID, role)
			msg = "Unlinked " + c.Name + "."
		}
		switch {
		case errors.Is(err, store.ErrConflict):
			s.backToItem(w, r, it.Ref(), "error", c.Name+" is already linked that way.")
		case errors.Is(err, store.ErrNotFound):
			s.backToItem(w, r, it.Ref(), "error", c.Name+" isn't linked that way.")
		case err != nil:
			s.serverError(w, r, err)
		default:
			s.backToItem(w, r, it.Ref(), "notice", msg)
		}
	}
}

// parseChangeRef reads CHG-000123, or just 123.
func parseChangeRef(s string) (int64, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "CHG-")
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}

// workChange links or unlinks a change the user may see.
func (s *Server) workChange(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, ok := s.loadItem(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		kind := r.FormValue("kind")
		if !slices.Contains(store.ItemChangeKinds, kind) {
			s.backToItem(w, r, it.Ref(), "error", "Pick how the change relates.")
			return
		}
		var c store.Change
		n, ok := parseChangeRef(r.FormValue("change"))
		id, err := s.store.ChangeIDByNumber(ctx, n)
		if ok && err == nil {
			c, err = s.store.GetChange(ctx, id)
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		visible := false
		if ok && err == nil {
			hosts, herr := s.hostIndex(r)
			if herr != nil {
				s.serverError(w, r, herr)
				return
			}
			visible = canOnAll(principal(r).Grants, rbac.Viewer, c.HostIDs, hosts)
		}
		if !visible {
			s.backToItem(w, r, it.Ref(), "error", "There's no such change, e.g. CHG-000123.")
			return
		}
		msg := "Linked " + c.Ref() + "."
		if link {
			err = s.store.LinkWorkItemChange(ctx, s.actor(r), it.ID, c.ID, kind)
		} else {
			err = s.store.UnlinkWorkItemChange(ctx, s.actor(r), it.ID, c.ID, kind)
			msg = "Unlinked " + c.Ref() + "."
		}
		switch {
		case errors.Is(err, store.ErrConflict):
			s.backToItem(w, r, it.Ref(), "error", c.Ref()+" is already linked that way.")
		case errors.Is(err, store.ErrNotFound):
			s.backToItem(w, r, it.Ref(), "error", c.Ref()+" isn't linked that way.")
		case err != nil:
			s.serverError(w, r, err)
		default:
			s.backToItem(w, r, it.Ref(), "notice", msg)
		}
	}
}

// workLink links this item to another, "this <kind> other", or the other
// way round when direction is "in"; unlinking takes the same fields.
func (s *Server) workLink(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, ok := s.loadItem(w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		kind := r.FormValue("kind")
		if !slices.Contains(store.ItemLinkKinds, kind) {
			s.backToItem(w, r, it.Ref(), "error", "Pick a link type.")
			return
		}
		other, err := s.store.GetWorkItemByRef(ctx, r.FormValue("other"))
		if errors.Is(err, store.ErrNotFound) || (err == nil && other.ID == it.ID) {
			s.backToItem(w, r, it.Ref(), "error", "Name another work item, e.g. OPS-42.")
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		from, to := it.ID, other.ID
		if r.FormValue("direction") == "in" {
			from, to = to, from
		}
		msg := "Linked " + other.Ref() + "."
		if link {
			err = s.store.LinkWorkItems(ctx, s.actor(r), from, to, kind)
		} else {
			err = s.store.UnlinkWorkItems(ctx, s.actor(r), from, to, kind)
			msg = "Unlinked " + other.Ref() + "."
		}
		switch {
		case errors.Is(err, store.ErrConflict):
			s.backToItem(w, r, it.Ref(), "error", "That link already exists.")
		case errors.Is(err, store.ErrNotFound):
			s.backToItem(w, r, it.Ref(), "error", "There's no such link.")
		case err != nil:
			s.serverError(w, r, err)
		default:
			s.backToItem(w, r, it.Ref(), "notice", msg)
		}
	}
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Work tracking over the JSON API (docs/api.md §5): projects, work items
// and boards. As in the UI, anyone with a role may read, file, edit,
// transition and comment on work items: they track work rather than change
// hosts. The CIs and changes linked to an item show only to whoever may
// see them, and only those can be linked.

// opt is a field of a partial update: set when the request names it, null
// when it names it as null.
type opt[T any] struct {
	set, null bool
	v         T
}

func (o *opt[T]) UnmarshalJSON(b []byte) error {
	o.set = true
	if string(b) == "null" {
		o.null = true
		return nil
	}
	return json.Unmarshal(b, &o.v)
}

// JSON shapes --------------------------------------------------------------------

type userRefJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func userRef(id, name string) *userRefJSON {
	if id == "" {
		return nil
	}
	return &userRefJSON{ID: id, Name: name}
}

type itemRefJSON struct {
	Ref   string `json:"ref"`
	Title string `json:"title"`
}

type workItemJSON struct {
	ID              string         `json:"id"`
	Ref             string         `json:"ref"`
	Project         string         `json:"project"`
	ProjectName     string         `json:"project_name"`
	Number          int            `json:"number"`
	Type            string         `json:"type"`
	TypeName        string         `json:"type_name"`
	BaseKind        string         `json:"base_kind"`
	Status          string         `json:"status"`
	StatusCategory  string         `json:"status_category"`
	Resolution      string         `json:"resolution,omitempty"`
	Workflow        string         `json:"workflow"`
	WorkflowVersion int            `json:"workflow_version"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	Priority        string         `json:"priority"`
	Impact          string         `json:"impact,omitempty"`
	Urgency         string         `json:"urgency,omitempty"`
	Reporter        *userRefJSON   `json:"reporter,omitempty"`
	Assignee        *userRefJSON   `json:"assignee,omitempty"`
	Parent          *itemRefJSON   `json:"parent,omitempty"`
	Estimate        *float64       `json:"estimate,omitempty"`
	Due             string         `json:"due,omitempty"`
	Source          string         `json:"source"`
	SourceRef       string         `json:"source_ref,omitempty"`
	Custom          map[string]any `json:"custom"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
}

func workItemToJSON(it store.WorkItem) workItemJSON {
	custom := it.Custom
	if custom == nil {
		custom = map[string]any{}
	}
	j := workItemJSON{ID: it.ID, Ref: it.Ref(), Project: it.ProjectKey, ProjectName: it.ProjectName, Number: it.Number,
		Type: it.TypeKey, TypeName: it.TypeName, BaseKind: it.BaseKind, Status: it.StatusName, StatusCategory: it.Status,
		Resolution: it.Resolution, Workflow: it.WorkflowName, WorkflowVersion: it.WorkflowVersion, Title: it.Title,
		Description: it.Description, Priority: it.Priority, Impact: it.Impact, Urgency: it.Urgency,
		Reporter: userRef(it.ReporterID, it.Reporter), Assignee: userRef(it.AssigneeID, it.Assignee),
		Estimate: it.Estimate, Source: it.Source, SourceRef: it.SourceRef, Custom: custom,
		CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt, ResolvedAt: ts(it.ResolvedAt)}
	if it.ParentRef != "" {
		j.Parent = &itemRefJSON{Ref: it.ParentRef, Title: it.ParentTitle}
	}
	if !it.DueAt.IsZero() {
		j.Due = it.DueAt.Format(time.DateOnly)
	}
	return j
}

func workItemsToJSON(its []store.WorkItem) []workItemJSON {
	out := make([]workItemJSON, 0, len(its))
	for _, it := range its {
		out = append(out, workItemToJSON(it))
	}
	return out
}

type itemCIJSON struct {
	Role string `json:"role"`
	CI   ciJSON `json:"ci"`
}

type itemChangeJSON struct {
	Kind   string     `json:"kind"`
	Change changeJSON `json:"change"`
}

type itemLinkJSON struct {
	Kind string `json:"kind"`
	// Outgoing reads "this <kind> item"; otherwise "item <kind> this".
	Outgoing bool         `json:"outgoing"`
	Item     workItemJSON `json:"item"`
}

type slaJSON struct {
	Metric        string     `json:"metric"`
	Policy        string     `json:"policy"`
	TargetMinutes int        `json:"target_minutes"`
	StartedAt     time.Time  `json:"started_at"`
	TargetAt      time.Time  `json:"target_at"`
	MetAt         *time.Time `json:"met_at,omitempty"`
	State         string     `json:"state"` // running | met | breached
	Left          string     `json:"left,omitempty"`
}

type transitionJSON struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	To         string   `json:"to"`
	ToCategory string   `json:"to_category"`
	Allowed    bool     `json:"allowed"`
	Screen     []string `json:"screen"`
	Validators []string `json:"validators"`
}

type commentJSON struct {
	ID       string       `json:"id"`
	Author   *userRefJSON `json:"author,omitempty"`
	Body     string       `json:"body"`
	Internal bool         `json:"internal"`
	At       time.Time    `json:"at"`
}

type workItemDetailJSON struct {
	workItemJSON
	CIs         []itemCIJSON     `json:"cis"`
	Changes     []itemChangeJSON `json:"changes"`
	Links       []itemLinkJSON   `json:"links"`
	Children    []workItemJSON   `json:"children"`
	SLAs        []slaJSON        `json:"slas"`
	Watchers    []userRefJSON    `json:"watchers"`
	Watching    bool             `json:"watching"`
	Transitions []transitionJSON `json:"transitions"`
	Comments    []commentJSON    `json:"comments"`
}

type itemEventJSON struct {
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	ActorName  string    `json:"actor_name,omitempty"`
	Initial    bool      `json:"initial,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Transition string    `json:"transition,omitempty"`
	Migration  string    `json:"migration,omitempty"`
	CIID       string    `json:"ci_id,omitempty"`
	ChangeID   string    `json:"change_id,omitempty"`
	Diff       any       `json:"diff,omitempty"`
}

type formFieldJSON struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
	Required    bool     `json:"required"`
	Default     any      `json:"default,omitempty"`
}

type projectTypeJSON struct {
	ID          string          `json:"id"`
	Key         string          `json:"key"`
	Name        string          `json:"name"`
	BaseKind    string          `json:"base_kind"`
	Description string          `json:"description,omitempty"`
	Default     bool            `json:"default"`
	Workflow    string          `json:"workflow"`
	Fields      []formFieldJSON `json:"fields"`
}

type projectJSON struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Description string            `json:"description"`
	HostGroup   *ref              `json:"host_group,omitempty"`
	Archived    bool              `json:"archived"`
	Open        int               `json:"open_items"`
	CreatedAt   time.Time         `json:"created_at"`
	Types       []projectTypeJSON `json:"types,omitempty"`
}

func projectToJSON(p store.Project) projectJSON {
	j := projectJSON{ID: p.ID, Key: p.Key, Name: p.Name, Kind: p.Kind, Description: p.Description, Archived: p.Archived,
		Open: p.Open, CreatedAt: p.CreatedAt}
	if p.HostGroupID != "" {
		j.HostGroup = &ref{ID: p.HostGroupID, Name: p.HostGroupName}
	}
	return j
}

// Projects, users --------------------------------------------------------------

func (s *Server) apiProjects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListProjects(r.Context(), queryBool(r, "archived"))
	out := make([]projectJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, projectToJSON(p))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiLoadProject(r *http.Request, key string) (store.Project, error) {
	p, err := s.store.GetProject(r.Context(), key)
	if errors.Is(err, store.ErrNotFound) {
		return p, failf(http.StatusNotFound, "no project %s", strings.ToUpper(key))
	}
	return p, err
}

// apiProject is a project with its ticket types, and the custom fields
// each type's create screen asks for.
func (s *Server) apiProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.apiLoadProject(r, r.PathValue("key"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out := projectToJSON(p)
	out.Types = []projectTypeJSON{}
	for _, t := range p.Types {
		form, err := s.store.ResolveForm(r.Context(), p.ID, t.ID, store.ScreenCreate)
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		out.Types = append(out.Types, projectTypeJSON{ID: t.ID, Key: t.Key, Name: t.Name, BaseKind: t.BaseKind,
			Description: t.Description, Default: t.Default, Workflow: t.WorkflowName, Fields: formFieldsToJSON(form)})
	}
	writeJSON(w, http.StatusOK, out)
}

func formFieldsToJSON(form store.Form) []formFieldJSON {
	out := make([]formFieldJSON, 0, len(form.Fields))
	for _, f := range form.Fields {
		out = append(out, formFieldJSON{Key: f.Key, Label: f.Label, Type: f.Type, Description: f.Description,
			Options: f.Options, Required: f.Required, Default: f.Default})
	}
	return out
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.store.ListUsers(r.Context())
	out := make([]userJSON, 0, len(us))
	for _, u := range us {
		out = append(out, userJSON{ID: u.ID, Email: u.Email, Name: u.DisplayName(), Subject: u.OIDCSub})
	}
	s.respond(w, r, out, err)
}

// Reading items ------------------------------------------------------------------

func (s *Server) apiLoadItem(r *http.Request, ref string) (store.WorkItem, error) {
	it, err := s.store.GetWorkItemByRef(r.Context(), ref)
	if errors.Is(err, store.ErrNotFound) {
		return it, failf(http.StatusNotFound, "no work item %s", strings.ToUpper(ref))
	}
	return it, err
}

// apiUserID reads a user named in a request: "me", a user ID or an email,
// "" for nobody.
func (s *Server) apiUserID(r *http.Request, v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return "", nil
	case strings.EqualFold(v, "me"):
		return principal(r).User.ID, nil
	}
	us, err := s.store.ListUsers(r.Context())
	if err != nil {
		return "", err
	}
	for _, u := range us {
		if u.ID == strings.ToLower(v) || (u.Email != "" && strings.EqualFold(u.Email, v)) {
			return u.ID, nil
		}
	}
	return "", bad("no user %q: name one by ID (GET /users), by email, or as \"me\"", v)
}

// apiTicketType resolves a ticket type by key or ID.
func (s *Server) apiTicketType(r *http.Request, v string) (store.TicketType, error) {
	types, err := s.store.ListTicketTypes(r.Context())
	if err != nil {
		return store.TicketType{}, err
	}
	for _, t := range types {
		if t.ID == v || strings.EqualFold(t.Key, v) {
			return t, nil
		}
	}
	return store.TicketType{}, bad("no ticket type %q", v)
}

// apiWorkItems lists items: project, type, status (open by default, all,
// or a category), assignee (me, none or a user), parent, q, limit.
func (s *Server) apiWorkItems(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.WorkItemFilter{Query: q.Get("q"), Limit: queryInt(r, "limit", 200, 1000)}
	switch st := q.Get("status"); st {
	case "", "open":
	case "all", store.StatusTodo, store.StatusInProgress, store.StatusDone:
		f.Status = st
	default:
		apiError(w, http.StatusBadRequest, "status must be open, all, todo, in_progress or done")
		return
	}
	if key := q.Get("project"); key != "" {
		p, err := s.apiLoadProject(r, key)
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		f.ProjectID = p.ID
	}
	if t := q.Get("type"); t != "" {
		tt, err := s.apiTicketType(r, t)
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		f.TypeID = tt.ID
	}
	switch a := q.Get("assignee"); a {
	case "":
	case "none":
		f.Assignee = "none"
	default:
		id, err := s.apiUserID(r, a)
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		f.Assignee = id
	}
	if parent := q.Get("parent"); parent != "" {
		p, err := s.apiLoadItem(r, parent)
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		f.ParentID = p.ID
	}
	items, err := s.store.ListWorkItems(r.Context(), f)
	s.respond(w, r, workItemsToJSON(items), err)
}

// itemDetail is an item with what hangs off it, as its page shows it to
// the user.
func (s *Server) itemDetail(r *http.Request, it store.WorkItem) (workItemDetailJSON, error) {
	ctx := r.Context()
	out := workItemDetailJSON{workItemJSON: workItemToJSON(it), CIs: []itemCIJSON{}, Changes: []itemChangeJSON{},
		Links: []itemLinkJSON{}, SLAs: []slaJSON{}, Watchers: []userRefJSON{}, Transitions: []transitionJSON{},
		Comments: []commentJSON{}}
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		return out, err
	}
	cis, err := s.store.WorkItemCIs(ctx, it.ID)
	if err != nil {
		return out, err
	}
	for _, c := range cis {
		if canSeeCI(c.CI, ids) {
			out.CIs = append(out.CIs, itemCIJSON{Role: c.Role, CI: ciToJSON(c.CI)})
		}
	}
	changes, err := s.store.WorkItemChanges(ctx, it.ID)
	if err != nil {
		return out, err
	}
	if len(changes) > 0 {
		hosts, err := s.hostIndex(r)
		if err != nil {
			return out, err
		}
		for _, c := range changes {
			if canOnAll(principal(r).Grants, rbac.Viewer, c.Change.HostIDs, hosts) {
				out.Changes = append(out.Changes, itemChangeJSON{Kind: c.Kind, Change: changeToJSON(c.Change)})
			}
		}
	}
	links, err := s.store.WorkItemLinks(ctx, it.ID)
	if err != nil {
		return out, err
	}
	for _, l := range links {
		out.Links = append(out.Links, itemLinkJSON{Kind: l.Kind, Outgoing: l.Outgoing, Item: workItemToJSON(l.Other)})
	}
	children, err := s.store.ListWorkItems(ctx, store.WorkItemFilter{ParentID: it.ID, Status: "all"})
	if err != nil {
		return out, err
	}
	out.Children = workItemsToJSON(children)
	slas, err := s.store.WorkItemSLAs(ctx, it.ID)
	if err != nil {
		return out, err
	}
	for _, c := range slaClockViews(slas, time.Now()) {
		out.SLAs = append(out.SLAs, slaJSON{Metric: c.Metric, Policy: c.PolicyName, TargetMinutes: c.TargetMinutes,
			StartedAt: c.StartedAt, TargetAt: c.TargetAt, MetAt: ts(c.MetAt), State: c.State, Left: c.Left})
	}
	watchers, err := s.store.WorkItemWatchers(ctx, it.ID)
	if err != nil {
		return out, err
	}
	me := principal(r).User.ID
	for _, u := range watchers {
		out.Watchers = append(out.Watchers, userRefJSON{ID: u.ID, Name: u.DisplayName()})
		out.Watching = out.Watching || u.ID == me
	}
	transitions, err := s.transitionsFor(r, it)
	if err != nil {
		return out, err
	}
	for _, t := range transitions {
		tj := transitionJSON{ID: t.ID, Name: t.Name, To: t.ToName, ToCategory: t.ToCategory, Allowed: t.Allowed,
			Screen: []string{}, Validators: []string{}}
		for _, f := range t.Screen {
			if f == "resolution" && t.ToCategory != store.StatusDone {
				continue
			}
			tj.Screen = append(tj.Screen, f)
		}
		for _, v := range t.Validators {
			if v.Field != "" {
				tj.Validators = append(tj.Validators, v.Type+":"+v.Field)
			} else {
				tj.Validators = append(tj.Validators, v.Type)
			}
		}
		out.Transitions = append(out.Transitions, tj)
	}
	comments, err := s.store.WorkItemComments(ctx, it.ID)
	if err != nil {
		return out, err
	}
	for _, c := range comments {
		out.Comments = append(out.Comments, commentJSON{ID: c.ID, Author: userRef(c.AuthorID, c.Author), Body: c.Body,
			Internal: c.Internal, At: c.At})
	}
	return out, nil
}

func (s *Server) apiWorkItem(w http.ResponseWriter, r *http.Request) {
	it, err := s.apiLoadItem(r, r.PathValue("ref"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out, err := s.itemDetail(r, it)
	s.respond(w, r, out, err)
}

// respondItem answers a write with the item as it is now.
func (s *Server) respondItem(w http.ResponseWriter, r *http.Request, id string, status int) {
	it, err := s.store.GetWorkItem(r.Context(), id)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out, err := s.itemDetail(r, it)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if status == http.StatusCreated {
		w.Header().Set("Location", s.url(apiPrefix+"/work/"+it.Ref()))
	}
	writeJSON(w, status, out)
}

func (s *Server) apiWorkItemHistory(w http.ResponseWriter, r *http.Request) {
	it, err := s.apiLoadItem(r, r.PathValue("ref"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	events, err := s.store.WorkItemHistory(r.Context(), it.ID, queryInt(r, "limit", 100, 1000))
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if events, err = s.visibleHistory(r, events, ids); err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out := make([]itemEventJSON, 0, len(events))
	for _, e := range events {
		j := itemEventJSON{At: e.At, Actor: e.Actor, ActorName: e.ActorName, Initial: e.Initial, Summary: e.Summary,
			Transition: e.Transition, Migration: e.Migration, CIID: e.CIID, ChangeID: e.ChangeID}
		if !e.Diff.Empty() {
			j.Diff = e.Diff
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

// Creating and editing items -----------------------------------------------------

// workItemRequest is the body of POST /work. PATCH /work/{ref} takes the
// same fields, each optional (workItemPatch).
type workItemRequest struct {
	Project     string         `json:"project"`
	Type        string         `json:"type"` // key or ID; the project's default when empty
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Priority    string         `json:"priority"` // default medium
	Impact      string         `json:"impact"`
	Urgency     string         `json:"urgency"`
	Assignee    string         `json:"assignee"` // user ID, email or "me"
	Parent      string         `json:"parent"`   // a reference, OPS-42
	Estimate    *float64       `json:"estimate"`
	Due         string         `json:"due"` // YYYY-MM-DD
	Custom      map[string]any `json:"custom"`
}

type workItemPatch struct {
	Title       opt[string]    `json:"title"`
	Description opt[string]    `json:"description"`
	Priority    opt[string]    `json:"priority"`
	Impact      opt[string]    `json:"impact"`
	Urgency     opt[string]    `json:"urgency"`
	Assignee    opt[string]    `json:"assignee"`
	Parent      opt[string]    `json:"parent"`
	Estimate    opt[float64]   `json:"estimate"`
	Due         opt[string]    `json:"due"`
	Custom      map[string]any `json:"custom"`
}

// checkItemInput validates the core fields as the form does, and resolves
// the parent.
func (s *Server) checkItemInput(r *http.Request, in *store.WorkItemInput, parentRef, due string) error {
	in.Title, in.Description = strings.TrimSpace(in.Title), strings.TrimSpace(in.Description)
	switch {
	case in.Title == "":
		return bad("title is required")
	case !slices.Contains(store.Priorities, in.Priority):
		return bad("priority must be one of %s", strings.Join(store.Priorities, ", "))
	case in.Impact != "" && !slices.Contains(store.Levels, in.Impact):
		return bad("impact must be one of %s", strings.Join(store.Levels, ", "))
	case in.Urgency != "" && !slices.Contains(store.Levels, in.Urgency):
		return bad("urgency must be one of %s", strings.Join(store.Levels, ", "))
	case in.Estimate != nil && *in.Estimate < 0:
		return bad("estimate is a number, 0 or more")
	}
	in.DueAt = time.Time{}
	if due = strings.TrimSpace(due); due != "" {
		t, err := time.Parse(time.DateOnly, due)
		if err != nil {
			return bad("due is a date, YYYY-MM-DD")
		}
		in.DueAt = t
	}
	in.ParentID = ""
	if parentRef = strings.TrimSpace(parentRef); parentRef != "" {
		parent, err := s.store.GetWorkItemByRef(r.Context(), parentRef)
		if errors.Is(err, store.ErrNotFound) {
			return bad("there's no work item %s to be the parent", strings.ToUpper(parentRef))
		}
		if err != nil {
			return err
		}
		in.ParentID = parent.ID
	}
	return nil
}

// customRaw turns a JSON custom field value into form input: nil clears.
func customRaw(key string, v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{x}, nil
	case float64:
		return []string{strconv.FormatFloat(x, 'f', -1, 64)}, nil
	case bool:
		return []string{strconv.FormatBool(x)}, nil
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, bad("custom.%s: a list holds strings", key)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, bad("custom.%s: give a string, number, true or false, a list of strings, or null", key)
}

// apiCustom validates custom field values against the type's create screen
// (which the form edits with too). With create, fields left out take their
// defaults and required ones must be given; otherwise only the fields named
// change.
func (s *Server) apiCustom(r *http.Request, projectID, typeID string, given, current map[string]any, create bool) (map[string]any, error) {
	form, err := s.store.ResolveForm(r.Context(), projectID, typeID, store.ScreenCreate)
	if err != nil {
		return nil, err
	}
	raw := map[string][]string{}
	for k, v := range given {
		if form.Field(k) == nil {
			var keys []string
			for _, f := range form.Fields {
				keys = append(keys, f.Key)
			}
			if len(keys) == 0 {
				return nil, bad("this ticket type has no custom fields here, so custom.%s doesn't exist", k)
			}
			return nil, bad("no custom field %q here; the fields are %s", k, strings.Join(keys, ", "))
		}
		if raw[k], err = customRaw(k, v); err != nil {
			return nil, err
		}
	}
	defaults := map[string]any{}
	if create {
		defaults = customDefaults(form)
	}
	values, err := s.customValues(r, form, current, func(key string) ([]string, bool) {
		v, ok := raw[key]
		if !ok && create {
			_, hasDefault := defaults[key]
			return nil, !hasDefault
		}
		return v, ok
	})
	var badIn errBadInput
	if errors.As(err, &badIn) {
		return nil, bad("%s", strings.TrimSuffix(string(badIn), "."))
	}
	if err != nil {
		return nil, err
	}
	for k, v := range defaults {
		if _, ok := raw[k]; !ok {
			values[k] = v
		}
	}
	return values, nil
}

func (s *Server) apiWorkCreate(w http.ResponseWriter, r *http.Request) {
	var req workItemRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	id, err := s.createItemFromAPI(r, req)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	s.respondItem(w, r, id, http.StatusCreated)
}

func (s *Server) createItemFromAPI(r *http.Request, req workItemRequest) (string, error) {
	ctx := r.Context()
	if strings.TrimSpace(req.Project) == "" {
		return "", bad("project is required (a project key, GET /projects)")
	}
	p, err := s.store.GetProject(ctx, strings.TrimSpace(req.Project))
	if errors.Is(err, store.ErrNotFound) {
		return "", bad("no project %s", strings.ToUpper(req.Project))
	}
	if err != nil {
		return "", err
	}
	typeID := p.DefaultType()
	if req.Type != "" {
		i := slices.IndexFunc(p.Types, func(t store.ProjectType) bool { return t.ID == req.Type || strings.EqualFold(t.Key, req.Type) })
		if i < 0 {
			var keys []string
			for _, t := range p.Types {
				keys = append(keys, t.Key)
			}
			return "", bad("%s doesn't offer the ticket type %q; it offers %s", p.Key, req.Type, strings.Join(keys, ", "))
		}
		typeID = p.Types[i].ID
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}
	in := store.WorkItemInput{ProjectID: p.ID, TypeID: typeID, Title: req.Title, Description: req.Description,
		Priority: req.Priority, Impact: req.Impact, Urgency: req.Urgency, Estimate: req.Estimate, Source: "api"}
	if in.AssigneeID, err = s.apiUserID(r, req.Assignee); err != nil {
		return "", err
	}
	if err := s.checkItemInput(r, &in, req.Parent, req.Due); err != nil {
		return "", err
	}
	if in.Custom, err = s.apiCustom(r, p.ID, typeID, req.Custom, nil, true); err != nil {
		return "", err
	}
	id, _, err := s.store.CreateWorkItem(ctx, s.actor(r), principal(r).User.ID, in)
	switch {
	case errors.Is(err, store.ErrTypeNotOffered):
		return "", bad("%s doesn't offer that ticket type", p.Key)
	case errors.Is(err, store.ErrArchived):
		return "", bad("%s is archived", p.Key)
	case errors.Is(err, store.ErrNoPublished):
		return "", bad("the type's workflow has no published version")
	case errors.Is(err, store.ErrNotFound):
		return "", bad("that assignee no longer exists")
	}
	return id, err
}

// apiWorkUpdate changes the fields a PATCH names; null or "" clears an
// optional one.
func (s *Server) apiWorkUpdate(w http.ResponseWriter, r *http.Request) {
	it, err := s.apiLoadItem(r, r.PathValue("ref"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req workItemPatch
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	in := store.WorkItemInput{Title: it.Title, Description: it.Description, Priority: it.Priority, Impact: it.Impact,
		Urgency: it.Urgency, AssigneeID: it.AssigneeID, Estimate: it.Estimate}
	parent, due := it.ParentRef, ""
	if !it.DueAt.IsZero() {
		due = it.DueAt.Format(time.DateOnly)
	}
	str := func(o opt[string], into *string) {
		if o.set {
			*into = o.v // "" when null
		}
	}
	str(req.Title, &in.Title)
	str(req.Description, &in.Description)
	str(req.Priority, &in.Priority)
	str(req.Impact, &in.Impact)
	str(req.Urgency, &in.Urgency)
	str(req.Parent, &parent)
	str(req.Due, &due)
	if req.Estimate.set {
		in.Estimate = nil
		if !req.Estimate.null {
			e := req.Estimate.v
			in.Estimate = &e
		}
	}
	if req.Assignee.set {
		if in.AssigneeID, err = s.apiUserID(r, req.Assignee.v); err != nil {
			s.respond(w, r, nil, err)
			return
		}
	}
	if err := s.checkItemInput(r, &in, parent, due); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if len(req.Custom) > 0 {
		if in.Custom, err = s.apiCustom(r, it.ProjectID, it.TypeID, req.Custom, it.Custom, false); err != nil {
			s.respond(w, r, nil, err)
			return
		}
	}
	err = s.store.UpdateWorkItem(r.Context(), s.actor(r), it.ID, in)
	switch {
	case errors.Is(err, store.ErrParentCycle):
		apiError(w, http.StatusUnprocessableEntity, "the parent can't be this item or one below it")
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusUnprocessableEntity, "that assignee or parent no longer exists")
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.respondItem(w, r, it.ID, http.StatusOK)
	}
}

// Transitions, comments, watching ------------------------------------------------

type transitionRequest struct {
	Transition string `json:"transition"` // ID or name
	Resolution string `json:"resolution"`
	Assignee   string `json:"assignee"`
	Comment    string `json:"comment"`
}

func (s *Server) apiWorkTransition(w http.ResponseWriter, r *http.Request) {
	it, err := s.apiLoadItem(r, r.PathValue("ref"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req transitionRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	ts, err := s.store.ItemTransitions(r.Context(), it)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	want := strings.TrimSpace(req.Transition)
	i := slices.IndexFunc(ts, func(t store.WfTransition) bool { return t.ID == want })
	if i < 0 {
		i = slices.IndexFunc(ts, func(t store.WfTransition) bool { return strings.EqualFold(t.Name, want) })
	}
	if i < 0 {
		var names []string
		for _, t := range ts {
			names = append(names, fmt.Sprintf("%q (to %s)", t.Name, t.ToName))
		}
		msg := "no transition out of " + it.StatusName
		if len(names) > 0 {
			msg = fmt.Sprintf("no transition %q out of %s; the ones there are %s", want, it.StatusName, strings.Join(names, ", "))
		}
		apiError(w, http.StatusUnprocessableEntity, msg)
		return
	}
	in := store.TransitionInput{Resolution: req.Resolution, Comment: strings.TrimSpace(req.Comment)}
	if in.Resolution != "" && !slices.Contains(store.Resolutions, in.Resolution) {
		apiError(w, http.StatusUnprocessableEntity, "resolution must be one of "+strings.Join(store.Resolutions, ", "))
		return
	}
	if ts[i].Asks("assignee") {
		if in.AssigneeID, err = s.apiUserID(r, req.Assignee); err != nil {
			s.respond(w, r, nil, err)
			return
		}
	}
	err = s.store.TransitionWorkItem(r.Context(), s.actor(r), runner(r), it.ID, ts[i].ID, in)
	var tErr *store.TransitionError
	switch {
	case errors.As(err, &tErr):
		apiError(w, http.StatusUnprocessableEntity, tErr.Msg)
	case errors.Is(err, store.ErrStaleTransition):
		apiError(w, http.StatusConflict, "that transition doesn't apply any more: the item has moved on")
	case errors.Is(err, store.ErrTransitionDenied):
		apiError(w, http.StatusForbidden, "the transition's conditions don't let this token's user run it")
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusUnprocessableEntity, "that assignee no longer exists")
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.respondItem(w, r, it.ID, http.StatusOK)
	}
}

type commentRequest struct {
	Body     string `json:"body"`
	Internal bool   `json:"internal"` // a work note
}

func (s *Server) apiWorkComment(w http.ResponseWriter, r *http.Request) {
	it, err := s.apiLoadItem(r, r.PathValue("ref"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req commentRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		apiError(w, http.StatusUnprocessableEntity, "body is required")
		return
	}
	if err := s.store.AddComment(r.Context(), s.actor(r), principal(r).User.ID, it.ID, body, req.Internal); err != nil {
		s.apiServerError(w, r, err)
		return
	}
	s.respondItem(w, r, it.ID, http.StatusOK)
}

func (s *Server) apiWorkWatch(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, err := s.apiLoadItem(r, r.PathValue("ref"))
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		if err := s.store.SetWatching(r.Context(), s.actor(r), it.ID, principal(r).User.ID, on); err != nil {
			s.apiServerError(w, r, err)
			return
		}
		s.respondItem(w, r, it.ID, http.StatusOK)
	}
}

// Links --------------------------------------------------------------------------

type itemCIRequest struct {
	CI   string `json:"ci"`
	Role string `json:"role"`
}

// apiWorkCI links a CI the user may see (POST, the CI and role in the
// body) or unlinks one (DELETE /work/{ref}/cis/{ci}?role=).
func (s *Server) apiWorkCI(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, err := s.apiLoadItem(r, r.PathValue("ref"))
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		req := itemCIRequest{CI: r.PathValue("ci"), Role: r.URL.Query().Get("role")}
		if link {
			if err := readJSON(r, &req); err != nil {
				s.respond(w, r, nil, err)
				return
			}
		}
		if req.Role == "" {
			req.Role = "affected"
		}
		if !slices.Contains(store.ItemCIRoles, req.Role) {
			apiError(w, http.StatusUnprocessableEntity, "role must be one of "+strings.Join(store.ItemCIRoles, ", "))
			return
		}
		c, _, err := s.apiLoadCI(r, req.CI)
		if errors.Is(err, errAPINotFound) {
			apiError(w, http.StatusUnprocessableEntity, "no CI "+req.CI)
			return
		}
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		if link {
			err = s.store.LinkWorkItemCI(r.Context(), s.actor(r), it.ID, c.ID, req.Role)
		} else {
			err = s.store.UnlinkWorkItemCI(r.Context(), s.actor(r), it.ID, c.ID, req.Role)
		}
		s.linkResult(w, r, it.ID, err, c.Name)
	}
}

// linkResult answers a link or unlink.
func (s *Server) linkResult(w http.ResponseWriter, r *http.Request, itemID string, err error, what string) {
	switch {
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, what+" is already linked that way")
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, what+" isn't linked that way")
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.respondItem(w, r, itemID, http.StatusOK)
	}
}

type itemChangeRequest struct {
	Change string `json:"change"` // ID, CHG-000123 or 123
	Kind   string `json:"kind"`
}

// apiChangeByRef loads a change the user may see by ID or number.
func (s *Server) apiChangeByRef(r *http.Request, v string) (store.Change, error) {
	id := strings.TrimSpace(v)
	if n, ok := parseChangeRef(id); ok {
		found, err := s.store.ChangeIDByNumber(r.Context(), n)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.Change{}, err
		}
		id = found
	}
	c, _, err := s.apiLoadChange(r, id)
	if errors.Is(err, errAPINotFound) {
		return c, bad("no change %s (give its ID or a reference like CHG-000123)", v)
	}
	return c, err
}

func (s *Server) apiWorkChange(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, err := s.apiLoadItem(r, r.PathValue("ref"))
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		req := itemChangeRequest{Change: r.PathValue("change"), Kind: r.URL.Query().Get("kind")}
		if link {
			if err := readJSON(r, &req); err != nil {
				s.respond(w, r, nil, err)
				return
			}
		}
		if !slices.Contains(store.ItemChangeKinds, req.Kind) {
			apiError(w, http.StatusUnprocessableEntity, "kind must be one of "+strings.Join(store.ItemChangeKinds, ", "))
			return
		}
		c, err := s.apiChangeByRef(r, req.Change)
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		if link {
			err = s.store.LinkWorkItemChange(r.Context(), s.actor(r), it.ID, c.ID, req.Kind)
		} else {
			err = s.store.UnlinkWorkItemChange(r.Context(), s.actor(r), it.ID, c.ID, req.Kind)
		}
		s.linkResult(w, r, it.ID, err, c.Ref())
	}
}

type itemLinkRequest struct {
	Item      string `json:"item"` // the other item's reference
	Kind      string `json:"kind"`
	Direction string `json:"direction"` // out (default): this <kind> item; in: item <kind> this
}

func (s *Server) apiWorkLink(link bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		it, err := s.apiLoadItem(r, r.PathValue("ref"))
		if err != nil {
			s.respond(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		req := itemLinkRequest{Item: r.PathValue("other"), Kind: q.Get("kind"), Direction: q.Get("direction")}
		if link {
			if err := readJSON(r, &req); err != nil {
				s.respond(w, r, nil, err)
				return
			}
		}
		if !slices.Contains(store.ItemLinkKinds, req.Kind) {
			apiError(w, http.StatusUnprocessableEntity, "kind must be one of "+strings.Join(store.ItemLinkKinds, ", "))
			return
		}
		if req.Direction != "" && req.Direction != "out" && req.Direction != "in" {
			apiError(w, http.StatusUnprocessableEntity, "direction is out or in")
			return
		}
		other, err := s.store.GetWorkItemByRef(r.Context(), req.Item)
		if errors.Is(err, store.ErrNotFound) || (err == nil && other.ID == it.ID) {
			apiError(w, http.StatusUnprocessableEntity, "name another work item, e.g. OPS-42")
			return
		}
		if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		from, to := it.ID, other.ID
		if req.Direction == "in" {
			from, to = to, from
		}
		if link {
			err = s.store.LinkWorkItems(r.Context(), s.actor(r), from, to, req.Kind)
		} else {
			err = s.store.UnlinkWorkItems(r.Context(), s.actor(r), from, to, req.Kind)
		}
		s.linkResult(w, r, it.ID, err, other.Ref())
	}
}

// Boards -------------------------------------------------------------------------

type boardJSON struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Project     string              `json:"project,omitempty"`
	ProjectName string              `json:"project_name,omitempty"`
	Columns     []store.BoardColumn `json:"columns"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

func boardToJSON(b store.Board) boardJSON {
	cols := b.Columns
	if cols == nil {
		cols = []store.BoardColumn{}
	}
	return boardJSON{ID: b.ID, Name: b.Name, Project: b.ProjectKey, ProjectName: b.ProjectName, Columns: cols,
		CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt}
}

func (s *Server) apiBoards(w http.ResponseWriter, r *http.Request) {
	bs, err := s.store.ListBoards(r.Context())
	out := make([]boardJSON, 0, len(bs))
	for _, b := range bs {
		out = append(out, boardToJSON(b))
	}
	s.respond(w, r, out, err)
}

type boardCardJSON struct {
	workItemJSON
	Transitions []transitionJSON `json:"transitions"`
}

type boardColumnJSON struct {
	Name  string          `json:"name"`
	Cards []boardCardJSON `json:"cards"`
}

// apiBoard is a board with its columns filled as the board page fills
// them, each card with the transitions out of its status.
func (s *Server) apiBoard(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.GetBoard(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "no such board")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	v, _, err := s.boardData(r, b)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out := struct {
		boardJSON
		Filter   []string          `json:"filter"`
		Problems []string          `json:"filter_problems,omitempty"`
		Cards    []boardColumnJSON `json:"board"`
		Shown    int               `json:"shown"`
		Total    int               `json:"total"`
		Unplaced int               `json:"unplaced"`
	}{boardJSON: boardToJSON(b), Filter: strs(v.Filter), Problems: v.Problems, Cards: []boardColumnJSON{},
		Shown: v.Shown, Total: v.Total, Unplaced: v.Unplaced}
	for _, c := range v.Columns {
		col := boardColumnJSON{Name: c.Name, Cards: []boardCardJSON{}}
		for _, card := range c.Cards {
			bc := boardCardJSON{workItemJSON: workItemToJSON(card.WorkItem), Transitions: []transitionJSON{}}
			for _, t := range card.Targets {
				bc.Transitions = append(bc.Transitions, transitionJSON{ID: t.ID, Name: t.Name, To: t.To, Allowed: t.Allowed,
					Screen: nonNilStrings(t.Screen), Validators: []string{}})
			}
			col.Cards = append(col.Cards, bc)
		}
		out.Cards = append(out.Cards, col)
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Items linked to CIs and changes ------------------------------------------------

type linkedItemJSON struct {
	Rel  string       `json:"rel"` // the CI's role, or the change's kind
	Item workItemJSON `json:"item"`
}

func (s *Server) ciWorkItems(r *http.Request, ciID string) ([]linkedItemJSON, error) {
	ls, err := s.store.CIWorkItems(r.Context(), ciID)
	out := make([]linkedItemJSON, 0, len(ls))
	for _, l := range ls {
		out = append(out, linkedItemJSON{Rel: l.Role, Item: workItemToJSON(l.Item)})
	}
	return out, err
}

func (s *Server) changeWorkItems(r *http.Request, changeID string) ([]linkedItemJSON, error) {
	ls, err := s.store.ChangeWorkItems(r.Context(), changeID)
	out := make([]linkedItemJSON, 0, len(ls))
	for _, l := range ls {
		out = append(out, linkedItemJSON{Rel: l.Kind, Item: workItemToJSON(l.Item)})
	}
	return out, err
}

func (s *Server) apiCIWorkItems(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out, err := s.ciWorkItems(r, c.ID)
	s.respond(w, r, out, err)
}

// CI relationships ---------------------------------------------------------------

type relationshipRequest struct {
	Kind      string `json:"kind"`
	Other     string `json:"other"`     // the other CI's ID
	Direction string `json:"direction"` // out (default): this <kind> other; in: other <kind> this
}

// apiCIRelate adds a manual relationship between two CIs the user may see.
// Like the UI, it needs a global operator.
func (s *Server) apiCIRelate(w http.ResponseWriter, r *http.Request) {
	c, ids, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req relationshipRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if !slices.Contains(store.RelationKinds, req.Kind) {
		apiError(w, http.StatusUnprocessableEntity, "kind must be one of "+strings.Join(store.RelationKinds, ", "))
		return
	}
	if req.Direction != "" && req.Direction != "out" && req.Direction != "in" {
		apiError(w, http.StatusUnprocessableEntity, "direction is out or in")
		return
	}
	other, err := s.store.GetCI(r.Context(), req.Other)
	if (err != nil && errors.Is(err, store.ErrNotFound)) || (err == nil && (!canSeeCI(other, ids) || other.ID == c.ID)) {
		apiError(w, http.StatusUnprocessableEntity, "other must be another CI's ID")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	from, to := c.ID, other.ID
	if req.Direction == "in" {
		from, to = to, from
	}
	err = s.store.AddRelationship(r.Context(), s.actor(r), from, to, req.Kind)
	if errors.Is(err, store.ErrConflict) {
		apiError(w, http.StatusConflict, "that relationship already exists")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	rels, err := s.visibleRelationships(r, c.ID, ids)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, relationshipsToJSON(rels))
}

// apiCIUnrelate removes a manual relationship; discovered ones follow
// discovery.
func (s *Server) apiCIUnrelate(w http.ResponseWriter, r *http.Request) {
	c, ids, err := s.apiLoadCI(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	err = s.store.DeleteRelationship(r.Context(), s.actor(r), c.ID, r.PathValue("rel"))
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "no manual relationship "+r.PathValue("rel")+" on this CI; discovered ones can't be removed")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	rels, err := s.visibleRelationships(r, c.ID, ids)
	s.respond(w, r, relationshipsToJSON(rels), err)
}

// Cancelling and closing changes -------------------------------------------------

// readOptionalJSON is readJSON for a body that may be left out.
func readOptionalJSON(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return readJSON(r, v)
}

// apiChangeCancel cancels an open change, asking its running jobs to stop.
// As in the UI, its requester, an approver on all its hosts or an admin may.
func (s *Server) apiChangeCancel(w http.ResponseWriter, r *http.Request) {
	c, hosts, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if !s.mayManage(r, c, hosts) {
		apiError(w, http.StatusForbidden, "only the requester, an approver on its hosts or an admin cancels a change")
		return
	}
	running, err := s.store.CancelChange(r.Context(), s.actor(r), c.ID, strings.TrimSpace(req.Reason))
	if errors.Is(err, store.ErrState) {
		apiError(w, http.StatusConflict, "this change has already ended ("+c.State+")")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if s.jobs != nil {
		s.jobs.Cancel(running)
	}
	s.respondChange(w, r, c.ID)
}

// apiChangeClose closes a change that has ended, with its post-implementation
// review where it needs one.
func (s *Server) apiChangeClose(w http.ResponseWriter, r *http.Request) {
	c, hosts, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	var req struct {
		Review string `json:"review"`
	}
	if err := readOptionalJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	if !s.mayManage(r, c, hosts) {
		apiError(w, http.StatusForbidden, "only the requester, an approver on its hosts or an admin closes a change")
		return
	}
	err = s.store.CloseChange(r.Context(), s.actor(r), c.ID, strings.TrimSpace(req.Review))
	switch {
	case errors.Is(err, store.ErrState):
		apiError(w, http.StatusConflict, "this change can't be closed while it is "+c.State)
	case err != nil && strings.Contains(err.Error(), "review"):
		apiError(w, http.StatusUnprocessableEntity, "this change needs a post-implementation review (review): what happened, and what follows from it")
	case err != nil:
		s.apiServerError(w, r, err)
	default:
		s.respondChange(w, r, c.ID)
	}
}

func (s *Server) respondChange(w http.ResponseWriter, r *http.Request, id string) {
	c, err := s.store.GetChange(r.Context(), id)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out, err := s.changeDetail(r, c)
	s.respond(w, r, out, err)
}

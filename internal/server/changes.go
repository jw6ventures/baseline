package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/stackname"
	"github.com/jw6ventures/baseline/internal/store"
)

// hostIndex maps every host to its record, for permission checks on
// changes that span hosts.
func (s *Server) hostIndex(r *http.Request) (map[string]store.Host, error) {
	all, err := s.store.ListHosts(r.Context())
	if err != nil {
		return nil, err
	}
	m := make(map[string]store.Host, len(all))
	for _, h := range all {
		m[h.ID] = h
	}
	return m, nil
}

// canOnAll reports whether the user holds role on every one of the hosts.
func canOnAll(g rbac.Grants, role rbac.Role, hostIDs []string, hosts map[string]store.Host) bool {
	for _, id := range hostIDs {
		h, ok := hosts[id]
		if !ok || !g.HasOn(role, h.GroupIDs) {
			return false
		}
	}
	return len(hostIDs) > 0 || g.Has(role)
}

// Change list -------------------------------------------------------------------

type changeListView struct {
	CanRun bool
	List   *listView
}

var changeFilters = map[string][]string{
	"open":      {store.ChangeDraft, store.ChangeSubmitted, store.ChangeApproved, store.ChangeScheduled, store.ChangeInProgress},
	"approval":  {store.ChangeSubmitted},
	"scheduled": {store.ChangeApproved, store.ChangeScheduled},
	"review":    {store.ChangeImplemented, store.ChangeFailed, store.ChangeRolledBack, store.ChangeReview},
	"all":       nil,
}

func (s *Server) changeList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "change")
	if !ok {
		return
	}
	s.renderList(w, r, "changes", "Changes", changeListView{CanRun: principal(r).Grants.HasAnywhere(rbac.Operator), List: v}, v)
}

// Change detail -----------------------------------------------------------------

type changeView struct {
	Change    store.Change
	Approvals []store.Approval
	Jobs      []store.Job
	Cycle     *store.PatchCycle // the patch group run it implements
	WorkItems []linkedItem
	// Revisions are the files of a Compose deploy or edit; operators of
	// the hosts may look at the .env values.
	Revisions  []store.ComposeRevision
	CanSeeEnv  bool
	CanApprove bool
	CanCancel  bool
	CanSubmit  bool
	CanClose   bool
	Notice     string
	Error      string
}

// loadChange fetches the change in the path, if the user may see it.
func (s *Server) loadChange(w http.ResponseWriter, r *http.Request) (store.Change, map[string]store.Host, bool) {
	c, err := s.store.GetChange(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such change.")
		return c, nil, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return c, nil, false
	}
	hosts, err := s.hostIndex(r)
	if err != nil {
		s.serverError(w, r, err)
		return c, nil, false
	}
	if !canOnAll(principal(r).Grants, rbac.Viewer, c.HostIDs, hosts) {
		s.errorPage(w, r, http.StatusNotFound, "No such change.")
		return c, nil, false
	}
	return c, hosts, true
}

func (s *Server) changePage(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadChange(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	v := changeView{Change: c, Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	var err error
	if v.Approvals, err = s.store.ChangeApprovals(ctx, c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Jobs, err = s.store.ListJobs(ctx, store.JobFilter{ChangeID: c.ID, Limit: 1000}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Cycle, err = s.store.ChangeCycle(ctx, c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	items, err := s.store.ChangeWorkItems(ctx, c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, it := range items {
		v.WorkItems = append(v.WorkItems, linkedItem{Rel: it.Kind, Item: it.Item})
	}
	if v.Revisions, err = s.store.ChangeRevisions(ctx, c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	p := principal(r)
	v.CanSeeEnv = canOnAll(p.Grants, rbac.Operator, c.HostIDs, hosts)
	v.CanApprove = c.State == store.ChangeSubmitted && canOnAll(p.Grants, rbac.Approver, c.HostIDs, hosts)
	v.CanCancel = c.Open() && s.mayManage(r, c, hosts)
	v.CanSubmit = c.State == store.ChangeDraft && c.RequestedBy == p.User.ID
	v.CanClose = c.Closable() && s.mayManage(r, c, hosts)
	s.pages.render(w, http.StatusOK, "change", s.data(r, c.Ref()+" "+c.Title, v))
}

func (s *Server) backToChange(w http.ResponseWriter, r *http.Request, id, kind, msg string) {
	http.Redirect(w, r, s.url("/changes/"+id+"?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) changeDecide(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadChange(w, r)
	if !ok {
		return
	}
	if !canOnAll(principal(r).Grants, rbac.Approver, c.HostIDs, hosts) {
		s.errorPage(w, r, http.StatusForbidden, "Approving this change needs the approver role on every host it affects.")
		return
	}
	comment := strings.TrimSpace(r.FormValue("comment"))
	reject := r.FormValue("decision") == "reject"
	var err error
	if reject {
		err = s.store.RejectChange(r.Context(), s.actor(r), c.ID, comment)
	} else {
		err = s.store.ApproveChange(r.Context(), s.actor(r), c.ID, comment)
	}
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "This change is no longer waiting for approval.")
	case err != nil:
		s.serverError(w, r, err)
	case reject:
		s.backToChange(w, r, c.ID, "notice", "Change rejected. Its jobs won't run.")
	default:
		s.nudgeJobs()
		s.backToChange(w, r, c.ID, "notice", "Approved.")
	}
}

// mayManage reports whether the user may cancel or close the change: its
// requester, an approver of every host it affects, or an admin. Changes the
// scheduler requested belong to the approvers.
func (s *Server) mayManage(r *http.Request, c store.Change, hosts map[string]store.Host) bool {
	p := principal(r)
	return (c.RequestedBy != "" && c.RequestedBy == p.User.ID) || canOnAll(p.Grants, rbac.Approver, c.HostIDs, hosts) ||
		p.Grants.Has(rbac.Admin)
}

func (s *Server) changeSubmit(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadChange(w, r)
	if !ok {
		return
	}
	err := s.store.SubmitChange(r.Context(), s.actor(r), c.ID)
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "Only its requester submits a draft.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToChange(w, r, c.ID, "notice", "Submitted. It runs once an approver approves it.")
	}
}

func (s *Server) changeClose(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadChange(w, r)
	if !ok {
		return
	}
	if !s.mayManage(r, c, hosts) {
		s.errorPage(w, r, http.StatusForbidden, "Only the requester or an approver can close this change.")
		return
	}
	err := s.store.CloseChange(r.Context(), s.actor(r), c.ID, strings.TrimSpace(r.FormValue("review")))
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "This change can't be closed now.")
	case err != nil && strings.Contains(err.Error(), "review"):
		s.backToChange(w, r, c.ID, "error", "Write the post-implementation review first: what happened, and what follows from it.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToChange(w, r, c.ID, "notice", "Change closed.")
	}
}

func (s *Server) changeCancel(w http.ResponseWriter, r *http.Request) {
	c, hosts, ok := s.loadChange(w, r)
	if !ok {
		return
	}
	if !s.mayManage(r, c, hosts) {
		s.errorPage(w, r, http.StatusForbidden, "Only the requester or an approver can cancel this change.")
		return
	}
	running, err := s.store.CancelChange(r.Context(), s.actor(r), c.ID, strings.TrimSpace(r.FormValue("reason")))
	switch {
	case errors.Is(err, store.ErrState):
		s.backToChange(w, r, c.ID, "error", "This change has already ended.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	if s.jobs != nil {
		s.jobs.Cancel(running)
	}
	msg := "Change cancelled."
	if len(running) > 0 {
		msg += " " + plural(len(running), "running job was", "running jobs were") + " asked to stop."
	}
	s.backToChange(w, r, c.ID, "notice", msg)
}

func (s *Server) nudgeJobs() {
	if s.jobs != nil {
		s.jobs.Nudge()
	}
}

// New change --------------------------------------------------------------------

type changeFormView struct {
	Spec       action.Spec // the chosen action; Name "" until one is
	Actions    []action.Spec
	Hosts      []targetHost
	Form       url.Values
	Title      string
	Risk       action.Risk
	Risks      []action.Risk
	Error      string
	CanApprove bool // approver somewhere; checked per host on submit
	Category   string

	// pkg.upgrade
	Packages   string
	ImageBased bool
	// script.run
	Scripts []store.Script
	Script  *store.ScriptVersion
	// container.restart: the containers to pick from
	Containers []containerChoice
	// compose.*: the stacks to pick from
	Stacks []stackChoice
	// Stack filters, from what stack names say (internal/stackname).
	Envs, Categories, Visibilities []string
	// Picked is how many containers or stacks are ticked.
	Picked int
	// compose.deploy and compose.edit: the stack's files.
	Files *stackFileForm
	// compose.move: the Compose roots of the stacks' hosts.
	Roots []string

	// Standard changes come from an approved model, which fixes the
	// action and its parameters.
	Model *store.ChangeModel
	// Normal and Emergency changes: kind, approvals and schedule.
	Kind         string
	Windows      []store.MaintenanceWindow
	PlannedStart string // datetime-local, in the display time zone
	TZ           string
}

type targetHost struct {
	store.Host
	Checked  bool
	Disabled string // why the host can't run this action
}

// stackChoice is a Compose stack offered on the new-change form.
type stackChoice struct {
	store.Stack
	Checked  bool
	Disabled string   // why the change can't include it
	Services []string // its Compose services, to pick from
	Picked   []string // the ones ticked; none is all of them
}

// containerChoice is a container offered on the new-change form, with its
// stack's classification for the filters.
type containerChoice struct {
	store.ContainerRow
	Checked                           bool
	Disabled                          string
	Environment, Category, Visibility string
}

// stackServices are the services ticked for a stack: its own field, or
// the plain one when the form is about one stack.
func stackServices(f url.Values, ciID string) []string {
	if svc := f["svc."+ciID]; len(svc) > 0 {
		return svc
	}
	if len(f["stack"]) == 1 {
		return f["service"]
	}
	return nil
}

// stackBlock says why a compose.* change can't include the stack, or "".
func stackBlock(spec action.Spec, model *store.ChangeModel, st store.Stack, h store.Host) string {
	if ok, why := st.Can(spec.Name); !ok {
		return why
	}
	if ok, why := h.Policy.Allows(spec.Name); !ok {
		return h.DisplayName() + ": " + why
	}
	if ok, why := spec.Supported(h.Capabilities); !ok {
		return h.DisplayName() + " can't do this: it " + why
	}
	if why := stackDirBlock(spec.Name, h); why != "" {
		return why
	}
	if model != nil && st.ModelID != model.ID {
		return "its updates don't run under this change model"
	}
	return ""
}

// operable lists the hosts the user may change, by ID.
func operable(p *Principal, hosts []store.Host) (map[string]store.Host, []string) {
	m := map[string]store.Host{}
	var ids []string
	for _, h := range hosts {
		if !h.Revoked && p.Grants.HasOn(rbac.Operator, h.GroupIDs) {
			m[h.ID] = h
			ids = append(ids, h.ID)
		}
	}
	return m, ids
}

// stackChoices lists the stacks on hosts the user may change, for a
// compose.* change; ticked ones that are gone are kept so the form can say
// why they can't be updated.
func (s *Server) stackChoices(ctx context.Context, spec action.Spec, model *store.ChangeModel, f url.Values,
	hosts map[string]store.Host, ids []string) ([]stackChoice, error) {
	stacks, err := s.store.ListStacks(ctx, ids)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListContainers(ctx, ids)
	if err != nil {
		return nil, err
	}
	services := map[string][]string{}
	for _, c := range rows {
		if c.StackCI != "" && c.ComposeService != "" && !slices.Contains(services[c.StackCI], c.ComposeService) {
			services[c.StackCI] = append(services[c.StackCI], c.ComposeService)
		}
	}
	var out []stackChoice
	for _, st := range stacks {
		checked := slices.Contains(f["stack"], st.CIID)
		if !st.Present && !checked {
			continue
		}
		c := stackChoice{Stack: st, Checked: checked, Services: slices.Sorted(slices.Values(services[st.CIID])),
			Picked: stackServices(f, st.CIID), Disabled: stackBlock(spec, model, st, hosts[st.HostID])}
		out = append(out, c)
	}
	return out, nil
}

// containerChoices lists the containers on hosts the user may change, for
// container.restart.
func (s *Server) containerChoices(ctx context.Context, spec action.Spec, f url.Values, hosts map[string]store.Host,
	ids []string) ([]containerChoice, error) {
	rows, err := s.store.ListContainers(ctx, ids)
	if err != nil {
		return nil, err
	}
	stacks, err := s.store.ListStacks(ctx, ids)
	if err != nil {
		return nil, err
	}
	byCI := map[string]store.Stack{}
	for _, st := range stacks {
		byCI[st.CIID] = st
	}
	out := make([]containerChoice, 0, len(rows))
	for _, c := range rows {
		ch := containerChoice{ContainerRow: c, Checked: slices.Contains(f["container"], c.CIID)}
		if st, ok := byCI[c.StackCI]; ok {
			ch.Environment, ch.Category, ch.Visibility = st.Environment, st.Category, st.Visibility
		}
		h := hosts[c.HostID]
		if ok, why := h.Policy.Allows(spec.Name); !ok {
			ch.Disabled = h.DisplayName() + ": " + why
		} else if ok, why := spec.Supported(h.Capabilities); !ok {
			ch.Disabled = h.DisplayName() + " can't do this: it " + why
		}
		out = append(out, ch)
	}
	return out, nil
}

func (s *Server) changeNew(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.renderChangeForm(w, r, http.StatusOK, "")
}

// renderChangeForm shows the new-change form with the request's values.
func (s *Server) renderChangeForm(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	ctx := r.Context()
	p := principal(r)
	f := r.Form
	v := changeFormView{Form: f, Risks: action.Risks, Error: errMsg, CanApprove: p.Grants.HasAnywhere(rbac.Approver),
		Kind: f.Get("kind"), PlannedStart: f.Get("planned_start"), TZ: s.cfg.Location.String(),
		Envs: stackname.Environments, Categories: stackname.Categories, Visibilities: stackname.Visibilities}
	if v.Kind != store.KindEmergency {
		v.Kind = store.KindNormal
	}
	for _, n := range action.Names {
		if sp := action.MustGet(n); !sp.OwnForm {
			v.Actions = append(v.Actions, sp)
		}
	}
	if id := f.Get("model"); id != "" {
		m, err := s.store.GetChangeModel(ctx, id)
		if err != nil || !m.Approved() {
			s.errorPage(w, r, http.StatusNotFound, "No such approved change model.")
			return
		}
		v.Model, v.Kind = &m, store.KindStandard
		f.Set("action", m.Action)
	}
	ws, err := s.store.ListWindows(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, w := range ws {
		if w.Kind == store.WindowKindWindow && w.Active {
			v.Windows = append(v.Windows, w)
		}
	}
	spec, ok := action.Get(f.Get("action"))
	if !ok {
		s.pages.render(w, status, "change_new", s.data(r, "New change", v))
		return
	}
	v.Spec = spec
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	mine, mineIDs := operable(p, hosts)
	risk := spec.Risk
	switch spec.Name {
	case action.ScriptRun:
		if v.Scripts, err = s.store.ListScripts(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
		v.Scripts = slices.DeleteFunc(v.Scripts, func(sc store.Script) bool { return sc.Archived })
		if id := f.Get("script"); id != "" {
			ver, _ := strconv.Atoi(f.Get("version"))
			if ver == 0 {
				if sc, err := s.store.GetScript(ctx, id); err == nil {
					ver = sc.Latest
				}
			}
			if sv, err := s.store.GetScriptVersion(ctx, id, ver); err == nil {
				v.Script = &sv
				risk = action.Risk(sv.Risk)
			}
		}
	case action.ContainerRestart:
		if v.Containers, err = s.containerChoices(ctx, spec, f, mine, mineIDs); err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, c := range v.Containers {
			if c.Checked && c.Disabled == "" {
				v.Picked++
			}
		}
	case action.ComposeDeploy, action.ComposeEdit:
		if v.Model != nil {
			s.errorPage(w, r, http.StatusNotFound, "No such approved change model.")
			return
		}
		if v.Files, err = s.stackFileFormView(r, spec, mine); err != nil {
			s.serverError(w, r, err)
			return
		}
		if v.Files.Block == "" {
			v.Picked = 1
		}
	case action.ComposePull, action.ComposeUpdate, action.ComposeStart, action.ComposeArchive, action.ComposeMove:
		if v.Stacks, err = s.stackChoices(ctx, spec, v.Model, f, mine, mineIDs); err != nil {
			s.serverError(w, r, err)
			return
		}
		if spec.Name == action.ComposeMove {
			v.Roots = moveRoots(v.Stacks, mine)
		}
		for _, c := range v.Stacks {
			if c.Checked && c.Disabled == "" {
				v.Picked++
			}
		}
	case action.PkgUpgrade:
		v.Packages = f.Get("packages")
		if v.Packages == "" {
			v.Packages = strings.Join(f["pkg"], "\n")
		}
	}
	if v.Model != nil {
		risk = action.Risk(v.Model.Risk)
	}
	checked := f["host"]
	n := v.Picked
	for _, h := range hosts {
		if h.Revoked || !p.Grants.HasOn(rbac.Operator, h.GroupIDs) {
			continue
		}
		if spec.Name == action.ContainerRestart || spec.Category == action.CategoryCompose {
			break // they pick containers or stacks, not hosts
		}
		t := targetHost{Host: h, Checked: slices.Contains(checked, h.ID)}
		if ok, why := h.Policy.Allows(spec.Name); !ok {
			t.Disabled = why
		} else if ok, why := spec.Supported(h.Capabilities); !ok {
			t.Disabled = why
		} else if v.Model != nil && action.NeedsPin(spec.Name, v.Model.Params) && !slices.Contains(h.Capabilities, action.CapPkgPin) {
			t.Disabled = "its agent can't pin versions; update it"
		}
		if t.Checked && t.Disabled == "" {
			n++
			if slices.Contains(h.Capabilities, "image-based") {
				v.ImageBased = true
			}
		}
		v.Hosts = append(v.Hosts, t)
	}
	v.Risk = action.SuggestRisk([]action.Risk{risk}, n)
	if rk, err := action.ParseRisk(f.Get("risk")); err == nil {
		v.Risk = rk
	}
	v.Title = f.Get("title")
	title := "New change: " + spec.Label
	if v.Model != nil {
		title = "New Standard change: " + v.Model.Name
	}
	s.pages.render(w, status, "change_new", s.data(r, title, v))
}

func (s *Server) changeCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	ctx := r.Context()
	p := principal(r)
	f := r.Form
	fail := func(msg string) { s.renderChangeForm(w, r, http.StatusUnprocessableEntity, msg) }
	spec, ok := action.Get(f.Get("action"))
	if !ok {
		fail("Pick an action.")
		return
	}
	hosts, err := s.hostIndex(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var model *store.ChangeModel
	if id := f.Get("model"); id != "" {
		m, err := s.store.GetChangeModel(ctx, id)
		if err != nil || !m.Approved() || m.Action != spec.Name {
			fail("That change model isn't approved (any more).")
			return
		}
		model = &m
	}
	// Compose changes and container restarts pick stacks or containers, and
	// get a step for each; their hosts follow. Deploys and edits carry their
	// stack's files.
	var stacks []store.Stack
	var containers []store.ContainerRow
	var fileStep *store.PlanStep
	var revs []store.ComposeRevision
	var fileCI, fileObject string
	switch {
	case spec.OwnForm:
		if model != nil {
			fail("Deploys and edits of Compose stacks don't come from change models.")
			return
		}
		step, rev, ci, object, err := s.stackFilesPlan(r, spec, formStackFiles(f), hosts)
		if err != nil {
			fail(strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + ".")
			return
		}
		fileStep, revs, fileCI, fileObject = &step, []store.ComposeRevision{rev}, ci, object
		f["host"] = step.HostIDs
	case spec.Category == action.CategoryCompose:
		f["host"] = nil
		for _, id := range slices.Compact(slices.Sorted(slices.Values(f["stack"]))) {
			st, err := s.store.GetStack(ctx, id)
			if err != nil {
				fail("One of the Compose stacks is gone; pick them again.")
				return
			}
			if ok, why := st.Can(spec.Name); !ok {
				fail("Baseline can't " + stackVerb(spec.Name) + " " + st.Project + " on " + st.Hostname + ": " + why + ".")
				return
			}
			if model != nil && st.ModelID != model.ID {
				fail(st.Project + "'s updates don't run under that change model; an approver sets it on the stack's page.")
				return
			}
			stacks = append(stacks, st)
			f["host"] = append(f["host"], st.HostID)
		}
		if len(stacks) == 0 {
			fail("Pick at least one Compose stack.")
			return
		}
		slices.SortFunc(stacks, func(a, b store.Stack) int {
			return strings.Compare(strings.ToLower(a.Hostname)+"\x00"+a.Project, strings.ToLower(b.Hostname)+"\x00"+b.Project)
		})
	case spec.Name == action.ContainerRestart:
		f["host"] = nil
		for _, id := range slices.Compact(slices.Sorted(slices.Values(f["container"]))) {
			c, err := s.store.GetContainer(ctx, id)
			if err != nil {
				fail("One of the containers is gone; pick them again.")
				return
			}
			containers = append(containers, c)
			f["host"] = append(f["host"], c.HostID)
		}
		if len(containers) == 0 {
			fail("Pick at least one container.")
			return
		}
		slices.SortFunc(containers, func(a, b store.ContainerRow) int {
			return strings.Compare(strings.ToLower(a.Hostname)+"\x00"+a.Name, strings.ToLower(b.Hostname)+"\x00"+b.Name)
		})
	}
	targets := slices.Compact(slices.Sorted(slices.Values(f["host"])))
	if len(targets) == 0 {
		fail("Pick at least one host.")
		return
	}
	names, err := checkTargets(p.Grants, spec, targets, hosts)
	if err != nil {
		fail(strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + ".")
		return
	}
	var steps []store.PlanStep
	var cis, objects []string // affected CIs beside the hosts, and their names
	var risk action.Risk
	switch {
	case fileStep != nil:
		steps, risk, objects = []store.PlanStep{*fileStep}, spec.Risk, []string{fileObject}
		if fileCI != "" {
			cis = []string{fileCI}
		}
	case stacks != nil:
		for _, st := range stacks {
			var step store.PlanStep
			if model != nil {
				step, risk, err = s.modelStep(*model, &st)
			} else {
				step, risk, err = s.planStep(r, spec, &st)
			}
			if err == nil {
				err = checkDest(step, hosts[st.HostID])
			}
			if err != nil {
				fail(st.Project + ": " + err.Error())
				return
			}
			step.HostIDs = []string{st.HostID}
			steps, cis, objects = append(steps, step), append(cis, st.CIID), append(objects, st.Project)
		}
	case containers != nil:
		for _, c := range containers {
			raw, _ := json.Marshal(action.ContainerParams{Engine: c.Engine, Name: c.Name})
			norm, err := action.Validate(spec.Name, raw)
			if err != nil {
				fail(c.Name + ": " + err.Error())
				return
			}
			steps = append(steps, store.PlanStep{Action: spec.Name, Params: norm, Summary: action.Describe(spec.Name, norm),
				HostIDs: []string{c.HostID}})
			cis, objects = append(cis, c.CIID), append(objects, c.Name)
		}
		risk = spec.Risk
	default:
		var step store.PlanStep
		if model != nil {
			step, risk, err = s.modelStep(*model, nil)
			if err == nil && action.NeedsPin(spec.Name, step.Params) {
				for _, id := range targets {
					if !slices.Contains(hosts[id].Capabilities, action.CapPkgPin) {
						err = errors.New(hosts[id].DisplayName() + "'s agent can't pin versions; update it")
					}
				}
			}
		} else {
			step, risk, err = s.planStep(r, spec, nil)
		}
		if err != nil {
			fail(err.Error())
			return
		}
		step.HostIDs = targets
		steps = []store.PlanStep{step}
	}
	kind := store.KindNormal
	switch {
	case model != nil:
		kind = store.KindStandard
	case f.Get("kind") == store.KindEmergency:
		kind = store.KindEmergency
	}
	draft := f.Get("submit") == "draft" && model == nil
	selfApprove := f.Get("submit") == "approve" && model == nil
	if selfApprove && !canOnAll(p.Grants, rbac.Approver, targets, hosts) {
		fail("Approving needs the approver role on every host in the change; submit it for approval instead.")
		return
	}
	if rk, err := action.ParseRisk(f.Get("risk")); err == nil && model == nil {
		risk = rk
	} else if model == nil {
		risk = action.SuggestRisk([]action.Risk{risk}, max(len(targets), len(steps)))
	}
	nc := store.NewChange{
		Kind: kind, Justification: strings.TrimSpace(f.Get("justification")), Risk: risk,
		BackoutPlan: strings.TrimSpace(f.Get("backout_plan")), TestPlan: strings.TrimSpace(f.Get("test_plan")),
		StopOnFailure: f.Get("stop_on_failure") != "" || f.Get("stop_on_failure_set") == "",
		Steps:         steps, SelfApprove: selfApprove, Draft: draft, CIs: cis, Revisions: revs,
		WindowID: f.Get("window"), OnWindowEnd: store.WindowCarryOver,
	}
	if model != nil {
		nc.ModelID = model.ID
	}
	if f.Get("on_window_end") == store.WindowFail {
		nc.OnWindowEnd = store.WindowFail
	}
	nc.RequiredApprovals, _ = strconv.Atoi(f.Get("approvals"))
	concurrency, _ := strconv.Atoi(f.Get("concurrency"))
	nc.Concurrency = max(concurrency, 1)
	if impact, err := action.ParseRisk(f.Get("impact")); err == nil {
		nc.Impact = impact
	}
	if v := strings.TrimSpace(f.Get("planned_start")); v != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", v, s.cfg.Location)
		if err != nil {
			fail("The planned start isn't a date and time.")
			return
		}
		if t.Before(time.Now().Add(-time.Minute)) {
			fail("The planned start is in the past; leave it empty to start once approved.")
			return
		}
		nc.PlannedStart = t
	}
	if err := s.changes.CheckStart(ctx, store.Change{Kind: kind, PlannedStart: nc.PlannedStart, WindowID: nc.WindowID,
		HostIDs: targets}, time.Now()); err != nil {
		fail(strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + ".")
		return
	}
	nc.Title = strings.TrimSpace(f.Get("title"))
	if nc.Title == "" {
		nc.Title = changeTitle(spec, steps, objects, names)
	}
	if len(nc.Title) > 200 {
		nc.Title = nc.Title[:200]
	}
	c, err := s.store.CreateChange(ctx, s.actor(r), nc)
	if errors.Is(err, store.ErrModel) {
		fail("That change model isn't approved (any more).")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if c.State != store.ChangeSubmitted && c.State != store.ChangeDraft {
		s.nudgeJobs()
		// The dispatcher starts it at once unless a window or freeze holds
		// it; give it a moment so the job page has something to show.
		startsNow := c.WindowID == "" && c.PlannedStart.IsZero() &&
			s.changes.CheckStart(ctx, store.Change{Kind: kind, PlannedStart: time.Now(), HostIDs: targets}, time.Now()) == nil
		if s.jobs != nil && startsNow && c.Jobs == 1 {
			if jobs, err := s.store.ListJobs(ctx, store.JobFilter{ChangeID: c.ID}); err == nil && len(jobs) == 1 {
				http.Redirect(w, r, s.url("/jobs/"+jobs[0].ID), http.StatusSeeOther)
				return
			}
		}
	}
	var msg string
	switch {
	case draft:
		msg = c.Ref() + " saved as a draft. Submit it when it's ready."
	case kind == store.KindStandard:
		msg = c.Ref() + " approved by its change model " + model.Name + "."
	case selfApprove:
		msg = c.Ref() + " approved by you (self-approval, recorded as such)."
	default:
		msg = c.Ref() + " submitted. It runs once " + plural(c.RequiredApprovals, "approver approves", "approvers approve") + " it."
	}
	if c.State != store.ChangeSubmitted && c.State != store.ChangeDraft {
		switch {
		case c.WindowID != "":
			msg += " It runs in maintenance window " + c.WindowName + "."
		case !c.PlannedStart.IsZero():
			msg += " It starts at its planned time."
		default:
			msg += " Its jobs are starting."
		}
	}
	s.backToChange(w, r, c.ID, "notice", msg)
}

// modelStep is the plan step of a Standard change from its model; stack is
// the stack for compose.* models.
func (s *Server) modelStep(m store.ChangeModel, stack *store.Stack) (store.PlanStep, action.Risk, error) {
	params := []byte(m.Params)
	if m.Action == action.ComposePull || m.Action == action.ComposeUpdate {
		var err error
		if params, err = change.StackParams(m.Action, m.Params, *stack, nil); err != nil {
			return store.PlanStep{}, "", err
		}
	}
	step := store.PlanStep{Action: m.Action, Params: params, Summary: action.Describe(m.Action, params),
		ScriptID: m.ScriptID, ScriptVersion: m.ScriptVersion}
	return step, action.Risk(m.Risk), nil
}

// planStep reads the action's parameters from the form. It returns the
// step (hosts not set) and the action's risk class. stack is the stack of
// compose.* actions; a change model's form has none.
func (s *Server) planStep(r *http.Request, spec action.Spec, stack *store.Stack) (store.PlanStep, action.Risk, error) {
	f := r.Form
	step := store.PlanStep{Action: spec.Name}
	risk := spec.Risk
	var params any
	switch spec.Name {
	case action.PkgUpgrade:
		pkgs := strings.Fields(f.Get("packages"))
		if f.Get("packages") == "" {
			pkgs = f["pkg"]
		}
		params = action.UpgradeParams{Mode: f.Get("mode"), Packages: pkgs, Exclude: splitList(f.Get("exclude")), Reboot: f.Get("reboot")}
	case action.ServiceRestart, action.ServiceStart, action.ServiceStop:
		params = action.UnitParams{Unit: strings.TrimSpace(f.Get("unit"))}
	case action.ComposePull, action.ComposeUpdate, action.ComposeStart, action.ComposeArchive, action.ComposeMove:
		p := action.ComposeParams{Services: f["service"]}
		if stack != nil {
			p.Services = stackServices(f, stack.CIID)
		}
		if spec.Name == action.ComposeStart || spec.Name == action.ComposeArchive || spec.Name == action.ComposeMove {
			p.Services = nil
		}
		if spec.Name != action.ComposePull && spec.Name != action.ComposeArchive {
			p.HealthTimeout, _ = strconv.Atoi(f.Get("health_timeout"))
		}
		if spec.Name == action.ComposeMove {
			p.Dest = f.Get("dest")
		}
		if stack == nil {
			raw, _ := json.Marshal(p)
			norm, err := change.ModelParams(spec.Name, raw)
			if err != nil {
				return step, risk, err
			}
			step.Params, step.Summary = norm, spec.Label
			return step, risk, nil
		}
		p.Engine, p.Project = stack.Engine, stack.Project
		params = p
	case action.HostReboot:
		delay, err := strconv.Atoi(f.Get("delay_s"))
		if err != nil {
			delay = action.DefaultRebootDelay
		}
		params = action.RebootParams{DelaySeconds: delay}
	case action.ScriptRun:
		ver, _ := strconv.Atoi(f.Get("version"))
		sv, err := s.store.GetScriptVersion(r.Context(), f.Get("script"), ver)
		if err != nil {
			return step, risk, errors.New("pick a script")
		}
		if sv.ScriptArchive {
			return step, risk, errors.New("that script is archived")
		}
		args := map[string]string{}
		for _, prm := range sv.Params {
			if v := strings.TrimSpace(f.Get("arg_" + prm.Name)); v != "" {
				args[prm.Name] = v
			}
		}
		if _, _, err := action.ScriptArgs(sv.Params, args); err != nil {
			return step, risk, err
		}
		minutes, _ := strconv.Atoi(f.Get("timeout_m"))
		params = action.ScriptParams{ScriptID: sv.ScriptID, Name: sv.ScriptName, Version: sv.Version, Args: args, Timeout: minutes * 60}
		step.ScriptID, step.ScriptVersion = sv.ScriptID, sv.Version
		risk = action.Risk(sv.Risk)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return step, risk, err
	}
	norm, err := action.Validate(spec.Name, raw)
	if err != nil {
		return step, risk, err
	}
	step.Params = norm
	step.Summary = action.Describe(spec.Name, norm)
	return step, risk, nil
}

// stackVerb is what a compose.* action does to a stack, for messages.
func stackVerb(act string) string {
	switch act {
	case action.ComposeStart:
		return "start"
	case action.ComposeArchive:
		return "archive"
	case action.ComposeMove:
		return "move"
	case action.ComposePull:
		return "pull the images of"
	}
	return "update"
}

// splitList splits on commas and whitespace.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })
}

// changeTitle is a change's title when its requester gave none: its one
// step on its hosts, or what its steps act on.
func changeTitle(spec action.Spec, steps []store.PlanStep, objects, hosts []string) string {
	if len(steps) == 1 {
		return steps[0].Summary + " on " + hostList(hosts)
	}
	what := plural(len(objects), "container")
	switch spec.Name {
	case action.ComposeUpdate:
		what = "Update " + plural(len(objects), "Compose stack")
	case action.ComposePull:
		what = "Pull the images of " + plural(len(objects), "Compose stack")
	case action.ComposeStart:
		what = "Start " + plural(len(objects), "Compose stack")
	case action.ComposeArchive:
		what = "Archive " + plural(len(objects), "Compose stack")
	case action.ComposeMove:
		what = "Move " + plural(len(objects), "Compose stack")
	case action.ContainerRestart:
		what = "Restart " + what
	}
	if len(objects) <= 3 {
		what += " (" + strings.Join(objects, ", ") + ")"
	}
	return what + " on " + hostList(hosts)
}

func hostList(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%d hosts", len(names))
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Change models (docs/change-management.md §1): Standard changes are
// pre-approved once, as a model; each change made from it is approved
// automatically. Admins write models, approvers approve them, and editing
// one needs approval again.

type modelListView struct {
	IsAdmin bool
	List    *listView
}

func (s *Server) modelList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "model")
	if !ok {
		return
	}
	s.renderList(w, r, "change_models", "Change models", modelListView{IsAdmin: principal(r).Grants.Has(rbac.Admin), List: v}, v)
}

// modelSummaries describes what each model does, by id, for the models
// list (modelTable).
func (s *Server) modelSummaries(ctx context.Context) (map[string]string, error) {
	ms, err := s.store.ListChangeModels(ctx, "")
	out := map[string]string{}
	for _, m := range ms {
		out[m.ID] = m.Summary()
	}
	return out, err
}

type modelView struct {
	Model      store.ChangeModel
	Changes    []store.Change
	CanApprove bool
	IsAdmin    bool
	CanRun     bool
	Notice     string
	Error      string
}

func (s *Server) loadModel(w http.ResponseWriter, r *http.Request) (store.ChangeModel, bool) {
	m, err := s.store.GetChangeModel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such change model.")
		return m, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return m, false
	}
	return m, true
}

func (s *Server) modelPage(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadModel(w, r)
	if !ok {
		return
	}
	hosts, err := s.hostIndex(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	all, err := s.store.ListChanges(r.Context(), store.ChangeFilter{ModelID: m.ID, Limit: 50})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	g := principal(r).Grants
	v := modelView{Model: m, Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error"),
		CanApprove: m.State == store.ModelPending && g.Has(rbac.Approver), IsAdmin: g.Has(rbac.Admin),
		CanRun: m.Approved() && g.HasAnywhere(rbac.Operator) && m.Action != action.ComposeUpdate}
	for _, c := range all {
		if canOnAll(g, rbac.Viewer, c.HostIDs, hosts) {
			v.Changes = append(v.Changes, c)
		}
	}
	s.pages.render(w, http.StatusOK, "change_model", s.data(r, "Change model "+m.Name, v))
}

func (s *Server) backToModel(w http.ResponseWriter, r *http.Request, id, kind, msg string) {
	http.Redirect(w, r, s.url("/change-models/"+id+"?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) modelApprove(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadModel(w, r)
	if !ok {
		return
	}
	err := s.store.ApproveChangeModel(r.Context(), s.actor(r), m.ID)
	switch {
	case errors.Is(err, store.ErrState):
		s.backToModel(w, r, m.ID, "error", "This model isn't waiting for approval.")
	case err != nil:
		s.serverError(w, r, err)
	case m.RequestedBy == principal(r).User.ID:
		s.backToModel(w, r, m.ID, "notice", "Approved by you (self-approval, recorded as such). Changes made from it are approved automatically.")
	default:
		s.backToModel(w, r, m.ID, "notice", "Approved. Changes made from it are approved automatically.")
	}
}

func (s *Server) modelRetire(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadModel(w, r)
	if !ok {
		return
	}
	err := s.store.RetireChangeModel(r.Context(), s.actor(r), m.ID)
	switch {
	case errors.Is(err, store.ErrState):
		s.backToModel(w, r, m.ID, "error", "This model is already retired.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToModel(w, r, m.ID, "notice", "Retired. No more changes are made from it.")
	}
}

// modelFormView is the new-change form's view, reused for a model's action
// and parameters.
type modelFormView struct {
	changeFormView
	ID          string // editing
	Name        string
	Description string
}

// Actions a model can't hold: a container lives on one host, so a model
// for restarting "it" would be one change; stacks run their updates under a
// compose.update model, and nothing runs under a compose.pull one; deploys
// and edits carry their own files; a stack is started, archived or moved
// when someone asks.
func modelActions() []action.Spec {
	var out []action.Spec
	for _, n := range action.Names {
		if n != action.ContainerRestart && n != action.ComposePull && n != action.ComposeStart &&
			n != action.ComposeArchive && n != action.ComposeMove && !action.MustGet(n).OwnForm {
			out = append(out, action.MustGet(n))
		}
	}
	return out
}

func (s *Server) modelNew(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.renderModelForm(w, r, http.StatusOK, "", "")
}

func (s *Server) modelEdit(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadModel(w, r)
	if !ok {
		return
	}
	if m.State == store.ModelRetired {
		s.errorPage(w, r, http.StatusConflict, "A retired model can't be edited.")
		return
	}
	r.ParseForm()
	f := r.Form
	if f.Get("action") == "" {
		f.Set("action", m.Action)
		f.Set("name", m.Name)
		f.Set("description", m.Description)
		f.Set("risk", m.Risk)
		modelForm(f, m)
	}
	s.renderModelForm(w, r, http.StatusOK, m.ID, "")
}

// modelForm fills the form's parameter fields from a model.
func modelForm(f url.Values, m store.ChangeModel) {
	var p struct {
		action.UpgradeParams
		action.UnitParams
		action.RebootParams
		action.ScriptParams
		HealthTimeout int `json:"health_timeout"`
	}
	json.Unmarshal(m.Params, &p)
	switch m.Action {
	case action.PkgUpgrade:
		f.Set("mode", p.Mode)
		f.Set("packages", strings.Join(p.Packages, "\n"))
		f.Set("exclude", strings.Join(p.Exclude, " "))
		f.Set("reboot", p.Reboot)
	case action.ServiceRestart, action.ServiceStart, action.ServiceStop:
		f.Set("unit", p.Unit)
	case action.HostReboot:
		f.Set("delay_s", itoa(p.DelaySeconds))
	case action.ScriptRun:
		f.Set("script", m.ScriptID)
		f.Set("version", itoa(m.ScriptVersion))
		for k, v := range p.Args {
			f.Set("arg_"+k, v)
		}
		if p.Timeout > 0 {
			f.Set("timeout_m", itoa(p.Timeout/60))
		}
	case action.ComposeUpdate:
		f.Set("health_timeout", itoa(p.HealthTimeout))
	}
}

func (s *Server) renderModelForm(w http.ResponseWriter, r *http.Request, status int, id, errMsg string) {
	ctx := r.Context()
	f := r.Form
	v := modelFormView{changeFormView: changeFormView{Form: f, Risks: action.Risks, Error: errMsg, Actions: modelActions()},
		ID: id, Name: f.Get("name"), Description: f.Get("description")}
	title := "New change model"
	if id != "" {
		title = "Edit change model"
	}
	spec, ok := action.Get(f.Get("action"))
	if !ok || !slices.ContainsFunc(modelActions(), func(a action.Spec) bool { return a.Name == spec.Name }) {
		s.pages.render(w, status, "change_model_form", s.data(r, title, v))
		return
	}
	v.Spec = spec
	v.Risk = spec.Risk
	switch spec.Name {
	case action.ScriptRun:
		var err error
		if v.Scripts, err = s.store.ListScripts(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
		v.Scripts = slices.DeleteFunc(v.Scripts, func(sc store.Script) bool { return sc.Archived })
		if sid := f.Get("script"); sid != "" {
			ver := atoi(f.Get("version"))
			if ver == 0 {
				if sc, err := s.store.GetScript(ctx, sid); err == nil {
					ver = sc.Latest
				}
			}
			if sv, err := s.store.GetScriptVersion(ctx, sid, ver); err == nil {
				v.Script = &sv
				v.Risk = action.Risk(sv.Risk)
			}
		}
	case action.PkgUpgrade:
		v.Packages = f.Get("packages")
	}
	if rk, err := action.ParseRisk(f.Get("risk")); err == nil {
		v.Risk = rk
	}
	s.pages.render(w, status, "change_model_form", s.data(r, title+": "+spec.Label, v))
}

func (s *Server) modelSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	id := r.PathValue("id")
	fail := func(msg string) { s.renderModelForm(w, r, http.StatusUnprocessableEntity, id, msg) }
	f := r.Form
	spec, ok := action.Get(f.Get("action"))
	if !ok || !slices.ContainsFunc(modelActions(), func(a action.Spec) bool { return a.Name == spec.Name }) {
		fail("Pick an action.")
		return
	}
	name := strings.TrimSpace(f.Get("name"))
	if name == "" || len(name) > 100 {
		fail("Give the model a name (up to 100 characters).")
		return
	}
	step, risk, err := s.planStep(r, spec, nil)
	if err != nil {
		fail(err.Error())
		return
	}
	if rk, err := action.ParseRisk(f.Get("risk")); err == nil {
		risk = rk
	}
	m := store.ChangeModel{ID: id, Name: name, Description: strings.TrimSpace(f.Get("description")), Action: spec.Name,
		Params: step.Params, ScriptID: step.ScriptID, ScriptVersion: step.ScriptVersion, Risk: string(risk)}
	newID, err := s.store.SaveChangeModel(r.Context(), s.actor(r), m)
	switch {
	case errors.Is(err, store.ErrConflict):
		fail("Another model already has that name.")
		return
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such change model, or it's retired.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	msg := "Saved. It needs an approver's approval before changes can be made from it."
	if id != "" {
		msg = "Saved. Edited models need approval again; until then, changes can't be made from it."
	}
	s.backToModel(w, r, newID, "notice", msg)
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

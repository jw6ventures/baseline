package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// changeRequest is the body of POST /api/v1/changes. It mirrors the
// new-change form: one action on some hosts, with the record's text and
// schedule. The API submits the change for approval (or saves a draft);
// it never approves one.
type changeRequest struct {
	Action string          `json:"action"`
	Hosts  []string        `json:"hosts"`
	Params json.RawMessage `json:"params"`
	// Containers are container CIs for container.restart: a step for each,
	// on its host. (Alternatively params.engine and params.name plus hosts.)
	Containers []string `json:"containers"`
	Container  string   `json:"container"` // shorthand for one
	// Stacks are the Compose stack CIs of a compose.* change: a step for
	// each, on its host, with params.services applying to all of them.
	Stacks []string `json:"stacks"`
	Stack  string   `json:"stack"` // shorthand for one
	// Model makes a Standard change from an approved change model, which
	// fixes the action and its parameters.
	Model string `json:"model"`

	Kind          string `json:"kind"` // normal (default) | emergency; standard with model
	Title         string `json:"title"`
	Description   string `json:"description"`
	Justification string `json:"justification"`
	BackoutPlan   string `json:"backout_plan"`
	TestPlan      string `json:"test_plan"`
	Risk          string `json:"risk"`   // low | medium | high; suggested from the action when empty
	Impact        string `json:"impact"` // low | medium | high

	RequiredApprovals int   `json:"required_approvals"`
	Concurrency       int   `json:"concurrency"`
	StopOnFailure     *bool `json:"stop_on_failure"` // default true

	Window       string     `json:"window"`        // maintenance window ID
	PlannedStart *time.Time `json:"planned_start"` // holds the change until then
	OnWindowEnd  string     `json:"on_window_end"` // carry_over (default) | fail

	Draft bool `json:"draft"` // save without submitting
}

func (s *Server) apiChangeCreate(w http.ResponseWriter, r *http.Request) {
	var req changeRequest
	if err := readJSON(r, &req); err != nil {
		s.respond(w, r, nil, err)
		return
	}
	c, err := s.createChangeFromAPI(r, req)
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out, err := s.changeDetail(r, c)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	w.Header().Set("Location", s.url(apiPrefix+"/changes/"+c.ID))
	writeJSON(w, http.StatusCreated, out)
}

func bad(format string, args ...any) error {
	return failf(http.StatusUnprocessableEntity, format, args...)
}

// createChangeFromAPI validates the request the way changeCreate validates
// the form, and creates the change submitted (or as a draft).
func (s *Server) createChangeFromAPI(r *http.Request, req changeRequest) (store.Change, error) {
	ctx := r.Context()
	p := principal(r)
	var zero store.Change
	hosts, err := s.hostIndex(r)
	if err != nil {
		return zero, err
	}
	var model *store.ChangeModel
	if req.Model != "" {
		m, err := s.store.GetChangeModel(ctx, req.Model)
		if err != nil || !m.Approved() {
			return zero, bad("that change model isn't approved (any more)")
		}
		if req.Action != "" && req.Action != m.Action {
			return zero, bad("the change model's action is %s", m.Action)
		}
		req.Action, model = m.Action, &m
	}
	spec, ok := action.Get(req.Action)
	if !ok {
		return zero, bad("pick an action: one of %s", strings.Join(action.Names, ", "))
	}
	if req.Stack != "" {
		req.Stacks = append(req.Stacks, req.Stack)
	}
	if req.Container != "" {
		req.Containers = append(req.Containers, req.Container)
	}
	// Compose changes and container restarts name stacks or containers, and
	// get a step for each; their hosts follow.
	var stacks []store.Stack
	var containers []store.ContainerRow
	var fileStep *store.PlanStep
	var revs []store.ComposeRevision
	var fileCI, fileObject string
	switch {
	case spec.OwnForm:
		if model != nil {
			return zero, bad("deploys and edits of Compose stacks don't come from change models")
		}
		in, err := apiStackFiles(spec, req)
		if err != nil {
			return zero, err
		}
		step, rev, ci, object, err := s.stackFilesPlan(r, spec, in, hosts)
		if err != nil {
			return zero, bad("%s", err)
		}
		fileStep, revs, fileCI, fileObject = &step, []store.ComposeRevision{rev}, ci, object
		req.Hosts = step.HostIDs
	case spec.Category == action.CategoryCompose:
		if len(req.Stacks) == 0 {
			return zero, bad("a %s change names Compose stacks (stacks)", spec.Name)
		}
		req.Hosts = nil
		for _, id := range slices.Compact(slices.Sorted(slices.Values(req.Stacks))) {
			st, err := s.store.GetStack(ctx, id)
			if err != nil {
				return zero, bad("no such Compose stack: %s", id)
			}
			if ok, why := st.Can(spec.Name); !ok {
				return zero, bad("Baseline can't %s %s on %s: %s", stackVerb(spec.Name), st.Project, st.Hostname, why)
			}
			if model != nil && st.ModelID != model.ID {
				return zero, bad("%s's updates don't run under that change model; an approver sets it on the stack's page", st.Project)
			}
			stacks = append(stacks, st)
			req.Hosts = append(req.Hosts, st.HostID)
		}
		slices.SortFunc(stacks, func(a, b store.Stack) int {
			return strings.Compare(strings.ToLower(a.Hostname)+"\x00"+a.Project, strings.ToLower(b.Hostname)+"\x00"+b.Project)
		})
	case len(req.Stacks) > 0:
		return zero, bad("stacks only apply to compose.* changes")
	case len(req.Containers) > 0 && spec.Name != action.ContainerRestart:
		return zero, bad("containers only apply to container.restart")
	case len(req.Containers) > 0:
		if len(req.Params) > 0 && string(req.Params) != "{}" {
			return zero, bad("containers name the containers; leave params out")
		}
		req.Hosts = nil
		for _, id := range slices.Compact(slices.Sorted(slices.Values(req.Containers))) {
			c, err := s.store.GetContainer(ctx, id)
			if err != nil {
				return zero, bad("no such container: %s", id)
			}
			containers = append(containers, c)
			req.Hosts = append(req.Hosts, c.HostID)
		}
		slices.SortFunc(containers, func(a, b store.ContainerRow) int {
			return strings.Compare(strings.ToLower(a.Hostname)+"\x00"+a.Name, strings.ToLower(b.Hostname)+"\x00"+b.Name)
		})
	}
	targets := slices.Compact(slices.Sorted(slices.Values(req.Hosts)))
	if len(targets) == 0 {
		return zero, bad("pick at least one host (hosts)")
	}
	if spec.Name == action.ContainerRestart && containers == nil && len(targets) != 1 {
		return zero, bad("a container lives on one host")
	}
	names, err := checkTargets(p.Grants, spec, targets, hosts)
	if err != nil {
		return zero, bad("%s", err)
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
				step, risk, err = s.apiPlanStep(r, spec, req.Params, &st)
			}
			if err == nil {
				err = checkDest(step, hosts[st.HostID])
			}
			if err != nil {
				return zero, bad("%s: %s", st.Project, err)
			}
			step.HostIDs = []string{st.HostID}
			steps, cis, objects = append(steps, step), append(cis, st.CIID), append(objects, st.Project)
		}
	case containers != nil:
		for _, c := range containers {
			raw, _ := json.Marshal(action.ContainerParams{Engine: c.Engine, Name: c.Name})
			norm, err := action.Validate(spec.Name, raw)
			if err != nil {
				return zero, bad("%s: %s", c.Name, err)
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
			step, risk, err = s.apiPlanStep(r, spec, req.Params, nil)
		}
		if err != nil {
			return zero, bad("%s", err)
		}
		step.HostIDs = targets
		steps = []store.PlanStep{step}
	}

	kind := store.KindNormal
	switch {
	case model != nil:
		if req.Kind != "" && req.Kind != store.KindStandard {
			return zero, bad("a change from a model is a Standard change")
		}
		kind = store.KindStandard
	case req.Kind == "" || req.Kind == store.KindNormal:
	case req.Kind == store.KindEmergency:
		kind = store.KindEmergency
	case req.Kind == store.KindStandard:
		return zero, bad("a Standard change needs a change model (model)")
	default:
		return zero, bad("kind must be normal, emergency or standard")
	}
	if model == nil {
		if req.Risk != "" {
			if risk, err = action.ParseRisk(req.Risk); err != nil {
				return zero, bad("risk must be low, medium or high")
			}
		} else {
			risk = action.SuggestRisk([]action.Risk{risk}, max(len(targets), len(steps)))
		}
	} else if req.Risk != "" {
		return zero, bad("a Standard change's risk comes from its model")
	}
	draft := req.Draft && model == nil
	nc := store.NewChange{
		Kind: kind, Description: strings.TrimSpace(req.Description), Justification: strings.TrimSpace(req.Justification),
		Risk: risk, BackoutPlan: strings.TrimSpace(req.BackoutPlan), TestPlan: strings.TrimSpace(req.TestPlan),
		StopOnFailure: req.StopOnFailure == nil || *req.StopOnFailure,
		Steps:         steps, Draft: draft, CIs: cis, Revisions: revs,
		WindowID: req.Window, OnWindowEnd: store.WindowCarryOver,
		RequiredApprovals: req.RequiredApprovals, Concurrency: max(req.Concurrency, 1),
	}
	if model != nil {
		nc.ModelID = model.ID
	}
	switch req.OnWindowEnd {
	case "", store.WindowCarryOver:
	case store.WindowFail:
		nc.OnWindowEnd = store.WindowFail
	default:
		return zero, bad("on_window_end must be carry_over or fail")
	}
	if req.Impact != "" {
		if nc.Impact, err = action.ParseRisk(req.Impact); err != nil {
			return zero, bad("impact must be low, medium or high")
		}
	}
	if req.RequiredApprovals < 0 || req.RequiredApprovals > store.MaxApprovals {
		return zero, bad("required_approvals is 0 to %d", store.MaxApprovals)
	}
	if req.Window != "" {
		if mw, err := s.store.GetWindow(ctx, req.Window); err != nil || mw.Kind != store.WindowKindWindow || !mw.Active {
			return zero, bad("no such active maintenance window")
		}
	}
	if req.PlannedStart != nil {
		if req.PlannedStart.Before(time.Now().Add(-time.Minute)) {
			return zero, bad("the planned start is in the past; leave it out to start once approved")
		}
		nc.PlannedStart = *req.PlannedStart
	}
	if err := s.changes.CheckStart(ctx, store.Change{Kind: kind, PlannedStart: nc.PlannedStart, WindowID: nc.WindowID,
		HostIDs: targets}, time.Now()); err != nil {
		return zero, bad("%s", err)
	}
	nc.Title = strings.TrimSpace(req.Title)
	if nc.Title == "" {
		nc.Title = changeTitle(spec, steps, objects, names)
	}
	if len(nc.Title) > 200 {
		nc.Title = nc.Title[:200]
	}
	c, err := s.store.CreateChange(ctx, s.actor(r), nc)
	if errors.Is(err, store.ErrModel) {
		return zero, bad("that change model isn't approved (any more)")
	}
	if err != nil {
		return zero, err
	}
	// A Standard change is approved by its model and may start at once.
	if c.State != store.ChangeSubmitted && c.State != store.ChangeDraft {
		s.nudgeJobs()
	}
	return c, nil
}

// stackFilesParams are the params of a compose.deploy or compose.edit
// request: the step's own (action.StackFileParams) are filled in by the
// server, which keeps the files and sends them with the job.
type stackFilesParams struct {
	Engine  string `json:"engine"`  // compose.deploy
	Project string `json:"project"` // compose.deploy
	Root    string `json:"root"`    // compose.deploy, when the host has Compose roots
	// Compose and Env are the files' text. An edit leaves out the one it
	// keeps; a deploy needs Compose, and leaving Env out (or empty) writes
	// no .env.
	Compose *string `json:"compose"`
	Env     *string `json:"env"`
	// BaseSHA256 (compose.edit) is the hash of the Compose file the edit
	// starts from (GET /stacks/{id}/files); the edit is refused if the
	// host's file is another one by now.
	BaseSHA256    string `json:"base_sha256"`
	HealthTimeout int    `json:"health_timeout"`
}

// apiStackFiles reads a compose.deploy or compose.edit request.
func apiStackFiles(spec action.Spec, req changeRequest) (stackFiles, error) {
	var p stackFilesParams
	var in stackFiles
	if len(req.Params) > 0 {
		if err := strictUnmarshal(req.Params, &p); err != nil {
			return in, bad("%s", err)
		}
	}
	if len(req.Containers) > 0 {
		return in, bad("containers only apply to container.restart")
	}
	in.HealthTimeout, in.BaseSHA256 = p.HealthTimeout, p.BaseSHA256
	if p.Compose != nil {
		in.Compose, in.ChangeCompose = *p.Compose, true
	}
	if p.Env != nil {
		in.Env, in.ChangeEnv = *p.Env, true
	}
	if spec.Name == action.ComposeDeploy {
		if len(req.Stacks) > 0 {
			return in, bad("a deploy names its host (hosts) and the stack's engine and project in params; stacks are for edits")
		}
		if len(req.Hosts) != 1 {
			return in, bad("a deploy goes to one host (hosts)")
		}
		if p.BaseSHA256 != "" {
			return in, bad("params.base_sha256 is for edits")
		}
		if p.Engine == "" || strings.TrimSpace(p.Project) == "" {
			return in, bad("params.engine and params.project name the new stack")
		}
		if !in.ChangeCompose {
			return in, bad("params.compose is the stack's Compose file")
		}
		in.ChangeEnv = in.ChangeEnv && strings.TrimSpace(in.Env) != ""
		in.Host, in.Engine, in.Project, in.Root = req.Hosts[0], p.Engine, strings.TrimSpace(p.Project), p.Root
		return in, nil
	}
	if len(req.Hosts) > 0 {
		return in, bad("an edit names its stack (stack); its host follows")
	}
	if len(req.Stacks) != 1 {
		return in, bad("an edit changes one Compose stack (stack)")
	}
	if p.Engine != "" || p.Project != "" || p.Root != "" {
		return in, bad("the stack names the engine, project and directory; leave them out of params")
	}
	in.Stack = req.Stacks[0]
	return in, nil
}

// apiPlanStep builds the plan step of a change from the request's
// parameters: the action's own (action.Validate), plus the script lookup
// and the stack's naming that the form does for the user.
func (s *Server) apiPlanStep(r *http.Request, spec action.Spec, params json.RawMessage, stack *store.Stack) (store.PlanStep, action.Risk, error) {
	step := store.PlanStep{Action: spec.Name}
	risk := spec.Risk
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	switch spec.Name {
	case action.ComposePull, action.ComposeUpdate, action.ComposeStart, action.ComposeArchive, action.ComposeMove:
		var p action.ComposeParams
		if err := strictUnmarshal(params, &p); err != nil {
			return step, risk, err
		}
		if p.Engine != "" || p.Project != "" {
			return step, risk, errors.New("the stack names the engine and project; leave them out of params")
		}
		p.Engine, p.Project = stack.Engine, stack.Project
		params, _ = json.Marshal(p)
	case action.ScriptRun:
		var p action.ScriptParams
		if err := strictUnmarshal(params, &p); err != nil {
			return step, risk, err
		}
		if p.ScriptID == "" {
			return step, risk, errors.New("params.script_id names the script to run")
		}
		if p.Version == 0 {
			sc, err := s.store.GetScript(r.Context(), p.ScriptID)
			if err != nil {
				return step, risk, errors.New("no such script")
			}
			p.Version = sc.Latest
		}
		sv, err := s.store.GetScriptVersion(r.Context(), p.ScriptID, p.Version)
		if err != nil {
			return step, risk, errors.New("no such script version")
		}
		if sv.ScriptArchive {
			return step, risk, errors.New("that script is archived")
		}
		if p.Args == nil {
			p.Args = map[string]string{}
		}
		if _, _, err := action.ScriptArgs(sv.Params, p.Args); err != nil {
			return step, risk, err
		}
		p.Name = sv.ScriptName
		step.ScriptID, step.ScriptVersion = sv.ScriptID, sv.Version
		risk = action.Risk(sv.Risk)
		params, _ = json.Marshal(p)
	}
	norm, err := action.Validate(spec.Name, params)
	if err != nil {
		return step, risk, err
	}
	step.Params = norm
	step.Summary = action.Describe(spec.Name, norm)
	return step, risk, nil
}

func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("params: " + err.Error())
	}
	return nil
}

// checkTargets checks that every target host may run the action for this
// user: operator on it, not revoked, and its policy and capabilities allow
// it. It returns the hosts' display names.
func checkTargets(g rbac.Grants, spec action.Spec, targets []string, hosts map[string]store.Host) ([]string, error) {
	var names []string
	for _, id := range targets {
		h, ok := hosts[id]
		if !ok || !g.HasOn(rbac.Operator, h.GroupIDs) {
			return nil, errors.New("changing a host needs the operator role on it")
		}
		if h.Revoked {
			return nil, errors.New(h.DisplayName() + " is revoked")
		}
		if ok, why := h.Policy.Allows(spec.Name); !ok {
			return nil, errors.New(h.DisplayName() + ": " + why)
		}
		if ok, why := spec.Supported(h.Capabilities); !ok {
			return nil, errors.New(h.DisplayName() + " can't do this: it " + why)
		}
		if why := stackDirBlock(spec.Name, h); why != "" {
			return nil, errors.New(why)
		}
		names = append(names, h.DisplayName())
	}
	return names, nil
}

// stackFilesJSON is GET /stacks/{id}/files: what a compose.edit starts
// from.
type stackFilesJSON struct {
	CIID    string `json:"ci_id"`
	HostID  string `json:"host_id"`
	Engine  string `json:"engine"`
	Project string `json:"project"`
	// Editable is false when Baseline can't edit the stack, and EditBlock
	// says why.
	Editable  bool   `json:"editable"`
	EditBlock string `json:"edit_block,omitempty"`
	// Compose is the stack's one Compose file, or null when it runs from
	// several or the host hasn't reported it.
	Compose *stackComposeJSON `json:"compose"`
	Env     stackEnvJSON      `json:"env"`
}

type stackComposeJSON struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	// Content is Baseline's own copy when it wrote the file on the host;
	// otherwise inventory's, with secret values masked (Masked).
	Content string `json:"content"`
	Masked  bool   `json:"masked"`
}

type stackEnvJSON struct {
	// Known is false when Baseline never wrote the stack's .env.
	Known    bool     `json:"known"`
	Revision string   `json:"revision,omitempty"`
	Keys     []string `json:"keys"`
	Hash     string   `json:"hash,omitempty"`
	// Text is the .env itself, with env=1 and the operator role on the
	// host; each read is audited.
	Text *string `json:"text,omitempty"`
}

func (s *Server) apiStackFiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, err := s.store.GetStack(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	var h store.Host
	if err == nil {
		h, err = s.apiLoadHost(r, st.HostID, rbac.Viewer)
	}
	withEnv := queryBool(r, "env")
	if err == nil && withEnv && !principal(r).Grants.HasOn(rbac.Operator, h.GroupIDs) {
		err = failf(http.StatusForbidden, "reading the .env needs the operator role on the stack's host")
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out := stackFilesJSON{CIID: st.CIID, HostID: st.HostID, Engine: st.Engine, Project: st.Project, Env: stackEnvJSON{Keys: []string{}}}
	out.EditBlock = s.editBlock(ctx, action.MustGet(action.ComposeEdit), st, h)
	out.Editable = out.EditBlock == ""
	revs, err := s.store.StackRevisions(ctx, st.HostID, st.Engine, st.Project, 20)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if files := s.stackComposeFiles(r, st); len(files) == 1 && files[0].SHA256 != "" {
		c := &stackComposeJSON{Path: files[0].Path, SHA256: files[0].SHA256}
		c.Content, c.Masked = editStart(files[0], revs)
		out.Compose = c
	}
	rev, err := s.store.StackEnv(ctx, st.HostID, st.Engine, st.Project)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.apiServerError(w, r, err)
		return
	default:
		out.Env = stackEnvJSON{Known: true, Revision: rev.ID, Keys: rev.EnvKeys, Hash: rev.EnvHash}
		if out.Env.Keys == nil {
			out.Env.Keys = []string{}
		}
		if withEnv {
			text, err := s.openEnv(r, rev, "api")
			if err != nil {
				s.apiServerError(w, r, err)
				return
			}
			t := string(text)
			out.Env.Text = &t
		}
	}
	writeJSON(w, http.StatusOK, out)
}

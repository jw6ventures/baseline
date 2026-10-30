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
	"unicode/utf8"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/stackenv"
	"github.com/jw6ventures/baseline/internal/store"
)

// Compose stack management (docs/change-management.md §5.1): changes that
// deploy a stack to a host, or edit a stack's Compose file or .env. They
// carry files, so they are made from their own section of the new-change
// form, opened from a host's or a stack's page, or through the API with the
// files in params (api_changes.go).

// composeMask is what the agent puts in place of secret values in the
// Compose files inventory shows (internal/agent/collect).
const composeMask = "********"

const maxComposeSize = 1 << 20

// stackFileForm is the compose.deploy or compose.edit part of the new-change
// form.
type stackFileForm struct {
	Host  store.Host
	Stack *store.Stack // compose.edit
	Block string       // why the change can't be made, or ""
	// compose.deploy: the engines the host has.
	Engines []string
	// compose.edit: the stack's one Compose file as the host reports it,
	// and whether the form starts from inventory's masked copy (Baseline has
	// no copy of its own that matches).
	File   composeFileView
	Masked bool
	// The .env Baseline last wrote, by revision; Known is false when it never
	// wrote one.
	EnvKnown bool
	EnvKeys  []string
	EnvHash  string
	EnvRev   store.ComposeRevision
}

// stackFilesBlock says why a host can't take compose.deploy or
// compose.edit, or "".
func stackFilesBlock(spec action.Spec, h store.Host) string {
	switch {
	case h.Revoked:
		return h.DisplayName() + " is revoked"
	case !h.ManageCompose:
		return "Compose stack management is off for " + h.DisplayName() + "; an admin turns it on on the host's Settings tab"
	}
	if ok, why := h.Policy.Allows(spec.Name); !ok {
		return h.DisplayName() + ": " + why
	}
	if ok, why := spec.Supported(h.Capabilities); !ok {
		return h.DisplayName() + "'s agent can't do this: it " + why + " (a Compose CLI, and an agent from this release on)"
	}
	return ""
}

// deployEngines are the engines compose.deploy can put a stack on: Docker
// and rootful Podman when the host has them, and the rootless Podman
// engines its latest containers section reports, when its agent writes
// their files.
func (s *Server) deployEngines(r *http.Request, h store.Host) []string {
	var out []string
	for _, e := range []string{"docker", "podman"} {
		if slices.Contains(h.Capabilities, e) {
			out = append(out, e)
		}
	}
	if !slices.Contains(h.Capabilities, action.CapComposeRootless) {
		return out
	}
	var sec struct {
		Engines []struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		} `json:"engines"`
	}
	if _, err := s.section(r, h.ID, "containers", &sec); err == nil {
		for _, e := range sec.Engines {
			if strings.HasPrefix(e.Name, "podman:") && e.Error == "" && !slices.Contains(out, e.Name) {
				out = append(out, e.Name)
			}
		}
	}
	return out
}

// stackComposeFiles are a stack's Compose files from the host's latest
// containers section, with their content as the agent showed it.
func (s *Server) stackComposeFiles(r *http.Request, st store.Stack) []composeFileView {
	var sec struct {
		Stacks []struct {
			Engine      string            `json:"engine"`
			Project     string            `json:"project"`
			ConfigFiles []composeFileJSON `json:"config_files"`
		} `json:"stacks"`
	}
	var out []composeFileView
	if _, err := s.section(r, st.HostID, "containers", &sec); err == nil {
		for _, x := range sec.Stacks {
			if x.Engine == st.Engine && x.Project == st.Project {
				for _, f := range x.ConfigFiles {
					out = append(out, composeFileView(f))
				}
			}
		}
	}
	return out
}

// openEnv decrypts a revision's .env and records who read it.
func (s *Server) openEnv(r *http.Request, rev store.ComposeRevision, why string) ([]byte, error) {
	enc, err := s.store.RevisionEnv(r.Context(), rev.ID)
	if err != nil {
		return nil, err
	}
	text, err := stackenv.Open(s.secrets, rev.ID, enc)
	if err != nil {
		return nil, err
	}
	err = s.store.Audit(r.Context(), s.actor(r), store.AuditEvent{Action: "stack.env_view", ObjectType: "host", ObjectID: rev.HostID,
		Details: map[string]any{"stack": rev.Project, "engine": rev.Engine, "revision": rev.ID, "why": why}})
	return text, err
}

// stackFileFormView fills in the form's compose.deploy or compose.edit part.
// On the first look at an edit (nothing posted yet), the fields start from
// the stack's current files.
func (s *Server) stackFileFormView(r *http.Request, spec action.Spec, mine map[string]store.Host) (*stackFileForm, error) {
	ctx := r.Context()
	f := r.Form
	v := &stackFileForm{}
	if spec.Name == action.ComposeDeploy {
		h, ok := mine[f.Get("host")]
		if !ok {
			v.Block = "Pick a host you can change; deploying needs the operator role on it"
			return v, nil
		}
		v.Host, v.Block = h, stackFilesBlock(spec, h)
		v.Engines = s.deployEngines(r, h)
		return v, nil
	}
	st, err := s.store.GetStack(ctx, f.Get("stack"))
	if errors.Is(err, store.ErrNotFound) {
		v.Block = "No such stack"
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	h, ok := mine[st.HostID]
	if !ok {
		v.Block = "Editing a stack needs the operator role on its host"
		return v, nil
	}
	v.Host, v.Stack = h, &st
	v.Block = s.editBlock(ctx, spec, st, h)
	files := s.stackComposeFiles(r, st)
	if len(files) == 1 {
		v.File = files[0]
	}
	revs, err := s.store.StackRevisions(ctx, st.HostID, st.Engine, st.Project, 20)
	if err != nil {
		return nil, err
	}
	if rev, err := s.store.StackEnv(ctx, st.HostID, st.Engine, st.Project); err == nil {
		v.EnvKnown, v.EnvKeys, v.EnvHash, v.EnvRev = true, rev.EnvKeys, rev.EnvHash, rev
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if f.Get("posted") != "" || v.Block != "" {
		return v, nil
	}
	var compose string
	compose, v.Masked = editStart(v.File, revs)
	f.Set("compose", compose)
	if v.EnvKnown {
		text, err := s.openEnv(r, v.EnvRev, "edit form")
		if err != nil {
			return nil, err
		}
		f.Set("env", string(text))
	}
	return v, nil
}

// editStart is the Compose file an edit starts from: Baseline's own copy
// when it is the one on the host, since inventory's copy has its secrets
// masked; masked says the copy returned has.
func editStart(file composeFileView, revs []store.ComposeRevision) (content string, masked bool) {
	for _, rev := range revs {
		if rev.HasCompose && rev.ComposeSHA256 == file.SHA256 {
			return rev.Compose, false
		}
	}
	return file.Content, strings.Contains(file.Content, composeMask)
}

// editBlock says why a stack's files can't be edited, or "".
func (s *Server) editBlock(ctx context.Context, spec action.Spec, st store.Stack, h store.Host) string {
	if why := stackFilesBlock(spec, h); why != "" {
		return why
	}
	if ok, why := st.Drivable(); !ok {
		return "Baseline can't edit it: " + why
	}
	if strings.HasPrefix(st.Engine, "podman:") && !slices.Contains(h.Capabilities, action.CapComposeRootless) {
		return h.DisplayName() + "'s agent can't edit rootless Podman stacks yet; update it first"
	}
	if len(st.ConfigFiles) != 1 {
		return fmt.Sprintf("it runs from %d Compose files; Baseline edits stacks that run from one", len(st.ConfigFiles))
	}
	if open, err := s.store.OpenRevisions(ctx, st.HostID, st.Engine, st.Project); err == nil && len(open) > 0 {
		return open[0].ChangeRef() + " deploys or edits it already; finish or cancel that first"
	}
	return ""
}

// textField reads a textarea: browsers send CRLF line ends.
func textField(f url.Values, name string) string {
	return strings.ReplaceAll(f.Get(name), "\r\n", "\n")
}

// stackFiles is what a compose.deploy or compose.edit change is made
// from: the form's fields, or an API request's parameters.
type stackFiles struct {
	Host    string // compose.deploy
	Engine  string // compose.deploy
	Project string // compose.deploy
	Root    string // compose.deploy, when the host has Compose roots
	Stack   string // compose.edit
	// BaseSHA256 (compose.edit, optional) is the hash of the Compose file
	// the edit was made from; the edit is refused if the host's differs.
	BaseSHA256    string
	Compose, Env  string
	ChangeCompose bool // compose.edit: Compose is the new file
	ChangeEnv     bool // compose.edit: Env is the new .env; compose.deploy: there is one
	HealthTimeout int
}

// formStackFiles reads the stack files part of the new-change form.
func formStackFiles(f url.Values) stackFiles {
	in := stackFiles{Host: f.Get("host"), Engine: f.Get("engine"), Project: strings.TrimSpace(f.Get("project")),
		Root: f.Get("root"), Stack: f.Get("stack"), Compose: textField(f, "compose"), Env: textField(f, "env"),
		ChangeCompose: f.Get("change_compose") != "", ChangeEnv: f.Get("change_env") != ""}
	in.HealthTimeout, _ = strconv.Atoi(f.Get("health_timeout"))
	if f.Get("action") == action.ComposeDeploy {
		in.ChangeCompose, in.ChangeEnv = true, strings.TrimSpace(in.Env) != ""
	}
	return in
}

// stackFilesPlan is the step and revision of a compose.deploy or
// compose.edit change, with the stack's CI (edits) and name.
func (s *Server) stackFilesPlan(r *http.Request, spec action.Spec, in stackFiles, hosts map[string]store.Host) (store.PlanStep,
	store.ComposeRevision, string, string, error) {
	ctx := r.Context()
	p := principal(r)
	fail := func(format string, args ...any) (store.PlanStep, store.ComposeRevision, string, string, error) {
		return store.PlanStep{}, store.ComposeRevision{}, "", "", fmt.Errorf(format, args...)
	}
	rev := store.ComposeRevision{ID: store.NewID(), Action: spec.Name}
	params := action.StackFileParams{Revision: rev.ID, HealthTimeout: in.HealthTimeout}
	var h store.Host
	var stackCI, object string
	changeCompose, changeEnv := in.ChangeCompose, in.ChangeEnv
	compose, env := in.Compose, in.Env

	switch spec.Name {
	case action.ComposeDeploy:
		var ok bool
		if h, ok = hosts[in.Host]; !ok || !p.Grants.HasOn(rbac.Operator, h.GroupIDs) {
			return fail("deploying a stack needs the operator role on its host")
		}
		if why := stackFilesBlock(spec, h); why != "" {
			return fail("%s", why)
		}
		params.Engine, params.Project = in.Engine, in.Project
		if !slices.Contains(s.deployEngines(r, h), params.Engine) {
			return fail("%s has no %s engine Baseline can deploy to", h.DisplayName(), params.Engine)
		}
		if len(h.ComposeRoots) > 0 {
			params.Root = in.Root
			if !slices.Contains(h.ComposeRoots, params.Root) {
				return fail("pick one of %s's Compose roots", h.DisplayName())
			}
			if !slices.Contains(h.Capabilities, action.CapComposeRoots) {
				return fail("%s's agent can't deploy to a Compose root yet; update it first", h.DisplayName())
			}
		}
		stacks, err := s.store.ListStacks(ctx, []string{h.ID})
		if err != nil {
			return fail("%v", err)
		}
		if slices.ContainsFunc(stacks, func(st store.Stack) bool {
			return st.Present && st.Engine == params.Engine && st.Project == params.Project
		}) {
			return fail("a stack %s already runs on %s; edit it instead", params.Project, h.DisplayName())
		}
		if open, err := s.store.OpenRevisions(ctx, h.ID, params.Engine, params.Project); err != nil {
			return fail("%v", err)
		} else if len(open) > 0 {
			return fail("%s already deploys %s to %s", open[0].ChangeRef(), params.Project, h.DisplayName())
		}
		if !changeCompose {
			return fail("a deploy needs a Compose file")
		}
		object = params.Project
	case action.ComposeEdit:
		st, err := s.store.GetStack(ctx, in.Stack)
		if err != nil {
			return fail("the stack is gone; open its page again")
		}
		var ok bool
		if h, ok = hosts[st.HostID]; !ok || !p.Grants.HasOn(rbac.Operator, h.GroupIDs) {
			return fail("editing a stack needs the operator role on its host")
		}
		if why := s.editBlock(ctx, spec, st, h); why != "" {
			return fail("%s", why)
		}
		params.Engine, params.Project, stackCI, object = st.Engine, st.Project, st.CIID, st.Project
		files := s.stackComposeFiles(r, st)
		if len(files) != 1 || files[0].SHA256 == "" {
			return fail("the host hasn't reported the stack's Compose file yet")
		}
		base := files[0]
		if in.BaseSHA256 != "" && in.BaseSHA256 != base.SHA256 {
			return fail("the stack's Compose file on the host changed since (it is %s now); start from the current one", base.SHA256)
		}
		changeCompose = changeCompose && stackenv.SHA256([]byte(compose)) != base.SHA256
		if changeEnv {
			if cur, err := s.store.StackEnv(ctx, st.HostID, st.Engine, st.Project); err == nil {
				if text, err := s.openEnv(r, cur, "compare"); err == nil && string(text) == env {
					changeEnv = false
				}
			}
		}
		if !changeCompose && !changeEnv {
			return fail("nothing changed: edit the Compose file, the .env, or both")
		}
		if changeCompose {
			if strings.Contains(compose, composeMask) {
				return fail("the Compose file still holds masked values (%s); put the real values back, or move them into the .env as ${VARIABLES}", composeMask)
			}
			rev.BaseSHA256, rev.BaseCompose = base.SHA256, base.Content
			params.BaseSHA256 = base.SHA256
		}
	}

	if changeCompose {
		switch {
		case strings.TrimSpace(compose) == "":
			return fail("the Compose file is empty")
		case len(compose) > maxComposeSize:
			return fail("the Compose file is larger than 1 MiB")
		case !utf8.ValidString(compose) || strings.ContainsRune(compose, 0):
			return fail("the Compose file isn't text")
		}
		if !strings.HasSuffix(compose, "\n") {
			compose += "\n"
		}
		rev.Compose, rev.HasCompose, rev.ComposeSHA256 = compose, true, stackenv.SHA256([]byte(compose))
		params.ComposeSHA256 = rev.ComposeSHA256
	}
	if changeEnv {
		if env != "" && !strings.HasSuffix(env, "\n") {
			env += "\n"
		}
		keys, err := stackenv.Check([]byte(env))
		if err != nil {
			return fail("the .env: %v", err)
		}
		if rev.EnvEnc, err = stackenv.Seal(s.secrets, rev.ID, []byte(env)); err != nil {
			return fail("%v", err)
		}
		rev.HasEnv, rev.EnvKeys, rev.EnvHash = true, keys, stackenv.Hash(stackenv.HashKey(s.cfg.SecretKey), []byte(env))
		params.Env = true
	}
	rev.HostID, rev.Engine, rev.Project = h.ID, params.Engine, params.Project
	raw, err := json.Marshal(params)
	if err != nil {
		return fail("%v", err)
	}
	norm, err := action.Validate(spec.Name, raw)
	if err != nil {
		return fail("%v", err)
	}
	step := store.PlanStep{Action: spec.Name, Params: norm, Summary: action.Describe(spec.Name, norm), HostIDs: []string{h.ID}}
	return step, rev, stackCI, object, nil
}

// hostManageCompose turns Compose stack management on or off for a host.
func (s *Server) hostManageCompose(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	on := r.FormValue("manage_compose") == "1"
	changed, err := s.store.SetHostManageCompose(r.Context(), s.actor(r), h.ID, on)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if changed && len(h.ComposeRoots) > 0 {
		s.configureAgent(r, h.ID) // it lists stacks under the roots only while on
	}
	notice := "Compose stack management turned off: no new deploys or edits on this host."
	if on {
		notice = "Compose stack management turned on: operators can deploy stacks to this host and edit its stacks' files, through changes."
	}
	s.backToHostTab(w, r, h.ID, "settings", notice)
}

// hostComposeRoots adds a Compose root to a host, or removes one.
func (s *Server) hostComposeRoots(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Admin)
	if !ok {
		return
	}
	var notice string
	if root := r.FormValue("remove"); root != "" {
		removed, err := s.store.RemoveHostComposeRoot(r.Context(), s.actor(r), h.ID, root)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if removed {
			s.configureAgent(r, h.ID)
		}
		notice = "Compose root " + root + " removed. Stacks already deployed under it stay where they are."
	} else {
		root := strings.TrimSpace(r.FormValue("root"))
		if len(root) > 1 {
			root = strings.TrimRight(root, "/")
		}
		if err := action.CheckComposeRoot(root); err != nil {
			s.errorPage(w, r, http.StatusBadRequest, "Not added: "+err.Error()+".")
			return
		}
		if !h.ManageCompose {
			s.errorPage(w, r, http.StatusBadRequest, "Turn on Compose stack management first.")
			return
		}
		added, err := s.store.AddHostComposeRoot(r.Context(), s.actor(r), h.ID, root)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		notice = "Compose root " + root + " added."
		if added {
			s.configureAgent(r, h.ID)
		} else {
			notice = root + " is a Compose root already."
		}
	}
	s.backToHostTab(w, r, h.ID, "settings", notice)
}

// revisionEnvPage shows the .env a revision writes, to operators of its
// host; each look is audited.
func (s *Server) revisionEnvPage(w http.ResponseWriter, r *http.Request) {
	rev, err := s.store.ComposeRevision(r.Context(), r.PathValue("id"))
	if err == nil && !rev.HasEnv {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such .env.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	h, ok := s.hostAccess(w, r, rev.HostID, rbac.Operator, "No such .env.")
	if !ok {
		return
	}
	text, err := s.openEnv(r, rev, "shown")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "stack_env", s.data(r, ".env of "+rev.Project, struct {
		Revision store.ComposeRevision
		Host     store.Host
		Env      string
	}{rev, h, string(text)}))
}

// stackDirBlock says why a host can't take compose.archive or compose.move,
// which move a stack's directory, or "": like edits, they need Compose
// stack management on.
func stackDirBlock(act string, h store.Host) string {
	if (act == action.ComposeArchive || act == action.ComposeMove) && !h.ManageCompose {
		return "Compose stack management is off for " + h.DisplayName() + "; an admin turns it on on the host's Settings tab"
	}
	return ""
}

// checkDest checks that a compose.move step moves the stack under one of
// its host's Compose roots.
func checkDest(step store.PlanStep, h store.Host) error {
	if step.Action != action.ComposeMove {
		return nil
	}
	var p action.ComposeParams
	json.Unmarshal(step.Params, &p)
	if !slices.Contains(h.ComposeRoots, p.Dest) {
		if len(h.ComposeRoots) == 0 {
			return errors.New(h.DisplayName() + " has no Compose roots to move it to; an admin adds them on the host's Settings tab")
		}
		return fmt.Errorf("%s isn't one of %s's Compose roots (%s)", p.Dest, h.DisplayName(), strings.Join(h.ComposeRoots, ", "))
	}
	return nil
}

// moveRoots are the Compose roots compose.move offers: those of the hosts
// of the stacks that can move.
func moveRoots(stacks []stackChoice, hosts map[string]store.Host) []string {
	var out []string
	for _, c := range stacks {
		if c.Disabled != "" {
			continue
		}
		for _, root := range hosts[c.HostID].ComposeRoots {
			if !slices.Contains(out, root) {
				out = append(out, root)
			}
		}
	}
	return out
}

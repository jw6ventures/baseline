package server

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// maxScript caps a script body.
const maxScript = 256 << 10

type scriptListView struct {
	Scripts []store.Script
	IsAdmin bool
	Notice  string
}

func (s *Server) scriptList(w http.ResponseWriter, r *http.Request) {
	scripts, err := s.store.ListScripts(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "scripts", s.data(r, "Scripts", scriptListView{
		Scripts: scripts, IsAdmin: principal(r).Grants.Has(rbac.Admin), Notice: r.URL.Query().Get("notice"),
	}))
}

type scriptView struct {
	Script   store.Script
	Versions []store.ScriptVersion
	Shown    store.ScriptVersion // the version being looked at
	IsAdmin  bool
	CanRun   bool
	Notice   string
}

func (s *Server) scriptPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := s.store.GetScript(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such script.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	versions, err := s.store.ScriptVersions(ctx, sc.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	g := principal(r).Grants
	v := scriptView{Script: sc, Versions: versions, IsAdmin: g.Has(rbac.Admin), CanRun: g.HasAnywhere(rbac.Operator) && !sc.Archived,
		Notice: r.URL.Query().Get("notice")}
	want, _ := strconv.Atoi(r.URL.Query().Get("v"))
	for _, ver := range versions {
		if ver.Version == want || (want == 0 && ver.Version == sc.Latest) {
			v.Shown = ver
		}
	}
	if v.Shown.Version == 0 && len(versions) > 0 {
		v.Shown = versions[0]
	}
	s.pages.render(w, http.StatusOK, "script", s.data(r, sc.Name, v))
}

type scriptFormView struct {
	New         bool
	ID          string
	Name        string
	Description string
	Interpreter string
	Risk        string
	Params      string
	Body        string
	Notes       string
	Error       string
	Next        int // the version number saving creates
	Interps     []string
	Risks       []action.Risk
}

func (s *Server) scriptNew(w http.ResponseWriter, r *http.Request) {
	s.pages.render(w, http.StatusOK, "script_form", s.data(r, "New script", scriptFormView{
		New: true, Interpreter: "/bin/sh", Risk: string(action.Medium), Body: "#!/bin/sh\nset -eu\n\n", Next: 1,
		Interps: action.Interpreters, Risks: action.Risks,
	}))
}

func (s *Server) scriptEdit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := s.store.GetScript(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such script.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	latest, err := s.store.GetScriptVersion(ctx, sc.ID, sc.Latest)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "script_form", s.data(r, "New version of "+sc.Name, scriptFormView{
		ID: sc.ID, Name: sc.Name, Description: sc.Description, Interpreter: latest.Interpreter, Risk: latest.Risk,
		Params: action.FormatScriptParams(latest.Params), Body: latest.Body, Next: sc.Latest + 1,
		Interps: action.Interpreters, Risks: action.Risks,
	}))
}

// scriptSave creates a script, or (with an ID in the path) a new version of
// one. Saved versions never change.
func (s *Server) scriptSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v := scriptFormView{
		New: id == "", ID: id, Name: strings.TrimSpace(r.FormValue("name")), Description: strings.TrimSpace(r.FormValue("description")),
		Interpreter: r.FormValue("interpreter"), Risk: r.FormValue("risk"), Params: r.FormValue("params"),
		Body: strings.ReplaceAll(r.FormValue("body"), "\r\n", "\n"), Notes: strings.TrimSpace(r.FormValue("notes")),
		Interps: action.Interpreters, Risks: action.Risks,
	}
	fail := func(msg string) {
		v.Error = msg
		title := "New script"
		if !v.New {
			title = "New version of " + v.Name
		}
		s.pages.render(w, http.StatusUnprocessableEntity, "script_form", s.data(r, title, v))
	}
	risk, err := action.ParseRisk(v.Risk)
	switch {
	case v.New && (v.Name == "" || len(v.Name) > 100):
		fail("Give the script a name (up to 100 characters).")
		return
	case !slices.Contains(action.Interpreters, v.Interpreter):
		fail("Pick an interpreter.")
		return
	case err != nil:
		fail("Pick a risk class.")
		return
	case strings.TrimSpace(v.Body) == "":
		fail("The script is empty.")
		return
	case len(v.Body) > maxScript:
		fail("Scripts are limited to 256 KiB.")
		return
	case strings.ContainsRune(v.Body, 0):
		fail("The script contains a NUL byte.")
		return
	}
	params, err := action.ParseScriptParams(v.Params)
	if err != nil {
		fail("Parameters: " + err.Error())
		return
	}
	nv := store.NewScriptVersion{Interpreter: v.Interpreter, Params: params, Risk: risk, Body: v.Body, Notes: v.Notes}
	if v.New {
		id, err = s.store.CreateScript(r.Context(), s.actor(r), v.Name, v.Description, nv)
		if errors.Is(err, store.ErrConflict) {
			fail("A script named " + v.Name + " already exists.")
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		http.Redirect(w, r, s.url("/scripts/"+id+"?notice="+urlQueryEscape("Script saved as version 1.")), http.StatusSeeOther)
		return
	}
	n, err := s.store.AddScriptVersion(r.Context(), s.actor(r), id, v.Description, nv)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such script.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/scripts/"+id+"?notice="+urlQueryEscape("Saved as version "+strconv.Itoa(n)+".")), http.StatusSeeOther)
}

func (s *Server) scriptArchive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	archived := r.FormValue("archived") == "1"
	err := s.store.SetScriptArchived(r.Context(), s.actor(r), id, archived)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such script.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "Script restored."
	if archived {
		msg = "Script archived: it can't be run, and its versions stay for the jobs that used them."
	}
	http.Redirect(w, r, s.url("/scripts/"+id+"?notice="+urlQueryEscape(msg)), http.StatusSeeOther)
}

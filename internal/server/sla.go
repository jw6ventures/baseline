package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

// SLA policies (Settings > SLAs) and the clocks on the record view
// (docs/data-model.md §13).

// formatSpan writes minutes as parseSpan reads them: "1d4h", "30m".
func formatSpan(min int) string {
	if min <= 0 {
		return ""
	}
	var parts []string
	for _, u := range []struct {
		n    int
		unit string
	}{{24 * 60, "d"}, {60, "h"}, {1, "m"}} {
		if min >= u.n {
			parts = append(parts, fmt.Sprintf("%d%s", min/u.n, u.unit))
			min %= u.n
		}
	}
	return strings.Join(parts, "")
}

type slaPoliciesView struct {
	Policies   []store.SLAPolicy
	Edit       store.SLAPolicy   // the form: empty ID for a new policy
	Spans      map[string]string // the form's targets as typed, by "<metric>_<priority>"
	Projects   []store.Project
	Types      []store.TicketType
	Priorities []string
	Metrics    []string
	Notice     string
	Error      string
}

// Span is the form's target for a metric and priority.
func (v slaPoliciesView) Span(metric, priority string) string {
	if s, ok := v.Spans[metric+"_"+priority]; ok {
		return s
	}
	return formatSpan(v.Edit.Targets.Target(priority, metric))
}

func (s *Server) slaPoliciesPage(w http.ResponseWriter, r *http.Request, v slaPoliciesView, status int) {
	ctx := r.Context()
	var err error
	if v.Policies, err = s.store.ListSLAPolicies(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Projects, err = s.store.ListProjects(ctx, true); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Types, err = s.store.ListTicketTypes(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Priorities, v.Metrics = store.Priorities, store.SLAMetrics
	s.pages.render(w, status, "sla_policies", s.data(r, "SLAs", v))
}

func (s *Server) slaPolicies(w http.ResponseWriter, r *http.Request) {
	v := slaPoliciesView{Edit: store.SLAPolicy{Enabled: true}, Notice: r.URL.Query().Get("notice")}
	if id := r.URL.Query().Get("edit"); id != "" {
		p, err := s.store.GetSLAPolicy(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, r, err)
			return
		}
		if err == nil {
			v.Edit = p
		}
	}
	s.slaPoliciesPage(w, r, v, http.StatusOK)
}

func (s *Server) slaPolicySave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in := store.SLAPolicy{ID: id, Name: strings.TrimSpace(r.FormValue("name")), ProjectID: r.FormValue("project"),
		TypeID: r.FormValue("type"), Enabled: r.FormValue("enabled") == "1", Targets: store.SLATargets{}}
	spans := map[string]string{}
	var msg string
	for _, prio := range store.Priorities {
		for _, metric := range store.SLAMetrics {
			key := metric + "_" + prio
			spans[key] = r.FormValue(key)
			if strings.TrimSpace(spans[key]) == "" {
				continue
			}
			d, err := parseSpan(spans[key])
			min := int(d / time.Minute)
			if (err != nil || min <= 0) && msg == "" {
				msg = "Write targets as durations such as 30m, 4h, 2d or 1d4h."
			}
			if min > 0 {
				if in.Targets[prio] == nil {
					in.Targets[prio] = map[string]int{}
				}
				in.Targets[prio][metric] = min
			}
		}
	}
	if in.Name == "" {
		msg = "Enter a name."
	}
	if msg == "" {
		_, err := s.store.SaveSLAPolicy(r.Context(), s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrSLAScopeTaken):
			msg = "Another policy already covers that project and ticket type."
		case errors.Is(err, store.ErrConflict):
			msg = "A policy called " + in.Name + " already exists."
		case errors.Is(err, store.ErrNotFound) && id != "":
			s.errorPage(w, r, http.StatusNotFound, "No such SLA policy.")
			return
		case errors.Is(err, store.ErrNotFound):
			msg = "That project or ticket type no longer exists."
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		s.slaPoliciesPage(w, r, slaPoliciesView{Edit: in, Spans: spans, Error: msg}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/slas?notice="+url.QueryEscape("Saved "+in.Name+".")), http.StatusSeeOther)
}

func (s *Server) slaPolicyDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteSLAPolicy(r.Context(), s.actor(r), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such SLA policy.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/settings/slas?notice="+url.QueryEscape("Deleted. Clocks it started keep running.")), http.StatusSeeOther)
}

// slaClockView is an SLA clock as the record view shows it.
type slaClockView struct {
	store.SLAClock
	State string // running | met | breached
	Left  string // time left, or how late
}

func slaClockViews(clocks []store.SLAClock, now time.Time) []slaClockView {
	var out []slaClockView
	for _, c := range clocks {
		v := slaClockView{SLAClock: c, State: "running"}
		end := now
		if !c.Running() {
			v.State, end = "met", c.MetAt
		}
		if c.Breached(now) {
			v.State = "breached"
		}
		d := int(c.TargetAt.Sub(end).Minutes())
		switch {
		case d > 0 && c.Running():
			v.Left = formatSpan(d) + " left"
		case d < 0:
			v.Left = formatSpan(-d) + " late"
		}
		out = append(out, v)
	}
	return out
}

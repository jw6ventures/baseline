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
	"github.com/jw6ventures/baseline/internal/change"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/scheduler"
	"github.com/jw6ventures/baseline/internal/stackname"
	"github.com/jw6ventures/baseline/internal/store"
)

// Maintenance windows and freezes, the calendar and patch groups
// (docs/change-management.md §3, §4).

func (s *Server) scheduleRoutes(mux *http.ServeMux) {
	mux.Handle("GET /windows", s.page(anyRole, s.windowList))
	mux.Handle("GET /windows/new", s.page(adminOnly, s.windowNew))
	mux.Handle("POST /windows", s.page(adminOnly, s.windowSave))
	mux.Handle("GET /windows/{id}/edit", s.page(adminOnly, s.windowEdit))
	mux.Handle("POST /windows/{id}", s.page(adminOnly, s.windowSave))
	mux.Handle("POST /windows/{id}/delete", s.page(adminOnly, s.windowDelete))

	mux.Handle("GET /calendar", s.page(anyRole, s.calendar))

	mux.Handle("GET /patch-groups", s.page(anyRole, s.patchGroupList))
	mux.Handle("GET /patch-groups/new", s.page(adminOnly, s.patchGroupNew))
	mux.Handle("POST /patch-groups", s.page(adminOnly, s.patchGroupSave))
	mux.Handle("GET /patch-groups/{id}", s.page(anyRole, s.patchGroupPage))
	mux.Handle("GET /patch-groups/{id}/edit", s.page(adminOnly, s.patchGroupEdit))
	mux.Handle("POST /patch-groups/{id}", s.page(adminOnly, s.patchGroupSave))
	mux.Handle("POST /patch-groups/{id}/delete", s.page(adminOnly, s.patchGroupDelete))
	mux.Handle("POST /patch-groups/{id}/run", s.page(anyOperator, s.patchGroupRun))
}

const (
	minWindow = time.Minute
	maxWindow = 31 * 24 * time.Hour
	// maxSoak bounds a patch group's soak time.
	maxSoak = 90 * 24 * time.Hour
)

// Formatting ------------------------------------------------------------------

// when formats a time in the display time zone, to the minute.
func (s *Server) when(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(s.cfg.Location).Format("Mon 2006-01-02 15:04 MST")
}

// openingText describes a window opening: "Sun 2026-10-18 02:00 – 05:00 CDT",
// with the end's date when it falls on another day.
func (s *Server) openingText(o scheduler.Opening) string {
	loc := s.cfg.Location
	a, b := o.Start.In(loc), o.End.In(loc)
	if a.YearDay() == b.YearDay() && a.Year() == b.Year() || b.Equal(midnightAfter(a)) {
		return a.Format("Mon 2006-01-02 15:04") + " – " + b.Format("15:04 MST")
	}
	return a.Format("Mon 2006-01-02 15:04") + " – " + b.Format("Mon 2006-01-02 15:04 MST")
}

func midnightAfter(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, t.Location())
}

// inText is a coarse time until t: "in 5m", "in 3h", "in 2d".
func inText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "in under a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	}
	return fmt.Sprintf("in %dd", int(d.Hours()/24))
}

// parseSpan reads a duration such as "3h", "90m", "1h30m" or "2d".
func parseSpan(in string) (time.Duration, error) {
	str := strings.ToLower(strings.TrimSpace(in))
	bad := fmt.Errorf("%q isn't a duration such as 3h, 90m or 2d", in)
	var d time.Duration
	if i := strings.IndexByte(str, 'd'); i >= 0 {
		n, err := strconv.Atoi(str[:i])
		if err != nil || n < 0 || n > 3660 {
			return 0, bad
		}
		d, str = time.Duration(n)*24*time.Hour, str[i+1:]
		if str == "" {
			return d, nil
		}
	}
	r, err := time.ParseDuration(str)
	if err != nil || r < 0 {
		return 0, bad
	}
	return d + r, nil
}

// spanText formats a duration the way parseSpan reads it: "3h", "1h30m",
// "2d" (whole days only).
func spanText(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	day := 24 * time.Hour
	if d%day == 0 {
		return fmt.Sprintf("%dd", d/day)
	}
	var b strings.Builder
	for _, u := range []struct {
		unit time.Duration
		sfx  string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if n := d / u.unit; n > 0 {
			fmt.Fprintf(&b, "%d%s", n, u.sfx)
			d -= n * u.unit
		}
	}
	return b.String()
}

var cronMacros = map[string]string{
	"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
	"@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}

var weekdays = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// cronWords puts the common shapes of cron expression into words ("Sundays
// at 02:00"); "" for anything else, which is shown as written.
func cronWords(expr string) string {
	e := strings.TrimSpace(expr)
	if m, ok := cronMacros[strings.ToLower(e)]; ok {
		e = m
	}
	f := strings.Fields(e)
	if len(f) != 5 {
		return ""
	}
	minute, err := strconv.Atoi(f[0])
	if err != nil || minute < 0 || minute > 59 {
		return ""
	}
	if f[1] == "*" && f[2] == "*" && f[3] == "*" && f[4] == "*" {
		return fmt.Sprintf("hourly at :%02d", minute)
	}
	hour, err := strconv.Atoi(f[1])
	if err != nil || hour < 0 || hour > 23 {
		return ""
	}
	at := fmt.Sprintf("at %02d:%02d", hour, minute)
	dom, domErr := strconv.Atoi(f[2])
	switch {
	case f[3] != "*":
		mon, err := strconv.Atoi(f[3])
		if err != nil || mon < 1 || mon > 12 || domErr != nil || f[4] != "*" {
			return ""
		}
		return fmt.Sprintf("yearly on %d %s %s", dom, time.Month(mon).String()[:3], at)
	case f[2] == "*" && f[4] == "*":
		return "daily " + at
	case f[2] == "*":
		if days := dowWords(f[4]); days != "" {
			return days + " " + at
		}
	case f[4] == "*" && domErr == nil:
		return fmt.Sprintf("monthly on day %d %s", dom, at)
	}
	return ""
}

// dowWords reads a day-of-week field made of days and ranges.
func dowWords(field string) string {
	var set [7]bool
	value := func(s string) (int, bool) {
		for i, n := range weekdays {
			if strings.EqualFold(s, n[:3]) {
				return i, true
			}
		}
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 0 && n <= 7
	}
	for item := range strings.SplitSeq(field, ",") {
		a, b, isRange := strings.Cut(item, "-")
		lo, ok1 := value(a)
		hi, ok2 := lo, true
		if isRange {
			hi, ok2 = value(b)
		}
		if !ok1 || !ok2 || hi < lo {
			return ""
		}
		for d := lo; d <= hi; d++ {
			set[d%7] = true
		}
	}
	var names []string
	for i, on := range set {
		if on {
			names = append(names, weekdays[i])
		}
	}
	switch {
	case set == [7]bool{false, true, true, true, true, true, false}:
		return "weekdays"
	case set == [7]bool{true, false, false, false, false, false, true}:
		return "weekends"
	case len(names) == 7:
		return "daily"
	case len(names) == 1:
		return names[0] + "s"
	}
	for i, n := range names {
		names[i] = n[:3]
	}
	return strings.Join(names, ", ")
}

// scheduleError explains a bad cron expression or time zone, or is "".
func scheduleError(cron, tz string) string {
	if strings.TrimSpace(cron) == "" {
		return "Give a schedule: a cron expression such as 0 2 * * SUN."
	}
	if _, err := scheduler.Parse(cron); err != nil {
		return "Schedule: " + err.Error() + "."
	}
	if strings.TrimSpace(tz) == "" {
		return "Give a time zone, such as UTC or America/Chicago."
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "Time zone: " + tz + " isn't one this server knows (use a name such as UTC or America/Chicago)."
	}
	return ""
}

// groupChoice is a host group offered in a form.
type groupChoice struct {
	ID      string
	Name    string
	Hosts   int
	Checked bool
}

// groupChoices lists host groups with how many hosts each holds.
func (s *Server) groupChoices(ctx context.Context, checked []string) ([]groupChoice, error) {
	groups, err := s.store.ListHostGroups(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	count := map[string]int{}
	for _, h := range hosts {
		if !h.Revoked {
			for _, g := range h.GroupIDs {
				count[g]++
			}
		}
	}
	out := make([]groupChoice, len(groups))
	for i, g := range groups {
		out[i] = groupChoice{ID: g.ID, Name: g.Name, Hosts: count[g.ID], Checked: slices.Contains(checked, g.ID)}
	}
	return out, nil
}

// Windows -----------------------------------------------------------------------

type windowListView struct {
	IsAdmin   bool
	DisplayTZ string
	List      *listView
}

// windowFactsOf works out each window's schedule in words and its current
// or next opening, for the windows list (windowTable).
func (s *Server) windowFactsOf(ctx context.Context) (windowFacts, error) {
	f := windowFacts{Schedule: map[string]string{}, Next: map[string]string{}, Closes: map[string]string{},
		State: map[string]string{}}
	ws, err := s.store.ListWindows(ctx)
	if err != nil {
		return f, err
	}
	now := time.Now()
	for _, mw := range ws {
		words := "for " + spanText(mw.Duration)
		if w := cronWords(mw.Cron); w != "" {
			words = w + ", " + words
		}
		f.Schedule[mw.ID] = words
		cw, err := change.Compile(mw)
		switch {
		case err != nil:
			f.State[mw.ID] = "error"
			continue
		case !mw.Active || mw.ScopeGone:
			f.State[mw.ID] = "inactive"
			continue
		}
		o := cw.Sched.NextOpening(now)
		if o.IsZero() {
			f.State[mw.ID] = "never"
			continue
		}
		f.State[mw.ID] = "closed"
		if o.Contains(now) {
			f.State[mw.ID] = "open"
		}
		f.Next[mw.ID], f.Closes[mw.ID] = o.Start.Format(time.RFC3339), o.End.Format(time.RFC3339)
	}
	return f, nil
}

func (s *Server) windowList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "window")
	if !ok {
		return
	}
	s.renderList(w, r, "windows", "Maintenance windows", windowListView{IsAdmin: principal(r).Grants.Has(rbac.Admin),
		DisplayTZ: s.cfg.Location.String(), List: v}, v)
}

type windowFormView struct {
	New          bool
	ID           string
	Name         string
	Description  string
	Kind         string
	Cron         string
	Duration     string
	TZ           string
	Active       bool
	Groups       []groupChoice
	Error        string
	Preview      []string // the next openings
	PreviewNote  string
	PatchGroups  []string // that use it (edit)
	DisplayTZ    string
	ExampleZones []string
}

var exampleZones = []string{"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
	"Europe/London", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"}

// fill loads the form's choices and the schedule preview.
func (s *Server) fillWindowForm(ctx context.Context, v *windowFormView, scope []string) error {
	var err error
	if v.Groups, err = s.groupChoices(ctx, scope); err != nil {
		return err
	}
	v.DisplayTZ, v.ExampleZones = s.cfg.Location.String(), exampleZones
	d, derr := parseSpan(v.Duration)
	if scheduleError(v.Cron, v.TZ) != "" || derr != nil || d < minWindow {
		return nil
	}
	cw, err := change.Compile(store.MaintenanceWindow{Cron: v.Cron, TZ: v.TZ, Duration: d})
	if err != nil {
		return nil
	}
	now := time.Now()
	for _, o := range cw.Sched.Openings(now, now.AddDate(5, 0, 0), 3) {
		t := s.openingText(o)
		if o.Contains(now) {
			t += " (open now)"
		}
		v.Preview = append(v.Preview, t)
	}
	if len(v.Preview) == 0 {
		v.PreviewNote = "This schedule doesn't fire in the next five years."
	}
	return nil
}

func (s *Server) windowNew(w http.ResponseWriter, r *http.Request) {
	v := windowFormView{New: true, Kind: store.WindowKindWindow, Cron: "0 2 * * SUN", Duration: "3h",
		TZ: s.cfg.Location.String(), Active: true}
	if r.URL.Query().Get("kind") == store.WindowKindFreeze {
		v.Kind, v.Cron, v.Duration = store.WindowKindFreeze, "0 0 20 12 *", "14d"
	}
	if err := s.fillWindowForm(r.Context(), &v, nil); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "window_form", s.data(r, "New window", v))
}

func (s *Server) windowEdit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mw, err := s.store.GetWindow(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such window.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := windowFormView{ID: mw.ID, Name: mw.Name, Description: mw.Description, Kind: mw.Kind, Cron: mw.Cron,
		Duration: spanText(mw.Duration), TZ: mw.TZ, Active: mw.Active}
	if err := s.fillWindowForm(ctx, &v, mw.ScopeGroups); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.PatchGroups, err = s.windowUsers(ctx, mw.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "window_form", s.data(r, "Edit "+mw.Name, v))
}

// windowUsers names the patch groups that run in a window.
func (s *Server) windowUsers(ctx context.Context, id string) ([]string, error) {
	groups, err := s.store.ListPatchGroups(ctx)
	var out []string
	for _, g := range groups {
		if g.WindowID == id {
			out = append(out, g.Name)
		}
	}
	return out, err
}

func (s *Server) windowSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	id := r.PathValue("id")
	v := windowFormView{New: id == "", ID: id, Name: strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")), Kind: r.FormValue("kind"),
		Cron: strings.Join(strings.Fields(r.FormValue("cron")), " "), Duration: strings.TrimSpace(r.FormValue("duration")),
		TZ: strings.TrimSpace(r.FormValue("tz")), Active: r.FormValue("active") == "1"}
	scope := r.Form["scope"]
	fail := func(msg string) {
		v.Error = msg
		if err := s.fillWindowForm(ctx, &v, scope); err != nil {
			s.serverError(w, r, err)
			return
		}
		if !v.New {
			v.PatchGroups, _ = s.windowUsers(ctx, id)
		}
		title := "New window"
		if !v.New {
			title = "Edit " + v.Name
		}
		s.pages.render(w, http.StatusUnprocessableEntity, "window_form", s.data(r, title, v))
	}
	d, derr := parseSpan(v.Duration)
	switch {
	case v.Name == "" || len(v.Name) > 100:
		fail("Give it a name (up to 100 characters).")
		return
	case v.Kind != store.WindowKindWindow && v.Kind != store.WindowKindFreeze:
		fail("Choose a window or a freeze.")
		return
	case scheduleError(v.Cron, v.TZ) != "":
		fail(scheduleError(v.Cron, v.TZ))
		return
	case derr != nil:
		fail("Duration: " + derr.Error() + ".")
		return
	case d < minWindow || d > maxWindow:
		fail("The duration must be between 1 minute and 31 days.")
		return
	}
	groups, err := s.store.ListHostGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, g := range scope {
		if !slices.ContainsFunc(groups, func(hg store.HostGroup) bool { return hg.ID == g }) {
			fail("One of the host groups no longer exists; choose the scope again.")
			return
		}
	}
	mw := store.MaintenanceWindow{ID: id, Name: v.Name, Description: v.Description, Kind: v.Kind, Cron: v.Cron,
		Duration: d, TZ: v.TZ, ScopeGroups: scope, Active: v.Active}
	_, err = s.store.SaveWindow(ctx, s.actor(r), mw)
	switch {
	case errors.Is(err, store.ErrConflict):
		fail("A window or freeze named " + v.Name + " already exists.")
		return
	case errors.Is(err, store.ErrNotFound) && !v.New:
		s.errorPage(w, r, http.StatusNotFound, "No such window.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	noun := "Window"
	if v.Kind == store.WindowKindFreeze {
		noun = "Freeze"
	}
	http.Redirect(w, r, s.url("/windows?notice="+urlQueryEscape(noun+" "+v.Name+" saved.")), http.StatusSeeOther)
}

func (s *Server) windowDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mw, err := s.store.GetWindow(ctx, r.PathValue("id"))
	if err == nil {
		err = s.store.DeleteWindow(ctx, s.actor(r), mw.ID)
	}
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such window.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/windows?notice="+urlQueryEscape("Deleted "+mw.Name+".")), http.StatusSeeOther)
}

// Calendar ----------------------------------------------------------------------

// Calendar item kinds.
const (
	calWindow = "window"
	calFreeze = "freeze"
	calChange = "change"
	calPatch  = "patch"
)

// calItem is something on the calendar: a window or freeze opening (with
// an end), a change planned to start, or a patch group's run.
type calItem struct {
	Kind   string
	Start  time.Time
	End    time.Time // zero for a point in time
	Name   string
	Href   string // under Base
	Detail string
}

// calEntry is an item as one day of the grid shows it.
type calEntry struct {
	calItem
	Time string // "02:00–05:00", "from 22:00", "until 05:00", "all day"
}

type calDay struct {
	ID      string // "d-2026-10-13"
	Day     int
	InMonth bool
	Today   bool
	Past    bool
	Entries []calEntry
	More    int
}

type upcomingItem struct {
	calItem
	When string
}

type calendarView struct {
	Month     string // "October 2026"
	Prev      string // "2026-09"
	Next      string
	This      string
	IsCurrent bool
	Weekdays  []string
	Weeks     [][]calDay
	Upcoming  []upcomingItem
	DisplayTZ string
}

// perDay caps the entries a day of the grid shows.
const perDay = 6

// calendarItems collects what's on the calendar in [from, to): window and
// freeze openings that overlap it, changes the user can see planned to
// start in it, and the enabled patch groups' runs after now.
func (s *Server) calendarItems(ctx context.Context, g rbac.Grants, from, to, now time.Time) ([]calItem, error) {
	var items []calItem
	ws, err := s.store.ListWindows(ctx)
	if err != nil {
		return nil, err
	}
	for _, mw := range ws {
		if !mw.Active {
			continue
		}
		cw, err := change.Compile(mw)
		if err != nil {
			continue
		}
		detail := "all hosts"
		if !mw.Global() {
			detail = strings.Join(mw.ScopeNames, ", ")
		}
		if mw.Kind == store.WindowKindFreeze {
			detail = "freeze: " + detail
		}
		for _, o := range cw.Sched.Openings(from, to, 500) {
			items = append(items, calItem{Kind: mw.Kind, Start: o.Start, End: o.End, Name: mw.Name,
				Href: "/windows?" + url.Values{"cf": {"name"}, "co": {"eq"}, "cv": {mw.Name}}.Encode(), Detail: detail})
		}
	}

	changes, err := s.store.ListChanges(ctx, store.ChangeFilter{
		States:      []string{store.ChangeApproved, store.ChangeScheduled, store.ChangeInProgress},
		PlannedFrom: from, PlannedTo: to, Limit: 1000,
	})
	if err != nil {
		return nil, err
	}
	if len(changes) > 0 {
		hosts, err := s.store.ListHosts(ctx)
		if err != nil {
			return nil, err
		}
		index := make(map[string]store.Host, len(hosts))
		for _, h := range hosts {
			index[h.ID] = h
		}
		for _, c := range changes {
			if !canOnAll(g, rbac.Viewer, c.HostIDs, index) {
				continue
			}
			items = append(items, calItem{Kind: calChange, Start: c.PlannedStart, Name: c.Ref() + " " + c.Title,
				Href: "/changes/" + c.ID, Detail: humanState(c.State)})
		}
	}

	groups, err := s.store.ListPatchGroups(ctx)
	if err != nil {
		return nil, err
	}
	after := from.Add(-time.Minute) // NextRun is strictly after
	if now.After(after) {
		after = now
	}
	for _, pg := range groups {
		if !pg.Enabled {
			continue
		}
		detail := "patch group: " + pg.Targets()
		if pg.ModelState != store.ModelApproved {
			detail += " (model not approved: skipped)"
		}
		n := 0
		for t := change.NextRun(pg, after); !t.IsZero() && t.Before(to) && n < 500; t = change.NextRun(pg, t) {
			items = append(items, calItem{Kind: calPatch, Start: t, Name: pg.Name, Href: "/patch-groups/" + pg.ID, Detail: detail})
			n++
		}
	}
	slices.SortStableFunc(items, func(a, b calItem) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return items, nil
}

func (s *Server) calendar(w http.ResponseWriter, r *http.Request) {
	loc := s.cfg.Location
	now := time.Now().In(loc)
	this := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
	first := this
	if m := r.URL.Query().Get("month"); m != "" {
		t, err := time.ParseInLocation("2006-01", m, loc)
		if err != nil || t.Year() < 2000 || t.Year() > 2200 {
			s.errorPage(w, r, http.StatusBadRequest, "Give the month as YYYY-MM, such as "+now.Format("2006-01")+".")
			return
		}
		first = t
	}
	// Weeks run Monday to Sunday.
	start := first.AddDate(0, 0, -((int(first.Weekday()) + 6) % 7))
	last := first.AddDate(0, 1, -1)
	end := last.AddDate(0, 0, 7-((int(last.Weekday())+6)%7))

	g := principal(r).Grants
	items, err := s.calendarItems(r.Context(), g, start, end, now)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := calendarView{
		Month: first.Format("January 2006"), Prev: first.AddDate(0, -1, 0).Format("2006-01"),
		Next: first.AddDate(0, 1, 0).Format("2006-01"), This: this.Format("2006-01"), IsCurrent: first.Equal(this),
		Weekdays:  []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		DisplayTZ: loc.String(),
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	var week []calDay
	for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
		next := d.AddDate(0, 0, 1)
		day := calDay{ID: "d-" + d.Format("2006-01-02"), Day: d.Day(), InMonth: d.Month() == first.Month(),
			Today: d.Equal(today), Past: d.Before(today)}
		for _, it := range items {
			label, ok := dayLabel(it, d, next, loc)
			if !ok {
				continue
			}
			if len(day.Entries) == perDay {
				day.More++
				continue
			}
			day.Entries = append(day.Entries, calEntry{calItem: it, Time: label})
		}
		week = append(week, day)
		if len(week) == 7 {
			v.Weeks = append(v.Weeks, week)
			week = nil
		}
	}

	// The next fortnight as a list, whatever month is shown.
	soon, err := s.calendarItems(r.Context(), g, today, now.Add(14*24*time.Hour), now)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, it := range soon {
		if !it.End.IsZero() && !it.End.After(now) {
			continue // an opening that ended earlier today
		}
		v.Upcoming = append(v.Upcoming, upcomingItem{calItem: it, When: s.itemWhen(it, now)})
	}
	s.pages.render(w, http.StatusOK, "calendar", s.data(r, "Calendar", v))
}

// dayLabel places an item on the day [d, next): the time it shows there,
// and whether it shows at all.
func dayLabel(it calItem, d, next time.Time, loc *time.Location) (string, bool) {
	a := it.Start.In(loc)
	if it.End.IsZero() {
		return a.Format("15:04"), !a.Before(d) && a.Before(next)
	}
	b := it.End.In(loc)
	if !a.Before(next) || !b.After(d) {
		return "", false
	}
	startsToday, endsToday := !a.Before(d), !b.After(next)
	switch {
	case !a.After(d) && !b.Before(next):
		return "all day", true
	case startsToday && endsToday:
		return a.Format("15:04") + "–" + b.Format("15:04"), true
	case startsToday:
		return "from " + a.Format("15:04"), true
	case endsToday:
		return "until " + b.Format("15:04"), true
	}
	return "all day", true
}

// itemWhen describes when an upcoming item happens.
func (s *Server) itemWhen(it calItem, now time.Time) string {
	if it.End.IsZero() {
		return s.when(it.Start)
	}
	if !it.Start.After(now) {
		return "now, until " + s.when(it.End)
	}
	return s.openingText(scheduler.Opening{Start: it.Start, End: it.End})
}

// Patch groups ------------------------------------------------------------------

type patchGroupRow struct {
	store.PatchGroup
	Words   string
	Soak    string
	NextRun string
	NextIn  string
}

type patchGroupListView struct {
	Groups  []patchGroupRow
	IsAdmin bool
	Notice  string
}

func (s *Server) patchGroupList(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListPatchGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	now := time.Now()
	v := patchGroupListView{IsAdmin: principal(r).Grants.Has(rbac.Admin), Notice: r.URL.Query().Get("notice")}
	for _, g := range groups {
		row := patchGroupRow{PatchGroup: g, Words: cronWords(g.Cron), Soak: spanText(g.Soak)}
		if g.Enabled {
			if t := change.NextRun(g, now); !t.IsZero() {
				row.NextRun, row.NextIn = s.when(t), inText(t.Sub(now))
			}
		}
		v.Groups = append(v.Groups, row)
	}
	s.pages.render(w, http.StatusOK, "patch_groups", s.data(r, "Patch groups", v))
}

type patchGroupView struct {
	Group       store.PatchGroup
	Words       string
	Soak        string
	Action      string // the model's action
	Promotes    bool   // promote_validated applies
	NextRuns    []string
	Blocks      []store.PatchGroup // groups this one blocks
	Cycles      []store.PatchCycle
	IsAdmin     bool
	CanRun      bool
	Notice      string
	Warn        string
	OutOfWindow bool // the next run falls outside its window
}

// mayRun reports whether the user holds operator on every host of the
// group's host group, or that its stacks run on (globally, when it has
// none).
func (s *Server) mayRun(ctx context.Context, g rbac.Grants, pg store.PatchGroup) (bool, error) {
	members, err := s.store.HostGroupMembers(ctx, pg.HostGroupID)
	if err != nil {
		return false, err
	}
	if pg.Compose() {
		if members, err = s.stackHosts(ctx, pg.Stacks); err != nil {
			return false, err
		}
	}
	if len(members) == 0 {
		return g.Has(rbac.Operator), nil
	}
	for _, h := range members {
		if !g.HasOn(rbac.Operator, h.GroupIDs) {
			return false, nil
		}
	}
	return true, nil
}

// stackHosts lists the hosts the stacks run on.
func (s *Server) stackHosts(ctx context.Context, stacks []string) ([]store.Host, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	var on []string
	for _, id := range stacks {
		st, err := s.store.GetStack(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		on = append(on, st.HostID)
	}
	return slices.DeleteFunc(hosts, func(h store.Host) bool { return !slices.Contains(on, h.ID) }), nil
}

func (s *Server) loadPatchGroup(w http.ResponseWriter, r *http.Request) (store.PatchGroup, bool) {
	pg, err := s.store.GetPatchGroup(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such patch group.")
		return pg, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return pg, false
	}
	return pg, true
}

func (s *Server) patchGroupPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pg, ok := s.loadPatchGroup(w, r)
	if !ok {
		return
	}
	cycles, err := s.store.ListPatchCycles(ctx, pg.ID, 50)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	all, err := s.store.ListPatchGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	m, err := s.store.GetChangeModel(ctx, pg.ModelID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	g := principal(r).Grants
	v := patchGroupView{Group: pg, Words: cronWords(pg.Cron), Soak: spanText(pg.Soak), Action: m.Action,
		Cycles: cycles, IsAdmin: g.Has(rbac.Admin), Notice: r.URL.Query().Get("notice"), Warn: r.URL.Query().Get("warn")}
	v.Promotes = pg.PromoteValidated && ((len(pg.BlockedBy) > 0 && m.Action == action.PkgUpgrade) || pg.Compose())
	if g.HasAnywhere(rbac.Operator) {
		if v.CanRun, err = s.mayRun(ctx, g, pg); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	for _, o := range all {
		if slices.Contains(o.BlockedBy, pg.ID) {
			v.Blocks = append(v.Blocks, o)
		}
	}
	now := time.Now()
	var win *change.Window
	if pg.WindowID != "" {
		if mw, err := s.store.GetWindow(ctx, pg.WindowID); err == nil {
			if cw, err := change.Compile(mw); err == nil {
				win = &cw
			}
		}
	}
	for t, i := change.NextRun(pg, now), 0; !t.IsZero() && i < 3; t, i = change.NextRun(pg, t), i+1 {
		text := s.when(t)
		if win != nil {
			if _, open := win.Sched.At(t); !open {
				text += " (outside the window: waits for its next opening)"
				v.OutOfWindow = true
			}
		}
		v.NextRuns = append(v.NextRuns, text)
	}
	s.pages.render(w, http.StatusOK, "patch_group", s.data(r, pg.Name, v))
}

type patchGroupFormView struct {
	New           bool
	ID            string
	Name          string
	Description   string
	HostGroupID   string
	Stacks        []string // Compose groups
	Cron          string
	TZ            string
	WindowID      string
	ModelID       string
	BlockedBy     []string
	Soak          string
	Threshold     string
	Concurrency   string
	Promote       bool
	StopOnFailure bool
	Enabled       bool

	HostGroups   []groupChoice
	StackChoices []stackChoice // Compose groups: every stack, the ticked ones first
	Envs         []string
	Categories   []string
	Visibilities []string
	Windows      []store.MaintenanceWindow
	Models       []store.ChangeModel
	Others       []store.PatchGroup // that may block it
	Preview      []string
	PreviewNote  string
	DisplayTZ    string
	ExampleZones []string
	Error        string
}

// fillPatchGroupForm loads the form's choices and the schedule preview.
// A retired model stays on offer to a group already using it.
func (s *Server) fillPatchGroupForm(ctx context.Context, v *patchGroupFormView, currentModel string) error {
	var err error
	if v.HostGroups, err = s.groupChoices(ctx, []string{v.HostGroupID}); err != nil {
		return err
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return err
	}
	var ids []string
	for _, h := range hosts {
		if !h.Revoked {
			ids = append(ids, h.ID)
		}
	}
	stacks, err := s.store.ListStacks(ctx, ids)
	if err != nil {
		return err
	}
	v.StackChoices = nil
	for _, st := range stacks {
		c := stackChoice{Stack: st, Checked: slices.Contains(v.Stacks, st.CIID)}
		if !st.Present && !c.Checked {
			continue
		}
		if ok, why := st.Updatable(); !ok {
			c.Disabled = why // listed, so a stack that comes back is updated again
		}
		v.StackChoices = append(v.StackChoices, c)
	}
	v.Envs, v.Categories, v.Visibilities = stackname.Environments, stackname.Categories, stackname.Visibilities
	ws, err := s.store.ListWindows(ctx)
	if err != nil {
		return err
	}
	v.Windows = nil
	for _, mw := range ws {
		if mw.Kind == store.WindowKindWindow {
			v.Windows = append(v.Windows, mw)
		}
	}
	models, err := s.store.ListChangeModels(ctx, "")
	if err != nil {
		return err
	}
	v.Models = nil
	for _, m := range models {
		if m.State != store.ModelRetired || m.ID == currentModel {
			v.Models = append(v.Models, m)
		}
	}
	groups, err := s.store.ListPatchGroups(ctx)
	if err != nil {
		return err
	}
	v.Others = nil
	for _, g := range groups {
		if g.ID != v.ID {
			v.Others = append(v.Others, g)
		}
	}
	v.DisplayTZ, v.ExampleZones = s.cfg.Location.String(), exampleZones

	if scheduleError(v.Cron, v.TZ) != "" {
		return nil
	}
	var win *change.Window
	if v.WindowID != "" {
		if i := slices.IndexFunc(v.Windows, func(w store.MaintenanceWindow) bool { return w.ID == v.WindowID }); i >= 0 {
			if cw, err := change.Compile(v.Windows[i]); err == nil {
				win = &cw
			}
		}
	}
	pg := store.PatchGroup{Cron: v.Cron, TZ: v.TZ}
	for t, i := change.NextRun(pg, time.Now()), 0; !t.IsZero() && i < 3; t, i = change.NextRun(pg, t), i+1 {
		text := s.when(t)
		if win != nil {
			if _, open := win.Sched.At(t); !open {
				text += " (outside the window: the change waits for its next opening)"
			}
		}
		v.Preview = append(v.Preview, text)
	}
	if len(v.Preview) == 0 {
		v.PreviewNote = "This schedule doesn't fire in the next five years."
	}
	return nil
}

func (s *Server) patchGroupNew(w http.ResponseWriter, r *http.Request) {
	v := patchGroupFormView{New: true, Cron: "0 3 * * SAT", TZ: s.cfg.Location.String(), Soak: "0", Threshold: "100",
		Concurrency: "1", Promote: true, StopOnFailure: true, Enabled: true}
	if err := s.fillPatchGroupForm(r.Context(), &v, ""); err != nil {
		s.serverError(w, r, err)
		return
	}
	// The first approved pkg.upgrade model is the likely choice.
	for _, m := range v.Models {
		if m.Action == action.PkgUpgrade && m.Approved() {
			v.ModelID = m.ID
			break
		}
	}
	s.pages.render(w, http.StatusOK, "patch_group_form", s.data(r, "New patch group", v))
}

func (s *Server) patchGroupEdit(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.loadPatchGroup(w, r)
	if !ok {
		return
	}
	v := patchGroupFormView{ID: pg.ID, Name: pg.Name, Description: pg.Description, HostGroupID: pg.HostGroupID,
		Stacks: pg.Stacks, Cron: pg.Cron, TZ: pg.TZ, WindowID: pg.WindowID, ModelID: pg.ModelID, BlockedBy: pg.BlockedBy,
		Soak: spanText(pg.Soak), Threshold: strconv.Itoa(pg.SuccessThreshold), Concurrency: strconv.Itoa(pg.Concurrency),
		Promote: pg.PromoteValidated, StopOnFailure: pg.StopOnFailure, Enabled: pg.Enabled}
	if err := s.fillPatchGroupForm(r.Context(), &v, pg.ModelID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "patch_group_form", s.data(r, "Edit "+pg.Name, v))
}

func (s *Server) patchGroupSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	id := r.PathValue("id")
	var current store.PatchGroup
	if id != "" {
		var ok bool
		if current, ok = s.loadPatchGroup(w, r); !ok {
			return
		}
	}
	v := patchGroupFormView{New: id == "", ID: id, Name: strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")), HostGroupID: r.FormValue("host_group"),
		Stacks: slices.Compact(slices.Sorted(slices.Values(r.Form["stack"]))),
		Cron:   strings.Join(strings.Fields(r.FormValue("cron")), " "), TZ: strings.TrimSpace(r.FormValue("tz")),
		WindowID: r.FormValue("window"), ModelID: r.FormValue("model"), BlockedBy: r.Form["blocked_by"],
		Soak: strings.TrimSpace(r.FormValue("soak")), Threshold: strings.TrimSpace(r.FormValue("threshold")),
		Concurrency: strings.TrimSpace(r.FormValue("concurrency")), Promote: r.FormValue("promote") == "1",
		StopOnFailure: r.FormValue("stop_on_failure") == "1", Enabled: r.FormValue("enabled") == "1"}
	fail := func(msg string) {
		v.Error = msg
		title := "New patch group"
		if !v.New {
			title = "Edit " + current.Name
		}
		s.pages.render(w, http.StatusUnprocessableEntity, "patch_group_form", s.data(r, title, v))
	}
	if err := s.fillPatchGroupForm(ctx, &v, current.ModelID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.Soak == "" {
		v.Soak = "0"
	}
	soak, soakErr := parseSpan(v.Soak)
	threshold, thErr := strconv.Atoi(v.Threshold)
	concurrency, ccErr := strconv.Atoi(v.Concurrency)
	var model store.ChangeModel
	if i := slices.IndexFunc(v.Models, func(m store.ChangeModel) bool { return m.ID == v.ModelID }); i >= 0 {
		model = v.Models[i]
	}
	compose := strings.HasPrefix(model.Action, "compose.")
	if compose {
		// Stacks deleted meanwhile, or on hosts since revoked, drop out.
		v.HostGroupID = ""
		v.Stacks = slices.DeleteFunc(v.Stacks, func(id string) bool {
			return !slices.ContainsFunc(v.StackChoices, func(c stackChoice) bool { return c.CIID == id })
		})
	} else {
		v.Stacks = nil
	}
	switch {
	case v.Name == "" || len(v.Name) > 100:
		fail("Give the patch group a name (up to 100 characters).")
		return
	case model.ID == "":
		fail("Choose the change model its runs are made from.")
		return
	case compose && len(v.Stacks) == 0:
		fail("Pick the Compose stacks this group updates.")
		return
	case !compose && !slices.ContainsFunc(v.HostGroups, func(g groupChoice) bool { return g.ID == v.HostGroupID }):
		fail("Choose the host group to patch.")
		return
	case scheduleError(v.Cron, v.TZ) != "":
		fail(scheduleError(v.Cron, v.TZ))
		return
	case v.WindowID != "" && !slices.ContainsFunc(v.Windows, func(w store.MaintenanceWindow) bool { return w.ID == v.WindowID }):
		fail("That maintenance window no longer exists.")
		return
	case soakErr != nil:
		fail("Soak: " + soakErr.Error() + ".")
		return
	case soak > maxSoak:
		fail("The soak time can be at most 90 days.")
		return
	case thErr != nil || threshold < 1 || threshold > 100:
		fail("The success threshold is a percentage from 1 to 100.")
		return
	case ccErr != nil || concurrency < 1 || concurrency > 1000:
		fail("Hosts (or stacks) at a time must be a number from 1 to 1000.")
		return
	}
	for _, b := range v.BlockedBy {
		if !slices.ContainsFunc(v.Others, func(g store.PatchGroup) bool { return g.ID == b }) {
			fail("A patch group can't wait for itself, or for a group that no longer exists.")
			return
		}
	}
	pg := store.PatchGroup{ID: id, Name: v.Name, Description: v.Description, HostGroupID: v.HostGroupID, Stacks: v.Stacks, Cron: v.Cron,
		TZ: v.TZ, WindowID: v.WindowID, ModelID: v.ModelID, BlockedBy: v.BlockedBy, Soak: soak,
		SuccessThreshold: threshold, PromoteValidated: v.Promote, Concurrency: concurrency,
		StopOnFailure: v.StopOnFailure, Enabled: v.Enabled}
	saved, err := s.store.SavePatchGroup(ctx, s.actor(r), pg)
	switch {
	case errors.Is(err, store.ErrCycle):
		fail("Blocked by: these groups would wait for each other in a loop, so none would ever run. " +
			"Patch groups can be chained (canary, then staging, then prod) but not in a circle.")
		return
	case errors.Is(err, store.ErrConflict):
		fail("A patch group named " + v.Name + " already exists.")
		return
	case errors.Is(err, store.ErrNotFound):
		fail("The host group, change model or window was deleted meanwhile; check the form and save again.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/patch-groups/"+saved+"?notice="+urlQueryEscape("Patch group saved.")), http.StatusSeeOther)
}

func (s *Server) patchGroupDelete(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.loadPatchGroup(w, r)
	if !ok {
		return
	}
	err := s.store.DeletePatchGroup(r.Context(), s.actor(r), pg.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such patch group.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, s.url("/patch-groups?notice="+urlQueryEscape("Deleted patch group "+pg.Name+".")), http.StatusSeeOther)
}

// patchGroupRun runs a cycle now, as if it were scheduled now. The
// schedule is unaffected. It needs operator on every host in the group.
func (s *Server) patchGroupRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pg, ok := s.loadPatchGroup(w, r)
	if !ok {
		return
	}
	allowed, err := s.mayRun(ctx, principal(r).Grants, pg)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !allowed {
		where := "every host in " + pg.HostGroupName
		if pg.Compose() {
			where = "every host its stacks run on"
		}
		s.errorPage(w, r, http.StatusForbidden, "Running "+pg.Name+" needs the operator role on "+where+".")
		return
	}
	if err := s.store.Audit(ctx, s.actor(r), store.AuditEvent{Action: "patch_group.run", ObjectType: "patch_group",
		ObjectID: pg.ID, Details: map[string]any{"name": pg.Name}}); err != nil {
		s.serverError(w, r, err)
		return
	}
	now := time.Now()
	created, err := s.changes.RunCycle(ctx, pg, now, now)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if created {
		s.nudgeJobs()
	}
	back := func(kind, msg string) {
		http.Redirect(w, r, s.url("/patch-groups/"+pg.ID+"?"+kind+"="+urlQueryEscape(msg)), http.StatusSeeOther)
	}
	cycles, err := s.store.ListPatchCycles(ctx, pg.ID, 1)
	if err != nil || len(cycles) == 0 {
		back("notice", "Run requested.")
		return
	}
	c := cycles[0]
	switch {
	case c.ChangeID != "":
		what := plural(c.Hosts, "host")
		if pg.Compose() {
			what = plural(c.Hosts, "stack")
		}
		msg := "Started " + c.ChangeRef() + " on " + what + "."
		if pg.WindowID != "" {
			msg += " It runs inside " + pg.WindowName + "."
		}
		back("notice", msg)
	case c.Result == store.CycleBlocked:
		back("warn", "Not run, blocked: "+c.Reason+".")
	case c.Result == store.CycleSkipped:
		back("warn", "Not run, skipped: "+c.Reason+".")
	default:
		back("notice", "Nothing to do: "+c.Reason+".")
	}
}

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/alert"
	"github.com/jw6ventures/baseline/internal/notify"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// Notifier delivers the notification outbox (internal/notify).
type Notifier interface{ Nudge() }

// SetNotifier lets test messages go out at once.
func (s *Server) SetNotifier(n Notifier) { s.notifier = n }

func (s *Server) alertRoutes(mux *http.ServeMux) {
	mux.Handle("GET /alerts", s.page(anyRole, s.alertList))
	mux.Handle("GET /alerts/{id}", s.page(anyRole, s.alertPage))
	mux.Handle("POST /alerts/{id}/ack", s.page(anyOperator, s.alertAck))
	mux.Handle("POST /alerts/{id}/close", s.page(anyOperator, s.alertClose))
	mux.Handle("POST /alerts/{id}/silence", s.page(anyOperator, s.alertSilence))
	mux.Handle("POST /silences", s.page(anyOperator, s.silenceCreate))
	mux.Handle("POST /silences/{id}/end", s.page(anyOperator, s.silenceEnd))
	mux.Handle("GET /alert-rules/new", s.page(adminOnly, s.ruleNew))
	mux.Handle("POST /alert-rules", s.page(adminOnly, s.ruleSave))
	mux.Handle("GET /alert-rules/{id}", s.page(adminOnly, s.ruleEdit))
	mux.Handle("POST /alert-rules/{id}", s.page(adminOnly, s.ruleSave))
	mux.Handle("POST /alert-rules/{id}/delete", s.page(adminOnly, s.ruleDelete))
	mux.Handle("GET /settings/notifications", s.page(adminOnly, s.channels))
	mux.Handle("POST /settings/notifications", s.page(adminOnly, s.channelSave))
	mux.Handle("POST /settings/notifications/{id}", s.page(adminOnly, s.channelSave))
	mux.Handle("POST /settings/notifications/{id}/test", s.page(adminOnly, s.channelTest))
	mux.Handle("POST /settings/notifications/{id}/delete", s.page(adminOnly, s.channelDelete))
}

// canSee reports whether the user may see something on hosts in these
// groups; things outside every group (agentless CIs) need a global role.
func canSee(r *http.Request, groups []string) bool {
	return principal(r).Grants.HasOn(rbac.Viewer, groups)
}

// canOperate is the same for acknowledging and silencing.
func canOperate(r *http.Request, groups []string) bool {
	return principal(r).Grants.HasOn(rbac.Operator, groups)
}

type alertCounts struct {
	Critical, Warning, Info, Pending int
}

func (c *alertCounts) add(a store.Alert) {
	switch {
	case a.State == store.AlertPending:
		c.Pending++
	case a.Severity == "critical":
		c.Critical++
	case a.Severity == "warning":
		c.Warning++
	default:
		c.Info++
	}
}

type alertsView struct {
	View     string    // open | rules | silences
	List     *listView // the open view's alerts
	Counts   alertCounts
	Rules    []ruleRow
	Silences []silenceRow
	// For the silence form.
	RuleChoices []store.AlertRule
	Hosts       []store.Host
	Groups      []store.HostGroup
	CanOperate  bool
	IsAdmin     bool
	NoChannels  bool
	Notice      string
	Error       string
}

type ruleRow struct {
	store.AlertRule
	KindLabel string
	Settings  string
}

type silenceRow struct {
	store.Silence
	CanEnd   bool
	Upcoming bool
}

// ruleSettings describes a rule's parameters in a few words.
func ruleSettings(r store.AlertRule) string {
	p := r.Params
	var parts []string
	switch r.Kind {
	case "host_offline":
		parts = append(parts, plural(p.Minutes, "minute")+" offline")
	case "disk_full", "inodes_full":
		parts = append(parts, "≥ "+strconv.Itoa(p.Percent)+"%")
	case "smart":
		if p.Degrading {
			parts = append(parts, "failing, or bad sectors rising within "+plural(p.Days, "day"))
			if p.Sectors > 0 {
				parts = append(parts, "or ≥ "+strconv.Itoa(p.Sectors))
			}
		} else {
			parts = append(parts, "failing only")
		}
	case "failed_units":
		if len(p.Exclude) > 0 {
			parts = append(parts, "ignoring "+strings.Join(p.Exclude, ", "))
		}
	case "cert_expiry":
		parts = append(parts, "within "+plural(p.Days, "day"))
	case "reboot_pending":
		parts = append(parts, "for "+plural(p.Days, "day"))
	case "cve_fixable":
		parts = append(parts, p.MinSeverity+" or worse")
	case "patch_cycle":
		if p.Partial {
			parts = append(parts, "also partial")
		}
	case "unplanned_change":
		parts = append(parts, "in "+plural(p.Hours, "hour"))
	case "change_approval":
		parts = append(parts, "after "+plural(p.Hours, "hour"))
	}
	if r.For > 0 {
		parts = append(parts, "for "+spanText(r.For))
	}
	if r.Repeat > 0 {
		parts = append(parts, "remind every "+spanText(r.Repeat))
	}
	return strings.Join(parts, "; ")
}

func kindLabel(kind string) string {
	if k, ok := alert.KindByKey(kind); ok {
		return k.Label
	}
	return kind
}

func (s *Server) alertList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	g := principal(r).Grants
	v := alertsView{View: q.Get("view"), CanOperate: g.HasAnywhere(rbac.Operator), IsAdmin: g.Has(rbac.Admin),
		Notice: q.Get("notice"), Error: q.Get("error")}
	switch v.View {
	case "", "open", "history":
		v.View = "open"
		if v.List, _ = s.buildList(w, r, "alert"); v.List == nil {
			return
		}
		if isHTMX(r) {
			s.renderList(w, r, "alerts", "Alerts", v, v.List)
			return
		}
	}
	open, err := s.store.ListAlerts(ctx, store.AlertFilter{Open: true})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, a := range open {
		if canSee(r, a.GroupIDs) {
			v.Counts.add(a)
		}
	}
	switch v.View {
	case "open":
		s.renderList(w, r, "alerts", "Alerts", v, v.List)
		return
	case "rules":
		rules, err := s.store.ListAlertRules(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, rl := range rules {
			v.Rules = append(v.Rules, ruleRow{rl, kindLabel(rl.Kind), ruleSettings(rl)})
		}
		chs, err := s.store.ListChannels(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		v.NoChannels = len(chs) == 0
	case "silences":
		now := time.Now()
		sils, err := s.store.ListSilences(ctx, now.Add(-24*time.Hour))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		hosts, err := s.visibleHosts(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		groupsOf := map[string][]string{}
		for _, h := range hosts {
			groupsOf[h.ID] = h.GroupIDs
		}
		for _, sl := range sils {
			if row, ok := s.silenceAccess(r, sl, groupsOf); ok {
				row.Upcoming = sl.Starts.After(now)
				v.Silences = append(v.Silences, row)
			}
		}
		if v.CanOperate {
			if v.RuleChoices, err = s.store.ListAlertRules(ctx); err != nil {
				s.serverError(w, r, err)
				return
			}
			for _, h := range hosts {
				if !h.Revoked && canOperate(r, h.GroupIDs) {
					v.Hosts = append(v.Hosts, h)
				}
			}
			groups, err := s.store.ListHostGroups(ctx)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			for _, hg := range groups {
				if canOperate(r, []string{hg.ID}) {
					v.Groups = append(v.Groups, hg)
				}
			}
		}
	default:
		s.errorPage(w, r, http.StatusNotFound, "No such view.")
		return
	}
	s.pages.render(w, http.StatusOK, "alerts", s.data(r, "Alerts", v))
}

// silenceAccess decides whether the user sees a silence and may end it.
// groupsOf holds the groups of the hosts the user can see.
func (s *Server) silenceAccess(r *http.Request, sl store.Silence, groupsOf map[string][]string) (silenceRow, bool) {
	row := silenceRow{Silence: sl}
	switch {
	case sl.CIID != "":
		groups, ok := groupsOf[sl.CIID]
		if !ok {
			// Not a host the user sees: an agentless CI needs a global role.
			if !canSee(r, nil) {
				return row, false
			}
		}
		row.CanEnd = canOperate(r, groups)
	case sl.HostGroupID != "":
		if !canSee(r, []string{sl.HostGroupID}) {
			return row, false
		}
		row.CanEnd = canOperate(r, []string{sl.HostGroupID})
	default:
		row.CanEnd = canOperate(r, nil)
	}
	return row, true
}

func (s *Server) backToAlerts(w http.ResponseWriter, r *http.Request, view, kind, msg string) {
	q := url.Values{}
	if view != "" && view != "open" {
		q.Set("view", view)
	}
	q.Set(kind, msg)
	http.Redirect(w, r, s.url("/alerts?"+q.Encode()), http.StatusSeeOther)
}

type alertPageView struct {
	Alert         store.Alert
	Rule          store.AlertRule
	Notifications []store.Notification
	Details       [][2]string
	CanAct        bool
	IsAdmin       bool
	Notice        string
}

// loadAlert fetches the alert in the path if the user may see it.
func (s *Server) loadAlert(w http.ResponseWriter, r *http.Request) (store.Alert, bool) {
	a, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && !canSee(r, a.GroupIDs) {
		s.errorPage(w, r, http.StatusNotFound, "No such alert.")
		return a, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return a, false
	}
	return a, true
}

func (s *Server) alertPage(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAlert(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	rule, err := s.store.GetAlertRule(ctx, a.RuleID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ns, err := s.store.AlertNotifications(ctx, a.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := alertPageView{Alert: a, Rule: rule, Notifications: ns, CanAct: (a.State == store.AlertPending || a.State == store.AlertFiring) && canOperate(r, a.GroupIDs),
		IsAdmin: principal(r).Grants.Has(rbac.Admin), Notice: r.URL.Query().Get("notice")}
	keys := make([]string, 0, len(a.Details))
	for k := range a.Details {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		val := diffValue(a.Details[k])
		if val == "" || val == "[]" || val == "null" {
			continue
		}
		label := strings.ReplaceAll(k, "_", " ")
		v.Details = append(v.Details, [2]string{strings.ToUpper(label[:1]) + label[1:], val})
	}
	s.pages.render(w, http.StatusOK, "alert", s.data(r, rule.Name, v))
}

func (s *Server) alertAck(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAlert(w, r)
	if !ok {
		return
	}
	if !canOperate(r, a.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this here.")
		return
	}
	err := s.store.AckAlert(r.Context(), s.actor(r), a.ID, strings.TrimSpace(r.FormValue("comment")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	s.backFromAlert(w, r, a.ID, "Acknowledged: no more reminders for this alert.")
}

func (s *Server) alertClose(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAlert(w, r)
	if !ok {
		return
	}
	if !canOperate(r, a.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this here.")
		return
	}
	err := s.store.CloseAlert(r.Context(), s.actor(r), a.ID, strings.TrimSpace(r.FormValue("comment")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	// Closed alerts show nowhere, so back to the list either way.
	s.backToAlerts(w, r, "", "notice", "Closed. It won't notify or show again unless it gets worse.")
}

// backFromAlert returns to the alert's page, or to the list the form was
// posted from.
func (s *Server) backFromAlert(w http.ResponseWriter, r *http.Request, id, notice string) {
	if r.FormValue("from") == "list" {
		s.backToAlerts(w, r, "", "notice", notice)
		return
	}
	http.Redirect(w, r, s.url("/alerts/"+id+"?notice="+url.QueryEscape(notice)), http.StatusSeeOther)
}

// bulkAck acknowledges a firing alert from the list, as its button did;
// any other is skipped.
func bulkAck(s *Server, r *http.Request, id, _ string) error {
	a, err := s.store.GetAlert(r.Context(), id)
	if err != nil {
		return err
	}
	if !canOperate(r, a.GroupIDs) || a.State != store.AlertFiring || a.Acked() {
		return store.ErrNotFound
	}
	return s.store.AckAlert(r.Context(), s.actor(r), a.ID, "")
}

// bulkClose closes a pending or firing alert from the list; any other is
// skipped.
func bulkClose(s *Server, r *http.Request, id, _ string) error {
	a, err := s.store.GetAlert(r.Context(), id)
	if err != nil {
		return err
	}
	if !canOperate(r, a.GroupIDs) || (a.State != store.AlertPending && a.State != store.AlertFiring) {
		return store.ErrNotFound
	}
	return s.store.CloseAlert(r.Context(), s.actor(r), a.ID, "")
}

// bulkSilence silences an open alert from the list for a span, as its
// button did; resolved and silenced ones are skipped.
func bulkSilence(s *Server, r *http.Request, id, span string) error {
	a, err := s.store.GetAlert(r.Context(), id)
	if err != nil {
		return err
	}
	d, err := parseSpan(span)
	if err != nil || d <= 0 {
		return errBadValue
	}
	if !canOperate(r, a.GroupIDs) || (a.State != store.AlertPending && a.State != store.AlertFiring) || a.Silenced() {
		return store.ErrNotFound
	}
	now := time.Now()
	_, err = s.store.CreateSilence(r.Context(), s.actor(r), store.Silence{RuleID: a.RuleID, CIID: a.CIID, Key: a.Key,
		Starts: now, Ends: now.Add(d)})
	return err
}

// silenceSpans are the durations the forms offer.
var silenceSpans = []string{"1h", "4h", "1d", "3d", "7d"}

func (s *Server) alertSilence(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAlert(w, r)
	if !ok {
		return
	}
	if !canOperate(r, a.GroupIDs) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this here.")
		return
	}
	d, err := parseSpan(r.FormValue("for"))
	if err != nil || d <= 0 || d > 90*24*time.Hour {
		s.backFromAlert(w, r, a.ID, "Pick how long to silence it for.")
		return
	}
	sl := store.Silence{RuleID: a.RuleID, CIID: a.CIID, Key: a.Key, Starts: time.Now(), Ends: time.Now().Add(d),
		Comment: strings.TrimSpace(r.FormValue("comment"))}
	if r.FormValue("match") == "subject" {
		sl.Key = "" // everything this rule finds on the subject
		if a.CIID == "" {
			sl.Key = a.Key
		}
	}
	if _, err := s.store.CreateSilence(r.Context(), s.actor(r), sl); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.backFromAlert(w, r, a.ID, "Silenced for "+spanText(d)+". It takes effect within a minute.")
}

func (s *Server) silenceCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func(msg string) { s.backToAlerts(w, r, "silences", "error", msg) }
	sl := store.Silence{RuleID: r.FormValue("rule"), CIID: r.FormValue("host"), HostGroupID: r.FormValue("group"),
		Comment: strings.TrimSpace(r.FormValue("comment"))}
	if sl.Comment == "" {
		fail("Say why, so others know.")
		return
	}
	start := time.Now()
	if v := r.FormValue("starts"); v != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", v, s.cfg.Location)
		if err != nil {
			fail("The start time isn't a date and time.")
			return
		}
		start = t
	}
	d, err := parseSpan(r.FormValue("for"))
	if err != nil || d <= 0 || d > 90*24*time.Hour {
		fail("Silence for between a minute and 90 days, e.g. 4h or 2d.")
		return
	}
	sl.Starts, sl.Ends = start, start.Add(d)
	if sl.Ends.Before(time.Now()) {
		fail("That silence would already be over.")
		return
	}
	switch {
	case sl.CIID != "":
		h, err := s.store.GetHost(ctx, sl.CIID)
		if err != nil || !canOperate(r, h.GroupIDs) {
			fail("You can't silence that host.")
			return
		}
		sl.HostGroupID = ""
	case sl.HostGroupID != "":
		if !canOperate(r, []string{sl.HostGroupID}) {
			fail("You can't silence that host group.")
			return
		}
	default:
		if !canOperate(r, nil) {
			fail("Pick a host or host group: silencing everything needs a global operator role.")
			return
		}
	}
	if sl.RuleID != "" {
		if _, err := s.store.GetAlertRule(ctx, sl.RuleID); err != nil {
			fail("That rule no longer exists.")
			return
		}
	}
	if _, err := s.store.CreateSilence(ctx, s.actor(r), sl); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.backToAlerts(w, r, "silences", "notice", "Silence added. It takes effect within a minute.")
}

func (s *Server) silenceEnd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sl, err := s.store.GetSilence(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.backToAlerts(w, r, "silences", "error", "That silence is already over.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groupsOf := map[string][]string{}
	for _, h := range hosts {
		groupsOf[h.ID] = h.GroupIDs
	}
	if row, ok := s.silenceAccess(r, sl, groupsOf); !ok || !row.CanEnd {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this here.")
		return
	}
	if err := s.store.EndSilence(ctx, s.actor(r), sl.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	s.backToAlerts(w, r, "silences", "notice", "Silence ended. Alerts it muted notify within a minute if they still fire.")
}

// Rules ------------------------------------------------------------------------

type ruleFormView struct {
	New            bool
	Rule           store.AlertRule
	Kind           alert.Kind
	Kinds          []alert.Kind
	Groups         []groupChoice
	Channels       []channelChoice
	Severities     []string
	VulnSeverities []string
	For, Repeat    string
	Exclude        string
	Error          string
}

type channelChoice struct {
	store.NotifyChannel
	Checked bool
}

func (s *Server) ruleNew(w http.ResponseWriter, r *http.Request) {
	k, ok := alert.KindByKey(r.URL.Query().Get("kind"))
	if !ok {
		s.renderRuleForm(w, r, ruleFormView{New: true, Kinds: alert.Kinds})
		return
	}
	rule := store.AlertRule{Kind: k.Key, Name: k.Label, Params: k.Defaults, Severity: "warning", NotifyResolved: true, Enabled: true}
	s.renderRuleForm(w, r, ruleFormView{New: true, Rule: rule})
}

func (s *Server) ruleEdit(w http.ResponseWriter, r *http.Request) {
	rule, err := s.store.GetAlertRule(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such rule.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderRuleForm(w, r, ruleFormView{Rule: rule})
}

func (s *Server) renderRuleForm(w http.ResponseWriter, r *http.Request, v ruleFormView) {
	ctx := r.Context()
	status := http.StatusOK
	if v.Error != "" {
		status = http.StatusUnprocessableEntity
	}
	if v.Rule.Kind != "" {
		v.Kind, _ = alert.KindByKey(v.Rule.Kind)
		var err error
		if v.Groups, err = s.groupChoices(ctx, v.Rule.ScopeGroups); err != nil {
			s.serverError(w, r, err)
			return
		}
		chs, err := s.store.ListChannels(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, c := range chs {
			v.Channels = append(v.Channels, channelChoice{c, slices.Contains(v.Rule.Channels, c.ID)})
		}
		v.Severities, v.VulnSeverities = alert.Severities, alert.VulnSeverities
		if v.For == "" && v.Rule.For > 0 {
			v.For = spanText(v.Rule.For)
		}
		if v.Repeat == "" && v.Rule.Repeat > 0 {
			v.Repeat = spanText(v.Rule.Repeat)
		}
		if v.Exclude == "" {
			v.Exclude = strings.Join(v.Rule.Params.Exclude, ", ")
		}
	}
	title := "New alert rule"
	if !v.New {
		title = "Edit " + v.Rule.Name
	}
	s.pages.render(w, status, "alert_rule_form", s.data(r, title, v))
}

func (s *Server) ruleSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rule := store.AlertRule{Kind: r.FormValue("kind")}
	id := r.PathValue("id")
	if id != "" {
		old, err := s.store.GetAlertRule(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			s.errorPage(w, r, http.StatusNotFound, "No such rule.")
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		rule = old
	}
	atoi := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k))); return n }
	rule.Name = strings.TrimSpace(r.FormValue("name"))
	rule.Severity = r.FormValue("severity")
	rule.ScopeGroups = r.Form["scope"]
	rule.Channels = r.Form["channel"]
	rule.NotifyResolved = r.FormValue("notify_resolved") == "1"
	rule.Enabled = r.FormValue("enabled") == "1"
	rule.Params = store.AlertParams{Minutes: atoi("minutes"), Percent: atoi("percent"), Days: atoi("days"), Hours: atoi("hours"), Sectors: atoi("sectors"),
		Degrading: r.FormValue("degrading") == "1", Partial: r.FormValue("partial") == "1", MinSeverity: r.FormValue("min_severity"),
		Exclude: strings.Split(r.FormValue("exclude"), ",")}
	v := ruleFormView{New: id == "", For: strings.TrimSpace(r.FormValue("for")), Repeat: strings.TrimSpace(r.FormValue("repeat")),
		Exclude: r.FormValue("exclude")}
	var err error
	rule.For, rule.Repeat = 0, 0
	if v.For != "" && v.For != "0" {
		if rule.For, err = parseSpan(v.For); err != nil {
			v.Error = err.Error()
		}
	}
	if v.Repeat != "" && v.Repeat != "0" {
		if rule.Repeat, err = parseSpan(v.Repeat); err != nil {
			v.Error = err.Error()
		}
	}
	if v.Error == "" {
		if rule, err = alert.Check(rule); err != nil {
			v.Error = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
		}
	}
	v.Rule = rule
	if v.Error != "" {
		s.renderRuleForm(w, r, v)
		return
	}
	_, err = s.store.SaveAlertRule(ctx, s.actor(r), rule)
	switch {
	case errors.Is(err, store.ErrConflict):
		v.Error = "A rule named " + rule.Name + " already exists."
		s.renderRuleForm(w, r, v)
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such rule.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAlerts(w, r, "rules", "notice", "Saved "+rule.Name+". It applies from the next evaluation, within a minute.")
	}
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteAlertRule(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToAlerts(w, r, "rules", "error", "That rule was already deleted.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToAlerts(w, r, "rules", "notice", "Rule deleted, with its alerts and silences.")
	}
}

// Channels ---------------------------------------------------------------------

type channelsView struct {
	Channels []store.NotifyChannel
	Recent   []store.Notification
	Rules    map[string][]string // channel ID -> rule names
	Error    string
	Notice   string
}

// channels is Settings → Notifications.
func (s *Server) channels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	chs, err := s.store.ListChannels(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	recent, err := s.store.RecentNotifications(ctx, 20)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rules, err := s.store.ListAlertRules(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := channelsView{Channels: chs, Recent: recent, Rules: map[string][]string{}, Error: r.URL.Query().Get("error"),
		Notice: r.URL.Query().Get("notice")}
	for _, rl := range rules {
		for _, c := range rl.Channels {
			v.Rules[c] = append(v.Rules[c], rl.Name)
		}
	}
	s.pages.render(w, http.StatusOK, "notifications", s.data(r, "Notifications", v))
}

func (s *Server) backToChannels(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/notifications?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) channelSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := store.NotifyChannel{ID: r.PathValue("id"), Kind: r.FormValue("kind"), Name: strings.TrimSpace(r.FormValue("name")),
		Enabled: r.FormValue("enabled") == "1" || r.PathValue("id") == ""}
	if c.ID != "" {
		old, err := s.store.GetChannel(ctx, c.ID)
		if errors.Is(err, store.ErrNotFound) {
			s.backToChannels(w, r, "error", "That channel was deleted.")
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		c.Kind = old.Kind
	}
	if c.Name == "" {
		s.backToChannels(w, r, "error", "Enter a name for the channel.")
		return
	}
	cfg := notify.Config{Homeserver: strings.TrimSpace(r.FormValue("homeserver")), Room: strings.TrimSpace(r.FormValue("room")),
		Server: strings.TrimSpace(r.FormValue("server")), Topic: strings.TrimSpace(r.FormValue("topic")),
		Token: strings.TrimSpace(r.FormValue("token"))}
	// Editing without new settings keeps the stored ones (and the token).
	if c.ID == "" || cfg != (notify.Config{}) {
		summary, err := notify.Check(c.Kind, cfg)
		if err != nil {
			s.backToChannels(w, r, "error", strings.ToUpper(err.Error()[:1])+err.Error()[1:]+".")
			return
		}
		if c.ConfigEnc, err = s.secrets.Seal(cfg, 0); err != nil {
			s.serverError(w, r, err)
			return
		}
		c.Summary = summary
	}
	_, err := s.store.SaveChannel(ctx, s.actor(r), c)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.backToChannels(w, r, "error", "A channel named "+c.Name+" already exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToChannels(w, r, "notice", "Saved "+c.Name+". Send a test message to check it, then pick it in alert rules.")
	}
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.store.GetChannel(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.backToChannels(w, r, "error", "That channel was deleted.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !c.Enabled {
		s.backToChannels(w, r, "error", c.Name+" is turned off.")
		return
	}
	p := principal(r)
	if err := s.store.QueueNotifications(ctx, []store.Notification{{ChannelID: c.ID, Event: store.EventTest, Severity: "info",
		Title: "Baseline test message", Body: "Sent by " + p.User.DisplayName() + " from Settings → Notifications.",
		Link: s.cfg.PublicURL.String() + "/settings/notifications"}}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.store.Audit(ctx, s.actor(r), store.AuditEvent{Action: "notify_channel.test", ObjectType: "notify_channel", ObjectID: c.ID,
		Details: map[string]any{"name": c.Name}})
	if s.notifier != nil {
		s.notifier.Nudge()
	}
	s.backToChannels(w, r, "notice", "Test message queued for "+c.Name+". Reload to see whether it went out.")
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteChannel(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToChannels(w, r, "error", "That channel was already deleted.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToChannels(w, r, "notice", "Channel deleted. Rules that used it no longer notify it.")
	}
}

// openAlertCounts counts the open alerts the user can see, for the
// dashboard.
func (s *Server) openAlertCounts(ctx context.Context, r *http.Request) (alertCounts, error) {
	var c alertCounts
	open, err := s.store.ListAlerts(ctx, store.AlertFilter{Open: true})
	if err != nil {
		return c, err
	}
	for _, a := range open {
		if canSee(r, a.GroupIDs) {
			c.add(a)
		}
	}
	return c, nil
}

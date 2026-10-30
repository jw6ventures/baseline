package server

import (
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/alert"
	"github.com/jw6ventures/baseline/internal/list"
)

// The list engine's operations tables: maintenance windows, change models,
// alerts and the audit log.

// Maintenance windows -----------------------------------------------------------

// windowFacts are what Go works out about each window from its cron
// schedule (windowFactsOf), by window id.
type windowFacts struct {
	Schedule map[string]string // in words, for its duration
	Next     map[string]string // the next or current opening's start, RFC 3339
	Closes   map[string]string // and its end
	State    map[string]string // windowStates
}

var windowStates = []list.Option{
	{Value: "open", Label: "open now"}, {Value: "closed", Label: "closed"}, {Value: "never", Label: "never opens"},
	{Value: "inactive", Label: "inactive"}, {Value: "error", Label: "schedule error"},
}

// windowTable is built per request from the windows' facts. admin links
// each window to its edit form.
func windowTable(f windowFacts, admin bool) *list.Table {
	t := &list.Table{
		Key: "window", Label: "Maintenance windows", Noun: "window",
		From:    `maintenance_window w`,
		ID:      `w.id::text`,
		DimExpr: `NOT w.active`,
		Fields: []list.Field{
			{Key: "name", Label: "Name", Type: list.Text, Expr: `w.name`, Search: true, Class: "strong", NoGroup: true},
			{Key: "kind", Label: "Kind", Type: list.Enum, Expr: `w.kind`, Badge: "window-kind",
				Options: []list.Option{{Value: "window", Label: "window"}, {Value: "freeze", Label: "freeze"}}},
			{Key: "active", Label: "Active", Type: list.Bool, Expr: `w.active`},
			{Key: "state", Label: "Now", Type: list.Enum, Options: windowStates, Badge: "window-state",
				ViewerExpr: list.Lookup("w.id::text", "text", f.State)},
			{Key: "schedule", Label: "Schedule", Type: list.Text, Search: true, NoGroup: true,
				ViewerExpr: list.Lookup("w.id::text", "text", f.Schedule)},
			{Key: "cron", Label: "Cron", Type: list.Text, Expr: `w.cron`, Class: "mono small"},
			{Key: "tz", Label: "Time zone", Type: list.Text, Expr: `w.tz`},
			{Key: "hours", Label: "Hours open", Type: list.Number, Class: "num", Expr: `round(w.duration_s / 3600.0, 2)::float8`},
			{Key: "next", Label: "Next opening", Type: list.Time, ViewerExpr: list.Lookup("w.id::text", "timestamptz", f.Next)},
			{Key: "closes", Label: "Closes", Type: list.Time, ViewerExpr: list.Lookup("w.id::text", "timestamptz", f.Closes)},
			// A scope whose groups were all deleted applies to nobody
			// (store.MaintenanceWindow.ScopeGone).
			{Key: "scope", Label: "Scope", Type: list.Tags, Search: true,
				Expr: `CASE WHEN cardinality(w.scope_groups) = 0 THEN ARRAY['all hosts']
					ELSE COALESCE(NULLIF(ARRAY(SELECT g.name FROM host_group g WHERE g.id = ANY(w.scope_groups) ORDER BY g.name), '{}'),
					ARRAY['nobody']) END`},
			{Key: "patch_groups", Label: "Patch groups", Type: list.Tags, Search: true, Class: "small",
				Expr: `ARRAY(SELECT g.name FROM patch_group g WHERE g.window_id = w.id ORDER BY g.name)`},
			{Key: "description", Label: "Description", Type: list.Text, Expr: `w.description`, Search: true,
				NoGroup: true, NoSort: true, Class: "small"},
			{Key: "updated_at", Label: "Updated", Type: list.Time, Expr: `w.updated_at`},
		},
	}
	if admin {
		t.LinkExpr = `'/windows/' || w.id || '/edit'`
		t.Fields[0].LinkExpr = t.LinkExpr
	}
	view := viewOf(list.Query{Cols: []string{"name", "kind", "schedule", "scope", "state", "next", "closes"},
		Sort: list.Sort{Field: "name"}})
	all := view("all", "All")
	t.Default = all.Query
	t.Views = []list.View{all,
		view("windows", "Windows", []list.Cond{cond("kind", list.Eq, "window")}),
		view("freezes", "Freezes", []list.Cond{cond("kind", list.Eq, "freeze")}),
		view("open", "Open now", []list.Cond{cond("state", list.Eq, "open")}),
		view("inactive", "Inactive", []list.Cond{cond("active", list.IsFalse, "")}),
	}
	return t
}

// Change models ---------------------------------------------------------------

// modelTable is built per request: summaries describes each model's
// action and parameters (store.ChangeModel.Summary), by model id.
func modelTable(summaries map[string]string) *list.Table {
	var actions []list.Option
	for _, n := range action.Names {
		actions = append(actions, list.Option{Value: n, Label: action.MustGet(n).Label})
	}
	t := &list.Table{
		Key: "model", Label: "Change models", Noun: "change model",
		From:     `change_model m LEFT JOIN app_user u ON u.id = m.requested_by LEFT JOIN app_user ap ON ap.id = m.approved_by`,
		ID:       `m.id::text`,
		LinkExpr: `'/change-models/' || m.id`,
		DimExpr:  `m.state = 'retired'`,
		Fields: []list.Field{
			{Key: "name", Label: "Model", Type: list.Text, Expr: `m.name`, LinkExpr: `'/change-models/' || m.id`,
				Search: true, Class: "strong", NoGroup: true},
			{Key: "summary", Label: "Does", Type: list.Text, Search: true, NoGroup: true,
				ViewerExpr: list.Lookup("m.id::text", "text", summaries)},
			{Key: "action", Label: "Action", Type: list.Enum, Expr: `m.action`, Options: actions},
			{Key: "state", Label: "State", Type: list.Enum, Expr: `m.state`, Badge: "model",
				Options: []list.Option{{Value: "approved", Label: "approved"}, {Value: "pending", Label: "awaiting approval"},
					{Value: "retired", Label: "retired"}}},
			{Key: "risk", Label: "Risk", Type: list.Enum, Expr: `m.risk`, Options: opts("low", "medium", "high"),
				SortExpr: `array_position(ARRAY['low', 'medium', 'high'], m.risk)`},
			{Key: "changes", Label: "Changes", Type: list.Number, Class: "num",
				Expr: `(SELECT count(*) FROM change c WHERE c.model_id = m.id)`},
			{Key: "patch_groups", Label: "Patch groups", Type: list.Number, Class: "num",
				Expr: `(SELECT count(*) FROM patch_group g WHERE g.change_model_id = m.id)`},
			{Key: "stacks", Label: "Stacks", Type: list.Number, Class: "num",
				Expr: `(SELECT count(*) FROM compose_stack s WHERE s.change_model_id = m.id)`},
			{Key: "requested_by", Label: "Requested by", Type: list.Text, Search: true,
				Expr: `COALESCE(NULLIF(u.name, ''), u.email, '')`},
			{Key: "approved_by", Label: "Approved by", Type: list.Text, Expr: `COALESCE(NULLIF(ap.name, ''), ap.email, '')`},
			{Key: "approved_at", Label: "Approved", Type: list.Time, Expr: `m.approved_at`},
			{Key: "self_approved", Label: "Self-approved", Type: list.Bool, Expr: `m.self_approved`},
			{Key: "description", Label: "Description", Type: list.Text, Expr: `m.description`, Search: true,
				NoGroup: true, NoSort: true, Class: "small"},
			{Key: "updated_at", Label: "Updated", Type: list.Time, Expr: `m.updated_at`},
		},
	}
	view := viewOf(list.Query{Cols: []string{"name", "summary", "state", "risk", "changes", "patch_groups", "stacks"},
		Sort: list.Sort{Field: "name"}})
	current := view("current", "Current", []list.Cond{cond("state", list.Ne, "retired")})
	t.Default = current.Query
	t.Views = []list.View{current,
		view("approved", "Approved", []list.Cond{cond("state", list.Eq, "approved")}),
		view("pending", "Awaiting approval", []list.Cond{cond("state", list.Eq, "pending")}),
		view("retired", "Retired", []list.Cond{cond("state", list.Eq, "retired")}),
		view("all", "All"),
	}
	return t
}

// Alerts ----------------------------------------------------------------------

var alertSeverities = []string{"critical", "warning", "info"}

// alertKinds offers the rule kinds alerts can come from.
func alertKinds() []list.Option {
	out := make([]list.Option, len(alert.Kinds))
	for i, k := range alert.Kinds {
		out[i] = list.Option{Value: k.Key, Label: k.Label}
	}
	return out
}

var alertTable = &list.Table{
	Key: "alert", Label: "Alerts", Noun: "alert",
	From: `alert a JOIN alert_rule r ON r.id = a.rule_id LEFT JOIN app_user ak ON ak.id = a.acked_by
		LEFT JOIN silence sl ON sl.id = a.silence_id`,
	ID: `a.id::text`, LinkExpr: `'/alerts/' || a.id`,
	DimExpr: `a.state = 'pending' OR a.silence_id IS NOT NULL`,
	// As canSee: a global role, or one on any of the alert's host groups.
	// Alerts closed by hand show nowhere, resolved since or not.
	Scope: func(a *list.Args, v list.Viewer) string {
		return `a.closed_at IS NULL AND (` + a.Add(v.Global) + `::bool OR a.group_ids::text[] && ` +
			a.Add(list.TextArray(v.GroupIDs)) + `::text[])`
	},
	Fields: []list.Field{
		{Key: "severity", Label: "Severity", Type: list.Enum, Expr: `a.severity`, Options: opts(alertSeverities...),
			Badge: "severity", SortExpr: `array_position(ARRAY['critical', 'warning', 'info'], a.severity)`},
		{Key: "summary", Label: "Alert", Type: list.Text, Expr: `a.summary`, LinkExpr: `'/alerts/' || a.id`,
			Search: true, NoGroup: true},
		{Key: "state", Label: "State", Type: list.Enum, Expr: `a.state`, Options: opts("pending", "firing", "resolved"),
			SortExpr: `array_position(ARRAY['firing', 'pending', 'resolved'], a.state)`},
		{Key: "flags", Label: "Flags", Type: list.Tags, Badge: "flag",
			Expr: `array_remove(ARRAY[CASE WHEN a.silence_id IS NOT NULL THEN 'silenced' END,
				CASE WHEN a.acked_at IS NOT NULL THEN 'acknowledged' END], NULL)`},
		{Key: "rule", Label: "Rule", Type: list.Text, Expr: `r.name`, Search: true},
		{Key: "kind", Label: "Watches", Type: list.Enum, Expr: `r.kind`, Options: alertKinds()},
		{Key: "subject", Label: "On", Type: list.Text, Expr: `a.subject`, LinkExpr: `NULLIF(a.link, '')`, Search: true},
		{Key: "since", Label: "Since", Type: list.Time, Expr: `COALESCE(a.fired_at, a.first_at)`},
		{Key: "first_at", Label: "First seen", Type: list.Time, Expr: `a.first_at`},
		{Key: "fired_at", Label: "Fired", Type: list.Time, Expr: `a.fired_at`},
		{Key: "last_at", Label: "Last seen", Type: list.Time, Expr: `a.last_at`},
		{Key: "resolved_at", Label: "Resolved", Type: list.Time, Expr: `a.resolved_at`},
		{Key: "acked_by", Label: "Acknowledged by", Type: list.Text,
			Expr: `CASE WHEN a.acked_at IS NULL THEN '' ELSE COALESCE(NULLIF(ak.name, ''), ak.email, '') END`},
		{Key: "ack_comment", Label: "Acknowledgement", Type: list.Text, Expr: `a.ack_comment`, NoGroup: true, Class: "small"},
		{Key: "silenced_until", Label: "Silenced until", Type: list.Time, Expr: `sl.ends_at`},
	},
}

func init() {
	view := viewOf(list.Query{Cols: []string{"severity", "summary", "rule", "subject", "flags", "since"},
		Sort: list.Sort{Field: "severity"}})
	open := view("open", "Open", []list.Cond{cond("state", list.Ne, "resolved")})
	alertTable.Default = open.Query
	resolved := viewOf(list.Query{Cols: []string{"severity", "summary", "rule", "subject", "resolved_at"},
		Sort: list.Sort{Field: "resolved_at", Desc: true}})
	alertTable.Views = []list.View{open,
		view("firing", "Firing", []list.Cond{cond("state", list.Eq, "firing")}),
		view("pending", "Pending", []list.Cond{cond("state", list.Eq, "pending")}),
		// Older ones are kept for 90 days (the old Resolved tab).
		resolved("resolved", "Resolved this week", []list.Cond{cond("state", list.Eq, "resolved"), cond("resolved_at", list.Within, "7d")}),
		resolved("history", "All resolved", []list.Cond{cond("state", list.Eq, "resolved")}),
	}
}

// Audit log -------------------------------------------------------------------

var auditTable = &list.Table{
	Key: "audit", Label: "Audit log entries", Noun: "entry",
	From: `audit_log a LEFT JOIN app_user u ON a.actor = 'user:' || u.id::text`,
	ID:   `a.id::text`,
	// Entries name hosts across every group: a global role only, as the page.
	Scope: func(a *list.Args, v list.Viewer) string { return a.Add(v.Global) + `::bool` },
	Fields: []list.Field{
		{Key: "id", Label: "#", Type: list.Number, Expr: `a.id`, Class: "num", NoGroup: true},
		{Key: "at", Label: "When", Type: list.Time, Expr: `a.at`},
		{Key: "actor", Label: "Actor", Type: list.Text, Expr: `COALESCE(NULLIF(u.name, ''), u.email, a.actor)`, Search: true},
		{Key: "actor_id", Label: "Actor ID", Type: list.Text, Expr: `a.actor`, Class: "mono small"},
		{Key: "actor_ip", Label: "IP address", Type: list.Text, Expr: `a.actor_ip`, Search: true},
		{Key: "action", Label: "Action", Type: list.Text, Expr: `a.action`, Search: true, Class: "mono"},
		{Key: "object_type", Label: "Object type", Type: list.Text, Expr: `a.object_type`},
		{Key: "object_id", Label: "Object", Type: list.Text, Expr: `a.object_id`, Search: true, Class: "mono small"},
		{Key: "details", Label: "Details", Type: list.Text, Expr: `a.details::text`, Search: true,
			NoGroup: true, NoSort: true, Class: "mono small wrap"},
	},
}

func init() {
	view := viewOf(list.Query{Cols: []string{"id", "at", "actor", "actor_ip", "action", "object_type", "object_id", "details"},
		Sort: list.Sort{Field: "id", Desc: true}})
	all := view("all", "All")
	auditTable.Default = all.Query
	auditTable.Views = []list.View{all,
		view("day", "Last 24 hours", []list.Cond{cond("at", list.Within, "1d")}),
		view("logins", "Sign-ins", []list.Cond{cond("action", list.Starts, "auth.")}),
		view("system", "By the system", []list.Cond{cond("actor_id", list.Eq, "system")}),
	}
}

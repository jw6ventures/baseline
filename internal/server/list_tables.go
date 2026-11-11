package server

import (
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

// The list engine's tables (docs/lists.md). Field SQL lives here and only
// here: a URL picks fields and operators by key and supplies values.

func opts(values ...string) []list.Option {
	out := make([]list.Option, len(values))
	for i, v := range values {
		out[i] = list.Option{Value: v, Label: humanState(v)}
	}
	return out
}

func cond(field string, op list.Op, value string) list.Cond {
	return list.Cond{Field: field, Op: op, Value: value}
}

// anyOf is one group per value: field is any of them.
func anyOf(field string, values ...string) [][]list.Cond {
	out := make([][]list.Cond, len(values))
	for i, v := range values {
		out[i] = []list.Cond{cond(field, list.Eq, v)}
	}
	return out
}

// visibleHostsSQL limits a host id expression to the viewer's hosts.
func visibleHostsSQL(expr string, a *list.Args, v list.Viewer) string {
	return expr + "::text = ANY(" + a.Add(list.TextArray(v.HostIDs)) + "::text[])"
}

// hostFlagClass styles a host's flags as the old host list did, and a
// stack's or an alert's as their old lists did.
func hostFlagClass(flag string) string {
	switch flag {
	case "duplicate ID", "drive failing", "failed services":
		return "warn"
	case "drive degrading", "reboot required", "orphaned":
		return "caution"
	case "acknowledged":
		return "ok"
	}
	return ""
}

var hostTable = &list.Table{
	Key: "host", Label: "Hosts", Noun: "host",
	From:     `host h JOIN ci ON ci.id = h.ci_id`,
	ID:       `h.ci_id::text`,
	LinkExpr: `'/hosts/' || h.ci_id`,
	DimExpr:  `h.revoked`,
	// Cluster agents aren't machines: they are listed on the Kubernetes
	// page, and a node's host links to its cluster (the cluster field).
	Scope: func(a *list.Args, v list.Viewer) string {
		return visibleHostsSQL("h.ci_id", a, v) + " AND NOT " + a.Add(model.CapK8sCluster) + "::text = ANY(h.capabilities)"
	},
	Fields: []list.Field{
		{Key: "name", Label: "Host", Type: list.Text, Expr: `COALESCE(NULLIF(h.hostname, ''), ci.name)`,
			LinkExpr: `'/hosts/' || h.ci_id`, Search: true, Class: "nowrap strong"},
		{Key: "fqdn", Label: "FQDN", Type: list.Text, Expr: `h.fqdn`, Search: true},
		{Key: "status", Label: "Status", Type: list.Enum, Badge: "host",
			Expr:    `CASE WHEN h.revoked THEN 'revoked' WHEN h.connected THEN 'online' ELSE 'offline' END`,
			Options: opts("online", "offline", "revoked")},
		{Key: "last_seen", Label: "Last seen", Type: list.Time, Expr: `h.last_seen`},
		{Key: "os", Label: "OS", Type: list.Text, Expr: `h.os_pretty`, Search: true},
		{Key: "os_id", Label: "OS ID", Type: list.Text, Expr: `h.os_id`},
		{Key: "kernel", Label: "Kernel", Type: list.Text, Expr: `h.kernel`, Search: true, Class: "mono"},
		{Key: "arch", Label: "Architecture", Type: list.Text, Expr: `h.arch`},
		{Key: "packages", Label: "Packages", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) FROM host_package p WHERE p.host = h.ci_id)`},
		{Key: "updates", Label: "Updates", Type: list.Number, Class: "num",
			Expr:     `(SELECT count(*) FROM host_update u WHERE u.host = h.ci_id)`,
			LinkExpr: `'/hosts/' || h.ci_id || '?tab=updates'`},
		{Key: "security_updates", Label: "Security updates", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) FROM host_update u WHERE u.host = h.ci_id AND u.security)`},
		{Key: "containers", Label: "Containers", Type: list.Number, Class: "num",
			Expr:     `(SELECT count(*) FROM container c WHERE c.host = h.ci_id)`,
			LinkExpr: `'/hosts/' || h.ci_id || '/containers'`},
		{Key: "containers_running", Label: "Containers running", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) FROM container c WHERE c.host = h.ci_id AND c.state = 'running')`},
		{Key: "cluster", Label: "Cluster", Type: list.Text, Search: true,
			Expr: `(SELECT k.name` + hostClusterFrom + `)`, LinkExpr: `(SELECT '/kubernetes/' || k.ci_id` + hostClusterFrom + `)`},
		{Key: "vulns", Label: "Fixable vulnerabilities", Type: list.Number, Class: "num",
			Expr: `(SELECT count(DISTINCT v.vuln_id) FROM host_vuln v WHERE v.host = h.ci_id AND v.fix_available)`},
		{Key: "open_jobs", Label: "Open jobs", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) FROM job j WHERE j.host = h.ci_id AND j.state IN ('queued', 'dispatched', 'running'))`},
		{Key: "groups", Label: "Groups", Type: list.Tags, Search: true,
			Expr: `ARRAY(SELECT g.name FROM host_group_member m JOIN host_group g ON g.id = m.group_id
			       WHERE m.ci_id = h.ci_id ORDER BY g.name)`},
		{Key: "flags", Label: "Flags", Type: list.Tags, Badge: "flag",
			Expr: `array_remove(ARRAY[
				CASE WHEN h.duplicate_identity THEN 'duplicate ID' END,
				CASE WHEN EXISTS (SELECT 1 FROM host_smart d WHERE d.host = h.ci_id AND d.passed = false) THEN 'drive failing'
				     WHEN EXISTS (SELECT 1 FROM host_smart d WHERE d.host = h.ci_id AND d.degrading) THEN 'drive degrading' END,
				CASE WHEN h.reboot_required AND NOT h.revoked THEN 'reboot required' END,
				CASE WHEN EXISTS (SELECT 1 FROM host_service v WHERE v.host = h.ci_id AND v.active = 'failed') THEN 'failed services' END,
				CASE WHEN h.high_security THEN 'high security' END], NULL)`},
		{Key: "reboot_required", Label: "Reboot required", Type: list.Bool, Expr: `h.reboot_required`},
		{Key: "high_security", Label: "High security", Type: list.Bool, Expr: `h.high_security`},
		{Key: "agent_version", Label: "Agent", Type: list.Text, Expr: `h.agent_version`, Class: "mono"},
		{Key: "enrolled_at", Label: "Enrolled", Type: list.Time, Expr: `h.enrolled_at`},
	},
	Default: list.Query{
		Cols: []string{"name", "status", "os", "kernel", "packages", "updates", "containers", "cluster", "groups", "flags", "agent_version"},
		Sort: list.Sort{Field: "name"},
	},
}

// hostClusterFrom finds the Kubernetes cluster a host is a node of, by the
// runs_on link discovery keeps from the node to the host's agent.
const hostClusterFrom = ` FROM ci_relationship r JOIN k8s_object o ON o.ci_id = r.from_ci
	JOIN k8s_cluster k ON k.ci_id = o.cluster_ci
	WHERE r.to_ci = h.ci_id AND r.kind = 'runs_on' AND r.source = 'discovered' AND o.kind = 'Node'
	ORDER BY o.present DESC, lower(k.name), k.ci_id LIMIT 1`

func init() {
	q := hostTable.Default
	view := func(key, label string, groups ...[]list.Cond) list.View {
		v := q
		v.Groups = groups
		return list.View{Key: key, Label: label, Query: v}
	}
	hostTable.Views = []list.View{
		view("all", "All"),
		view("online", "Online", []list.Cond{cond("status", list.Eq, "online")}),
		view("offline", "Offline", []list.Cond{cond("status", list.Eq, "offline")}),
		view("updates", "With updates", []list.Cond{cond("updates", list.Gt, "0"), cond("status", list.Ne, "revoked")}),
		view("reboot", "Reboot required", []list.Cond{cond("flags", list.Has, "reboot required")}),
	}
}

// ciTable is built per request: its type field offers the CI types in the
// database.
func ciTable(types []store.CIType) *list.Table {
	typeOpts := make([]list.Option, len(types))
	for i, t := range types {
		typeOpts[i] = list.Option{Value: t.Key, Label: t.Label}
	}
	t := &list.Table{
		Key: "ci", Label: "Configuration items", Noun: "CI",
		From: `ci CROSS JOIN LATERAL (SELECT ` + store.CIHostRef + ` AS host_ref) hr`,
		ID:   `ci.id::text`,
		// Where ciLink sends each type.
		LinkExpr: `CASE
			WHEN ci.type = 'host' THEN '/hosts/' || ci.id
			WHEN ci.type = 'container' AND ci.status = 'active' THEN '/containers/' || ci.id
			WHEN ci.type = 'compose_stack' THEN '/stacks/' || ci.id
			WHEN ci.type IN ('vm', 'lxc') AND ci.source <> 'manual' THEN '/vms/' || ci.id
			WHEN ci.type = 'k8s_cluster' THEN '/kubernetes/' || ci.id
			ELSE '/cis/' || ci.id END`,
		DimExpr:  `ci.status IN ('missing', 'retired')`,
		EditExpr: `ci.source = 'manual'`,
		Scope: func(a *list.Args, v list.Viewer) string {
			return store.AgentlessSQL + " OR " + visibleHostsSQL("hr.host_ref", a, v)
		},
		Fields: []list.Field{
			{Key: "name", Label: "Name", Type: list.Text, Expr: `ci.name`, Search: true, Class: "strong"},
			{Key: "type", Label: "Type", Type: list.Enum, Expr: `ci.type`, Options: typeOpts},
			{Key: "status", Label: "Status", Type: list.Enum, Expr: `ci.status`, Badge: "ci",
				Options: opts("active", "planned", "missing", "retired")},
			{Key: "source", Label: "Source", Type: list.Enum, Expr: `ci.source`,
				Options: []list.Option{{Value: "agent", Label: "agent"}, {Value: "proxmox", Label: "Proxmox"},
					{Value: "libvirt", Label: "libvirt"}, {Value: "k8s", Label: "Kubernetes"}, {Value: "unifi", Label: "UniFi"},
					{Value: "manual", Label: "manual"}}},
			{Key: "owner", Label: "Owner", Type: list.Text, Expr: `ci.owner`, Search: true},
			{Key: "description", Label: "Description", Type: list.Text, Expr: `ci.description`, Search: true,
				NoGroup: true, NoSort: true, Class: "small"},
			{Key: "tags", Label: "Tags", Type: list.Tags, Expr: `ci.tags`, Search: true},
			{Key: "relations", Label: "Relations", Type: list.Number, Class: "num",
				Expr: `(SELECT count(*) FROM ci_relationship r WHERE r.from_ci = ci.id OR r.to_ci = ci.id)`},
			{Key: "first_seen", Label: "First seen", Type: list.Time, Expr: `ci.first_seen`},
			{Key: "last_seen", Label: "Last seen", Type: list.Time, Expr: `ci.last_seen`},
			{Key: "updated_at", Label: "Updated", Type: list.Time, Expr: `ci.updated_at`},
		},
	}
	t.Fields[0].LinkExpr = t.LinkExpr
	base := list.Query{Cols: []string{"name", "type", "status", "source", "relations", "tags"}, Sort: list.Sort{Field: "name"}}
	view := func(key, label string, groups ...[]list.Cond) list.View {
		v := base
		v.Groups = groups
		return list.View{Key: key, Label: label, Query: v}
	}
	current := view("current", "Active and planned", []list.Cond{cond("status", list.Ne, "missing"), cond("status", list.Ne, "retired")})
	t.Default = current.Query
	t.Views = []list.View{current,
		view("manual", "Agentless", []list.Cond{cond("source", list.Eq, "manual")}),
		view("missing", "Missing", []list.Cond{cond("status", list.Eq, "missing")}),
		view("retired", "Retired", []list.Cond{cond("status", list.Eq, "retired")}),
		view("all", "All"),
	}
	return t
}

var changeStates = []string{store.ChangeDraft, store.ChangeSubmitted, store.ChangeApproved, store.ChangeScheduled,
	store.ChangeInProgress, store.ChangeImplemented, store.ChangeFailed, store.ChangeRolledBack, store.ChangeReview,
	store.ChangeClosed, store.ChangeRejected, store.ChangeCancelled}

// changeHostsSQL is the hosts a change targets, as canOnAll counts them.
const changeHostsSQL = `FROM change_ci cc JOIN host h ON h.ci_id = cc.ci_id WHERE cc.change_id = c.id`

var changeTable = &list.Table{
	Key: "change", Label: "Changes", Noun: "change",
	From: `change c LEFT JOIN app_user u ON u.id = c.requested_by LEFT JOIN change_model m ON m.id = c.model_id`,
	ID:   `c.id::text`, LinkExpr: `'/changes/' || c.id`,
	// The viewer must see every host the change touches (canOnAll); a
	// change with no hosts needs a global grant.
	Scope: func(a *list.Args, v list.Viewer) string {
		return `NOT EXISTS (SELECT 1 ` + changeHostsSQL + ` AND NOT (` + visibleHostsSQL("h.ci_id", a, v) + `))
			AND (EXISTS (SELECT 1 ` + changeHostsSQL + `) OR ` + a.Add(v.Global) + `::bool)`
	},
	Fields: []list.Field{
		{Key: "ref", Label: "Change", Type: list.Text, Expr: `'CHG-' || lpad(c.number::text, 6, '0')`,
			LinkExpr: `'/changes/' || c.id`, Search: true, Class: "nowrap strong", NoGroup: true},
		{Key: "title", Label: "Title", Type: list.Text, Expr: `c.title`, Search: true, NoGroup: true},
		{Key: "state", Label: "State", Type: list.Enum, Expr: `c.state`, Options: opts(changeStates...), Badge: "change"},
		{Key: "kind", Label: "Kind", Type: list.Enum, Expr: `c.kind`, Options: opts("standard", "normal", "emergency"), Badge: "kind"},
		{Key: "risk", Label: "Risk", Type: list.Enum, Expr: `c.risk`, Options: opts("low", "medium", "high")},
		{Key: "impact", Label: "Impact", Type: list.Enum, Expr: `c.impact`, Options: opts("low", "medium", "high")},
		{Key: "outcome", Label: "Outcome", Type: list.Enum, Expr: `c.outcome`,
			Options: opts("success", "partial", "failed", "rolled_back", "cancelled")},
		{Key: "hosts", Label: "Hosts", Type: list.Tags, Search: true, Class: "small",
			Expr: `ARRAY(SELECT h.hostname ` + changeHostsSQL + ` ORDER BY h.hostname)`},
		{Key: "jobs", Label: "Jobs", Type: list.Number, Class: "num", Expr: `(SELECT count(*) FROM job j WHERE j.change_id = c.id)`},
		{Key: "jobs_failed", Label: "Failed jobs", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) FROM job j WHERE j.change_id = c.id AND j.state IN ('failed', 'timed_out', 'rejected', 'rolled_back'))`},
		{Key: "requested_by", Label: "Requested by", Type: list.Text, Search: true,
			Expr: `CASE WHEN c.requested_by IS NULL THEN 'the scheduler' ELSE COALESCE(NULLIF(u.name, ''), u.email, '') END`},
		{Key: "model", Label: "Change model", Type: list.Text, Expr: `COALESCE(m.name, '')`},
		{Key: "created_at", Label: "Requested", Type: list.Time, Expr: `c.created_at`},
		{Key: "planned_start", Label: "Planned start", Type: list.Time, Expr: `c.planned_start`},
		{Key: "actual_end", Label: "Ended", Type: list.Time, Expr: `c.actual_end`},
	},
	Default: list.Query{
		Cols: []string{"ref", "title", "state", "kind", "risk", "hosts", "jobs", "requested_by", "created_at"},
		Sort: list.Sort{Field: "created_at", Desc: true},
	},
}

// changeViews are the old ?show= filters (changeFilters).
var changeViews = []struct{ key, label string }{
	{"all", "All"}, {"open", "Open"}, {"approval", "Awaiting approval"}, {"scheduled", "Scheduled"}, {"review", "To close"},
}

func init() {
	for _, cv := range changeViews {
		q := changeTable.Default
		q.Groups = anyOf("state", changeFilters[cv.key]...)
		changeTable.Views = append(changeTable.Views, list.View{Key: cv.key, Label: cv.label, Query: q})
	}
	for _, jv := range []struct{ key, label string }{{"all", "All"}, {"open", "Queued and running"}, {"failed", "Failed"}} {
		q := jobTable.Default
		q.Groups = anyOf("state", jobFilters[jv.key]...)
		jobTable.Views = append(jobTable.Views, list.View{Key: jv.key, Label: jv.label, Query: q})
	}
}

var jobTable = &list.Table{
	Key: "job", Label: "Jobs", Noun: "job",
	From: `job j JOIN change c ON c.id = j.change_id JOIN host h ON h.ci_id = j.host LEFT JOIN app_user u ON u.id = j.requested_by`,
	ID:   `j.id::text`, LinkExpr: `'/jobs/' || j.id`,
	Scope: func(a *list.Args, v list.Viewer) string { return visibleHostsSQL("j.host", a, v) },
	Fields: []list.Field{
		{Key: "action", Label: "Job", Type: list.Text, Expr: `j.action`, LinkExpr: `'/jobs/' || j.id`, Search: true, Badge: "action"},
		{Key: "host", Label: "Host", Type: list.Text, Expr: `h.hostname`, LinkExpr: `'/hosts/' || h.ci_id || '/jobs'`, Search: true},
		{Key: "change", Label: "Change", Type: list.Text, Expr: `'CHG-' || lpad(c.number::text, 6, '0')`,
			LinkExpr: `'/changes/' || c.id`, Search: true, Class: "nowrap", NoGroup: true},
		{Key: "change_title", Label: "Change title", Type: list.Text, Expr: `c.title`, Search: true, NoGroup: true},
		{Key: "state", Label: "State", Type: list.Enum, Expr: `j.state`, Badge: "job",
			Options: opts(store.JobQueued, store.JobDispatched, store.JobRunning, store.JobSucceeded, store.JobFailed,
				store.JobCancelled, store.JobTimedOut, store.JobRejected, store.JobRolledBack)},
		{Key: "queued_at", Label: "Queued", Type: list.Time, Expr: `j.queued_at`},
		{Key: "started_at", Label: "Started", Type: list.Time, Expr: `j.started_at`},
		{Key: "finished_at", Label: "Finished", Type: list.Time, Expr: `j.finished_at`},
		{Key: "exit_code", Label: "Exit status", Type: list.Number, Expr: `j.exit_code`, Class: "num"},
		{Key: "error", Label: "Error", Type: list.Text, Expr: `j.error`, Search: true, NoGroup: true, Class: "small"},
		{Key: "requested_by", Label: "Requested by", Type: list.Text,
			Expr: `CASE WHEN j.requested_by IS NULL THEN 'the scheduler' ELSE COALESCE(NULLIF(u.name, ''), u.email, '') END`},
	},
	Default: list.Query{
		Cols: []string{"action", "host", "change", "state", "started_at", "error"},
		Sort: list.Sort{Field: "queued_at", Desc: true},
	},
}

// workItemRef is SQL for an item's reference, OPS-42.
const workItemRef = `p.key || '-' || w.number`

func workUserName(alias string) string {
	return "COALESCE(NULLIF(" + alias + ".name, ''), NULLIF(" + alias + ".email, ''), " + alias + ".oidc_sub, '')"
}

// workTable is built per request: its project, type, status and workflow
// fields offer what the database holds. Work items have no host scope:
// everyone with a role sees them, as on their pages.
func workTable(projects []store.Project, types []store.TicketType, statuses []string, workflows []store.Workflow, fields []store.FieldDef, labels projectLabels) *list.Table {
	var projectOpts, typeOpts, statusOpts, resolutionOpts, nameOpts, workflowOpts []list.Option
	for _, p := range projects {
		projectOpts = append(projectOpts, list.Option{Value: p.Key, Label: p.Key + " " + p.Name})
	}
	for _, t := range types {
		typeOpts = append(typeOpts, list.Option{Value: t.Key, Label: t.Name})
	}
	for _, s := range store.StatusCategories {
		statusOpts = append(statusOpts, list.Option{Value: s, Label: itemStatusLabel(s)})
	}
	for _, n := range statuses {
		nameOpts = append(nameOpts, list.Option{Value: n, Label: n})
	}
	for _, f := range workflows {
		workflowOpts = append(workflowOpts, list.Option{Value: f.Name, Label: f.Name})
	}
	for _, r := range store.Resolutions {
		resolutionOpts = append(resolutionOpts, list.Option{Value: r, Label: r})
	}
	// A table needs options for its enums even before the first project.
	if len(projectOpts) == 0 {
		projectOpts = []list.Option{{Value: "-", Label: "no projects yet"}}
	}
	if len(typeOpts) == 0 {
		typeOpts = []list.Option{{Value: "-", Label: "no types yet"}}
	}
	if len(nameOpts) == 0 {
		nameOpts = []list.Option{{Value: "-", Label: "no statuses yet"}}
	}
	if len(workflowOpts) == 0 {
		workflowOpts = []list.Option{{Value: "-", Label: "no workflows yet"}}
	}
	rank := func(expr string, values []string) string {
		return "array_position(ARRAY['" + strings.Join(values, "', '") + "'], " + expr + ")"
	}
	t := &list.Table{
		Key: "work", Label: "Work items", Noun: "work item",
		From: `work_item w JOIN project p ON p.id = w.project_id JOIN ticket_type t ON t.id = w.ticket_type_id
			LEFT JOIN app_user ru ON ru.id = w.reporter LEFT JOIN app_user au ON au.id = w.assignee
			LEFT JOIN work_item pw ON pw.id = w.parent_id LEFT JOIN project pp ON pp.id = pw.project_id
			JOIN wf_status ws ON ws.id = w.status_id JOIN workflow_version wv ON wv.id = w.workflow_version_id
			JOIN workflow wf ON wf.id = wv.workflow_id`,
		ID:       `w.id::text`,
		LinkExpr: `'/work/' || ` + workItemRef,
		DimExpr:  `w.status_category = 'done'`,
		EditExpr: `true`,
		Fields: []list.Field{
			{Key: "ref", Label: "Item", Type: list.Text, Expr: workItemRef, LinkExpr: `'/work/' || ` + workItemRef,
				Search: true, Class: "nowrap strong", NoGroup: true, SortExpr: `p.key, w.number`},
			{Key: "title", Label: "Title", Type: list.Text, Expr: `w.title`, Search: true, NoGroup: true},
			{Key: "description", Label: "Description", Type: list.Text, Expr: `w.description`, Search: true,
				NoGroup: true, NoSort: true, Class: "small"},
			{Key: "project", Label: "Project", Type: list.Enum, Expr: `p.key`, Options: projectOpts},
			{Key: "type", Label: "Type", Type: list.Enum, Expr: `t.key`, Options: typeOpts},
			{Key: "status_name", Label: "Status", Type: list.Enum, Expr: `ws.name`, Options: nameOpts,
				SortExpr: rank("w.status_category", store.StatusCategories) + ", ws.position"},
			{Key: "status", Label: "Status category", Type: list.Enum, Expr: `w.status_category`, Options: statusOpts,
				Badge: "item-status", SortExpr: rank("w.status_category", store.StatusCategories)},
			{Key: "workflow", Label: "Workflow", Type: list.Enum, Expr: `wf.name`, Options: workflowOpts},
			{Key: "workflow_version", Label: "Workflow version", Type: list.Number, Expr: `wv.version`, Class: "num"},
			{Key: "resolution", Label: "Resolution", Type: list.Enum, Expr: `w.resolution`, Options: resolutionOpts},
			{Key: "priority", Label: "Priority", Type: list.Enum, Expr: `w.priority`, Options: opts(store.Priorities...),
				Badge: "item-priority", SortExpr: rank("w.priority", store.Priorities)},
			{Key: "impact", Label: "Impact", Type: list.Enum, Expr: `w.impact`, Options: opts(store.Levels...),
				SortExpr: rank("w.impact", store.Levels)},
			{Key: "urgency", Label: "Urgency", Type: list.Enum, Expr: `w.urgency`, Options: opts(store.Levels...),
				SortExpr: rank("w.urgency", store.Levels)},
			{Key: "assignee", Label: "Assignee", Type: list.Text, Expr: `CASE WHEN w.assignee IS NULL THEN '' ELSE ` + workUserName("au") + ` END`, Search: true},
			{Key: "assigned_to_me", Label: "Assigned to me", Type: list.Bool, NoGroup: true,
				ViewerExpr: func(a *list.Args, v list.Viewer) string {
					return "COALESCE(w.assignee::text = " + a.Add(v.UserID) + ", false)"
				}},
			{Key: "watching", Label: "Watching", Type: list.Bool, NoGroup: true,
				ViewerExpr: func(a *list.Args, v list.Viewer) string {
					return "EXISTS (SELECT 1 FROM watcher x WHERE x.work_item_id = w.id AND x.user_id::text = " + a.Add(v.UserID) + ")"
				}},
			{Key: "reporter", Label: "Reporter", Type: list.Text, Expr: `CASE WHEN w.reporter IS NULL THEN 'the system' ELSE ` + workUserName("ru") + ` END`},
			{Key: "parent", Label: "Parent", Type: list.Text, Expr: `COALESCE(pp.key || '-' || pw.number, '')`,
				LinkExpr: `'/work/' || pp.key || '-' || pw.number`},
			{Key: "cis", Label: "CIs", Type: list.Tags, Search: true, Class: "small",
				Expr: `ARRAY(SELECT DISTINCT c.name FROM work_item_ci wc JOIN ci c ON c.id = wc.ci_id WHERE wc.work_item_id = w.id ORDER BY c.name)`},
			{Key: "changes", Label: "Changes", Type: list.Tags, Class: "small",
				Expr: `ARRAY(SELECT DISTINCT 'CHG-' || lpad(c.number::text, 6, '0') FROM work_item_change wc JOIN change c ON c.id = wc.change_id
				       WHERE wc.work_item_id = w.id ORDER BY 1)`},
			{Key: "estimate", Label: "Estimate", Type: list.Number, Expr: `w.estimate::float8`, Class: "num"},
			{Key: "due_at", Label: "Due", Type: list.Time, Expr: `w.due_at`},
			{Key: "source", Label: "Source", Type: list.Enum, Expr: `w.source`,
				Options: opts("user", "alert", "unplanned_change", "email", "api")},
			{Key: "created_at", Label: "Created", Type: list.Time, Expr: `w.created_at`},
			{Key: "updated_at", Label: "Updated", Type: list.Time, Expr: `w.updated_at`},
			{Key: "resolved_at", Label: "Resolved", Type: list.Time, Expr: `w.resolved_at`},
		},
	}
	t.Fields = slices.Insert(t.Fields, slices.IndexFunc(t.Fields, func(f list.Field) bool { return f.Key == "project" })+1,
		projectLabelFields("p", "project_", "Project ", labels)...)
	t.Fields = append(t.Fields, customListFields(fields)...)
	base := list.Query{Cols: []string{"ref", "title", "type", "status_name", "priority", "assignee", "updated_at"},
		Sort: list.Sort{Field: "priority"}}
	view := func(key, label string, groups ...[]list.Cond) list.View {
		v := base
		v.Groups = groups
		return list.View{Key: key, Label: label, Query: v}
	}
	notDone := cond("status", list.Ne, store.StatusDone)
	open := view("open", "Open", []list.Cond{notDone})
	t.Default = open.Query
	t.Views = []list.View{open,
		view("mine", "Assigned to me", []list.Cond{notDone, cond("assigned_to_me", list.IsTrue, "")}),
		view("unassigned", "Unassigned", []list.Cond{notDone, cond("assignee", list.Empty, "")}),
		view("watching", "Watching", []list.Cond{notDone, cond("watching", list.IsTrue, "")}),
		view("done", "Done", []list.Cond{cond("status", list.Eq, store.StatusDone)}),
		view("all", "All"),
	}
	return t
}

// customListFields registers work items' custom fields, keyed cf_<key>.
// A key is spliced into SQL as a string literal, so only keys that match
// store.FieldKeyRe (letters, digits and underscores) are registered.
// Values are checked when saved; the expressions still guard their casts,
// so a stray value reads as empty rather than failing the list.
func customListFields(fields []store.FieldDef) []list.Field {
	var out []list.Field
	for _, f := range fields {
		if !store.FieldKeyRe.MatchString(f.Key) {
			continue
		}
		raw := "(w.custom->>'" + f.Key + "')"
		val := "(w.custom->'" + f.Key + "')"
		lf := list.Field{Key: "cf_" + f.Key, Label: f.Label, Expr: raw}
		switch f.Type {
		case store.FieldText:
			lf.Type, lf.Search = list.Text, true
		case store.FieldTextarea:
			lf.Type, lf.Search, lf.NoGroup, lf.NoSort, lf.Class = list.Text, true, true, true, "small"
		case store.FieldURL:
			lf.Type, lf.NoGroup, lf.Class = list.Text, true, "small"
		case store.FieldNumber:
			lf.Type, lf.Class = list.Number, "num"
			lf.Expr = "(CASE WHEN jsonb_typeof(" + val + ") = 'number' THEN " + raw + "::float8 END)"
		case store.FieldDate:
			lf.Type = list.Time
			lf.Expr = "(CASE WHEN " + raw + " ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN " + raw + "::date::timestamptz END)"
		case store.FieldDatetime:
			lf.Type = list.Time
			lf.Expr = "(CASE WHEN " + raw + " ~ '^\\d{4}-\\d{2}-\\d{2}T' THEN " + raw + "::timestamptz END)"
		case store.FieldBool:
			lf.Type = list.Bool
			lf.Expr = "(" + val + " = 'true'::jsonb)"
		case store.FieldSelect:
			if len(f.Options) == 0 {
				continue
			}
			lf.Type = list.Enum
			for _, o := range f.Options {
				lf.Options = append(lf.Options, list.Option{Value: o, Label: o})
			}
		case store.FieldMultiselect:
			lf.Type, lf.Class = list.Tags, "small"
			lf.Expr = "ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(" + val + ") = 'array' THEN " + val + " ELSE '[]' END))"
		case store.FieldUser:
			lf.Type = list.Text
			lf.Expr = "COALESCE((SELECT " + workUserName("cu") + " FROM app_user cu WHERE cu.id::text = " + raw + "), '')"
		case store.FieldItem:
			ref := "(SELECT xp.key || '-' || xw.number FROM work_item xw JOIN project xp ON xp.id = xw.project_id WHERE xw.id::text = " + raw + ")"
			lf.Type, lf.Class, lf.NoGroup = list.Text, "nowrap", true
			lf.Expr = "COALESCE(" + ref + ", '')"
			lf.LinkExpr = "'/work/' || " + ref
		case store.FieldCI:
			// A CI's name shows only to people who may see the CI, as on
			// the item's page.
			lf.Type, lf.Expr = list.Text, ""
			lf.ViewerExpr = func(a *list.Args, v list.Viewer) string {
				return "COALESCE((SELECT ci.name FROM ci WHERE ci.id::text = " + raw + " AND (" + store.AgentlessSQL + " OR " +
					visibleHostsSQL("("+store.CIHostRef+")", a, v) + ")), '')"
			}
		default:
			continue
		}
		out = append(out, lf)
	}
	return out
}

// Projects --------------------------------------------------------------------

// projectLabels are the category tree and the tag list, for lists that
// show projects' categories and tags.
type projectLabels struct {
	Cats []store.ProjectCategory
	Tags []store.ProjectTag
}

// categoryUp walks a project's category and its ancestors: up(id, name, d),
// d counting up from 0 at the category itself. p is the project's alias.
func categoryUp(p string) string {
	return `WITH RECURSIVE up AS (
		SELECT c.id, c.parent_id, c.name, 0 AS d FROM project_category c WHERE c.id = ` + p + `.category_id
		UNION ALL
		SELECT c.id, c.parent_id, c.name, up.d + 1 FROM project_category c JOIN up ON c.id = up.parent_id)`
}

// projectLabelFields are a project's category and tags, for the projects
// list and, keyed with prefix, the work items list. p is the project's
// alias. A category matches its subcategories too.
func projectLabelFields(p, prefix, labelPrefix string, l projectLabels) []list.Field {
	var catOpts, tagOpts []list.Option
	for _, c := range l.Cats {
		catOpts = append(catOpts, list.Option{Value: c.ID, Label: c.Path, Color: c.ShownColor})
	}
	if len(catOpts) == 0 {
		catOpts = []list.Option{{Value: "-", Label: "no categories yet"}}
	}
	for _, t := range l.Tags {
		tagOpts = append(tagOpts, list.Option{Value: t.Name, Label: t.Name, Color: t.Color})
	}
	return []list.Field{
		{Key: prefix + "category", Label: labelPrefix + "Category", Type: list.Enum, Badge: "color", Options: catOpts,
			Expr:      `COALESCE(` + p + `.category_id::text, '')`,
			MatchExpr: `ARRAY(` + categoryUp(p) + ` SELECT up.id::text FROM up)`,
			SortExpr:  `(` + categoryUp(p) + ` SELECT string_agg(lower(up.name), ' / ' ORDER BY up.d DESC) FROM up)`},
		{Key: prefix + "tags", Label: labelPrefix + "Tags", Type: list.Tags, Badge: "color", Options: tagOpts, Search: true,
			Expr: `ARRAY(SELECT g.name FROM project_tag_link l JOIN project_tag g ON g.id = l.tag_id
			       WHERE l.project_id = ` + p + `.id ORDER BY lower(g.name))`},
	}
}

// projectTable lists work item projects. Everyone with a role sees them,
// as on their pages. It is built per request: its category and tag
// fields offer what the database holds.
func projectTable(l projectLabels) *list.Table {
	t := &list.Table{
		Key: "project", Label: "Projects", Noun: "project",
		From:     `project p LEFT JOIN host_group g ON g.id = p.host_group_id`,
		ID:       `p.id::text`,
		LinkExpr: `'/projects/' || p.key`,
		DimExpr:  `p.archived`,
		Fields: []list.Field{
			{Key: "key", Label: "Key", Type: list.Text, Expr: `p.key`, LinkExpr: `'/projects/' || p.key`,
				Search: true, Class: "strong nowrap", NoGroup: true},
			{Key: "name", Label: "Name", Type: list.Text, Expr: `p.name`, Search: true, NoGroup: true},
			{Key: "kind", Label: "Kind", Type: list.Enum, Expr: `p.kind`, Options: opts("service_desk", "software")},
			{Key: "description", Label: "Description", Type: list.Text, Expr: `p.description`, Search: true,
				NoGroup: true, NoSort: true, Class: "small"},
			{Key: "host_group", Label: "Host group", Type: list.Text, Expr: `COALESCE(g.name, '')`, Search: true},
			{Key: "types", Label: "Ticket types", Type: list.Tags,
				Expr: `ARRAY(SELECT tt.name FROM project_ticket_type pt JOIN ticket_type tt ON tt.id = pt.ticket_type_id
				       WHERE pt.project_id = p.id ORDER BY pt.position, tt.name)`},
			{Key: "open", Label: "Open items", Type: list.Number, Class: "num",
				Expr:     `(SELECT count(*) FROM work_item w WHERE w.project_id = p.id AND w.status_category <> 'done')`,
				LinkExpr: `'/work?project=' || p.key`},
			{Key: "items", Label: "All items", Type: list.Number, Class: "num",
				Expr: `(SELECT count(*) FROM work_item w WHERE w.project_id = p.id)`},
			{Key: "archived", Label: "Archived", Type: list.Bool, Expr: `p.archived`},
			{Key: "created_at", Label: "Created", Type: list.Time, Expr: `p.created_at`},
		},
	}
	t.Fields = slices.Insert(t.Fields, 3, projectLabelFields("p", "", "", l)...)
	view := viewOf(list.Query{Cols: []string{"key", "name", "category", "tags", "kind", "host_group", "open"},
		Sort: list.Sort{Field: "key"}})
	active := view("active", "Active", []list.Cond{cond("archived", list.IsFalse, "")})
	t.Default = active.Query
	t.Views = []list.View{active,
		view("archived", "Archived", []list.Cond{cond("archived", list.IsTrue, "")}),
		view("all", "All"),
	}
	return t
}

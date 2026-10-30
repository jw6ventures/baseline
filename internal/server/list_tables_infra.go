package server

import (
	"fmt"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/stackname"
)

// The list engine's infrastructure tables: containers, Compose stacks,
// pending updates by host and by package, and virtual machines.

// viewOf returns a builder of a table's built-in lists from its base query.
func viewOf(base list.Query) func(key, label string, groups ...[]list.Cond) list.View {
	return func(key, label string, groups ...[]list.Cond) list.View {
		v := base
		v.Groups = groups
		return list.View{Key: key, Label: label, Query: v}
	}
}

// Containers ------------------------------------------------------------------

const containerFrom = `container c JOIN host h ON h.ci_id = c.host LEFT JOIN container_update u ON u.ci_id = c.ci_id
	LEFT JOIN compose_stack st ON st.host = c.host AND st.engine = c.engine AND st.project = c.compose_project AND c.compose_project <> ''`

var containerStates = []string{"running", "created", "paused", "restarting", "exited", "dead"}

// containerUpdates are the values of a container's update field, in the
// order the old list's update cell checked them (ctr-update).
var containerUpdates = []list.Option{
	{Value: "pinned", Label: "pinned"}, {Value: "newer_image", Label: "newer image"},
	{Value: "new_version", Label: "newer version"}, {Value: "not_checked", Label: "not checked"},
	{Value: "check_failed", Label: "check failed"}, {Value: "pending", Label: "pending"}, {Value: "current", Label: "current"},
}

// containerTable is built per request: advice maps container CI ids to the
// newest version tag their semver rule allows, which Go works out
// (containerAdvice).
func containerTable(advice map[string]string) *list.Table {
	adv := list.Lookup("c.ci_id::text", "text", advice)
	t := &list.Table{
		Key: "container", Label: "Containers", Noun: "container",
		From: containerFrom, ID: `c.ci_id::text`, LinkExpr: `'/containers/' || c.ci_id`,
		Scope: func(a *list.Args, v list.Viewer) string { return visibleHostsSQL("c.host", a, v) },
		Fields: []list.Field{
			{Key: "name", Label: "Container", Type: list.Text, Expr: `c.name`, LinkExpr: `'/containers/' || c.ci_id`,
				Search: true, Class: "nowrap strong", NoGroup: true},
			{Key: "stack", Label: "Compose stack", Type: list.Text, Expr: `c.compose_project`, Search: true,
				LinkExpr: `'/stacks/' || st.ci_id`},
			{Key: "service", Label: "Compose service", Type: list.Text, Expr: `c.compose_service`},
			{Key: "host", Label: "Host", Type: list.Text, Expr: `h.hostname`, Search: true,
				LinkExpr: `'/hosts/' || h.ci_id || '/containers'`},
			{Key: "engine", Label: "Engine", Type: list.Text, Expr: `c.engine`},
			{Key: "image", Label: "Image", Type: list.Text, Expr: `c.image_ref`, Search: true, Class: "mono small"},
			{Key: "state", Label: "State", Type: list.Enum, Expr: `c.state`, Options: opts(containerStates...), Badge: "state"},
			{Key: "health", Label: "Health", Type: list.Enum, Expr: `NULLIF(c.health, '')`, Badge: "health",
				Options: opts("healthy", "unhealthy", "starting")},
			{Key: "restarts", Label: "Restarts", Type: list.Number, Class: "num",
				Expr: `COALESCE((c.attrs->>'restart_count')::int, 0)`},
			{Key: "update", Label: "Update", Type: list.Enum, Options: containerUpdates, Badge: "update",
				ViewerExpr: func(a *list.Args, v list.Viewer) string {
					return `CASE WHEN COALESCE(u.pinned, false) THEN 'pinned'
						WHEN COALESCE(u.drift, false) THEN 'newer_image'
						WHEN ` + adv(a, v) + ` IS NOT NULL THEN 'new_version'
						WHEN c.check_ref = '' THEN 'not_checked'
						WHEN COALESCE(u.error, '') <> '' THEN 'check_failed'
						WHEN u.checked_at IS NULL THEN 'pending'
						ELSE 'current' END`
				}},
			{Key: "has_update", Label: "Has an update", Type: list.Bool, NoGroup: true,
				ViewerExpr: func(a *list.Args, v list.Viewer) string {
					return `(NOT COALESCE(u.pinned, false) AND (COALESCE(u.drift, false) OR ` + adv(a, v) + ` IS NOT NULL))`
				}},
			{Key: "advice", Label: "Newer version", Type: list.Text, Class: "mono", ViewerExpr: func(a *list.Args, v list.Viewer) string {
				return `COALESCE(` + adv(a, v) + `, '')`
			}},
			{Key: "checked_at", Label: "Checked", Type: list.Time, Expr: `u.checked_at`},
			{Key: "check_error", Label: "Check error", Type: list.Text, Expr: `COALESCE(u.error, '')`, NoGroup: true, Class: "small"},
			{Key: "started_at", Label: "Started", Type: list.Time, Expr: `c.started_at`},
			{Key: "restart_policy", Label: "Restart policy", Type: list.Text, Expr: `COALESCE(c.attrs->>'restart_policy', '')`},
			{Key: "ports", Label: "Ports", Type: list.Tags, Class: "mono small",
				Expr: `ARRAY(SELECT (p->>'host_port') || '→' || (p->>'container_port') || '/' || (p->>'proto')
					FROM jsonb_array_elements(COALESCE(c.attrs->'ports', '[]')) p WHERE COALESCE((p->>'host_port')::int, 0) <> 0)`},
			{Key: "networks", Label: "Networks", Type: list.Tags, Class: "small",
				Expr: `ARRAY(SELECT jsonb_array_elements_text(COALESCE(c.attrs->'networks', '[]')))`},
		},
	}
	base := list.Query{Cols: []string{"name", "stack", "host", "image", "state", "update", "advice"}, Sort: list.Sort{Field: "name"}}
	view := viewOf(base)
	all := view("all", "All")
	t.Default = all.Query
	t.Views = []list.View{all,
		view("running", "Running", []list.Cond{cond("state", list.Eq, "running")}),
		view("stopped", "Not running", []list.Cond{cond("state", list.Ne, "running")}),
		view("updates", "With updates", []list.Cond{cond("has_update", list.IsTrue, "")}),
	}
	return t
}

// stackSelf are a Compose stack's own containers, as stackCols counts them.
const stackSelf = `FROM container c WHERE c.host = s.host AND c.engine = s.engine AND c.compose_project = s.project`

// classField is one of what a stack's name says (internal/stackname).
func classField(key, label string, values []string) list.Field {
	o := make([]list.Option, len(values))
	for i, v := range values {
		o[i] = list.Option{Value: v, Label: v}
	}
	return list.Field{Key: key, Label: label, Type: list.Enum, Options: o, Expr: `NULLIF(ci.attrs->>'` + key + `', '')`}
}

var stackTable = &list.Table{
	Key: "stack", Label: "Compose stacks", Noun: "stack",
	From: `compose_stack s JOIN host h ON h.ci_id = s.host JOIN ci ON ci.id = s.ci_id
		LEFT JOIN change_model m ON m.id = s.change_model_id LEFT JOIN maintenance_window w ON w.id = s.window_id`,
	ID: `s.ci_id::text`, LinkExpr: `'/stacks/' || s.ci_id`, DimExpr: `NOT s.present`,
	Scope: func(a *list.Args, v list.Viewer) string { return visibleHostsSQL("s.host", a, v) },
	Fields: []list.Field{
		{Key: "project", Label: "Stack", Type: list.Text, Expr: `s.project`, LinkExpr: `'/stacks/' || s.ci_id`,
			Search: true, Class: "strong"},
		{Key: "host", Label: "Host", Type: list.Text, Expr: `h.hostname`, Search: true,
			LinkExpr: `'/hosts/' || h.ci_id || '/stacks'`},
		{Key: "engine", Label: "Engine", Type: list.Text, Expr: `s.engine`},
		classField("environment", "Environment", stackname.Environments),
		classField("category", "Category", stackname.Categories),
		classField("visibility", "Visibility", stackname.Visibilities),
		{Key: "working_dir", Label: "Directory", Type: list.Text, Expr: `s.working_dir`, Search: true, NoGroup: true, Class: "mono small"},
		{Key: "containers", Label: "Containers", Type: list.Number, Class: "num", Expr: `(SELECT count(*) ` + stackSelf + `)`},
		{Key: "running", Label: "Running", Type: list.Number, Class: "num",
			Expr: `(SELECT count(*) ` + stackSelf + ` AND c.state = 'running')`},
		{Key: "drift", Label: "Newer images", Type: list.Number, Class: "num",
			Expr: `CASE WHEN s.pinned THEN 0 ELSE (SELECT count(*) FROM container c JOIN container_update u ON u.ci_id = c.ci_id
				WHERE c.host = s.host AND c.engine = s.engine AND c.compose_project = s.project AND u.drift) END`},
		{Key: "flags", Label: "Flags", Type: list.Tags, Badge: "flag",
			Expr: `array_remove(ARRAY[CASE WHEN s.pinned THEN 'pinned' END, CASE WHEN s.orphaned THEN 'orphaned' END, CASE WHEN s.stopped AND s.present THEN 'not running' END,
				CASE WHEN NOT s.present THEN 'gone' END, CASE WHEN s.auto_update THEN 'auto-update' END], NULL)`},
		{Key: "pinned", Label: "Pinned", Type: list.Bool, Expr: `s.pinned`},
		{Key: "orphaned", Label: "Orphaned", Type: list.Bool, Expr: `s.orphaned`},
		{Key: "present", Label: "Present", Type: list.Bool, Expr: `s.present`},
		{Key: "auto_update", Label: "Auto-update", Type: list.Bool, Expr: `s.auto_update`},
		{Key: "model", Label: "Change model", Type: list.Text, Expr: `COALESCE(m.name, '')`,
			LinkExpr: `'/change-models/' || m.id`},
		{Key: "window", Label: "Maintenance window", Type: list.Text, Expr: `COALESCE(w.name, '')`},
	},
}

func init() {
	view := viewOf(list.Query{Cols: []string{"project", "host", "environment", "category", "visibility", "working_dir",
		"containers", "drift", "flags"}, Sort: list.Sort{Field: "project"}})
	present := view("present", "Present", []list.Cond{cond("present", list.IsTrue, "")})
	stackTable.Default = present.Query
	stackTable.Views = []list.View{present,
		view("updates", "With newer images", []list.Cond{cond("drift", list.Gt, "0")}),
		view("orphaned", "Orphaned", []list.Cond{cond("orphaned", list.IsTrue, "")}),
		view("gone", "Gone", []list.Cond{cond("present", list.IsFalse, "")}),
		view("all", "All"),
	}
}

// Updates ---------------------------------------------------------------------

// updateHostTable lists hosts by their pending updates: the Updates page's
// "By host" tab.
var updateHostTable = &list.Table{
	Key: "update", Label: "Hosts with updates", Noun: "host",
	From:     `host h JOIN ci ON ci.id = h.ci_id LEFT JOIN host_inventory i ON i.host = h.ci_id AND i.section = 'updates'`,
	ID:       `h.ci_id::text`,
	LinkExpr: `'/hosts/' || h.ci_id || '?tab=updates'`,
	// Revoked hosts report nothing, so they don't count.
	Scope: func(a *list.Args, v list.Viewer) string {
		return "NOT h.revoked AND " + visibleHostsSQL("h.ci_id", a, v)
	},
	Fields: []list.Field{
		{Key: "name", Label: "Host", Type: list.Text, Expr: `COALESCE(NULLIF(h.hostname, ''), ci.name)`,
			LinkExpr: `'/hosts/' || h.ci_id || '?tab=updates'`, Search: true, Class: "strong"},
		{Key: "status", Label: "Status", Type: list.Enum, Badge: "host",
			Expr: `CASE WHEN h.connected THEN 'online' ELSE 'offline' END`, Options: opts("online", "offline")},
		{Key: "os", Label: "OS", Type: list.Text, Expr: `h.os_pretty`, Search: true},
		{Key: "groups", Label: "Groups", Type: list.Tags, Search: true,
			Expr: `ARRAY(SELECT g.name FROM host_group_member m JOIN host_group g ON g.id = m.group_id
			       WHERE m.ci_id = h.ci_id ORDER BY g.name)`},
		// Empty until the host first reports, as the old list's dash.
		{Key: "updates", Label: "Updates", Type: list.Number, Class: "num",
			Expr: `CASE WHEN i.received_at IS NOT NULL THEN (SELECT count(*) FROM host_update u WHERE u.host = h.ci_id) END`},
		{Key: "security", Label: "Security", Type: list.Number, Class: "num", Badge: "security",
			Expr: `CASE WHEN i.received_at IS NOT NULL THEN (SELECT count(*) FROM host_update u WHERE u.host = h.ci_id AND u.security) END`},
		{Key: "packages", Label: "Packages", Type: list.Tags, Search: true, Class: "small",
			Expr: `ARRAY(SELECT DISTINCT u.name FROM host_update u WHERE u.host = h.ci_id ORDER BY u.name)`},
		{Key: "checked_at", Label: "Checked", Type: list.Time, Expr: `i.received_at`},
	},
}

func init() {
	// Most urgent first: security updates, then any.
	view := viewOf(list.Query{Cols: []string{"name", "os", "updates", "security", "checked_at"},
		Sort: list.Sort{Field: "security", Desc: true}})
	all := view("all", "All")
	updateHostTable.Default = all.Query
	updateHostTable.Views = []list.View{all,
		view("pending", "With updates", []list.Cond{cond("updates", list.Gt, "0")}),
		view("security", "With security updates", []list.Cond{cond("security", list.Gt, "0")}),
		view("unchecked", "Not checked yet", []list.Cond{cond("checked_at", list.Empty, "")}),
	}
}

// packageUpdates is SQL over the pending updates of package p on the
// viewer's hosts: sel over host_update u JOIN host h, then tail (ORDER
// BY...).
func packageUpdates(sel, tail string) func(a *list.Args, v list.Viewer) string {
	return func(a *list.Args, v list.Viewer) string {
		return `SELECT ` + sel + ` FROM host_update u JOIN host h ON h.ci_id = u.host
			WHERE u.manager = p.manager AND u.name = p.name AND NOT h.revoked AND ` + visibleHostsSQL("u.host", a, v) + ` ` + tail
	}
}

// packageValue is one value over a package's updates (packageUpdates).
func packageValue(sel string) func(a *list.Args, v list.Viewer) string {
	q := packageUpdates(sel, "")
	return func(a *list.Args, v list.Viewer) string { return "(" + q(a, v) + ")" }
}

// packageTags is an array of one value per update. It is an ARRAY()
// rather than a subquery returning an array, which "= ANY" would read as
// a set of rows.
func packageTags(sel, tail string) func(a *list.Args, v list.Viewer) string {
	q := packageUpdates(sel, tail)
	return func(a *list.Args, v list.Viewer) string { return "ARRAY(" + q(a, v) + ")" }
}

// packageTable lists pending updates by package: the Updates page's "By
// package" tab. Each field counts only the hosts the viewer sees.
var packageTable = &list.Table{
	Key: "package", Label: "Packages with updates", Noun: "package",
	From: `(SELECT u.manager, u.name FROM host_update u JOIN host h ON h.ci_id = u.host WHERE NOT h.revoked
		GROUP BY u.manager, u.name) p`,
	ID: `p.manager || ':' || p.name`,
	Scope: func(a *list.Args, v list.Viewer) string {
		return `EXISTS (SELECT 1 FROM host_update u WHERE u.manager = p.manager AND u.name = p.name AND ` +
			visibleHostsSQL("u.host", a, v) + `)`
	},
	Fields: []list.Field{
		{Key: "name", Label: "Package", Type: list.Text, Expr: `p.name`, Search: true, Class: "strong", NoGroup: true},
		{Key: "manager", Label: "Manager", Type: list.Text, Expr: `p.manager`},
		{Key: "available", Label: "Available", Type: list.Tags, Class: "mono",
			ViewerExpr: packageTags(`DISTINCT u.candidate_ver`, `ORDER BY 1`)},
		{Key: "security", Label: "Security", Type: list.Bool, ViewerExpr: packageValue(`COALESCE(bool_or(u.security), false)`)},
		{Key: "image", Label: "OS image", Type: list.Bool, ViewerExpr: packageValue(`COALESCE(bool_or(u.image), false)`)},
		{Key: "host_count", Label: "Hosts", Type: list.Number, Class: "num", ViewerExpr: packageValue(`count(*)`)},
		{Key: "hosts", Label: "Host names", Type: list.Tags, Search: true, Class: "small",
			ViewerExpr: packageTags(`h.hostname`, `ORDER BY lower(h.hostname)`)},
		{Key: "advisories", Label: "Advisories", Type: list.Tags, Class: "small",
			ViewerExpr: func(a *list.Args, v list.Viewer) string {
				return "ARRAY(SELECT DISTINCT x FROM (" + packageUpdates("unnest(u.advisories) AS x", "")(a, v) + ") y ORDER BY 1)"
			}},
		{Key: "first_seen", Label: "Pending since", Type: list.Time, ViewerExpr: packageValue(`min(u.first_seen)`)},
	},
}

func init() {
	view := viewOf(list.Query{Cols: []string{"name", "manager", "security", "available", "host_count", "hosts", "first_seen"},
		Sort: list.Sort{Field: "host_count", Desc: true}})
	all := view("all", "All")
	packageTable.Default = all.Query
	packageTable.Views = []list.View{all,
		view("security", "Security", []list.Cond{cond("security", list.IsTrue, "")}),
		view("image", "OS images", []list.Cond{cond("image", list.IsTrue, "")}),
	}
}

// Virtual machines --------------------------------------------------------------

// guestAgentSQL is the host whose own agent runs in guest g, as guestCols
// finds it.
const guestAgentSQL = `(SELECT a.%s FROM ci_relationship r JOIN host a ON a.ci_id = r.from_ci
	WHERE r.to_ci = g.ci_id AND r.kind = 'runs_on' AND r.source = 'discovered' ORDER BY a.hostname LIMIT 1)`

var vmTable = &list.Table{
	Key: "vm", Label: "Virtual machines", Noun: "guest",
	From: `vm_guest g JOIN host h ON h.ci_id = g.host JOIN ci ON ci.id = g.ci_id`,
	ID:   `g.ci_id::text`, LinkExpr: `'/vms/' || g.ci_id`, DimExpr: `NOT g.present`,
	// Retired guests' hypervisors were revoked, as on the old list.
	Scope: func(a *list.Args, v list.Viewer) string {
		return "ci.status <> 'retired' AND " + visibleHostsSQL("g.host", a, v)
	},
	Fields: []list.Field{
		{Key: "name", Label: "Guest", Type: list.Text, Expr: `g.name`, LinkExpr: `'/vms/' || g.ci_id`, Search: true,
			Class: "nowrap strong", NoGroup: true},
		{Key: "type", Label: "Type", Type: list.Enum, Options: []list.Option{{Value: "vm", Label: "VM"}, {Value: "lxc", Label: "LXC"}},
			Expr: `CASE WHEN g.kind = 'lxc' THEN 'lxc' ELSE 'vm' END`},
		{Key: "platform", Label: "Platform", Type: list.Enum, Expr: `g.platform`,
			Options: []list.Option{{Value: "proxmox", Label: "Proxmox VE"}, {Value: "libvirt", Label: "libvirt"}}},
		{Key: "kind", Label: "Kind", Type: list.Text, Expr: `g.kind`},
		{Key: "guest_id", Label: "VMID or UUID", Type: list.Text, Expr: `g.guest_id`, Search: true, NoGroup: true, Class: "mono small"},
		{Key: "hypervisor", Label: "Hypervisor", Type: list.Text, Expr: `h.hostname`, Search: true,
			LinkExpr: `'/hosts/' || h.ci_id || '/vms'`},
		{Key: "state", Label: "State", Type: list.Text, Expr: `g.state`, Badge: "state"},
		{Key: "cpus", Label: "vCPU", Type: list.Number, Class: "num", Expr: `COALESCE((g.config->>'cpus')::int, 0)`},
		{Key: "memory", Label: "Memory (GiB)", Type: list.Number, Class: "num",
			Expr: `round(COALESCE((g.config->>'memory_bytes')::numeric, 0) / 1073741824, 1)::float8`},
		{Key: "agent", Label: "Agent", Type: list.Text, Search: true,
			Expr: `COALESCE(` + fmt.Sprintf(guestAgentSQL, "hostname") + `, '')`, LinkExpr: `'/hosts/' || ` + fmt.Sprintf(guestAgentSQL, "ci_id")},
		{Key: "os_type", Label: "OS type", Type: list.Text, Expr: `COALESCE(g.config->>'os_type', '')`, Search: true},
		{Key: "machine", Label: "Machine", Type: list.Text, Expr: `COALESCE(g.config->>'machine', '')`},
		{Key: "tags", Label: "Tags", Type: list.Tags, Search: true,
			Expr: `ARRAY(SELECT jsonb_array_elements_text(COALESCE(g.config->'tags', '[]')))`},
		{Key: "template", Label: "Template", Type: list.Bool, Expr: `COALESCE((g.config->>'template')::bool, false)`},
		{Key: "autostart", Label: "Autostart", Type: list.Bool, Expr: `COALESCE((g.config->>'autostart')::bool, false)`},
		{Key: "ha_state", Label: "HA state", Type: list.Text, Expr: `COALESCE(g.config->>'ha_state', '')`},
		{Key: "present", Label: "Present", Type: list.Bool, Expr: `g.present`},
	},
}

func init() {
	view := viewOf(list.Query{Cols: []string{"name", "type", "platform", "hypervisor", "state", "cpus", "memory", "agent", "tags"},
		Sort: list.Sort{Field: "name"}})
	all := view("all", "All")
	vmTable.Default = all.Query
	vmTable.Views = []list.View{all,
		view("running", "Running", []list.Cond{cond("state", list.Eq, "running")}),
		view("stopped", "Not running", []list.Cond{cond("state", list.Ne, "running"), cond("present", list.IsTrue, "")}),
		view("agent", "With their own agent", []list.Cond{cond("agent", list.NotEmpty, "")}),
		view("gone", "Gone", []list.Cond{cond("present", list.IsFalse, "")}),
	}
}

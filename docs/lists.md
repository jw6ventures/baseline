# The list engine

One list UI serves every table Baseline lists, so people learn it once: work
items, Hosts, CIs, Changes, Jobs, Containers and Compose stacks, Updates
(by host and by package), Virtual machines, Maintenance windows, Change
models, Alerts and the Audit log. The code is `internal/list` (registry, URL
format, SQL), `internal/server/list_tables*.go` (the tables),
`internal/server/lists.go` (pages, saved lists, inline edit, bulk actions),
`web/templates/list_parts.html` and `web/static/list.js`.

## Field registry

A `list.Table` names its `FROM` clause, the SQL of a row's id and link, a
scope that limits rows to what the viewer may see, and its fields. Each
field has a key, a label, a type and a SQL expression written in Go:

| Type | Operators |
|---|---|
| text | contains, is, is not, starts with, does not contain, is empty, is not empty |
| enum | is, is not, is empty, is not empty (values from the field's options) |
| number | is, is not, >, ≥, <, ≤, is empty, is not empty |
| bool | is true, is false |
| time | in the last (`30m`, `12h`, `7d`, `2w`), more than … ago, after, before (`2026-10-01`, `2026-10-01T15:04` in `BASELINE_TZ`), is empty, is not empty |
| tags (`text[]`) | has, lacks, is empty, is not empty |

The server builds SQL only from the registry. A URL picks fields, operators,
columns, the sort and the grouping by key, and every value it carries
reaches Postgres as a bound parameter. Values are checked before that
(enum options, numbers, spans, dates), and anything the registry doesn't
allow is dropped with a notice above the list, so a stale link still opens.

A field whose value depends on who is looking (work items' "Assigned to
me" and "Watching") sets `ViewerExpr` instead of `Expr`; its parameters are
bound only when a list uses the field. `SortExpr` sorts by rank instead of
by text, so priorities go critical, high, medium, low.

Some values are worked out in Go rather than SQL: a container's newest
version tag under its semver rule, a window's next opening from its cron
schedule, a change model's summary. The server computes them when it
builds the table and the field reads them with `list.Lookup`, which binds
the ids and values as two arrays and looks the row's id up in them, so
those fields filter, sort and group like any other.

An enum whose values form a tree (project categories) sets `MatchExpr`, an
array of the row's value and its ancestors: "is" and "is not" test
membership of it, so filtering by a category matches its subcategories too.
An option's `Color`, with `Badge: "color"`, draws the value as a colored
chip; tags fields can carry options too, and the builder offers them as a
pick list.

Records that belong to host groups rather than hosts (alerts) are scoped by
the viewer's groups (`Viewer.GroupIDs`), as their pages check them.

Custom fields (data-model.md §10) register with the same registry: work
items' table adds each `field_def` as `cf_<key>`. Text, long text and links
are text; numbers are numbers; dates and date-times are times; yes-or-no is
bool; pick one is an enum of the field's options; pick several is tags;
users, CIs and work items show the user's name, the CI's name or the item's
reference. A key is spliced into SQL as a string literal, so only keys that
match the field key pattern are registered, and the expressions guard their
casts so a stray value reads as empty instead of failing the list. A CI
field's name is built per viewer, like "Assigned to me", so people who may
not see the CI get an empty cell.

List statements run with JIT off: their many small correlated subqueries
make Postgres estimate a cost past `jit_above_cost`, and compiling such a
query takes seconds where running it takes a millisecond.

## URLs

A list's whole state is its URL, so any list is a shareable link:

| Parameter | Meaning |
|---|---|
| `cf`, `co`, `cv`, `cg` | Conditions as parallel lists: field, operator, value, group (from 0). Conditions in a group are ANDed and groups are ORed, which covers any filter and keeps the builder flat. |
| `q` | Quick search over the table's search fields |
| `cols` | Columns, comma separated, in order |
| `sort` | A field key, `-` first for descending |
| `group` | Group by a field |
| `page` | Page, 100 rows each |
| `list` | The saved list it came from (display only) |

A URL with none of these opens the table's default (Active and planned CIs,
for example). Engine-generated URLs always carry `sort`, so removing the
last condition doesn't bring the default back. The builder is a plain GET
form; what it sends (blank rows, one `cols` per checkbox) is answered with a
redirect to the canonical URL, or for htmx with `HX-Push-Url`. The old
filters (`?show=open`, `?type=nas&status=all`, for work items
`?project=OPS&assignee=me&status=all`, and `?updates=1`, `?security=1`,
`?platform=`, `?env=`, `?view=history` and the audit log's `?before=`) map
to conditions. `/containers?view=stacks` and `/updates?view=packages`
redirect to the lists that replaced those tabs, `/stacks` and
`/updates/packages`. The alert page's Rules and Silences tabs are settings,
not lists, and stay as they were.

## Page

- **Views:** each table's built-in lists (Open changes, Failed jobs...),
  then saved lists.
- **Condition builder:** groups of rows with a blank row to add one, and a
  blank group to start an OR. Breadcrumbs above the table remove one
  condition each.
- **Columns, sort, group-by:** the column picker, header links that sort,
  and group rows with counts. On the table's default columns, a column no
  row on the page has a value in is left out and named under the table;
  columns picked in the column picker always show.
- **Quick search:** the search box filters as you type, after a short pause.
- **Show matching / filter out:** clicking a cell (or a tag in it) offers
  both; they add the condition to every group.
- **Saved lists:** personal, or shared with everyone by an operator. Only
  whoever shared a list, or an admin, deletes it. Both are audited.
- **Inline edit:** owner, status and tags of agentless CIs, for global
  operators, through `UpdateCI` so history and audit are kept. Title and
  priority of work items, for anyone who can file them, through
  `UpdateWorkItem`.
- **Bulk actions:** checkboxes and an action bar. Work items: set the status
  (done takes a resolution) or the priority. CIs: set the status of
  agentless CIs (global operators). Hosts: add to or remove from a host group
  (admins). Alerts: acknowledge firing ones, or silence open ones for a
  span, where the viewer operates (as the buttons the old list had).
  Containers: restart; Compose stacks: pull images or update. These open
  the new-change form with the rows picked, so nothing runs until the
  change is submitted. Selected ids are re-checked against the viewer's scope and the
  row's editability before anything runs; at most 1000 per request.
- **Host related lists:** a host's Containers, Stacks, VMs and Jobs tabs are
  the same tables limited to the host, at `/hosts/{id}/containers` and so
  on (old `?tab=` links redirect), without the Host column. Saved lists are
  shared with the table's own page; forms posted from a host's list return
  to it.
- **Selections:** the workflow migration screen (data-model.md §12) shows the
  work items table limited to the migration's scope, every row ticked. A
  tick or untick, or the header box for a page, is saved as it happens
  (htmx), so a selection spans pages and filters; the list's query rides
  along with the migration form.

htmx (vendored) swaps `#list` in place: the server answers an htmx request
with the list alone. Without JS everything except the cell menu and inline
edit still works as links and forms.

## Schema

```sql
saved_list(id, table_key, name, owner NULL,     -- NULL owner: shared
           created_by, columns jsonb, conditions jsonb, search, sort jsonb, group_by,
           created_at, updated_at, UNIQUE(table_key, owner, lower(name)))
```

The design doc's `table_def` table isn't needed: tables are the Go registry.

Boards (data-model.md §12) store their filter in the same condition format as `saved_list.conditions` and run it through the work items table, so a board shows what the same conditions show in the list.

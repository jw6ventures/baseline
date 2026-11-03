# JSON API

Baseline has a read API over everything the web UI shows, plus creating,
submitting, cancelling and closing changes, adding and removing manual CI
relationships, and filing and working on work items, at `/api/v1` on the
web hostname. It exists for scripts and other systems: inventory exports,
dashboards, a ticketing system that raises a change when someone asks for
a restart, an assistant that files an incident and links the CIs it
concerns. Approving changes stays in the UI, with approvers.

## 1. Authentication

Requests carry an **API token** in the `Authorization` header:

```sh
curl -H "Authorization: Bearer baseline_api_…" https://baseline.example.com/api/v1/me
```

A token is made on **Your access** (the user menu). It belongs to the user
who made it and acts as them, limited to the **roles** picked at creation,
which must be roles the user holds (docs/architecture.md §5.1):

- `viewer` reads everything the user may see. As in the UI, any role also
  files, edits, transitions, comments on, watches and links work items
  (§5): they track work rather than change hosts.
- `operator` also creates and submits changes on the hosts the user holds
  operator on. A global operator adds and removes manual CI
  relationships.
- `approver` and `admin` don't approve anything through the API; they
  widen what a token may read (the audit log needs a global viewer, which
  admin implies), and let it cancel or close changes it didn't request
  (an approver on every host the change affects, or an admin).

Grants are resolved on every request from the token's roles, the Authentik
groups of the session that created it, and the current role bindings, so a
binding change applies to tokens at once. A token keeps the groups of the
day it was made: sign in and make a new one after joining a group. A token
expires after 30 days, 90 days, a year or never, as chosen, and can be
revoked on the same page. Only the SHA-256 of the secret is stored, so a
token is shown once. Creating and revoking tokens is audited; what a token
does is audited as its user.

Responses to a missing or bad token are `401` with `WWW-Authenticate:
Bearer`; a token whose roles don't allow an endpoint gets `403`.

## 2. Conventions

- Responses are JSON. Lists are arrays; a missing object is `404`
  `{"error": "..."}`; a bad request is `400` (malformed JSON, unknown
  fields) or `422` (a request that can't be carried out, with the reason).
- Field names are `snake_case`. Times are RFC 3339 in UTC; a time that
  isn't set is left out. Lists are never `null`.
- **Visibility is the UI's.** A host, and anything on it (containers,
  jobs, alerts…), is visible with the viewer role on one of its host
  groups or globally. What a token can't see doesn't exist to it: `404`,
  not `403`. Changes are visible when every host they affect is. Agentless
  CIs are visible to every viewer. The audit log needs a global viewer.
- Writes take JSON bodies. `PATCH` changes only the fields it names;
  `null` (or `""`) clears an optional one. `DELETE` names what to remove in
  the path and query.
- Query parameters filter lists; `limit` bounds them (each endpoint has a
  default and a maximum). Boolean parameters take `1`/`true`.
- Inventory sections (`/hosts/{id}/sections/{section}`) return the JSON
  the agent sent, with the types in `internal/model`; docs/agent.md
  describes each one.

## 3. Endpoints

All paths are under `/api/v1`.

### You and the fleet

| Method, path | Returns |
|---|---|
| `GET /me` | The token's user, name, roles and IdP groups, and the user's global and scoped roles as the token has them. |
| `GET /dashboard` | The dashboard's numbers over visible hosts: fleet counts, updates, drives, containers, guests, clusters, expiring certificates, change and alert counts, vulnerability totals, upcoming windows. |
| `GET /actions` | The typed actions a change can run, with category, risk class, timeout and the capabilities a host needs. |
| `GET /host-groups` | Host groups. |

### Hosts

| Method, path | Returns |
|---|---|
| `GET /hosts` | Visible hosts with their summary counts (updates, drives, containers, open jobs, vulnerabilities…). `q` searches hostname, FQDN, OS and groups; `group` keeps one host group; `connected=1` keeps online hosts; `revoked=1` includes revoked ones. |
| `GET /hosts/{id}` | One host. |
| `GET /hosts/{id}/sections` | The inventory sections the host has reported and when. |
| `GET /hosts/{id}/sections/{section}` | A section as reported: `os`, `hardware`, `packages`, `updates`, `smart`, `containers`, `vms`, `k8s_node`, `k8s`, `services`, `ports`, `reboot`, `certs`. |
| `GET /hosts/{id}/packages` | Installed packages; `q` filters by name. |
| `GET /hosts/{id}/updates` | Pending updates, security ones first, with when each was first seen. |
| `GET /hosts/{id}/certificates` | TLS certificates found on the host, with probe results. |
| `GET /hosts/{id}/history` | Inventory change history with diffs; `limit` (100). |
| `GET /hosts/{id}/metrics` | The metric panels and time ranges available. |
| `GET /hosts/{id}/metrics/{panel}` | A panel's series for `range` (`1h`, `6h`, `24h`, `7d`, `30d`): epoch-second times and one list of values per line. |
| `GET /hosts/{id}/jobs` | Jobs on the host; `show` is `open`, `failed` or `all`. |
| `GET /hosts/{id}/changes` | Changes affecting the host (filters as `/changes`). |
| `GET /hosts/{id}/vulnerabilities` | Matched CVEs on the host; `fixable=1`, `severity`, `q`. |
| `GET /hosts/{id}/alerts` | Open alerts on the host; `history=1` lists resolved ones of the last `days` (7). |
| `GET /updates` | Pending updates by package across visible hosts; `q`, `security=1`. |

### Containers, VMs, Kubernetes

| Method, path | Returns |
|---|---|
| `GET /containers` | Containers on visible hosts, with image check results and semver advice; `host`, `stack`, `q`, `updates=1`. |
| `GET /containers/{id}` | One container, by its CI ID. |
| `GET /stacks` | Compose stacks; `host`, `q`. |
| `GET /stacks/{id}` | A stack with its containers. |
| `GET /stacks/{id}/files` | What a `compose.edit` starts from: whether Baseline can edit the stack (`editable`, `edit_block`), its Compose file (`path`, `sha256`, `content`, and `masked` when it is inventory's copy with secret values masked rather than Baseline's own), and the .env Baseline last wrote (`known`, `revision`, `keys`, `hash`). `env=1` adds the .env's `text`; it needs the operator role on the host, and each read is audited. |
| `GET /vms` | Guests on visible hypervisors; `platform`, `host`, `q`, `gone=1` includes ones no longer present. |
| `GET /vms/{id}` | One guest, by its CI ID. |
| `GET /kubernetes` | Clusters reported by visible cluster agents. |
| `GET /kubernetes/{id}` | A cluster with its nodes, workloads, services and ingresses; `namespace` filters. |

### CIs

| Method, path | Returns |
|---|---|
| `GET /ci-types` | CI types and their fields. |
| `GET /cis` | CIs: `type`, `status` (default: everything but retired and missing), `q`, `limit` (500). |
| `GET /cis/{id}` | A CI with its visible relationships and the work items linked to it (`work_items`, each with its `rel`: the CI's role). |
| `GET /cis/{id}/relationships` | Its relationships. |
| `POST /cis/{id}/relationships` | Adds a manual relationship: `{"kind": "depends_on", "other": "<CI ID>", "direction": "out"}` reads "this CI depends on other"; `"in"` turns it round. `kind` is one of `runs_on`, `hosted_by`, `member_of`, `depends_on`, `connected_to`, `contains`, `uses`. Global operator; both CIs must be visible. `201` with the CI's relationships; `409` if it exists. |
| `DELETE /cis/{id}/relationships/{rel}` | Removes a manual relationship by its ID. Discovered ones follow discovery and are `404`. Global operator. |
| `GET /cis/{id}/work-items` | Work items the CI is linked to, open ones first. |
| `GET /cis/{id}/history` | Its change history. |
| `GET /cis/{id}/certificates` | Certificates on it (hosts and agentless endpoints). |
| `GET /map` | The CI map: nodes, edges, and the type and group filters, as the map page draws it. |

### Changes, jobs, scripts, schedule

| Method, path | Returns |
|---|---|
| `GET /changes` | Changes affecting only visible hosts, newest first: `show` (`open`, `approval`, `scheduled`, `review`, `all`), `state` (comma-separated), `host`, `model`, `ci`, `limit` (300). |
| `POST /changes` | Creates a change (§4). |
| `GET /changes/{id}` | A change with its approvals, jobs, patch cycle and linked work items (`work_items`, each with its `rel`: `fixes`, `implements` or `caused`). |
| `POST /changes/{id}/submit` | Submits a draft for approval. Only its requester may; `409` otherwise. |
| `POST /changes/{id}/cancel` | Cancels an open change, asking its running jobs to stop; `{"reason": "..."}` is optional. Its requester, an approver on all its hosts or an admin may; `409` once it has ended. |
| `POST /changes/{id}/close` | Closes a change that has ended (implemented, failed, rolled back or in review). One that didn't end implemented needs `{"review": "..."}`, its post-implementation review (`422` without). Who may: as cancel. |
| `GET /change-models` | Change models; `action`, `state`. |
| `GET /change-models/{id}` | One model. |
| `GET /jobs` | Jobs on visible hosts; `show`, `state`, `change`, `host`, `limit` (500). |
| `GET /jobs/{id}` | One job, with its parameters and result. |
| `GET /jobs/{id}/output` | Output chunks after `after` (a chunk ID), with the job's state; poll until `final`. |
| `GET /scripts` | The script library; `archived=1` includes archived scripts. |
| `GET /scripts/{id}` | A script with its versions (without bodies). |
| `GET /scripts/{id}/versions/{n}` | One version with its body and SHA-256. |
| `GET /windows` | Maintenance windows and freezes; `kind`. |
| `GET /calendar` | Window and freeze openings and planned changes from `from` to `to` (RFC 3339 or `YYYY-MM-DD`; the next 30 days). |
| `GET /patch-groups` | Patch groups with their latest cycle. |
| `GET /patch-groups/{id}` | A patch group with its cycles; `limit` (50). |

### Work tracking

| Method, path | Returns |
|---|---|
| `GET /projects` | Open projects with their open item counts; `archived=1` includes archived ones. |
| `GET /projects/{key}` | A project with its ticket types, each with its workflow and the custom fields its create screen asks for (`key`, `label`, `type`, `options`, `required`, `default`). |
| `GET /users` | Everyone who has signed in, for assignees. |
| `GET /work` | Work items: `project` (key), `type` (key or ID), `status` (`open`, the default, `all`, `todo`, `in_progress`, `done`), `assignee` (`me`, `none`, a user ID or email), `parent` (a reference), `q` (reference, title and description), `limit` (200, at most 1000). Open first, then by priority. |
| `POST /work` | Files a work item (§5). |
| `GET /work/{ref}` | An item, by its reference (`OPS-42`; one from before a move works too), with its visible CIs and changes, links, children, SLA clocks, watchers, comments and work notes, and the transitions out of its status (whether the token's user may run each, and what its screen takes). |
| `PATCH /work/{ref}` | Edits an item (§5). |
| `GET /work/{ref}/history` | Its history, newest first, without entries about CIs or changes the token can't see; `limit` (100). |
| `POST /work/{ref}/transitions` | Runs a transition (§5). |
| `POST /work/{ref}/comments` | Adds `{"body": "...", "internal": false}`; `internal` makes it a work note. The author then watches the item. |
| `POST /work/{ref}/watch`, `DELETE /work/{ref}/watch` | Starts or stops the token's user watching it. |
| `POST /work/{ref}/cis` | Links a visible CI: `{"ci": "<CI ID>", "role": "affected"}`; `role` is `affected` (default), `caused_by` or `target`. |
| `DELETE /work/{ref}/cis/{ci}?role=` | Unlinks it. |
| `POST /work/{ref}/changes` | Links a visible change: `{"change": "CHG-000123", "kind": "fixes"}` (its ID or number works too); `kind` is `fixes`, `implements` or `caused`. |
| `DELETE /work/{ref}/changes/{change}?kind=` | Unlinks it. |
| `POST /work/{ref}/links` | Links another item: `{"item": "OPS-7", "kind": "blocks", "direction": "out"}` reads "this blocks OPS-7"; `"in"` turns it round. `kind` is `blocks`, `relates`, `duplicates` or `caused_by`. |
| `DELETE /work/{ref}/links/{other}?kind=&direction=` | Removes the link. |
| `GET /boards` | Boards, with their columns. |
| `GET /boards/{id}` | A board filled as its page fills it: its filter in words, then each column's cards (items, with the transitions out of their status); `shown`, `total` and `unplaced` (matching items no column takes). |

Every write to an item answers with the item as `GET /work/{ref}` shows
it (`201` with `Location` for a new one). A link that exists is `409`;
unlinking one that doesn't is `404`.

### Vulnerabilities, alerts, audit

| Method, path | Returns |
|---|---|
| `GET /vulnerabilities` | CVEs matched on visible hosts, worst first; `fixable=1`, `severity` (minimum), `q`, `limit` (500). |
| `GET /vulnerabilities/{id}` | One vulnerability with its affected packages and the visible hosts it matches. |
| `GET /vulnerability-sources` | OSV sync state per ecosystem. |
| `GET /alerts` | Open alerts the token may see; `history=1` for resolved ones of the last `days` (7); `rule`, `ci`. |
| `GET /alerts/{id}` | One alert. |
| `GET /alert-rules` | Alert rules. |
| `GET /silences` | Silences of the last `days` (1) and upcoming ones. |
| `GET /audit` | Audit log entries, newest first, with their hash chain; `before` (an entry ID) pages back, `limit` (100). Global viewer only. |

## 4. Creating a change

`POST /changes` takes one action on some hosts and the change record's
text, and returns the change (`201`, with `Location`). It is submitted for
approval unless `draft` is set; the API has no way to approve it, so a
token holder can't approve their own work.

```json
{
  "action": "service.restart",
  "hosts": ["<host id>"],
  "params": {"unit": "nginx"},
  "justification": "stuck after the config change",
  "backout_plan": "start it again",
  "kind": "normal",
  "required_approvals": 1
}
```

| Field | Meaning |
|---|---|
| `action` | One of `GET /actions`: `pkg.upgrade`, `service.restart`, `service.start`, `service.stop`, `container.restart`, `compose.pull`, `compose.update`, `compose.start`, `compose.archive`, `compose.move`, `compose.deploy`, `compose.edit`, `host.reboot`, `script.run`. |
| `hosts` | Target host IDs. The token's user needs operator on each; a host's agent policy and capabilities must allow the action. |
| `params` | The action's parameters, as `internal/action` validates them (docs/agent.md §5): `pkg.upgrade` `{"mode": "all"|"security"|"selected", "packages": [...], "exclude": [...], "reboot": "never"|"if_required"|"always"}`; `service.*` `{"unit": "..."}`; `container.restart` `{"engine": "docker", "name": "..."}`; `compose.pull`, `compose.update`, `compose.start`, `compose.archive` `{"services": [...], "health_timeout": 120}`; `compose.move` the same plus `"dest": "<one of the host's Compose roots>"`; `compose.deploy` and `compose.edit` as §4.1; `host.reboot` `{"delay_s": 10}`; `script.run` `{"script_id": "...", "version": 2, "args": {"name": "value"}, "timeout_s": 600}` (`version` defaults to the newest). Unknown fields are rejected. |
| `containers` | For `container.restart`: container CI IDs, a step on each one's host, instead of `params` and `hosts`. `container` is shorthand for one. |
| `stacks` | For `compose.*`: Compose stack CI IDs, a step on each one's host; `params.services` applies to all of them. `stack` is shorthand for one. A `compose.edit` names one; a `compose.deploy` none. |
| `model` | An approved change model's ID: a Standard change, pre-approved, with the model's action and parameters. |
| `kind` | `normal` (default) or `emergency`; `standard` with `model`. |
| `title`, `description`, `justification`, `backout_plan`, `test_plan` | The record. The title defaults to the action and hosts. |
| `risk`, `impact` | `low`, `medium` or `high`. Risk defaults to the action's class, raised with the number of hosts. |
| `required_approvals` | Approvals a Normal change needs (default 1, at most 5). |
| `concurrency` | Hosts worked on at once (default 1). |
| `stop_on_failure` | Stop at the first failed host (default true). |
| `window` | A maintenance window's ID: the change runs only inside it. |
| `planned_start` | An RFC 3339 time to hold the change until. |
| `on_window_end` | `carry_over` (default) or `fail`: what happens to hosts left when the window closes. |
| `draft` | Save without submitting; `POST /changes/{id}/submit` later. |

A request a freeze or the window's schedule rules out is `422` with the
reason, as the form would say it.

### 4.1 Deploying and editing Compose stacks

`compose.deploy` and `compose.edit` carry the stack's files, as text in
`params` (docs/change-management.md §5.1). The host needs Compose stack
management turned on and an agent with `compose-files`, as in the UI; the
change is a Normal one, never from a model, with one step.

```json
{
  "action": "compose.deploy",
  "hosts": ["<host id>"],
  "params": {
    "engine": "docker",
    "project": "web",
    "root": "/srv/stacks",
    "compose": "services:\n  web:\n    image: nginx:1.27\n",
    "env": "DB_PASSWORD=hunter2\nTZ=UTC\n"
  }
}
```

| Param | Meaning |
|---|---|
| `engine`, `project` | Deploy: the new stack's engine (one the host has) and Compose project name. Left out of an edit, whose stack names them. |
| `root` | Deploy: one of the host's Compose roots (required when it has any); the stack goes in `<root>/<project>`. |
| `compose` | The Compose file, at most 1 MiB. A deploy needs it; an edit that leaves it out keeps the host's file. |
| `env` | The .env, `KEY=VALUE` lines. A deploy without it (or with it empty) writes none; an edit that leaves it out keeps the .env, and `""` empties it. It is stored encrypted and never returned with the change. |
| `base_sha256` | Edit, optional: the `sha256` of the Compose file the edit was made from (`GET /stacks/{id}/files`). The request is `422` if the host reports another file by now. The agent checks the same again before writing. |
| `health_timeout` | Seconds the containers get to be running and healthy before the change is undone (default 120, at most 1800). |

An edit names its stack (`stack`) and no hosts. To change one variable,
read the current files with `GET /stacks/{id}/files?env=1`, edit them,
and send them back with `base_sha256`. An edit that changes nothing is
`422`. The change's detail lists the files it writes under
`stack_revisions`: the Compose file in full, and the .env's variable names
and keyed hash only.

## 5. Work items

`POST /work` files an item in a project, as the new-item form does. It
starts at the initial status of its type's workflow, with `source`
`api`; the token's user is its reporter, and they and the assignee watch
it.

```json
{
  "project": "OPS",
  "type": "incident",
  "title": "NAS offline",
  "description": "No ping since 02:00",
  "priority": "high",
  "assignee": "me",
  "custom": {"site": "home"}
}
```

| Field | Meaning |
|---|---|
| `project` | The project's key. Required. |
| `type` | A ticket type the project offers, by key or ID; the project's default when left out. |
| `title`, `description` | The title is required. |
| `priority` | `critical`, `high`, `medium` (default) or `low`. |
| `impact`, `urgency` | `high`, `medium` or `low`, or left out. |
| `assignee` | A user ID, an email or `me` (`GET /users`). |
| `parent` | Another item's reference. |
| `estimate` | A number, 0 or more. |
| `due` | A date, `YYYY-MM-DD`. |
| `custom` | Custom field values by key, as `GET /projects/{key}` lists them for the type: a string, number, `true`/`false`, a list of strings for a pick-several, or `null`. Users and CIs are named by ID, work items by reference; a date and time is RFC 3339, or local time in the server's zone. Fields left out take their defaults; a required field must have a value. |

`PATCH /work/{ref}` takes the same fields but `project` and `type`, each
optional: only those named change, `null` or `""` clears `impact`,
`urgency`, `assignee`, `parent`, `estimate` or `due`, and in `custom`
only the keys named change (`null` clears one). Moving an item to
another project or type is an admin's migration in the UI.

`POST /work/{ref}/transitions` runs one of the transitions out of the
item's status, as listed under `transitions` in `GET /work/{ref}`:

```json
{"transition": "Done", "resolution": "Fixed", "comment": "PSU swapped"}
```

| Field | Meaning |
|---|---|
| `transition` | Its ID or name (case doesn't matter). An unknown one is `422` naming the ones there are. |
| `resolution` | Into a done status whose screen asks for it: `Done` (default), `Fixed`, `Won't do`, `Duplicate` or `Cannot reproduce`. |
| `assignee` | When the screen asks for it: a user ID, email or `me`; left out, nobody. |
| `comment` | When the screen asks for it; a `comment_required` validator needs one. |

The workflow's conditions apply to the token's user (with the token's
roles): failing them is `403`. A validator that fails is `422` with its
reason, and a transition that no longer applies because the item moved on
is `409`.

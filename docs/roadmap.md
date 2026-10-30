# Roadmap

Each milestone is a working, deployable increment. Agent self-update arrives early, in M2, so later agent changes can roll out to the fleet without touching every host by hand.

| M | Theme | Deliverables |
|---|---|---|
| **M0** ✅ | Skeleton | Repo, LICENSE (AGPL-3.0, © 2026 James Williams), `go.mod` (Go 1.27), vendoring, Makefile, Dockerfile, compose.yaml (server + Postgres, no published ports, Traefik labels). Server boot: config → jw6 logging → `database.Manager` (baseline + migrations) → OIDC login with Authentik → server-side sessions → role bindings → empty UI shell, audit log. CI with `go vet` and `go test`. |
| **M1** ✅ | Enrollment & host inventory | PKI, enrollment tokens, install.sh and systemd unit, gRPC `Connect` stream. Collectors: `os`, `hardware`, `packages` (apt, dnf, rpm-ostree, plus flatpak and snap). Host list and host detail pages. CI core tables and `ci_history` diffs. Clone detection, cert renewal, revocation. `scripts/e2e.sh` runs real agents on Ubuntu, Rocky and Fedora. |
| **M2** ✅ | Updates, metrics, self-update | `updates` collector for apt, dnf, rpm-ostree, flatpak and snap; the Updates page (by host and by package) and a host Updates tab with "Check now". Metrics every 60s with daily partitions, 5-minute rollups and retention; server-rendered SVG charts that uPlot makes interactive. `smart` collector and drive health. **Agent self-update**: signed releases published from the server image, desired-state targets, probation and automatic rollback. |
| **M3** ✅ | Containers & services | Docker/Podman client, containers and Compose discovery, server-side registry digest checks and semver advisories, pinned stacks, registry logins. Container metrics every 90s. `services`, `ports`, `reboot`, `certs` collectors, plus server-side TLS probes of agentless endpoints. Manual (agentless) CIs and the relationship view. |
| **M4** ✅ | Execution | Jobs with idempotent IDs, a journal on the agent and resends on reconnect. Typed actions `pkg.upgrade` (apt, dnf, rpm-ostree, flatpak, snap; all, security or selected, excludes, reboot policy, versions read back), `service.restart/start/stop`, `container.restart` and `host.reboot` (done when the host is back). The script library: immutable, SHA-256-checked versions with typed parameters. Live output over SSE. Agent-local policy (`allow_scripts`, `allow_actions`), reported in `Hello`. Every job runs under a minimal Normal change: submitted, approved (self-approval allowed and flagged), in progress one host at a time with stop-on-failure, then implemented or failed; inventory changes a job causes are attributed to its change. |
| **M5** ✅ | Change management | Full lifecycle (draft → submitted → approved → scheduled → in progress → implemented/failed/rolled back → review → closed), required approvals, Standard changes from approved change models, Emergency changes, maintenance windows and freezes (in-house cron, time zones, host-group scope), carry-over when a window closes, the calendar, patch groups with `blocked_by`/soak/threshold and promotion of validated versions (pinned with `pkg.upgrade` `versions`), `compose.pull` and `compose.update` with health checks and rollback, Compose auto-update under a change model. |
| **M6** ✅ | Alerting & CVEs | Alert rules (host offline, disk/inode full, SMART failing or degrading, failed units, cert expiry, reboot pending N days, CVE with fix available, patch cycle failed or blocked, unplanned change, change awaiting approval) with delays, reminders, acknowledgement and scope. Matrix and ntfy channels through a retrying outbox, silences. OSV sync (full distro dumps, then incremental from the change list) and matching for Ubuntu, Debian, Rocky Linux and AlmaLinux; OSV has no Fedora ecosystem, so Fedora and Bazzite hosts rely on vendor security updates. Vulnerabilities page, host tab, dashboard. |
| **M7** ✅ | Virtualization & Kubernetes | Proxmox VE and libvirt collectors (`vms`): VMs and LXC containers with their CPUs, memory, disks, NICs and state, Proxmox storage pools; guests keep their CI when they migrate, and a guest's own agent is linked to it by DMI UUID or MAC. The Virtual machines page, a host VMs tab. A cluster-mode agent (`baseline-agent --mode=k8s`, `deploy/k8s/baseline-agent.yaml`) with an in-house read-only REST client reports nodes, workloads, services and ingresses; nodes are linked to their hosts by machine-id. The Kubernetes pages, and a node's `crictl` view (pods, containers, images) on its host. |

## Work tracking (Conduit)

Work tracking extends Baseline itself (architecture.md §10, decision 25): Jira-style projects and boards and ServiceNow-style lists and records, on the same CIs and changes.

| Theme | Deliverables |
|---|---|
| **Work item core** ✅ | Projects (keys, service desk or software, host group), shared ticket types with a base kind, per-project numbering (OPS-42), the work item with priority, impact, urgency, assignee, parent, estimate and due date, links to CIs (affected, caused by, target), changes (fixes, implements, caused) and other items (blocks, relates, duplicates, caused by), comments and work notes, watchers and field-level history. |
| **Workflow engine** ✅ | Statuses with categories, transitions with conditions (role, assignee, reporter), validators (required fields, a linked change or CI, child items done, a comment), post-functions (assign, set priority) and a screen (resolution, assignee, comment), versioned workflows edited under Settings, a workflow per project ticket type, transitions on the item page and as a bulk action (data-model.md §9). Transition screens built from layouts come with custom fields; SLA and draft-change post-functions with SLAs. |
| **Workflow migration** ✅ | Settings > Migrations: move a published version's items to the newest version of a workflow, or a project and type's items to another project or type, on one screen: statuses mapped by key (else by category, each overridable), items picked in the list engine with unticking saved as you go, counts per status, custom fields a move drops listed. Runs in the background in batches with a history entry per item; old references keep working after a move; emptied versions retire (data-model.md §12). |
| **Boards** ✅ | Boards per project or across projects, with columns of status categories or statuses (by key), a filter in the list engine's condition format, and drag and drop that runs real transitions: a column several transitions lead into splits into a drop zone per transition, zones whose conditions fail are greyed out, and a transition with a screen asks for its input before it commits; a Move menu on each card does the same without dragging (data-model.md §11). |
| **Custom fields** ✅ | Field definitions (text, long text, number, date, date and time, yes or no, pick one, pick several, user, CI, work item, link), field groups with required fields and defaults, several groups per project ticket type (`project_ticket_type_group`), create and view layouts per ticket type with project overrides and "use this screen for view too", every field in the list engine as `cf_<key>`. Transition screens keep the workflow's own screen list for now; `form_layout` rows for transitions are not built yet. |
| **List engine** ✅ | One list view for every table: condition builder in the URL, columns, sort, group-by, saved lists, bulk actions. |
| **Record view** ✅ | A header with the key fields and transitions, layout sections, related lists as tabs (CIs, changes, linked items, child items, SLAs), one activity stream of comments, work notes and history with filters (data-model.md §8). |
| **SLAs** ✅ | Settings > SLAs: response and resolution targets per priority for a project, a ticket type, both or everything, the most specific enabled policy winning. Clocks kept by triggers on every path that changes an item: response met on leaving To do, resolution met on Done and running again on reopen, running targets moved on a priority change. The record view shows running and breached clocks in its header and every clock in an SLAs tab (data-model.md §13). Pausing, business hours, SLA post-functions and breach alerts come later. |
| **Workflow diagram** ✅ | The workflow page draws a version as a diagram on the CI map's canvas core: statuses as boxes, transitions as arrows. On a draft, statuses move (positions saved per version), transitions are drawn by dragging from one status to another, and statuses are added by double-clicking (data-model.md §14). |

Sprints and opening incidents from alerts and unplanned changes come after these.

## Later (not v1)

- Container image CVEs. The agent pulls just the package DB out of an image with `docker create` + `docker cp …:/var/lib/dpkg/status` (or the rpm/apk equivalent), so a full image export isn't needed.
- Hypervisor actions: a VM snapshot before patching (Proxmox `qm snapshot`), then start and stop.
- Config-file drift: watch chosen files, store hashes and diffs.
- Inventory of local users, sudoers and SSH authorized_keys.
- Services: main PID and the package that owns each unit.
- SNMP discovery of agentless network devices.
- Prometheus `/metrics` export of fleet metrics.
- zypper, apk and pacman package managers.
- Non-Linux agents (FreeBSD, Windows, macOS).

## Out of scope

- Multi-tenancy
- Horizontal scaling of the server

## Resolved questions (2026-10-10)

| Question | Answer |
|---|---|
| Reverse proxy | Traefik. No public binds on the host: no published ports, gRPC via TCP passthrough on SNI, VPN IP only as a fallback (architecture.md §7). |
| Self-approval | Allowed, flagged in the audit log |
| Distros | Ubuntu, Bazzite, Rocky Linux |
| Postgres | Its own container in Baseline's compose file |
| Group tagging | Authentik groups map to roles, optionally scoped to host groups. Admin is always global. |
| Copyright and license | James Williams; AGPL-3.0 (2026-10-30) |
| Agent packaging | Binary + install.sh + systemd unit is enough |

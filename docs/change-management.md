# Change management & orchestration

**Principle:** anything that changes a managed host runs as a **job** inside a **change**. Read-only work doesn't need a change: inventory, `pkg.refresh` and registry checks. Every state transition, approval, dispatch and result goes to `audit_log`.

**Implemented in M4:** a minimal Normal change behind every job, so the audit trail is complete from the first action. A change is created from **New change** (or a "…" button on a host, service, container or script) with its targets, action, justification and a suggested risk, and is *submitted*. Someone with `approver` on every affected host approves or rejects it; an approver may submit and approve in one step, recorded as self-approval. Approved changes go *in progress* at once (windows and scheduling arrive in M5), their jobs dispatched one host at a time by default with stop-on-failure, and end *implemented* when every job succeeded or *failed* otherwise (outcome `partial` when some did). Submitted and running changes can be cancelled by their requester or an approver: queued jobs are dropped and running ones asked to stop. A job whose host stays offline for an hour fails; one with no result well past its timeout is timed out. Reviews, Standard and Emergency changes, windows and patch groups are M5.

**Implemented in M5:** the full lifecycle below, with these specifics.
- **Kinds.** Normal changes need `required_approvals` (1–5) from distinct approvers of every affected host. Emergency changes need one, ignore freezes, and go to *review* when they succeed. Standard changes are made from an approved **change model** (admins write models, global approvers approve them, self-approval flagged; editing a model puts it back to pending) and are approved on creation; they close by themselves when every job succeeded. A model fixes the action and its parameters; the hosts (or, for `compose.*`, the stack) are chosen per change. Patch groups and Compose auto-updates request Standard changes as "the scheduler".
- **Drafts** are saved without submitting and submitted by their requester.
- **Scheduling.** An approved change starts at once unless its window, planned start or a freeze says otherwise; then it is *scheduled* with the time and the reason ("waiting for maintenance window nightly", "held by freeze year-end"). A planned start inside a freeze is refused for non-Emergency changes; a change approved "as soon as possible" during a freeze waits for the freeze to end rather than being refused. A window must cover every host of the change. While a change runs in a window, the dispatcher starts no job that is unlikely to finish before the window closes (each action has a typical duration: 30 min for `pkg.upgrade`, plus 10 for a reboot, the time limit for scripts…), and jobs on hosts that a freeze now covers wait. When the window closes with jobs left, they carry over to the next opening (*scheduled* again) or are skipped and the change fails, per the change's setting.
- **Results and review.** Every job succeeded: Normal → *implemented* (closing, with optional review notes, is up to its people), Emergency → *review*, Standard → *closed*. Otherwise *failed* (outcome `partial` or `failed`), or *rolled back* when every job that didn't succeed was rolled back (`compose.update`). Closing a failed, rolled-back or Emergency change needs review notes. Requesters, approvers of every affected host and admins cancel and close changes.
- **Patch groups.** The scheduler (every 30 s) runs each enabled group at most once per scheduled time; a run more than 6 hours late (the server was down) is recorded as skipped. A run whose model isn't approved, or whose host group is empty, is skipped. Block checks use each blocking group's latest cycle that ran: it must be `success` or `partial` with at least `success_threshold` % of its hosts, finished at least `soak` ago, and after this group's own last cycle started; otherwise the cycle is recorded as *blocked* with the reasons. With `promote_validated` (and a `pkg.upgrade` model), each host gets a selected upgrade of the pending updates whose candidate is exactly a version the blocking cycles validated on the same OS release (`os_id:version_id`), pinned with `pkg.upgrade` `versions` on agents that report `pkg-pin`; the model's mode and excludes still apply, and the rest are counted as deferred. Flatpak and snap updates are promoted by name without a pin. Image-based hosts validate and promote the image version. A cycle's validated set is the package versions its succeeded jobs installed (read back by the agent), plus the image versions its image-based hosts deployed. Cycles finish when their change ends: `success` when every host succeeded, `partial`, `failed`, or `cancelled`. The `patch_cycle` alert rule fires while a group's latest cycle that ran failed or was blocked (or, optionally, was partial), and `change_approval` while a submitted change waits for approval.
- **Compose.** A stack's page offers Update and Pull, which make Normal changes, or Standard ones when the stack has an approved `compose.update` model. **New change** offers them too, and container restarts: pick any number of stacks (and, per stack, services) or containers, filtered by text and by the environment, category and visibility their stack's name carries; the change gets a step and a job for each, run "stacks (containers) at a time" with stop-on-failure like hosts. With a model, only stacks whose updates run under it can be picked. Auto-update (approvers set it per stack, off by default, and it needs that model) runs when the stack has digest drift, isn't pinned or orphaned, its host is connected and allows `compose`, and nothing else is in flight for it; it waits 30 minutes after any update of the stack and a day after one that failed. It uses the stack's window, else the first window covering the host, else none.

## 1. Change types (ITIL)

| Type | Approval | Typical use |
|---|---|---|
| **Standard** | Pre-approved once, at the level of a **change model**. Each instance is auto-approved. Editing the model needs approval again. | Patch group runs, Compose auto-updates, routine service restarts |
| **Normal** | Needs approval from one or more users with `approver` scoped to the affected hosts | Ad-hoc patching from the UI, manual Compose update, running a library script, reboot |
| **Emergency** | One approver, can run **outside maintenance windows and during freezes**. A post-implementation review is mandatory before closing. | Urgent security fix |

## 2. Lifecycle

```
Draft ─▶ Submitted ─▶ Approved ─▶ Scheduled ─▶ In progress ─▶ Implemented ─▶ Review ─▶ Closed
            │             │                         │
            ▼             ▼                         ▼
        Rejected      Cancelled           Failed / Rolled back ─▶ Review ─▶ Closed
```

- **Draft:** built from the UI wizard (pick targets → action → schedule) or from a "Do this now" button. The button pre-fills a Normal or Emergency change.
- **Submitted:** affected CIs are filled in automatically from the targets. Risk is suggested from the action's risk class and the number of targets, and can be overridden.
- **Approved:** reaching it needs `required_approvals` (default 1). **Self-approval is allowed by default** (there's usually only one approver). The audit log records it explicitly as self-approved, and the change page shows a badge. A setting can forbid it later.
- **Scheduled:** set to the next opening of the selected maintenance window, or to an explicit time inside a window. If a freeze covers the time, scheduling is refused unless the change is Emergency.
- **In progress:** jobs are dispatched with a per-change concurrency limit (default 1 host at a time for Normal) and a **stop-on-failure** threshold.
- **Implemented / Failed / Rolled back:** set automatically from job outcomes.
- **Review:** required for Emergency, Failed and Rolled back. Optional for Normal. Standard changes skip it and close automatically.

## 3. Maintenance windows and freezes

- A window is `cron start + duration + timezone + scope` (global or host groups). For example: `0 2 * * SUN`, 3h, America/Chicago, groups [prod].
- A **freeze** is the same shape with `kind = freeze`. It blocks all non-Emergency changes in its scope.
- A job that would run past the end of its window isn't started. Jobs that have already started finish. Remaining hosts carry over to the next opening, or the change goes to Failed, depending on a per-change setting.
- A calendar view shows windows, freezes, scheduled changes and past changes with how they ended.

## 4. Patch groups

A patch group is a host group plus a schedule plus a policy. It's backed by a **Standard change model**.

| Field | Meaning |
|---|---|
| `host_group` | Which hosts (static or rule-based) |
| `schedule` | Cron in a timezone. It must fall inside `window`, if one is set. |
| `action_template` | e.g. `pkg.upgrade mode=security reboot=if_required exclude=[docker-ce, kernel*]` |
| `blocked_by` | Other patch groups that must have succeeded first |
| `soak` | How long after the blocking group's success this group must wait (e.g. 48h) |
| `success_threshold` | % of hosts in the blocking group that must succeed (default 100) |
| `promote_validated` | When on, this group installs only the `package@version` pairs the blocking group validated (see below) |
| `concurrency` / `stop_on_failure` | Rollout control inside the group |

**Run semantics:**
1. At the scheduled time, the scheduler creates a **patch cycle** and a Standard change that references the model.
2. **Block check:** for every group in `blocked_by`, the most recent cycle must be successful (≥ threshold), finished at least `soak` ago, and newer than this group's last cycle. If any check fails, the run is skipped and recorded as `blocked (reason)`, which the `patch_cycle` alert rule reports. *Example: `canary` (Sat 02:00) blocks `prod` (soak 48h, Mon 02:00). If canary fails, prod doesn't run.*
3. **Promotion:** with `promote_validated`, the blocking group's cycle stores a `validated_set` of the package@version pairs it installed successfully. The dependent group upgrades **only those exact versions**, to the extent the hosts share a distro. Packages that weren't validated are deferred to the next cycle. This stops prod from picking up a package version that was published after canary tested.
4. Every host in the group gets `pkg.refresh` then `pkg.upgrade`, with its reboot policy. If it reboots, the job completes once the agent reconnects with a new boot ID and the post-patch inventory shows the new versions.
5. The cycle result is stored and the change closes; a failed cycle fires the `patch_cycle` alert.

Groups can be chained (`canary → staging → prod`) or fanned out. Cycles in the dependency graph are rejected when the group is saved.

**Compose groups.** A group whose model is `compose.update` lists Compose stacks instead of a host group (an admin ticks them; new stacks don't join by themselves). Each run updates, in one Standard change with a step per stack, the listed stacks that have digest drift and aren't pinned, orphaned, on a host that refuses or can't run it, or in another open change. `blocked_by`, soak and the threshold work as above, counting stacks instead of hosts. With `promote_validated`, promotion follows the stacks' names (`<env><category><visibility>-<app>`, docs/data-model.md): Dev, then Test or Staging (one stage: Test for external stacks, Staging for internal ones), then Prod. A stack is checked against the present stacks of the same app and category at the nearest earlier stage that has any (a Prod stack against Test or Staging, else Dev), those of its own visibility when there are some. Each of its services with a newer image updates only if one of those copies runs exactly the digest the registry now serves for it, running and not unhealthy, since at least `soak` ago; the rest are deferred to a later cycle. A Dev stack, a stack whose name carries no environment, and one with no earlier copy update everything newer. One group can hold every stage: its Dev stacks update first, and the later ones follow on later runs, once the image has soaked. The update still pulls by tag (Compose files are never edited), so an image pushed between the registry check and the run isn't validated; the next registry check flags it as drift again.

## 5. Compose stack updates

- **Detection:** server-side digest checks show "update available" per service. Semver advisories are shown separately (see agent.md §3.3).
- **Manual update:** the "Update" button on a stack, or on selected services, creates a Normal change. A per-stack option allows it to be a Standard change instead. The action is `compose.update` with its pull → up → health → rollback procedure.
- **Auto-update:** set per stack and **off by default**. When on, it uses a Standard change model and runs inside the stack's maintenance window, or the host's if the stack has none. It runs only when digest drift exists. It never applies semver advisories, because that would mean editing Compose files.
- A stack can be marked `pinned`, which turns off update prompts. That's useful for databases.

### 5.1 Deploying stacks and editing their files

- **Turning it on.** An admin turns on **Manage Compose stacks** in the "Compose stacks" panel of the host's Settings tab (`host.manage_compose`, audited). It is off by default, and while it is off no change can deploy a stack to the host or edit a stack's files. It covers every stack on the host, including ones Baseline didn't deploy.
- **Compose roots.** While it is on, the admin can add directories on the host that new stacks go under (`host.compose_root_add` and `host.compose_root_remove`, audited, in the host's history). The deploy form offers them, the first by default, and the stack goes in `<root>/<project>`. A host with none deploys to the agent's own `compose_root` (agent.md §5.2). Removing a root doesn't move the stacks under it. The agent is told the roots (agent.md §3.2) and reports the stacks it finds under them that aren't running: they show as *not running*, can be edited (without starting them) and get a **Start…** button, a `compose.start` change (Low risk), but can't be updated until they run. Start is offered for any stack none of whose containers run.
- **Archive and move.** On a host with management on, a stack's page also offers **Archive…** (`compose.archive`, Medium risk): the stack is taken down and its directory moved to `.archive/<project>-<date>` beside it, so nothing is deleted and named volumes stay; the stack then drops off the list. With Compose roots on the host it offers **Move…** (`compose.move`, Medium risk): the stack goes to `<root>/<project>` under the root picked, and one that ran is started there and checked for health, or moved back. The server refuses a root that isn't one of the host's. Both work in bulk from the stack list, through the API, and never from change models.
- **Deploy.** "Deploy a stack…" on the host opens a change form with the engine, the project name, the Compose file and an optional .env. **Edit.** "Edit files…" on a stack opens one with the Compose file (Baseline's own copy when it still matches the host, otherwise the copy inventory shows, whose masked secrets must be replaced before it can be submitted) and the .env Baseline last wrote, each behind its own checkbox. An edit needs a stack with exactly one Compose file and no other open change deploying or editing it; a rootless Podman stack also needs an agent from this release on. Deploys can go to a rootless Podman engine (`podman:<user>`) too, into a Compose root that user can write to. Both are Normal changes (Medium risk) and go through the usual approval; neither is offered in the generic action form, and the API takes both (docs/api.md §4.1).
- **What the server keeps.** Each change writes one `compose_revision` per stack: the whole Compose file and its SHA-256 (so drift can later be checked against what the host reports), and for an edit the file it replaces. The .env is stored encrypted with `BASELINE_SECRET_KEY` (bound to its revision), with its variable names and an HMAC-SHA256 under a key derived from the secret key; neither the plain text nor a plain hash is stored anywhere else. The dispatcher decrypts it only to send it with the job (agent.md §5.3).
- **Who sees the values.** Viewers see the Compose file, the variable names and the hash. Operators of the host can press **Show values** on the change or the stack, and opening the edit form prefills the current .env; each of these records a `stack.env_view` audit event.

### 5.2 Kubernetes workloads

- **Turning it on.** Kubernetes actions run on the cluster agent (agent.md §6.1), which runs them once the opt-in ClusterRole is applied (`BASELINE_ALLOW_ACTIONS=none` on the agent turns them off). They are the `kubernetes` category of actions. Who may change a cluster is who has the operator role on its cluster agent's host. Namespaces in the agent's `BASELINE_DENY_NAMESPACES` (kube-system by default) are refused by the server and the agent.
- **Workload actions.** A workload's page (Kubernetes → cluster → workload) shows its live pods and offers what applies to its kind: **Restart…**, **Scale…**, **Change image…**, **Delete pod** on each pod, and for CronJobs **Suspend**, **Resume** and **Run now**. Each opens a change form; restart, scale, suspend, resume and run now can also pick several workloads at once from "New change", one step per workload. All are Normal changes (or Emergency) and go through approval and windows like any other. Restart, scale and image changes wait for the rollout, and a failed image change rolls back.
- **Manifests.** The cluster's **Manifests** tab lists the bundles Baseline applied. **Deploy a manifest…** opens a change with a bundle name, a default namespace and the manifest; **Edit** on a bundle starts from the manifest applied last. An edit is refused while another open change deploys or edits the same bundle, and one that changes nothing is refused. The server checks the manifest with the agent's rules when the change is made, so a Secret, an unknown kind or a denied namespace is refused at once. Each change stores one `k8s_manifest` revision per bundle (the whole manifest, its SHA-256 and objects, and for an edit the revision it replaces), shown on the change. Both are Medium risk, never from change models.
- **Logs.** Unless the agent has `BASELINE_K8S_LOGS=off`, operators of the cluster can read a pod's recent log from the workload's page. Each read records a `k8s.logs_view` audit event.

## 6. Scripts

- Scripts live in the library, are versioned, and are immutable per version. Admins create and edit them.
- A script declares an interpreter (`/bin/sh`, `/bin/bash`, `/usr/bin/python3`), a parameter list (name, type, required, validation regex) and a risk class.
- Running a script is always a change, Normal by default. A script version can be promoted into a Standard change model by an approver, for example "clear apt cache".

## 7. RBAC matrix

| Capability | viewer | operator | approver | admin |
|---|---|---|---|---|
| View inventory, metrics, CVEs, changes, audit | ✓ | ✓ | ✓ | ✓ |
| Refresh inventory, acknowledge alerts | | ✓ | | ✓ |
| Draft/submit changes, run Standard changes on demand | | ✓ | | ✓ |
| Approve/reject changes | | | ✓ | ✓ |
| Manage patch groups, windows, change models | | | | ✓ (approver approves models) |
| Script library, enrollment, settings, role bindings, agent releases | | | | ✓ |

All roles except admin can be scoped to host groups. A user's effective permission on a host is the union of every binding whose scope includes that host. Admin is global and implies all the other roles.

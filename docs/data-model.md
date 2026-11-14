# Data model (PostgreSQL)

- All access goes through `database/sql` + `lib/pq`, with hand-written SQL in `internal/store`. There's no ORM.
- The schema is managed by `jw6-go-utils/database`. `db/db.sql` is the baseline and inserts `('version','v0.1.0')` into `application`. `db/migrations/vX.Y.Z.sql` holds the migrations.
- IDs are UUIDs (`gen_random_uuid()`). Times are `timestamptz` in UTC. The UI renders them in `BASELINE_TZ` or the user's preference.

## 1. CMDB core: configuration items

The **CI** is the generic CMDB object. Anything with an identity people care about is a CI. High-volume facts that hang off a host, such as packages, ports and metrics, live in typed tables keyed to the host and are **not** CIs.

```sql
ci_type(key text PK, label, icon, attr_schema jsonb)   -- host, vm, lxc, container, compose_stack,
                                                       -- k8s_cluster, k8s_node, k8s_workload, disk, nic,
                                                       -- network_device, ups, nas, printer, license,
                                                       -- service_endpoint, certificate, site, rack,
                                                       -- network_client, camera, protect_device, ...
ci(id, type → ci_type, name, status [active|retired|planned|missing],
   source [agent|proxmox|libvirt|k8s|unifi|manual],
   source_key text,          -- natural key from discovery (machine-id, VM uuid, container id...) UNIQUE(source, source_key)
   owner, description, tags text[], attrs jsonb,
   first_seen, last_seen, created_at, updated_at)
ci_relationship(id, from_ci, to_ci, kind [runs_on|hosted_by|member_of|depends_on|connected_to|contains|uses],
   source [discovered|manual], attrs jsonb, UNIQUE(from_ci,to_ci,kind))
ci_history(id, ci_id, at, actor [agent|user:<id>|system], change_id NULL,
   section text, diff jsonb)                    -- field-level diff, see §3
host_group(id, name, description, rule jsonb NULL)  -- static members and/or dynamic rule (tag/os/attr match)
host_group_member(group_id, ci_id)
```

- **UniFi CIs** (`source = unifi`) are kept by the polls of a UniFi console: its sites, devices, Protect devices and the wired clients no other CI has the MAC of; wireless clients are only linked to their access point when a CI has their MAC (integrations.md §1). Like manual CIs they live on no host, so every viewer sees them.
- **Agentless CIs** are rows with `source = manual`. Their attributes follow `ci_type.attr_schema`, a small JSON-schema subset that drives the UI form.
- CIs that have **disappeared** from discovery move to `status = missing` after a grace period: 1h for containers, Compose stacks and Traefik hostnames (a sweep runs every 10 minutes). They're never deleted automatically, so history survives; an admin can delete a missing or retired one. Compose stacks can also be retired automatically once they've been missing for more than a number of days an admin sets under Settings > Inventory (`app_setting` key `stacks.retire_missing_days`, off by default; each one is audited as `stack.retire`). A retired stack drops off the stack lists and host Stacks tabs (the Retired view lists it), keeps its row and settings, and turns active again if its host reports it. Revoking a host retires its containers, stacks and Traefik hostnames.
- **Container identity:** `source_key` is `<host>/<engine>/<name>` for containers and `<host>/<engine>/compose:<project>` for stacks. Names survive Compose recreating a container; engine IDs don't.
- **Stack names carry metadata:** a Compose project named `<env><category><visibility>-<app>` (`pii-backup`, `pwe-proxy`) gets `environment`, `category` and `visibility` in its CI's `attrs` (internal/stackname). Env is d/s/t/p (Dev, Staging, Test, Prod); category is i/e/w/h (Infrastructure, Entertainment, Web, Health); visibility is i/e (Internal, External). A name without a full, known prefix (`Baseline`, `pi-rustdesk`) gets none.
- **The CI map** (`/map`) reads every CI the user may see, in any status, and the relationships whose both ends they may see from `/map.json`, with a health level (ok, warn, bad, off) and its reasons worked out from the host, container, guest, Kubernetes and alert tables. Filtering, bridging through hidden CIs, focus and layout happen in the browser (`web/static/cimap.js`, on the canvas core in `web/static/mapcore.js` that the workflow diagram (§14) shares; no dependencies).
- **Discovered relationships:** a container `runs_on` its host and is `member_of` its stack; a stack `runs_on` its host. Manual relationships are added from a CI's page and recorded in both CIs' history.
- **Traefik hostnames:** the server reads the `traefik.http.routers.*.rule` and `traefik.tcp.routers.*.rule` labels of each host's containers and keeps a `service_endpoint` CI (`source = agent`) for every hostname their `Host`, `HostHeader` and `HostSNI` matchers name, and for every `HostRegexp` and `HostSNIRegexp` pattern (named by the pattern). One per host and hostname: `source_key` is `<host>/traefik:<hostname>` or `<host>/traefik-re:<pattern>`, and `traefik_hostname` tracks which are present. Negated matchers, `HostSNI(*)` and containers with `traefik.enable=false` are skipped. Each hostname is `hosted_by` the containers whose routers match it, `member_of` their stacks, and `depends_on` the Traefik routing it: Traefik containers on the same host (found by image, `traefik` as the last path element) and the CI in `host.traefik_ci`, set on the host's Containers tab when a Traefik on another node (a container, or a host running it as a service) reads the host's Docker labels; its attributes hold the matchers, routers, entry points, TLS and service ports, and a URL for HTTP hostnames (https when a router has TLS labels or uses an entry point named `websecure` or `https`). It goes missing an hour after no container names it. Routers from Traefik's file provider aren't seen. Traefik labels are masked on the host without regard to the router's, service's or middleware's name, so a router named `auth` keeps its rule; one masked by an older agent is flagged on the container's page.
- **Ingress hostnames:** every hostname a cluster's Ingresses name (lowercased; wildcards kept as written) is a `service_endpoint` CI with `source = k8s` and `source_key` `<cluster UID>/ingress:<hostname>`, `member_of` the cluster, tracked present or not in `k8s_ingress_host`. Its attributes hold the cluster, the Ingresses (`namespace/name`), their classes, the backends and workloads for that hostname, TLS (yes when an Ingress naming it has a TLS section) and a URL for non-wildcard hostnames. It is `hosted_by` the workloads behind it: each backend's Service (and the Ingress's default backend), and the workloads that Service's selector matches, which the cluster agent works out from pod template labels and reports as the Service's `workloads` (an older cluster agent doesn't, so its hostnames have no `hosted_by` until its image is updated). It goes missing an hour after no Ingress names it, is linked from the cluster's Ingresses tab, and is retired with the cluster agent.
- **Manual CI types** (`network_device`, `nas`, `ups`, `printer`, `server`, `appliance`, `service_endpoint`, `license`, `certificate`, `site`, `rack`, `vm`, `lxc`, `other`) carry their form in `attr_schema`: `{"fields": [{"key", "label", "type"}]}` with types text, textarea, date, url and endpoint. An `endpoint` field (`tls_endpoint`) is probed by the server for its certificate.

## 2. Host-attached inventory (current state)

`host` is one row per enrolled agent, 1:1 with a `ci` of type `host`:

```sql
host(ci_id PK, agent_id uuid UNIQUE, cert_serial, prev_cert_serial, cert_not_after, revoked bool, revoked_at,
     machine_id, dmi_uuid, duplicate_identity bool, hostname, fqdn, os_id, os_version, os_pretty, kernel, arch,
     agent_version, capabilities text[], local_policy jsonb,
     connected bool, last_connect, last_seen, boot_id, boot_time, enrolled_at, enrollment_token_id,
     agent_arch, agent_update_target, agent_update_at, agent_update_error,   -- self-update (M2)
     reboot_required bool, reboot_reasons text[],   -- reboot_* (M3)
     high_security bool, high_security_since)       -- v0.11.0
```

Current-state tables. Each is replaced section by section on ingest, in one transaction.

| Table | Key columns |
|---|---|
| `host_hardware` | host, attrs jsonb (system/cpu/bios/bmc) |
| `host_dimm`, `host_disk`, `host_nic`, `host_fs`, `host_pci` | host + natural key |
| `host_package` | host, manager, name, arch, epoch, version, release, source_name, repo, installed_at |
| `host_update` | host, manager, name, arch, installed_ver, candidate_ver, repo, security, advisories text[], image bool (a whole OS image, rpm-ostree), first_seen (kept while the same candidate stays pending) |
| `host_service` | host, unit, load, active, sub, enabled, description |
| `host_port` | host, proto, addr, port, process, unit |
| `ci_cert` | ci_id, location (path, `tcp:<port>[/<sni>]`, or `host:port` for server probes), source [agent\|probe], subject, sans[], issuer, not_before, not_after, serial, fingerprint, self_signed, error, checked_at. Keyed to any CI, so hosts and agentless endpoints share one expiry list. |
| `host_smart` | host, device, model, serial, passed (NULL: no health status), degrading, attrs jsonb (the device as reported), rose_at (when the bad sector count last went up; §7). When it was checked is the section's `received_at`. |
| `container` | ci_id, host, engine, name, engine_id, image_ref, image_id, check_ref (the normalized ref registries are asked about; '' when the image can't be checked), image_digests[] (digests the image was pulled by), state, health, started_at, labels jsonb, attrs jsonb (the container as reported), compose_project, compose_service. Current state: a removed container loses its row, and its CI turns `missing` an hour later. |
| `compose_stack` | ci_id, host, engine, project, working_dir, config_files[], cli, orphaned, stopped (found under a Compose root, not running), present, auto_update bool **default false**, pinned, semver_rules jsonb (service → rule), update_groups jsonb (service → {group, order}, set on the stack's page; container labels win, change-management.md §5.3). Kept with `present = false` when the stack goes away, so its settings survive. |
| `image_check` | image_ref, registry, latest_digest, checked_at, error. One row per normalized reference, shared by every host. The view `container_update` joins it to containers: **drift** is a registry digest the image wasn't pulled by. |
| `registry_tags` | repository, tags[], checked_at, error: tags of repositories a semver rule watches. Advisories are computed from them when a page is shown, since rules differ per container. |
| `vm_guest` | ci_id, host (the hypervisor running it), platform [proxmox\|libvirt], kind (qemu or lxc on Proxmox, the domain type on libvirt), guest_id (VMID or domain UUID), name, uuid (the SMBIOS UUID the guest sees), macs[], state, config jsonb (the guest as reported), present. Kept with `present = false` when the guest goes away. |
| `k8s_cluster` | ci_id, host (the cluster agent), uid (the kube-system namespace's UID), name, version, platform |
| `k8s_object` | ci_id, cluster_ci, host (the cluster agent), kind (Node, Deployment, StatefulSet, DaemonSet, CronJob, Pod), namespace, name, images[], spec_summary jsonb (the object as reported), present |
| `k8s_ingress_host` | ci_id, cluster_ci, hostname, present: the hostnames Ingresses route (§1) |
| `host_inventory` | host, section, content_hash, data jsonb, received_at. The latest copy of every section as sent; history diffs are computed against it. In M1 hardware is read from here rather than from the typed tables above. |

Partial index: `host_update` WHERE `security`. The dashboard counts are simple `GROUP BY` queries.

The `updates` and `k8s_node` sections are not diffed into `ci_history`: what a repository offers isn't the host's configuration, and a node's pods come and go with every rollout. `smart` is, so a drive going from passed to failing, or its reallocated count rising, is in the host's history.

**Implemented in M7** (schema v0.8.0):

- **Guests.** A Proxmox or libvirt guest is a CI of type `vm` or `lxc` with source `proxmox` or `libvirt`, keyed by `<Proxmox cluster>/<VMID>` (`node:<name>/<VMID>` on a standalone node) or the libvirt domain UUID, so a guest that migrates keeps its CI: the node that now reports it takes its `vm_guest` row over and its `runs_on` relationship moves along. A guest gone from its hypervisor keeps its row with `present = false` and its CI turns missing an hour later. A hypervisor that couldn't be read keeps its earlier guests, as an engine does for containers. Revoking the hypervisor retires its guests.
- **Linking.** A host whose agent runs inside a guest `runs_on` the guest's CI: matched by DMI product UUID (VMs only; an LXC container reads its hypervisor's DMI) or else by a NIC MAC from the host's hardware section. A Kubernetes node `runs_on` the host whose agent reports its machine-id (or DMI UUID). Every such link is recomputed after a `vms`, `k8s` or `hardware` section changes, under an advisory lock, and links that no longer hold are dropped.
- **Kubernetes.** The cluster is a `k8s_cluster` CI (source `k8s`) keyed by the kube-system namespace's UID, so a re-enrolled agent takes it over. Nodes (`k8s_node`) and workloads (`k8s_workload`, named `namespace/name`) are CIs keyed by `<cluster UID>/<kind>/<namespace>/<name>` that are `member_of` the cluster; ci.attrs holds what the CI page shows (kind, namespace, images; a node's roles, kubelet and runtime). Services and ingresses are shown from the section, not kept as CIs. Objects that go away turn missing like containers; resources the agent couldn't list keep their earlier copy. The cluster agent's own host record is renamed after the cluster. Revoking it retires the cluster and its objects.
- **History.** Guests are diffed by platform and ID, leaving their run state out; the cluster section by node, workload, service and ingress, leaving readiness out, so a version upgrade or a new image is a history entry and a pod restarting isn't. Entries go to the reporting host's history, as containers' do.

## 3. Change history (the "config management" part)

On ingest, the server diffs the new section against the current rows and writes `ci_history` entries. For example:

```json
{"section":"packages","added":[{"name":"htop","ver":"3.3.0-4"}],
 "removed":[],"changed":[{"name":"openssl","from":"3.0.13-1","to":"3.0.15-1"}]}
```

If a job under a change record caused the diff (the agent sends the `job_id` with the post-job inventory), the entry is tagged with that `change_id`. Diffs with no change behind them are **unplanned changes**. The UI highlights them, and they can be routed to an alert. This is drift detection at the package, service, port, container and hardware level.

## 4. Jobs, changes and the schedule

See [change-management.md](change-management.md) for the behaviour.

```sql
script(id, name UNIQUE, description, archived, created_by, created_at)
script_version(script_id, version int, interpreter, params jsonb, risk, body text, sha256, notes,
               created_by, created_at)  -- immutable (a trigger rejects UPDATE); what it runs with is per version

change_model(id, name UNIQUE, description, action, params jsonb, script_id, script_version, risk,
             state [pending|approved|retired], requested_by, approved_by, approved_at, self_approved,
             created_at, updated_at)   -- a Standard change, approved once; compose.* params leave the stack out
change(id, number serial UNIQUE,     -- CHG-000123
       kind [standard|normal|emergency], model_id NULL,
       title, description, justification, risk [low|medium|high], impact [low|medium|high],
       implementation_plan jsonb,      -- list of {action, params, hosts}
       backout_plan text, test_plan text,
       state, requested_by NULL,       -- NULL: the scheduler (patch groups, auto-update)
       required_approvals, concurrency, stop_on_failure,
       window_id NULL, window_ends_at, on_window_end [carry_over|fail], schedule_note,
       planned_start, planned_end, submitted_at, approved_at,
       actual_start, actual_end, closed_at, outcome [success|partial|failed|rolled_back|cancelled],
       review_notes, reviewed_by, created_at, updated_at)
change_approval(change_id, approver, decision [approve|reject], comment, self_approved, at)
change_ci(change_id, ci_id)            -- affected CIs: the hosts, plus the Compose stacks or containers

maintenance_window(id, name UNIQUE, description, kind [window|freeze], cron, duration_s, tz,
                   scope_groups uuid[],  -- empty: every host
                   active, created_by, created_at, updated_at)
patch_group(id, name UNIQUE, description, host_group_id NULL, schedule_cron, tz, window_id NULL,
            stacks uuid[],               -- Compose groups (compose.update model): no host group
            change_model_id, blocked_by uuid[], soak_s, success_threshold int default 100,
            promote_validated bool default true, concurrency, stop_on_failure, enabled,
            last_run_at,                 -- the scheduled time last handled
            created_by, created_at, updated_at)
patch_cycle(id, patch_group_id, change_id NULL, scheduled_for, started_at, finished_at,
            result [running|success|partial|failed|blocked|skipped|cancelled], reason, hosts, succeeded,
            planned jsonb,               -- per host: packages, pins, deferred, note, image;
                                         -- per stack: project, services, validator, deferred, note
            validated_set jsonb)         -- [{os, manager, name, arch, version}] that succeeded
compose_stack(..., auto_update, change_model_id NULL, window_id NULL)  -- M5 columns

job(id, change_id, seq, host, action, params jsonb, script_id NULL, script_version NULL, timeout_s,
    state [queued|dispatched|running|succeeded|failed|cancelled|timed_out|rejected|rolled_back],
    awaiting_reboot, queued_at, dispatched_at, started_at, finished_at, exit_code, result jsonb, error,
    output_bytes, requested_by)
job_output(id bigserial, job_id, seq, stream [stdout|stderr|info], at, chunk text)  -- 5 MB per job; (job_id, seq) unique
```

**Implemented in M4** (schema v0.5.0): every job belongs to a change (M4 creates minimal Normal ones), and `ci_history.change_id` now references `change`. A history entry is tagged with a change when the agent sends the section for a job (`InventorySection.job_id`), or, without that, when a job whose action can change the section is running on the host or rebooted it in the last 10 minutes; a host's first inventory is never attributed. `job.state` `rejected` means the host's local policy refused the job. `job_output.seq` is the agent's chunk number (0 for notes from the server), so resent chunks are dropped; live readers follow `id`.

**Implemented in M5** (schema v0.6.0): change models, windows and freezes, patch groups and cycles, and the change columns for scheduling and review, as above. The planned `action_template` table became `change_model` itself: a model holds its action and parameters, and patch groups and stacks point at a model. A window's scope holds host-group IDs without a foreign key; groups deleted later drop out of it, and a window left with none applies to nobody. A host group used by a patch group can't be deleted.

## 5. Metrics

Plain Postgres with **native range partitioning by day**. The server creates partitions 3 days ahead and drops old ones with `DROP TABLE`, which is instant.

```sql
metric_series(id serial PK, host, kind [cpu|mem|disk|fs|net|smart|container|load],
              name text,        -- e.g. "iops_read"
              instance text,    -- device / mount / iface / container name ('' for host-level)
              UNIQUE(host, kind, name, instance))

metric_raw(ts timestamptz, series_id int, value double precision)  PARTITION BY RANGE (ts)  -- daily, kept 14 days
metric_5m (ts, series_id, avg, min, max, count)                     PARTITION BY RANGE (ts)  -- daily, kept 45 days
metric_rollup(done_until, redo_from)                                -- one row: rollup progress
```

- **Retention:** raw is kept 14 days. 5-minute rollups are kept 45 days, which covers the raw window plus the extra month. The UI picks raw data for ranges ≤ 2 days and rollups for anything longer.
- A rollup job runs every 5 min and aggregates every complete bucket since `done_until` (`INSERT … SELECT … GROUP BY`), recomputing whole buckets, so it's idempotent through `ON CONFLICT`. Late samples (an agent flushing its buffer after an outage) that land before `done_until` set `redo_from`, and the next run recomputes from there.
- Partitions are named `metric_raw_pYYYYMMDD` and cover UTC days. There's no default partition: the gateway accepts samples from the last 24 hours, and partitions exist from yesterday on.
- Charts average into buckets of 1 min (1h and 6h ranges), 2 min (24h), 15 min (7d) or 1 h (30d), keeping each line to a few hundred points.
- **Sizing:** assume 30 hosts × ~80 series × 1440 samples/day + 300 containers × 3 series × 960/day ≈ 4.3 M rows/day. At about 40 bytes per row on disk, 14 days ≈ 2.5 GB plus indexes. That's fine for a homelab Postgres. If it becomes a problem, `metric_raw` can switch to one row per (ts, host, kind) with a `real[]` array without changing the API.
- Index: `(series_id, ts)` on each partition.

## 6. Vulnerabilities

```sql
vuln_source(ecosystem PK, dump, etag, cursor, full_at, synced_at, tried_at, error, vulns)
                                          -- one OSV ecosystem release: "Ubuntu:24.04:LTS", "Rocky Linux:9"
vuln(id PK, aliases text[], summary, details, severity, cvss_score, cvss_vector, published, modified, refs jsonb)
vuln_affected(vuln_id, ecosystem, package, severity, ranges jsonb, binaries jsonb)   -- index (ecosystem, package)
host_vuln(host, vuln_id, package, arch, source, installed_ver, fixed_ver, candidate_ver, fix_available,
          severity, first_seen, PK(host, vuln_id, package, arch))
host(..., vuln_ecosystem, vulns_at)       -- what the host was matched in ('' = not covered), and when
```

**Implemented in M6** (schema v0.7.0, `internal/vuln`):

- **Coverage.** OSV covers Ubuntu (`Ubuntu:<release>[:LTS]`), Debian (`Debian:<major>`), Rocky Linux (`Rocky Linux:<major>`) and AlmaLinux (`AlmaLinux:<major>`); Baseline maps a host's os-release `ID` and `VERSION_ID` onto those. **Fedora is not an OSV ecosystem**, so Fedora and Fedora-based image hosts (Bazzite) aren't matched: they rely on the vendor's security flags on updates, and the UI says so. Ubuntu Pro and FIPS streams are not matched.
- **Sync.** Only ecosystems that enrolled hosts run are synced, once a day (a failed sync is retried after an hour; admins can sync now). The first sync, and one every 30 days, reads the distro's whole dump (`<Distro>/all.zip`, streamed to `BASELINE_DATA_DIR/tmp` and written in batches inside one transaction, so readers keep the old data until it commits). In between, the distro's `modified_id.csv` lists what changed since the newest record applied (`cursor`, less an hour of slack), and those records are fetched one by one, eight at a time; more than 1000 changes means a full read instead. ETags skip unchanged dumps. **OSV's per-release dumps (`Ubuntu:24.04:LTS/all.zip`, `Debian:12/all.zip`) stopped being updated in October 2024**, so only the distro-wide ones are read: Ubuntu's is about 780 MB and takes 2–3 minutes and ~160 MB of memory to read; Rocky Linux's is 5 MB. Several releases of one distro share a download. `BASELINE_OSV_URL` points at a mirror, or `off` stops syncing.
- **What is kept.** Records are trimmed: enumerated `versions` (most of a record's size) are dropped, since the ranges say the same; details are capped at 8 kB. Withdrawn records are removed. Ubuntu notices (`USN-*`) and Debian advisories (`DSA-`, `DLA-`, `DTSA-`) are skipped: they repeat the per-CVE records. `aliases` are the upstream CVE IDs. **Severity** is the vendor's rating where there is one (`Important:` in a Rocky summary, Ubuntu's priority), else the CVSS v3 base score's band (computed from the vector), else `unknown`; Ubuntu rates per release, kept in `vuln_affected.severity`.
- **Matching** runs after every `os`, `packages` or `updates` ingest that changed something, and for every host of an ecosystem after its data changed. Entries name source packages; an installed package matches by its source package (its own name when it has none), apt packages against dpkg ecosystems and dnf/rpm-ostree packages against rpm ones, with each distro's comparator (`internal/vercmp`). Ranges are evaluated as the OSV schema specifies (events in version order: `introduced`, `fixed`, `last_affected`). Where Ubuntu lists the fixed version of each binary package, that decides for the binary. Of several installed versions of one name and architecture (rpm kernels), only the newest is matched. `fix_available` is true when the host's pending update for the package installs at least the fixed version, so patching closes it now; `fixed_ver` empty means no fix exists yet. Matches keep `first_seen` across re-matching.
- Container image CVEs are a later milestone (see roadmap).

## 7. Alerts, notifications, auth, audit

```sql
alert_rule(id, name UNIQUE, kind, params jsonb, scope_groups uuid[], severity [info|warning|critical],
           channels uuid[], for_s, repeat_s, notify_resolved, enabled, created_by, created_at, updated_at)
alert(id, rule_id, ci_id NULL, subject, key, link, group_ids uuid[], severity, state [pending|firing|closed|resolved],
      summary, details jsonb, level, first_at, fired_at, last_at, resolved_at, notified_at,
      silence_id NULL, acked_by, acked_at, ack_comment,
      closed_by, closed_at, closed_level, closed_severity, close_comment)  -- one open per (rule, ci, key)
silence(id, rule_id NULL, ci_id NULL, host_group_id NULL, key, starts_at, ends_at, comment, created_by)
notify_channel(id, kind [matrix|ntfy], name UNIQUE, summary, config_enc, enabled, last_sent_at, last_error)
notification(id, channel_id, alert_id NULL, event [firing|reminder|resolved|test], severity, title, body, link,
             created_at, attempts, next_at NULL, sent_at, error)   -- the outbox; next_at NULL: gave up
host(..., reboot_required_since, high_security, high_security_since)
```

**Implemented in M6** (schema v0.7.0, `internal/alert`, `internal/notify`):

- **Rule kinds:** `host_offline` (minutes), `disk_full` and `inodes_full` (percent, from the latest `fs` reading of the last 15 minutes), `smart` (failing, always critical; optionally degrading, below), `failed_units` (glob excludes), `cert_expiry` (days; expired is critical; any CI, so agentless endpoints too), `reboot_pending` (days), `cve_fixable` (minimum CVE severity; one alert per host), `patch_cycle` (the latest cycle that ran failed or was blocked; optionally partial), `unplanned_change` (history entries without a change in the last N hours, agent upgrades and first inventories aside), `hardware_change` (high security hosts, below), `change_approval` (submitted for N hours) and `compose_drift` (below). The migration adds one rule of each kind without channels, `unplanned_change` turned off (hosts that patch themselves would trip it daily).
- **High security hosts** (schema v0.11.0): an admin marks a host high security on its page. The gateway then sends its agent a `Config` with `high_security` on and a 5-minute hardware interval, and again whenever the flag changes; the agent adds peripherals (USB devices, display connectors) and physical NIC link state to the hardware section and re-collects it within seconds of a kernel device or link event (docs/agent.md §1.1). The `hardware_change` rule (on by default, critical, reminding every 15 minutes) watches the host's hardware history from `high_security_since` on. Each unplanned entry (no change record; first inventories aside) is its own alert, keyed `hardware:<ci_history id>`, when it adds, removes or swaps a disk, DIMM, physical NIC, PCI or USB device (a swap is the same slot showing a new serial, WWN, model, MAC, part number or IDs), takes a physical NIC's link up, down or off, or connects, disconnects or swaps a display (`inventory.HardwareComponents`). Firmware, BIOS and microcode updates, filesystems, addresses, virtual NICs and high security collection starting or stopping don't count. Unlike other kinds, the condition holds until the alert is acknowledged, so acknowledging resolves it on the next pass; an unacknowledged one keeps firing however old. Turning the flag off resolves the host's alerts, and turning it back on starts afresh.
- **Evaluation** runs every minute. Each condition is a subject (a CI, or an object without one: a patch group, a change), a key within it (mount point, device, unit) and a summary. A rule's scope is host groups (empty: everything; agentless CIs belong to no group, so only global rules see them). A new condition opens a `pending` alert, which fires once it has held for `for_s`; firing notifies the rule's enabled channels once, and again every `repeat_s` until acknowledged. When the condition clears, a firing alert resolves (with a message if it notified and `notify_resolved`) and a pending one is dropped; a new occurrence is a new alert. A disabled rule resolves its alerts quietly; a rule whose query fails keeps them as they are. Resolved alerts are kept 90 days.
- **Silences** match by rule, CI, host group and key (empty matches anything) between two times. A silenced alert stays open and visible but doesn't notify; if it still fires when the silence ends, it notifies then. Silencing a host needs operator on it; a group, operator on the group; everything, a global operator.
- **Acknowledging** (operator on the alert's hosts) records who and why and stops reminders.
- **Compose file drift** (schema v0.28.0; rule on by default, warning): a stack whose Compose file Baseline wrote (its latest `compose_revision` with a file whose job succeeded, among those the host has reported its containers since) and whose single Compose file on the host now has another SHA-256, as the stack page's notice shows. One alert per stack and host file hash, keyed `compose:<engine>/<project>@<hash prefix>`, on the host, linking to the stack. Deploying or editing the stack through Baseline, or putting the file back, resolves it; closing it puts that version away, and a further change on the host opens a new one. Stacks Baseline never wrote, and stacks with several Compose files, aren't checked.
- **Closing** (schema v0.22.0; operator on the alert's hosts, from its page or the list) puts a pending or firing alert away for good. A `closed` alert stays open for the evaluator, so the next pass doesn't raise the condition again, but it never notifies and shows nowhere: not in the Alerts list (any view, the resolved ones included), on the host or the dashboard, or in the API. It resolves quietly when its condition ends. When the condition gets worse than when it was closed (its `level` or its severity rises), the closed alert resolves and a new one opens and fires as usual. Only `smart` sets a level so far (`compose_drift` puts the file's hash in its key instead); for `hardware_change` closing counts as acknowledging.
- **Degrading drives** (schema v0.22.0): a drive's bad sector count is its reallocated, pending and uncorrectable sectors plus NVMe media errors (`SmartDevice.BadSectors`), so a pending sector being remapped isn't a rise. `host_smart.rose_at` records when it last went up, carried across each `smart` ingest; a drive first seen with bad sectors rose then. The rule alerts on a degrading drive whose count rose within `days` (7 by default) or reached `sectors` (100 by default; 0 never), and on NVMe critical warnings and 90% wear whatever the count. The alert's level is the count, so closing one waits for the next bad sector.
- **Visibility:** `group_ids` are the subject's host groups at evaluation time; a user sees an alert with viewer on one of them, or globally.
- **Delivery:** notifications go through the outbox. The notifier tries due messages every 15 s (at once when nudged), backing off 30 s doubling to 1 h, and gives up after 16 tries (about 9 hours). A channel's messages are delivered in order: those queued behind one waiting for a retry wait too. Turning a channel off drops what it hasn't sent. Matrix messages are `m.text` with an HTML body, sent with the outbox row as transaction ID so a retry never posts twice; room aliases are resolved first. ntfy messages carry a title, a priority (critical 5, warning 4, info 3, resolved 2), tags and a click-through link to the alert. Channel settings, tokens included, are sealed with `BASELINE_SECRET_KEY`.

```sql
app_user(id, oidc_sub UNIQUE, email, name, last_login, prefs jsonb)
role_binding(id, idp_group text, role [viewer|operator|approver|admin], scope_group_id NULL)  -- NULL = global
session(id_hash PK, user_id, idp_groups text[], created_at, last_seen, expires_at, absolute_expires,
        oidc_blob_enc bytea, ip, user_agent)
api_token(id, user_id, name, hash bytea UNIQUE, roles text[], idp_groups text[], created_at, last_used, expires_at NULL, revoked_at NULL)  -- v0.13.0
saved_list(id, table_key, name, owner NULL, created_by, columns jsonb, conditions jsonb, search, sort jsonb, group_by,
           created_at, updated_at)  -- v0.15.0, the list engine (docs/lists.md); NULL owner: shared
enrollment_token(id, name, secret_hash, max_uses NULL, uses, expires_at, revoked, default_groups uuid[], created_by, created_at)
registry_cred(id, registry host UNIQUE, username, secret_enc text, created_by, created_at)  -- sealed with BASELINE_SECRET_KEY
agent_release(version, arch, sha256, signature, size, path, published_at, PK(version, arch))  -- signed over pki.ReleaseStatement

audit_log(id bigserial, at, actor, actor_ip, action, object_type, object_id, details jsonb,
          prev_hash bytea, hash bytea)        -- append-only (trigger-enforced), hash chained
```

## 8. Work items (schema v0.14.0)

Every ticket, whether an incident, a request or a story, is one `work_item` in a `project`. The bridge tables to CIs and changes are what make Baseline's work tracking part of the CMDB rather than a second tool beside it.

```sql
project(id, key text UNIQUE [A-Z][A-Z0-9]{1,9},   -- "OPS"; items are OPS-1, OPS-2, ...
        name, kind [service_desk|software], description,
        host_group_id NULL,                        -- the infrastructure a queue supports
        next_number, archived, created_at)
ticket_type(id, key UNIQUE, name, icon, description,
            base_kind [incident|request|problem|epic|story|task|bug|generic], created_at)
project_ticket_type(project_id, ticket_type_id, position, is_default,   -- one default per project
                    workflow_id,                                         -- v0.16.0, §9
                    PRIMARY KEY (project_id, ticket_type_id))

work_item(id, project_id, number, UNIQUE(project_id, number),
          ticket_type_id, status_category [todo|in_progress|done], resolution NULL,  -- set exactly when done
          workflow_version_id, status_id,         -- v0.16.0, §9; status_category follows the status
          title, description,                     -- markdown, shown as text for now
          priority [critical|high|medium|low], impact NULL, urgency NULL,  -- [high|medium|low]
          reporter NULL, assignee NULL, parent_id NULL, estimate NULL, due_at NULL,
          source [user|alert|unplanned_change|email|api], source_ref,
          custom jsonb,                           -- custom field values by field_def.key (§10)
          created_at, updated_at, resolved_at)

work_item_ci(work_item_id, ci_id, role [affected|caused_by|target])
work_item_change(work_item_id, change_id, kind [fixes|implements|caused])
work_item_link(from_id, to_id, kind [blocks|relates|duplicates|caused_by])   -- "from <kind> to"
work_item_history(id, work_item_id, at, actor, diff jsonb)                   -- shaped like ci_history
comment(id, work_item_id, author NULL, body, internal bool, at)              -- internal = work note
watcher(work_item_id, user_id)
```

- **Ticket types are shared.** Each is defined once and a project picks the ones it offers, with one default. `base_kind` tells built-in features what a type is whatever its name: SLAs and alerts will look for `incident`, parenting for `epic`. Seven types ship with the migration: Incident, Service request, Problem, Epic, Story, Task, Bug. A type's key is fixed once created.
- **Numbering** comes from `project.next_number`, taken under the project's row lock, so references never repeat. A project's key is fixed: it is in every reference. An archived project takes no new items and drops off the project list.
- **Status.** An item's status is a status of its workflow version (§9). `status_category` is kept in step with it by a trigger, since boards, SLAs and reports key off the category. A resolution (Done, Fixed, Won't do, Duplicate, Cannot reproduce) is set exactly when the category is done; `resolved_at` is set on reaching done and cleared on reopening. `project_ticket_type_group` came with custom field groups (§10).
- **Project and type** don't change on the edit form: moving an item or changing its type maps its status and fields, which a migration does (§12). A move to another project gives the item the next number there; its old reference keeps opening it (`work_item_old_ref`).
- **Parents:** any item can have a parent, in any project, as long as it isn't the item or one below it.
- **History:** creating an item, each edit (field by field), each status change and each link added or removed gets a `work_item_history` entry; link entries name the CI (`ci_id`) or change (`change_id`) so they can be hidden from people who may not see it. Comments aren't history entries; the record view's activity stream merges the two. Linking a CI to an item doesn't write `ci_history`, which records configuration changes only.
- **Record view.** An item's page has a header with the key fields (status and resolution, priority, assignee, reporter, due, updated) and the transitions out of its status, the view layout's sections (§10, less the fields the header shows), the related lists as tabs of one pane, each titled with its row count when it has rows (CIs, changes, linked items, child items, SLA clocks; `?rel=`, opening the first with rows, and kept when a link is added from it), and an activity stream: comments, work notes and history entries, newest first, filtered by `?activity=comments|notes|history`. History entries show as transitions when they carry the transition's name, as moves when they carry a `migration` marker (§12), else as field changes. The stream shows the newest 200 history entries and every comment.
- **Watchers:** the reporter, an assignee when set and anyone who comments start watching; anyone can watch or stop. Nothing is sent to watchers yet.
- **Visibility:** every role sees every work item. A linked CI or change shows on an item only to people who may see it (architecture.md §5.2), and a CI's or change's page lists the items linked to it.
- Every mutation is audited: `project.*`, `ticket_type.*`, `work_item.create|update|transition|comment|watch|unwatch|link|unlink|link_ci|unlink_ci|link_change|unlink_change`.

## 9. Workflows (schema v0.16.0)

A workflow is the statuses a work item moves through and the transitions between them. Each project sets one per ticket type (`project_ticket_type.workflow_id`). Workflows are edited in the UI (Settings > Workflows) as drafts and published as immutable versions.

```sql
workflow(id, name UNIQUE (case-insensitive), description, is_default, created_at)   -- exactly one default
workflow_version(id, workflow_id, version int, state [draft|published|retired],      -- UNIQUE(workflow_id, version)
                 created_at, created_by, published_at, published_by)                 -- at most one draft per workflow
wf_status(id, version_id, key, name, category [todo|in_progress|done], position,
          initial bool)                                    -- UNIQUE(version_id, key); one initial, never done
wf_transition(id, version_id, name, from_status NULL,     -- NULL: from any status
              to_status, position,
              conditions jsonb,      -- [{type: role, role}|{type: assignee}|{type: reporter}]: any one lets you run it
              validators jsonb,      -- [{type: field_required, field}|{type: linked_change}|{type: linked_ci}
                                     --  |{type: children_done}|{type: comment_required}]
              post_functions jsonb,  -- [{type: assign, value: actor|reporter|none}|{type: set_priority, value}]
              screen jsonb)          -- what it asks for: ["resolution", "assignee", "comment"]
```

- **Versions.** Editing a workflow makes a draft, a copy of its newest published version. Only a draft can be changed. Publishing checks the draft (it has statuses, one is initial, every status can be reached from the initial one) and makes it the version new items start on, at its initial status. Items stay on the version they started on until they are migrated (§12). Publishing, and the end of a migration, retire older versions no item is on any more.
- **Status keys** name a status across versions (`in_review` in v1 and v2), so a migration (§12) maps statuses that kept their key without asking. A key is fixed once created; the name can change.
- **Transitions.** An item offers the transitions of its version out of its status, or from any status, except one leading to the status it is in. Conditions decide who may run one (a role counts when the user holds it or one that implies it, as in architecture.md §5.2); the item page shows the others greyed out. The system may run any. Running one checks it still applies, applies the screen's input, runs the validators against the item as it will be, moves it, runs the post-functions and records one history entry (status, resolution and any fields the post-functions changed, with the transition's name). A comment from the screen is added as a comment.
- **Resolution.** A transition into a done status always sets a resolution: the one its screen asked for, else Done.
- **Default.** The migration creates the published Default workflow (To do, In progress, Done; Start progress, Stop progress, Done from any status asking for a resolution, Reopen) and puts every existing project type and item on it, status by category. A project's ticket types get the default workflow unless the project form picks another; only workflows with a published version can be picked. Changing a type's workflow affects new items only; a migration moves the rest.
- A workflow can be deleted only when it isn't the default, no project type uses it and no item is on any of its versions.
- Every change is audited: `workflow.create|update|delete|draft|edit|discard|publish` (`workflow.edit` carries what changed in the draft) and `work_item.transition`.

## 10. Custom fields, field groups and layouts (schema v0.17.0)

Fields are defined once and bundled into reusable groups; a project applies several groups to each ticket type it offers, and a layout orders core fields, groups and single fields on each screen.

```sql
field_def(id, key UNIQUE [a-z][a-z0-9_]{0,31}, label,
          type [text|textarea|number|date|datetime|bool|select|multiselect|user|ci_ref|item_ref|url],
          options jsonb,                -- select and multiselect values, in order
          description, created_at)
field_group(id, name UNIQUE (case-insensitive), description, created_at)
field_group_field(group_id, field_id, position, required, default_value jsonb NULL, PRIMARY KEY (group_id, field_id))
project_ticket_type_group(project_id, ticket_type_id, field_group_id, position)   -- FK to project_ticket_type
form_layout(id, project_id NULL,        -- NULL: the ticket type's default
            ticket_type_id, screen [create|view|transition], transition_id NULL,
            view_uses_create bool,      -- a create layout that serves view too
            sections jsonb, updated_at)
-- sections: [{title, columns: 1|2, collapsed, items: [{kind: "core", field: "priority"},
--             {kind: "group", group_id}, {kind: "field", field_id}]}]
```

- **Values** live in `work_item.custom`, keyed by the field's key: strings for text, long text, links, dates (`2026-10-01`), date-times (RFC 3339, UTC) and pick one; numbers; booleans; arrays of strings for pick several; IDs for users, CIs and work items. The server checks a value against its field before saving; a cleared value removes its key. A GIN index covers the column.
- **A field's key and type are fixed** once created, since stored values depend on them; its label, options and description can change. A field held by a group can't be deleted. Deleting a group takes it off every project; values already on items stay in `custom` and stop showing.
- **Applied fields:** a field in two applied groups shows once, required if either group requires it, with the first group's default. Defaults fill a new item's form. Removing a ticket type from a project removes its groups and layouts there; types the project keeps keep theirs.
- **Layouts inherit:** each screen uses the project's own layout, else the ticket type's default; for the view screen, a create layout marked "use this screen for view too" counts at each level. With no layout a screen shows the core fields, then a section per applied group. Core fields a layout leaves out lead in an untitled section (so the title can't be lost) and applied fields it leaves out trail in "Other", so applying a group never hides its fields. The create layout also lays out editing. Transition screens (`screen = 'transition'`, `transition_id` referencing `wf_transition`) aren't built yet; a transition belongs to one workflow version, so such a layout does too.
- **History:** changing a custom value adds a change to the item's history named by the field's label; users show by name and items by reference, while CIs stay IDs, since history is shown to people who may not see the CI.
- **Visibility:** a CI field shows the CI's name, on the item and in lists, only to people who may see the CI; others see "a CI you can't see" and may keep it but not pick it.
- **Lists:** every field registers with the list engine as `cf_<key>` (docs/lists.md).
- Every change is audited: `field.create|update|delete`, `field_group.create|update|delete`, `project.field_groups`, `layout.save|delete`.

## 11. Boards (schema v0.18.0)

A board shows work items in columns, and dropping a card on a column runs a real transition of the item's workflow (§9). Boards live under Boards in the navigation.

```sql
board(id, project_id NULL,   -- NULL: items of every project
      name UNIQUE (case-insensitive),
      columns jsonb,         -- [{name, categories: [todo|in_progress|done], statuses: [status key]}], in order
      filter jsonb,          -- the list engine's condition groups: [[{field, op, value}]], groups ORed
      created_by NULL, created_at, updated_at)
```

- **Columns.** A card goes in the first column that names its status's key, else the first that names its status's category; an item in a status no column takes doesn't show, and the board counts them. Keys name a status across versions and workflows, so a column for `in_review` holds every item in an In review status. A new board has a column per category; a board has one to 12.
- **Filter.** The board runs its filter through the list engine on the work items table (docs/lists.md), with “Project is <key>” added to every group when the board has a project, ordered by priority and capped at 500 cards. A new board shows items not done or resolved in the last 14 days. Conditions the registry no longer allows (a deleted custom field) are skipped with a warning, as on lists.
- **Moving a card.** Each card carries the transitions out of its status that its item offers (§9), the column each leads into and whether the user's conditions hold. While a card is dragged (`web/static/board.js`), a column one transition leads into is one drop zone, and a column several lead into splits into one zone per transition; zones whose conditions fail show greyed out and take no drop, and columns no transition leads into fade. A transition whose screen asks for something opens a small form first; cancelling leaves the card where it was. The move posts the item's ID (references change when an item moves project) and runs as on the item's page, validators and post-functions included, with the outcome shown on the board. Each card also has a Move menu with the same transitions, for keyboards, touch screens and browsers without the script.
- **Permissions.** Anyone with a role may make a board and see every board, as with work items; its maker and admins change or delete it.
- Every change is audited: `board.create|update|delete`; moves are `work_item.transition`.

## 12. Workflow migration (schema v0.19.0)

A migration moves work items to another workflow version, project or ticket type, mapping each item's status to one of the target version's. Admins draft and run them under Settings > Migrations; a workflow's version list and an item's Move button start one.

```sql
wf_migration(id, kind [workflow|move],
             from_version NULL, to_workflow NULL,           -- workflow: off a version, to its workflow's newest
             from_project NULL, from_type NULL,              -- move: from a project and type
             to_project NULL, to_type NULL,                  --       to another project and/or type
             to_version NULL,                                -- the target version, settled at start
             mapping jsonb,                                  -- {"<source wf_status id>": "<target status key>"}
             query text, excluded uuid[],                    -- the list engine query, less unticked items
             items uuid[],                                   -- the selection, frozen at start
             state [draft|running|done|failed], items_total, items_done, items_skipped, error,
             created_at, created_by, started_at, started_by, finished_at)
work_item_old_ref(project_id, number, work_item_id)          -- PRIMARY KEY (project_id, number)
```

- **Target.** A workflow migration takes a published version's items to the newest published version of a workflow, its own or another. A move takes the items of one project and type to another project and/or type the target project offers (not archived), on the newest published version of the workflow that pair uses. The target version is worked out again until the migration starts, so publishing meanwhile is fine.
- **Mapping.** Every status of every version the items in scope are on gets a target: the one picked, else the target status with the same key, else the first of the same category, else the initial one. The mapping is stored by target key, so it survives a new target version.
- **Items** are picked in the list engine, limited to the migration's scope (the version, or the project and type) and showing all of them by default: filter, then untick what should stay; unticking is saved as it happens. The screen counts the selection per source status. Starting freezes the selection (at most 20,000 items), less unticked items and any out of scope.
- **Running.** A runner in the server moves items in batches of 100, one transaction each, and picks up running migrations after a restart. Items that left the scope before their turn are skipped. Validators and post-functions don't run. A done target status keeps the item's resolution, or sets Done; leaving done clears it and `resolved_at`. A move to another project takes the next number there and records the old one in `work_item_old_ref`. Custom fields applied to the source project and type but not the target are dropped from `custom`. A failed batch rolls back and marks the migration failed; items moved before it stay moved.
- **History:** each item gets one entry: `changed` (ref, project, type, workflow as "Name vN", status, resolution, whichever changed), `removed` (dropped custom fields with their values, by label) and `migration: {id, kind}`.
- **Retiring.** When a migration ends, published versions no item is on any more are retired, except each workflow's newest.
- Every step is audited: `migration.create|delete|start|finish` (start carries the mapping, the item count and the dropped fields; finish what moved, what was skipped and what retired).

## 13. SLAs (schema v0.20.0)

A policy sets response and resolution targets per priority; a work item gets clocks from the policy that covers it when it is created.

```sql
sla_policy(id, name UNIQUE (case-insensitive),
           project_id NULL, ticket_type_id NULL,   -- NULL: any; UNIQUE (project_id, ticket_type_id) NULLS NOT DISTINCT
           targets jsonb,                          -- {"high": {"response": 30, "resolution": 1680}, ...} in minutes
           enabled, created_at)
sla_clock(work_item_id, metric [response|resolution], PRIMARY KEY (work_item_id, metric),
          policy_id NULL,                          -- SET NULL when the policy is deleted
          policy_name, target_minutes, started_at, target_at, met_at NULL)
```

- **Matching:** a new item takes the most specific enabled policy: its project and type, then its project, then its type, then the policy for everything. One policy per scope, so there is never a tie. A priority, or a metric, the policy sets no target for has no clock.
- **Clocks are kept by triggers** on `work_item`, so every path that changes an item (edits, transitions, bulk actions, workflow migration) keeps them right. The clocks start at `created_at`. Response is met when the item first leaves the To do category and stays met. Resolution is met when it reaches Done; reopening clears `met_at` and the clock runs on from its start. A priority change moves `target_minutes` and `target_at` of the running clocks to the policy's target for the new priority, when it sets one.
- **Moves keep their clocks.** A workflow migration (§12) that moves an item to another project or type keeps the clocks it has; the trigger only acts on status category and priority.
- **Policy changes** affect new items only: clocks copy their target and policy name. Deleting a policy leaves its clocks running. Disabling one stops it matching new items.
- **Breached** is computed, not stored: a running clock past `target_at`, or one met after it. Targets count around the clock; pausing (waiting on the customer), business hours, SLA post-functions and breach alerts are later work.
- **Where it shows:** Settings > SLAs (admins) lists and edits policies; the record view's header shows running and breached clocks, and its SLAs tab lists them all.
- Every change is audited: `sla_policy.create|update|delete`.

## 14. Workflow diagram (schema v0.21.0)

The workflow page (Settings > Workflows > a workflow) draws the version it shows as a diagram above its Statuses and Transitions tables: statuses as boxes coloured by category, transitions as arrows labelled with their names, a transition from any status as a dashed tag over the status it leads to, and a dot pointing at the initial status (`web/static/wfmap.js`, on `web/static/mapcore.js`). The page embeds the version as JSON; the diagram needs no other read.

```sql
wf_status(..., x double precision NULL, y double precision NULL)   -- where it sits on the diagram; NULL: not placed yet
```

- **Layout.** A status with no position is laid out in columns by how many transitions it is from the initial status (those only reachable from any status last), below any statuses already placed. Opening a draft saves the positions it was first shown with, so adding or moving one status never rearranges the rest; **Auto-arrange** lays everything out again. Positions are copied into a new draft with the rest of the version and, like the rest, only change on a draft (`POST /settings/workflows/{id}/layout`, `{"<status id>": [x, y]}`, admins only). Moves are layout and aren't audited.
- **Editing on a draft.** Drag a status to move it. Drag the + on a status's right edge (or shift-drag the status) onto another status to add a transition: it asks for a name and posts the same form as the Transitions table, with **More options** opening the full transition form. Double-click empty space, or **Add status**, to add a status at that spot. Click a status or a transition for its details, with Edit, Edit rules and Delete; the Delete key deletes what is selected after asking. Every change but a move goes through the page's own handlers, so it is checked and audited like one made in the tables, and comes back to the diagram.
- A published version's diagram is read-only: pan, zoom, details and **Export PNG**.

## 15. Compose stack files (schema v0.24.0)

```sql
host(..., manage_compose bool NOT NULL DEFAULT false, manage_compose_since timestamptz,
     compose_roots text[] NOT NULL DEFAULT '{}')   -- v0.26.0: where deploys go, and where stopped stacks are found
compose_stack(..., stopped bool)                    -- v0.26.0
compose_stack(..., update_groups jsonb)             -- v0.32.0: update groups set on the stack's page
job(..., update_group text, update_order int)       -- v0.32.0: a job waits for lower orders of its update group in its change

compose_revision(
  id uuid PK, host uuid FK host, engine text, project text,
  action text CHECK (action IN ('compose.deploy','compose.edit')),
  change_id uuid FK change ON DELETE CASCADE,
  compose text NULL,              -- NULL: the edit leaves the Compose file alone
  compose_sha256 text, base_sha256 text, base_compose text,   -- base_*: the file an edit replaces (masked copy, for the diff)
  env_enc text NULL,              -- the .env sealed with BASELINE_SECRET_KEY; NULL: no .env change
  env_keys text[], env_hash text, -- variable names; HMAC-SHA256 under a key derived from the secret key
  created_by uuid FK app_user, created_at timestamptz)
```

- One row per stack a `compose.deploy` or `compose.edit` change writes; the job's parameters carry its ID (`revision`), and the dispatcher reads the files from it when it sends the job. The stack's current .env, as far as Baseline knows, is the newest revision with one whose job succeeded.
- See change-management.md §5.1 for who can read `env_enc` decrypted.

## 16. Project categories and tags (schema v0.25.0)

Admins keep two lists in Settings (**Project categories**, **Project tags**), and the project form picks from them: at most one category per project, any number of tags. Both show as chips in their color, on the project page, the projects list and the work items list, where they filter, sort and group like any other field.

```sql
project_category(id, parent_id NULL → project_category, name, color, description, created_at)  -- a tree; names unique among siblings, no "/"
project_tag(id, name UNIQUE (case-insensitive), color, description, created_at)
project(..., category_id NULL → project_category ON DELETE SET NULL)
project_tag_link(project_id, tag_id)  -- PK both; cascades from either side
```

- **Colors** are `#rrggbb` or `''` for a plain chip. A category without one shows its nearest ancestor's. Chip text is black or white, whichever reads better on the color.
- **Hierarchy.** A category is shown by its path (`Infrastructure / Network`). Filtering the projects list by a category, or the work items list by **Project category**, matches its subcategories too (`list.Field.MatchExpr`); sorting and grouping go by path. A category can move under another, but not under itself or its subcategories. A category with subcategories can't be deleted; deleting a leaf leaves its projects uncategorized. Deleting a tag takes it off its projects.
- The projects page (`/projects`) is a list engine table (`project`) with Active, Archived and All views; the old `?archived=1` opens All. The audit log records each project's category path and tags on create and when they change.

## 17. UniFi consoles (schema v0.27.0)

```sql
unifi_controller(id, name, config jsonb,      -- internal/unifi.Config: url, tls_fingerprint, sites, protect
   api_key_enc,                               -- sealed with BASELINE_SECRET_KEY
   run_on → host NULL,                        -- the host whose agent polls it; NULL: the server
   enabled, network_version, protect_version, last_poll, last_ok, last_error, notes, created_at)
unifi_object(ci_id PK → ci, controller → unifi_controller ON DELETE CASCADE,
   kind [site|device|client|protect], key,    -- site ID or MAC (protect:<id> without one)
   state, state_since, firmware_updatable, present)
```

- A poll replaces what the console reported in one transaction; see integrations.md §1 for the CIs and relationships it keeps. Relationships have `attrs`: a wired client's `connected_to` carries its switch `port` and `address`, a wireless client's `via: wireless` and its `address`, and the CI page shows the port or "wireless".
- `unifi_object.state_since` moves only when the state changes, which is what `unifi_offline` alerts measure. A failed poll only sets `last_poll` and `last_error`.
- The agentless forms of network devices, NAS, UPS, printers, servers, appliances, VMs and LXC containers gained a `mac` field, which clients are matched by; `network_client`, `camera` and `protect_device` take network_device's form.

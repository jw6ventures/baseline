# Baseline design docs

Baseline is a homelab-scale IT configuration management database (CMDB), change-management system and systems-orchestration platform. Agents on Linux hosts report inventory, software versions, available updates, metrics and hardware. A central server stores this, renders a web UI and drives controlled changes back out: patching, Compose stack updates and saved scripts. It also tracks the work around the infrastructure: incidents, requests, problems and project work, linked to the CIs and changes they concern.

| Doc | Covers |
|---|---|
| [architecture.md](architecture.md) | Components, deployment, agent↔server protocol, security, dependency policy, decision log |
| [agent.md](agent.md) | Every agent collector and action, and exactly how each one talks to the OS |
| [data-model.md](data-model.md) | Postgres schema: CIs, inventory, metrics, jobs, changes, audit, work items, workflows, boards |
| [change-management.md](change-management.md) | ITIL-style change lifecycle, maintenance windows, patch groups, Compose updates, RBAC |
| [lists.md](lists.md) | The list engine: field registry, condition URLs, saved lists, inline edit and bulk actions |
| [search.md](search.md) | Global search: the Ctrl-K palette, what it finds and how it respects scope |
| [integrations.md](integrations.md) | Systems read without an agent, from the server or through one: UniFi Network and Protect |
| [api.md](api.md) | The JSON API at `/api/v1`: tokens, conventions, every endpoint, creating changes |
| [roadmap.md](roadmap.md) | Milestones, out-of-scope list, resolved questions |

Status: milestones M0 to M7 and the work-tracking features are implemented. See [roadmap.md](roadmap.md) for each milestone and what comes next.

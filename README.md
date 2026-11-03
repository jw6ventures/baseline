# Baseline

A homelab-scale CMDB, change-management system and orchestration platform
that also tracks the work around it. Agents on Linux hosts report inventory,
updates, metrics and hardware; the server stores it, renders a web UI, drives
controlled changes back out and keeps incidents, requests and project work
next to the CIs and changes they concern.

## Features

- **Inventory**: OS, hardware, packages, systemd services, listening ports,
  TLS certificates, SMART drive health and reboot-required state, with a
  change history for every host.
- **Updates and vulnerabilities**: pending updates for apt, dnf, rpm-ostree,
  flatpak and snap, matched against [OSV](https://osv.dev) CVE data.
- **Metrics**: host and container metrics with charts.
- **Containers**: Docker and Podman (rootful and rootless) containers and
  Compose stacks, with registry checks for newer images.
- **Virtualization and Kubernetes**: Proxmox VE and libvirt guests linked to
  the agents running inside them, and clusters read by a read-only cluster
  agent.
- **Change management**: package upgrades, restarts, reboots, library scripts
  and Compose updates with rollback, run as jobs inside Normal, Emergency or
  Standard changes, with maintenance windows, freezes, a calendar and patch
  groups that block and promote.
- **Alerts**: rules with silences, sent to Matrix and ntfy.
- **Work tracking**: incidents, requests, problems, stories, tasks and bugs
  in projects, with workflows, boards and SLAs, linked to the CIs and changes
  they concern.
- **Security**: Authentik (OIDC) sign-in, role bindings, a hash-chained audit
  log, agent enrollment over mTLS and signed agent self-update.

Design docs live in [docs/](docs/README.md); see
[docs/roadmap.md](docs/roadmap.md) for what's done and what's next.

## Run it

```sh
cp deploy/.env.example deploy/.env   # fill it in
docker compose -f deploy/compose.yaml up -d --build
```

That builds the image on the host. To run a published release instead, set
`BASELINE_IMAGE=ghcr.io/jw6ventures/baseline-server:v1.0.0` in `deploy/.env` and
pull:

```sh
docker compose -f deploy/compose.yaml pull
docker compose -f deploy/compose.yaml up -d
```

Pin a version rather than `latest`, so a pull never upgrades by surprise.
Pushing a tag like `v1.0.0` publishes a release: CI tests that commit, then
pushes `baseline-server` and `baseline-agent` (the cluster agent) for amd64 and
arm64 to ghcr.io, tagged with the version and `latest`. The tag is also the
version of the agents the server hands out. CI signs those agents with the
`RELEASE_SIGNING_KEY` secret; see "Release signing key" below.

No ports are published. Traefik reaches the server over the external network
named by `TRAEFIK_NETWORK`, and Postgres is on an internal-only network.
Agents reach the gateway through a Traefik TCP router with TLS passthrough on
`BASELINE_AGENT_HOST`, which needs a DNS record pointing at Traefik like the web
hostname.

### Sign-in

In Authentik, create an OAuth2/OpenID provider (confidential client) with the
redirect URI `<BASELINE_PUBLIC_URL>/auth/callback`, and attach it to an
application. The default `profile` scope mapping already sends the `groups`
claim. Members of `BASELINE_BOOTSTRAP_ADMIN_GROUP` are always admin; sign in as
one of them and add role bindings under **Settings**.

## Add hosts

**Settings → Enrollment** creates a token and shows the install command:

```sh
curl -fsSL https://baseline.example.com/install.sh | sudo sh -s -- --token baseline1....
```

It works on Ubuntu, Rocky Linux, Fedora and Bazzite. Running it again
upgrades the agent and keeps its identity. On the host, `baseline-agent collect`
prints what the agent reports (`baseline-agent collect metrics` takes one
reading), and `journalctl -u baseline-agent` shows its log. Install
smartmontools 7 or newer for drive health.

## Update agents

Each server image carries agent binaries built from the same source and
signed in CI. At startup the server publishes them as a release. **Settings →
Agents** moves the fleet to a release: connected agents update within
seconds, offline ones when they next connect. An agent checks the binary's
hash and its signature against the release keys built into it, keeps the
old binary, and rolls back by itself if the new one can't reach the server
within 5 minutes. The server never holds the signing key, so even someone
who controls the server can't push an agent binary of their own.

### Release signing key

Agents only install updates signed by a key listed in
`internal/pki/release-keys.pem`. The private key is the `RELEASE_SIGNING_KEY`
secret of the repository's `release` environment on GitHub, and the release
workflow refuses to run without it. To set one up:

```sh
openssl genpkey -algorithm ed25519 -out release.key
openssl pkey -in release.key -pubout >> internal/pki/release-keys.pem
```

Commit the public key, paste the whole of `release.key` into the secret,
and keep `release.key` offline. Images built without the secret (`make
image`) carry unsigned agents, which agents refuse; the server log says so
at startup. Rotation is described in [docs/agent.md](docs/agent.md) §5.2.

## Upgrading from jcmdb

Baseline was called jcmdb. An existing instance upgrades by changing only
its image: set `JCMDB_IMAGE=ghcr.io/jw6ventures/baseline-server:<version>`
in `deploy/.env`, pull, and start it as before. Keep your existing
`deploy/compose.yaml` and `.env`: the new compose file has a different
project name, so its Postgres volume would start out empty.

- **Environment.** Every `BASELINE_` variable falls back to its `JCMDB_`
  name, and the server log lists the old names it read. Rename them when
  convenient.
- **Agents** move to the new release the usual way (**Settings → Agents**).
  An updated agent keeps `/etc/jcmdb` and `/var/lib/jcmdb`, so the host
  keeps its identity and its Compose stacks stay where they are. Running
  the new `install.sh` on such a host replaces the `jcmdb-agent` unit and
  binary with `baseline-agent`'s and leaves those directories alone. Agents
  that haven't updated yet keep connecting: the gateway still answers to
  the old service name.
- **Cluster agents** update by changing the image. A deployment made from
  the old `jcmdb-agent.yaml` keeps working with its `JCMDB_` variables and
  its volume at `/var/lib/jcmdb`.
- **Scripts** get each value as both `BASELINE_PARAM_<NAME>` and
  `JCMDB_PARAM_<NAME>` (and `BASELINE_JOB_ID`/`JCMDB_JOB_ID`,
  `BASELINE_CHANGE`/`JCMDB_CHANGE`), so library scripts need no edits.
- **Tokens.** `jcmdb1.` enrollment tokens and `jcmdb_api_` API tokens keep
  working. Everyone signs in again once, as the session cookie is renamed.

## Containers and certificates

Agents read Docker and Podman (rootful and rootless) through their API
sockets and report containers, images and Compose stacks every minute. The
server asks each image's registry whether its tag has moved on, every 6 hours
and anonymously by default; add logins for private registries, or for Docker
Hub's higher rate limits, under **Settings → Registries**. A container's page
can turn on semver advice ("1.5.2 is out, you run 1.4.7"); Baseline never edits
Compose files. Values that look like secrets are masked in Compose files
before they leave the host. Hostnames named in containers' Traefik router
rules (`Host`, `HostSNI`, `HostRegexp`) become service endpoint CIs, linked
to the containers serving them, their stacks, and the Traefik routing them: a
Traefik container on the same host, or one on another node set on the host's
Containers tab. To have the agent start a rootful `podman.socket` that isn't
running, add `start_podman_socket = true` to `/etc/baseline/agent.conf`.

## Virtual machines and Kubernetes

Agents on Proxmox VE nodes and libvirt hosts report their guests (VMs and
LXC containers: CPUs, memory, disks, NICs and state) under **Virtual
machines**. When a guest runs an agent too, Baseline joins the two records by
the guest's DMI product UUID or a NIC's MAC address, and a guest that
migrates keeps its record.

For a Kubernetes cluster, use the published
`ghcr.io/jw6ventures/baseline-agent:<version>` or build your own with
`make image-agent`, fill in the image, gateway address, enrollment token and cluster name in
`deploy/k8s/baseline-agent.yaml`, and apply it. It reads the cluster with a
read-only service account (no Secrets or ConfigMaps) and reports nodes,
workloads, services and ingresses under **Kubernetes**; it keeps its
identity on a small volume and is updated by changing its image. Host agents
on the nodes still report each node's OS and packages, plus its runtime's
pods (with `crictl`), and nodes are linked to their hosts.

## UniFi

Add a UniFi console (UDM, UCG, Cloud Key or a self-hosted Network
application, 9.0 or newer) under **Settings → UniFi** with an API key made on
it, and Baseline reads it every 5 minutes, never changing it: adopted devices
become network device CIs with their firmware, UniFi Protect cameras become
camera CIs, and every wired client is linked to the switch port it is on (to
the host, guest or CI with its MAC, or a network client CI of its own). Pin
the console's self-signed certificate by its fingerprint. A console only one
host's network reaches is polled by that host's agent, which gets the key for
each poll and never stores it; `integrations = off` in its `agent.conf` stops
that. Alert rules can watch devices going offline and firmware updates. See
[docs/integrations.md](docs/integrations.md).

## CI map

**CI map** draws every CI you can see and every relationship between them,
whatever their status. Filters turn types, relationship kinds, statuses and
sources off and on, and limit the map to host groups or tags; a search
highlights matches. When a filter hides a CI in the middle of a chain (hide
hosts, and a container that runs on a host that runs on a VM), a dotted
edge bridges it, following relationships forwards so the containers on one
host aren't all joined to each other. Colour nodes by type, health (offline
agents, failing drives, security updates, reboots, stopped or unhealthy
containers, newer images, Kubernetes objects short of ready replicas,
firing alerts) or status. Click a CI for its details and **Focus here** to
see only what's within a few hops of it; **Export PNG** saves the current
view. The filters, focus and view are kept in the address, so a view can be
bookmarked.

## Run actions

Anything that changes a host runs as a job inside a change record:
**Install updates…** on a host's Updates tab (all, security only, or the
packages ticked), **Restart…** on a service or container, **Reboot…**, or a
script from the library (**Scripts**, written by admins; every version is
immutable and checked by its SHA-256 on the host). A change runs once someone
with the approver role on every affected host approves it; approvers can
approve their own, which the audit log records as self-approval. Jobs run one
host at a time by default and stop at the first failure; their output
streams live on the job page. Inventory changes a job causes are tagged with
its change in the host's history; the rest show as unplanned.

The host owner has the last word in `/etc/baseline/agent.conf`:
`allow_scripts = false` turns scripts off, and `allow_actions = patch,service`
(categories: `patch`, `container`, `service`, `reboot`, or `none`) limits the
rest, and `self_update = off` keeps the server from replacing the agent (update
it with `install.sh`). Restart the agent after changing them; the UI greys out
what a host refuses.

Agentless devices (switches, a NAS, a UPS, licences) are added under **CIs**,
and related to hosts and to each other. Give one a TLS endpoint and the
server checks its certificate's expiry itself.

## Windows, Standard changes and patch groups

A change can be held for a **maintenance window** (a cron start, a duration
and a time zone, for every host or some host groups) or a planned time.
**Freezes** have the same shape and hold every change but Emergency ones.
Jobs don't start unless they're likely to finish before the window closes;
hosts left over wait for the next opening, or are skipped, as the change
says. **Change models** (admins write them, approvers approve them) make
routine work Standard: changes from an approved model are approved at once.
**Patch groups** patch a host group on a schedule under a model, after the
groups that block them succeeded and soaked, installing only the package
versions those groups validated. A group with a `compose.update` model
updates the Compose stacks it lists instead, and promotes images Dev, then
Test or Staging, then Prod: a stack takes only the images its copy at the
stage before (the same app, named by the stack-name prefix) has run for the
soak time. A Compose stack can run its updates under a model and **update
itself** when its images drift (off by default). The
**Calendar** shows windows, freezes, scheduled changes and patch-group runs.

## Alerts and vulnerabilities

**Alerts** come from rules evaluated every minute: host offline, filesystem
or inodes almost full, drives failing or degrading, failed systemd units,
certificates expiring, reboots pending, fixable CVEs, failed or blocked
patch cycles, unplanned changes and changes waiting for approval. One rule of
each kind exists from the start, without channels: add a Matrix room or an
ntfy topic under **Settings → Notifications**, send it a test message, and
pick it in the rules that should notify. Rules can wait before firing,
remind until someone acknowledges, and watch only some host groups; silences
mute them for a while. Closing an alert puts it away for good: it stops
notifying and shows nowhere, and only fires again, as a new alert, if it gets
worse. Drives alert on a bad sector count that is rising, or past a threshold
set on the rule, not on a few bad sectors that stay put.

**High security** hosts, marked by an admin on the host's Settings tab, re-collect
hardware within seconds of the kernel reporting a device or network link
coming or going, with USB devices, displays and link state included. Any
disk, memory module, physical NIC, PCI or USB device added, removed or
swapped, network cable plugged or pulled, or display connected or
disconnected without a change record raises a critical alert that keeps
firing, and reminds every 15 minutes, until someone acknowledges it.

**Vulnerabilities** come from [OSV](https://osv.dev): the server downloads
the data of the distro releases its hosts run (Ubuntu, Debian, Rocky Linux,
AlmaLinux) and matches installed packages against it, marking what pending
updates fix now; a host's Vulnerabilities tab can install those updates as a
change. OSV has no Fedora data, so Fedora and Bazzite hosts aren't matched.
The first Ubuntu sync downloads about 780 MB; set `BASELINE_OSV_URL=off` to
turn syncing off, or point it at a mirror.

## API

Everything the UI shows is readable as JSON at `/api/v1`. Scripts can
also create, submit, cancel and close changes (never approve them), add
and remove manual CI relationships, and file, edit, transition, comment
on and link work items. Make a token on **Your access**, pick the roles
it may use, and send it as a bearer token:

```sh
curl -H "Authorization: Bearer baseline_api_..." https://baseline.example.com/api/v1/hosts
```

See [docs/api.md](docs/api.md) for the endpoints.

## Develop

```sh
make test       # vet + unit tests
make test-db    # also runs database tests against a throwaway Postgres on 127.0.0.1:55433
make build      # bin/baseline-server
make vendor     # after changing dependencies; vendor/ is committed
make proto      # after changing api/agent/v1/agent.proto (needs protoc)
scripts/e2e.sh  # server image + real agents in Ubuntu/Rocky/Fedora containers
                # (E2E_DOCKER=0: don't let the first agent read the local Docker socket;
                # E2E_PG_PORT: where its Postgres is published on 127.0.0.1, default 55434)
```

## License

Copyright © 2026 James Williams. Baseline is free software, licensed under the
[GNU Affero General Public License v3.0](LICENSE). Third-party components
under `vendor/` and `web/static/vendor/` keep their own licenses; see
[THIRD_PARTY.md](THIRD_PARTY.md).

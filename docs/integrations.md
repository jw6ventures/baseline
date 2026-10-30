# Integrations

Integrations read systems that run no Baseline agent and keep CIs for what they find. They only read: nothing is ever changed on the other side. Each one can be polled by the server, or, when only a host's network reaches the system, by that host's agent.

## 1. UniFi (schema v0.27.0)

Baseline reads a UniFi console (a UDM, UDM Pro, UCG or Cloud Key, or a self-hosted UniFi Network application) through its local **Integration API**, which UniFi Network 9.0 and newer serve under `/proxy/network/integration/v1`, and UniFi Protect's under `/proxy/protect/integration/v1`. It authenticates with an API key (`X-API-KEY`) made on the console under UniFi Network → Settings → Control Plane → Integrations; a key from a read-only admin is enough.

### Setting it up

Admins add consoles under **Settings → UniFi**:

- **Address**: `https://` and the console's host, nothing else.
- **API key**: sealed with `BASELINE_SECRET_KEY` like registry logins, never shown again, and kept when the form is saved without one.
- **TLS fingerprint**: consoles ship a self-signed certificate, so it can be pinned by its SHA-256 instead of verified. With no pin the certificate must verify. A poll that fails on an untrusted certificate says the fingerprint the console presented, to check against the console and paste. A pinned console that presents another certificate fails until the pin is changed.
- **Sites**: names, internal references (`default`) or IDs, comma-separated; empty reads every site.
- **Poll from**: the server, or a host whose agent reports the `unifi` capability. Hosts whose agents can't (too old, or `integrations = off`) are listed but can't be picked.
- **Read UniFi Protect too**, and **Poll it every 5 minutes** (off pauses it).

Each console is polled every 5 minutes, and at once after it is saved. **Poll now** polls it while the page waits (40 seconds at most) and says how it went. The list shows when each console was last polled, its last error, what it found, its Network and Protect versions, and notes about what could only be read in part.

### What a poll reads

`internal/unifi` makes the same `model.UniFi` snapshot whichever side polls:

- **Sites** (`/sites`), filtered by the console's site list.
- **Devices** (`/sites/{id}/devices`, then each device's details for its firmware, whether an update is offered, its features and its uplink).
- **Wired clients** (`/sites/{id}/clients`, `type` `WIRED`; wireless, VPN and Teleport clients are skipped). The Integration API doesn't say which switch port a client is on, so the classic API's `/proxy/network/api/s/{site}/stat/sta` is read too, with the same key, for `sw_mac` and `sw_port`. When that fails the clients still count, without ports, and the console's notes say why.
- **Protect** (`/meta/info`, `/cameras`, `/lights`, `/sensors`, `/chimes`, `/viewers`), when asked for. A console without Protect, or a key without access to it, leaves a note instead of failing the poll.

Lists are paged (200 at a time). MACs are normalized to lower-case `aa:bb:cc:dd:ee:ff`. Like an inventory section, the snapshot holds state, not readings: no uptimes or traffic, so a quiet network changes nothing.

### What it keeps

Every CI a console keeps has `source = unifi` and `source_key = <console id>/<key>`, and a `unifi_object` row (controller, kind, key, state, when the state last changed, whether a firmware update is offered, present):

| Found | CI | Key | Relationships |
|---|---|---|---|
| A site | `site` | `site:<id>` | |
| A device | `network_device`: vendor, model, MAC, address, firmware, state, features, `firmware_update` | `mac:<mac>` | `member_of` its site; `connected_to` its uplink device |
| A Protect camera or doorbell | `camera` | `mac:<mac>` (`protect:<id>` without one) | |
| Another Protect device | `protect_device`, with `protect_kind` | likewise | |
| A wired client | the CI that already has its MAC, or else a `network_client` | `mac:<mac>` for its own | `connected_to` the device it is plugged into, with the port and address in the relationship's attributes |

A wired client's MAC is matched, in this order, to a host by a NIC in its hardware section, to a hypervisor guest by one of its MACs, and to any other CI with a `mac` attribute (the agentless forms of network devices, NAS, UPS, printers, servers, appliances, VMs and LXC containers have a MAC field; separators and case don't matter). A Protect camera is also a wired client of the switch it is on, and gets that relationship. A client that matches nothing gets a `network_client` CI, which stays until the client is gone; if its MAC later turns up on a host (or another CI), the next poll merges the `network_client` into it: its manual relationships, changes, work items and silences move over, the `network_client` is deleted, and the audit log records a `ci.merge`.

Relationships to a console's sites and devices are rebuilt on every poll: a client that moved to another port or switch moves with it. A site, device, Protect device or client a poll no longer finds keeps its CI with `present = false`, and the missing-CI sweep turns it `missing` an hour later, like a container. Removing a console does the same to everything it kept. A failed poll changes nothing but the console's error.

UniFi CIs live on no host, so like agentless CIs they are visible to every viewer; they can't be edited by hand, and an admin can delete one once it is missing.

### Polling through an agent

The server sends the agent an `IntegrationPoll` (kind `unifi`, the console's settings as JSON, the API key, a timeout) over its mTLS stream, and the agent answers with an `IntegrationResult`: the snapshot, or the error. The agent holds the key only for the poll and never writes it to disk; the server never stores the snapshot as the host's inventory. Agents report the `unifi` capability unless `agent.conf` has `integrations = off` (`on` or `off`; anything else stops the agent from starting), and only those agents are asked. A result is accepted only from the agent the poll went to. If the agent is offline, too old, or doesn't answer within its timeout, the poll fails with that reason.

### Alerts

Two alert rule kinds:

- **UniFi device offline** (`unifi_offline`, default 10 minutes): a device (`OFFLINE`, `CONNECTION_INTERRUPTED`, `ISOLATED`) or Protect device (`DISCONNECTED`) of an enabled console has been down that long, or an enabled console couldn't be read for that long.
- **UniFi firmware update** (`unifi_firmware`): a console offers a firmware update for one of its devices.

UniFi CIs belong to no host group, so rules scoped to host groups don't see them.

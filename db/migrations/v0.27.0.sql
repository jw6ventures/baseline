-- UniFi integration (docs/integrations.md): consoles the server, or a
-- host's agent, polls through their Integration API for the Network
-- application's devices and wired clients and UniFi Protect's devices.

ALTER TABLE ci DROP CONSTRAINT IF EXISTS ci_source_check;
ALTER TABLE ci ADD CONSTRAINT ci_source_check
    CHECK (source IN ('agent', 'proxmox', 'libvirt', 'k8s', 'manual', 'unifi'));

INSERT INTO ci_type (key, label) VALUES
    ('network_client', 'Network client'), ('camera', 'Camera'), ('protect_device', 'Protect device')
ON CONFLICT DO NOTHING;

-- Agentless CIs can carry a MAC, so a wired client the console reports is
-- matched to them instead of getting a CI of its own.
UPDATE ci_type SET attr_schema = jsonb_set(attr_schema, '{fields}',
    (attr_schema->'fields') || '[{"key": "mac", "label": "MAC address", "type": "text"}]')
WHERE key IN ('network_device', 'nas', 'ups', 'printer', 'server', 'appliance', 'vm', 'lxc')
  AND attr_schema ? 'fields'
  AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(attr_schema->'fields') f WHERE f->>'key' = 'mac');

-- The new types, which can be added by hand too, take network_device's form.
UPDATE ci_type SET attr_schema = (SELECT attr_schema FROM ci_type WHERE key = 'network_device')
WHERE key IN ('network_client', 'camera', 'protect_device') AND attr_schema = '{}';

CREATE TABLE IF NOT EXISTS unifi_controller (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL CHECK (name <> ''),
    config          jsonb NOT NULL,            -- internal/unifi.Config: URL, TLS pin, sites, Protect
    api_key_enc     text NOT NULL,             -- sealed with BASELINE_SECRET_KEY
    run_on          uuid REFERENCES host(ci_id) ON DELETE SET NULL, -- NULL: the server polls it
    enabled         bool NOT NULL DEFAULT true,
    network_version text NOT NULL DEFAULT '',
    protect_version text NOT NULL DEFAULT '',
    last_poll       timestamptz,               -- last attempt
    last_ok         timestamptz,               -- last successful poll
    last_error      text NOT NULL DEFAULT '',
    notes           text NOT NULL DEFAULT '',  -- what was read only in part (Protect, switch ports)
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- The CIs a console's polls keep: its sites, devices, wired clients that
-- matched no other CI, and Protect devices. Kept with present = false when
-- gone, so the CI turns missing an hour later like a container's.
CREATE TABLE IF NOT EXISTS unifi_object (
    ci_id      uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    controller uuid NOT NULL REFERENCES unifi_controller(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('site', 'device', 'client', 'protect')),
    key        text NOT NULL,                  -- site ID, or MAC (Protect: its ID when it has no MAC)
    state      text NOT NULL DEFAULT '',       -- ONLINE, OFFLINE, CONNECTED...
    state_since timestamptz NOT NULL DEFAULT now(),
    firmware_updatable bool NOT NULL DEFAULT false,
    present    bool NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS unifi_object_controller_idx ON unifi_object (controller);

-- M6: alerting and CVEs (docs/data-model.md §6-7): notification channels,
-- alert rules, alerts and silences with a delivery outbox; OSV
-- vulnerability data and its matches against installed packages.

-- Since when a host has needed a reboot, for "reboot pending N days".
ALTER TABLE host
    ADD COLUMN reboot_required_since timestamptz,
    -- The OSV ecosystem the host's packages were last matched in ('' when
    -- OSV doesn't cover its distro), and when.
    ADD COLUMN vuln_ecosystem        text NOT NULL DEFAULT '',
    ADD COLUMN vulns_at              timestamptz;
UPDATE host SET reboot_required_since = now() WHERE reboot_required;

-- Matrix rooms and ntfy topics. config_enc is the channel's settings,
-- tokens included, sealed with BASELINE_SECRET_KEY; summary is the part that
-- is safe to show (homeserver and room, server and topic).
CREATE TABLE notify_channel (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         text NOT NULL CHECK (kind IN ('matrix', 'ntfy')),
    name         text NOT NULL UNIQUE,
    summary      text NOT NULL DEFAULT '',
    config_enc   text NOT NULL,
    enabled      bool NOT NULL DEFAULT true,
    last_sent_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    created_by   uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- A rule watches one kind of condition (internal/alert) over the hosts of
-- its scope (host groups; empty means everything) and notifies channels.
CREATE TABLE alert_rule (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE,
    kind            text NOT NULL,
    params          jsonb NOT NULL DEFAULT '{}',
    scope_groups    uuid[] NOT NULL DEFAULT '{}',
    severity        text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    channels        uuid[] NOT NULL DEFAULT '{}',
    -- The condition must hold this long before the alert fires.
    for_s           int NOT NULL DEFAULT 0 CHECK (for_s >= 0),
    -- Notify again this often while the alert fires unacknowledged; 0: once.
    repeat_s        int NOT NULL DEFAULT 0 CHECK (repeat_s >= 0),
    notify_resolved bool NOT NULL DEFAULT true,
    enabled         bool NOT NULL DEFAULT true,
    created_by      uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Silences mute notifications for matching alerts between two times. Empty
-- matchers match anything.
CREATE TABLE silence (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id       uuid REFERENCES alert_rule(id) ON DELETE CASCADE,
    ci_id         uuid REFERENCES ci(id) ON DELETE CASCADE,
    host_group_id uuid REFERENCES host_group(id) ON DELETE CASCADE,
    key           text NOT NULL DEFAULT '',
    starts_at     timestamptz NOT NULL DEFAULT now(),
    ends_at       timestamptz NOT NULL,
    comment       text NOT NULL DEFAULT '',
    created_by    uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);
CREATE INDEX silence_ends_idx ON silence (ends_at);

-- One row per occurrence: what fired (a CI, or an object without one such
-- as a change or a patch group, named by subject), and the key within it
-- (a mount point, a unit). At most one is open per rule, CI and key.
-- group_ids are the subject's host groups, for who may see it.
CREATE TABLE alert (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id     uuid NOT NULL REFERENCES alert_rule(id) ON DELETE CASCADE,
    ci_id       uuid REFERENCES ci(id) ON DELETE CASCADE,
    subject     text NOT NULL DEFAULT '',
    key         text NOT NULL DEFAULT '',
    link        text NOT NULL DEFAULT '',
    group_ids   uuid[] NOT NULL DEFAULT '{}',
    severity    text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    state       text NOT NULL CHECK (state IN ('pending', 'firing', 'resolved')),
    summary     text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}',
    first_at    timestamptz NOT NULL DEFAULT now(), -- condition first seen
    fired_at    timestamptz,
    last_at     timestamptz NOT NULL DEFAULT now(), -- condition last seen
    resolved_at timestamptz,
    notified_at timestamptz,                        -- last firing notification queued
    silence_id  uuid REFERENCES silence(id) ON DELETE SET NULL,
    acked_by    uuid REFERENCES app_user(id) ON DELETE SET NULL,
    acked_at    timestamptz,
    ack_comment text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX alert_open_idx ON alert (rule_id, COALESCE(ci_id, '00000000-0000-0000-0000-000000000000'), key)
    WHERE state <> 'resolved';
CREATE INDEX alert_ci_idx ON alert (ci_id);
CREATE INDEX alert_resolved_idx ON alert (resolved_at DESC) WHERE state = 'resolved';

-- The delivery outbox: one row per message and channel, retried with
-- backoff until it is sent or gives up (next_at NULL).
CREATE TABLE notification (
    id         bigserial PRIMARY KEY,
    channel_id uuid NOT NULL REFERENCES notify_channel(id) ON DELETE CASCADE,
    alert_id   uuid REFERENCES alert(id) ON DELETE CASCADE,
    event      text NOT NULL CHECK (event IN ('firing', 'reminder', 'resolved', 'test')),
    severity   text NOT NULL DEFAULT 'info',
    title      text NOT NULL,
    body       text NOT NULL DEFAULT '',
    link       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    attempts   int NOT NULL DEFAULT 0,
    next_at    timestamptz DEFAULT now(),
    sent_at    timestamptz,
    error      text NOT NULL DEFAULT ''
);
CREATE INDEX notification_due_idx ON notification (next_at) WHERE sent_at IS NULL AND next_at IS NOT NULL;
CREATE INDEX notification_alert_idx ON notification (alert_id);

-- Default rules, without channels: alerts show in the UI until an admin
-- adds a channel to a rule. Unplanned changes start off, since hosts that
-- patch themselves (unattended-upgrades, dnf-automatic) make them daily.
INSERT INTO alert_rule (name, kind, params, severity, for_s, enabled) VALUES
    ('Host offline', 'host_offline', '{"minutes": 10}', 'critical', 0, true),
    ('Filesystem almost full', 'disk_full', '{"percent": 90}', 'warning', 300, true),
    ('Inodes almost used up', 'inodes_full', '{"percent": 90}', 'warning', 300, true),
    ('Drive failing or degrading', 'smart', '{"degrading": true}', 'warning', 0, true),
    ('Failed systemd units', 'failed_units', '{}', 'warning', 300, true),
    ('Certificate expiring', 'cert_expiry', '{"days": 14}', 'warning', 0, true),
    ('Reboot pending', 'reboot_pending', '{"days": 7}', 'info', 0, true),
    ('Fixable CVEs', 'cve_fixable', '{"min_severity": "high"}', 'warning', 0, true),
    ('Patch cycle failed or blocked', 'patch_cycle', '{"partial": true}', 'warning', 0, true),
    ('Unplanned change', 'unplanned_change', '{"hours": 24}', 'info', 0, false),
    ('Change awaiting approval', 'change_approval', '{"hours": 4}', 'info', 0, true);

-- OSV data (docs/data-model.md §6). Each ecosystem release that enrolled
-- hosts run ("Ubuntu:24.04:LTS", "Rocky Linux:9") is synced on its own.
CREATE TABLE vuln_source (
    ecosystem text PRIMARY KEY,
    dump      text NOT NULL DEFAULT '',   -- the bucket directory the last full sync read
    etag      text NOT NULL DEFAULT '',
    cursor    timestamptz,                -- records modified up to here are applied
    full_at   timestamptz,                -- last full sync
    synced_at timestamptz,                -- last sync, full or incremental
    tried_at  timestamptz,
    error     text NOT NULL DEFAULT '',
    vulns     int NOT NULL DEFAULT 0
);

CREATE TABLE vuln (
    id          text PRIMARY KEY,                -- OSV ID: UBUNTU-CVE-..., RLSA-...
    aliases     text[] NOT NULL DEFAULT '{}',    -- upstream CVE IDs
    summary     text NOT NULL DEFAULT '',
    details     text NOT NULL DEFAULT '',
    severity    text NOT NULL DEFAULT 'unknown'
                CHECK (severity IN ('unknown', 'negligible', 'low', 'medium', 'high', 'critical')),
    cvss_score  real,
    cvss_vector text NOT NULL DEFAULT '',
    published   timestamptz,
    modified    timestamptz,
    refs        jsonb NOT NULL DEFAULT '[]'      -- [{type, url}]
);
CREATE INDEX vuln_aliases_idx ON vuln USING gin (aliases);

-- Which (source) packages a vulnerability affects in an ecosystem, as OSV
-- ranges: [[{"introduced": "0"}, {"fixed": "1.2-3"}], ...]. binaries maps
-- binary package names to their fixed versions where the ecosystem says
-- (Ubuntu), since those can differ from the source version.
CREATE TABLE vuln_affected (
    vuln_id   text NOT NULL REFERENCES vuln(id) ON DELETE CASCADE,
    ecosystem text NOT NULL,
    package   text NOT NULL,
    severity  text NOT NULL DEFAULT '',
    ranges    jsonb NOT NULL DEFAULT '[]',
    binaries  jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (vuln_id, ecosystem, package)
);
CREATE INDEX vuln_affected_pkg_idx ON vuln_affected (ecosystem, package);

-- Matches: an installed package a vulnerability affects. fix_available
-- means the version the host would upgrade to now fixes it.
CREATE TABLE host_vuln (
    host          uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    vuln_id       text NOT NULL REFERENCES vuln(id) ON DELETE CASCADE,
    package       text NOT NULL,
    arch          text NOT NULL DEFAULT '',
    source        text NOT NULL DEFAULT '',
    installed_ver text NOT NULL,
    fixed_ver     text NOT NULL DEFAULT '',     -- '' when there is no fix yet
    candidate_ver text NOT NULL DEFAULT '',
    fix_available bool NOT NULL DEFAULT false,
    severity      text NOT NULL DEFAULT 'unknown',
    first_seen    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host, vuln_id, package, arch)
);
CREATE INDEX host_vuln_vuln_idx ON host_vuln (vuln_id);
CREATE INDEX host_vuln_fixable_idx ON host_vuln (host) WHERE fix_available;

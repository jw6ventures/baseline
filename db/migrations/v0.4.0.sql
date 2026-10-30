-- M3: containers and Compose stacks, image update checks, services, ports,
-- certificates, reboot-required, and manual CIs (docs/data-model.md §1-2).

ALTER TABLE host
    ADD COLUMN reboot_required bool NOT NULL DEFAULT false,
    ADD COLUMN reboot_reasons  text[] NOT NULL DEFAULT '{}';

-- Containers are CIs keyed by host, engine and name (ci.source_key), which
-- survive Compose recreating them; the engine ID doesn't. This table is the
-- current state: a container that disappears loses its row here, and its CI
-- turns "missing" an hour later.
CREATE TABLE container (
    ci_id           uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    host            uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    engine          text NOT NULL,
    name            text NOT NULL,
    engine_id       text NOT NULL,
    image_ref       text NOT NULL,             -- as created, e.g. nginx:1.27
    image_id        text NOT NULL DEFAULT '',
    -- check_ref is image_ref normalized (docker.io/library/nginx:1.27), and
    -- image_digests the digests the image was pulled by from that
    -- repository. Both are empty for images no registry can be asked about:
    -- built locally, or pinned by digest.
    check_ref       text NOT NULL DEFAULT '',
    image_digests   text[] NOT NULL DEFAULT '{}',
    state           text NOT NULL DEFAULT '',
    health          text NOT NULL DEFAULT '',
    started_at      timestamptz,
    compose_project text NOT NULL DEFAULT '',
    compose_service text NOT NULL DEFAULT '',
    labels          jsonb NOT NULL DEFAULT '{}',
    attrs           jsonb NOT NULL DEFAULT '{}', -- the container as reported
    UNIQUE (host, engine, name)
);
CREATE INDEX container_check_ref_idx ON container (check_ref);

-- Compose stacks keep settings (pinned, semver rules), so a stack that
-- disappears keeps its row with present = false.
CREATE TABLE compose_stack (
    ci_id        uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    host         uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    engine       text NOT NULL,
    project      text NOT NULL,
    working_dir  text NOT NULL DEFAULT '',
    config_files text[] NOT NULL DEFAULT '{}',
    cli          text NOT NULL DEFAULT '',
    orphaned     bool NOT NULL DEFAULT false,
    present      bool NOT NULL DEFAULT true,
    auto_update  bool NOT NULL DEFAULT false, -- used from M5
    pinned       bool NOT NULL DEFAULT false, -- no update prompts (databases)
    semver_rules jsonb NOT NULL DEFAULT '{}', -- service -> {track, include, exclude}
    UNIQUE (host, engine, project)
);

-- What registries serve, checked by the server and shared by every host
-- running the same reference.
CREATE TABLE image_check (
    image_ref     text PRIMARY KEY,           -- normalized: docker.io/library/nginx:1.27
    registry      text NOT NULL,
    latest_digest text NOT NULL DEFAULT '',
    checked_at    timestamptz NOT NULL DEFAULT now(),
    error         text NOT NULL DEFAULT ''
);

-- Tags per repository, fetched only for repositories a semver rule watches.
CREATE TABLE registry_tags (
    repository text PRIMARY KEY,              -- docker.io/library/nginx
    tags       text[] NOT NULL DEFAULT '{}',
    checked_at timestamptz NOT NULL DEFAULT now(),
    error      text NOT NULL DEFAULT ''
);

-- A container's update status: digest drift is a registry digest for its tag
-- that the image wasn't pulled by. Pinned stacks never prompt.
CREATE VIEW container_update AS
SELECT c.ci_id, c.host, c.check_ref, ic.latest_digest, ic.checked_at, ic.error,
       COALESCE(s.pinned, false) AS pinned,
       (ic.latest_digest <> '' AND cardinality(c.image_digests) > 0
        AND NOT ic.latest_digest = ANY (c.image_digests)) AS drift
FROM container c
LEFT JOIN image_check ic ON ic.image_ref = c.check_ref
LEFT JOIN compose_stack s ON s.host = c.host AND s.engine = c.engine AND s.project = c.compose_project
                         AND c.compose_project <> '';

CREATE TABLE registry_cred (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    registry   text NOT NULL UNIQUE,          -- host, e.g. ghcr.io
    username   text NOT NULL,
    secret_enc text NOT NULL,                 -- sealed with BASELINE_SECRET_KEY
    created_by uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE host_service (
    host        uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    unit        text NOT NULL,
    description text NOT NULL DEFAULT '',
    load        text NOT NULL DEFAULT '',
    active      text NOT NULL DEFAULT '',
    sub         text NOT NULL DEFAULT '',
    enabled     text NOT NULL DEFAULT '',
    PRIMARY KEY (host, unit)
);
CREATE INDEX host_service_failed_idx ON host_service (host) WHERE active = 'failed';

CREATE TABLE host_port (
    host    uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    proto   text NOT NULL,
    addr    text NOT NULL,
    port    int NOT NULL,
    process text NOT NULL DEFAULT '',
    unit    text NOT NULL DEFAULT '',
    PRIMARY KEY (host, proto, addr, port)
);
CREATE INDEX host_port_port_idx ON host_port (port);

-- Certificates: reported by agents (files and listeners), or probed by the
-- server for agentless CIs with a TLS endpoint.
CREATE TABLE ci_cert (
    ci_id       uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    location    text NOT NULL,                -- path, tcp:<port>[/<sni>], or host:port for probes
    source      text NOT NULL CHECK (source IN ('agent', 'probe')),
    subject     text NOT NULL DEFAULT '',
    sans        text[] NOT NULL DEFAULT '{}',
    issuer      text NOT NULL DEFAULT '',
    not_before  timestamptz,
    not_after   timestamptz,
    serial      text NOT NULL DEFAULT '',
    fingerprint text NOT NULL DEFAULT '',
    self_signed bool NOT NULL DEFAULT false,
    error       text NOT NULL DEFAULT '',     -- probe failure
    checked_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ci_id, location)
);
CREATE INDEX ci_cert_not_after_idx ON ci_cert (not_after);

-- Fields of agentless CIs: {"fields": [{"key", "label", "type"}]}, types
-- text | textarea | date | url | endpoint (host:port, probed for TLS).
INSERT INTO ci_type (key, label) VALUES ('server', 'Server'), ('appliance', 'Appliance'), ('other', 'Other')
ON CONFLICT DO NOTHING;
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "vendor", "label": "Vendor", "type": "text"},
    {"key": "model", "label": "Model", "type": "text"},
    {"key": "serial", "label": "Serial number", "type": "text"},
    {"key": "firmware", "label": "Firmware", "type": "text"},
    {"key": "address", "label": "Management address", "type": "text"},
    {"key": "url", "label": "Management URL", "type": "url"},
    {"key": "tls_endpoint", "label": "TLS endpoint to check", "type": "endpoint"},
    {"key": "location", "label": "Location", "type": "text"}]}'
WHERE key IN ('network_device', 'nas', 'ups', 'printer', 'server', 'appliance');
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "url", "label": "URL", "type": "url"},
    {"key": "tls_endpoint", "label": "TLS endpoint to check", "type": "endpoint"}]}'
WHERE key = 'service_endpoint';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "vendor", "label": "Vendor", "type": "text"},
    {"key": "product", "label": "Product", "type": "text"},
    {"key": "seats", "label": "Seats", "type": "text"},
    {"key": "license_key", "label": "Reference (not the key itself)", "type": "text"},
    {"key": "expires", "label": "Expires", "type": "date"}]}'
WHERE key = 'license';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "subject", "label": "Subject", "type": "text"},
    {"key": "issuer", "label": "Issuer", "type": "text"},
    {"key": "expires", "label": "Expires", "type": "date"},
    {"key": "tls_endpoint", "label": "TLS endpoint to check", "type": "endpoint"}]}'
WHERE key = 'certificate';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "address", "label": "Address", "type": "textarea"}]}'
WHERE key = 'site';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "units", "label": "Height (U)", "type": "text"},
    {"key": "location", "label": "Location", "type": "text"}]}'
WHERE key = 'rack';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "address", "label": "Address", "type": "text"},
    {"key": "os", "label": "Operating system", "type": "text"},
    {"key": "hypervisor", "label": "Hypervisor", "type": "text"}]}'
WHERE key IN ('vm', 'lxc');
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "notes", "label": "Notes", "type": "textarea"}]}'
WHERE key = 'other';

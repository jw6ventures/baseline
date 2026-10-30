-- M1: configuration items, enrolled hosts, inventory and enrollment tokens
-- (docs/data-model.md §1-3).

CREATE TABLE ci_type (
    key         text PRIMARY KEY,
    label       text NOT NULL,
    icon        text NOT NULL DEFAULT '',
    attr_schema jsonb NOT NULL DEFAULT '{}'
);
INSERT INTO ci_type (key, label) VALUES
    ('host', 'Host'), ('vm', 'Virtual machine'), ('lxc', 'LXC container'),
    ('container', 'Container'), ('compose_stack', 'Compose stack'),
    ('k8s_cluster', 'Kubernetes cluster'), ('k8s_node', 'Kubernetes node'),
    ('k8s_workload', 'Kubernetes workload'), ('network_device', 'Network device'),
    ('ups', 'UPS'), ('nas', 'NAS'), ('printer', 'Printer'), ('license', 'License'),
    ('service_endpoint', 'Service endpoint'), ('certificate', 'Certificate'),
    ('site', 'Site'), ('rack', 'Rack');

CREATE TABLE ci (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type        text NOT NULL REFERENCES ci_type(key),
    name        text NOT NULL,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'planned', 'missing')),
    source      text NOT NULL CHECK (source IN ('agent', 'proxmox', 'libvirt', 'k8s', 'manual')),
    source_key  text, -- natural key from discovery; NULL for manual CIs and agent hosts (see host)
    owner       text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    tags        text[] NOT NULL DEFAULT '{}',
    attrs       jsonb NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source, source_key)
);
CREATE INDEX ci_type_idx ON ci (type);

CREATE TABLE ci_relationship (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    from_ci uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    to_ci   uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    kind    text NOT NULL CHECK (kind IN ('runs_on', 'hosted_by', 'member_of', 'depends_on', 'connected_to', 'contains', 'uses')),
    source  text NOT NULL CHECK (source IN ('discovered', 'manual')),
    attrs   jsonb NOT NULL DEFAULT '{}',
    UNIQUE (from_ci, to_ci, kind)
);

-- Field-level change history. change_id is set once jobs exist (M4); until
-- then every entry is an unplanned change.
CREATE TABLE ci_history (
    id        bigserial PRIMARY KEY,
    ci_id     uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text NOT NULL, -- agent:<uuid> | user:<uuid> | system
    change_id uuid,
    section   text NOT NULL,
    diff      jsonb NOT NULL
);
CREATE INDEX ci_history_ci_idx ON ci_history (ci_id, at DESC);

CREATE TABLE host_group_member (
    group_id uuid NOT NULL REFERENCES host_group(id) ON DELETE CASCADE,
    ci_id    uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, ci_id)
);
CREATE INDEX host_group_member_ci_idx ON host_group_member (ci_id);

CREATE TABLE enrollment_token (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    secret_hash    bytea NOT NULL UNIQUE,
    max_uses       int CHECK (max_uses > 0), -- NULL = unlimited
    uses           int NOT NULL DEFAULT 0,
    expires_at     timestamptz NOT NULL,
    revoked        bool NOT NULL DEFAULT false,
    default_groups uuid[] NOT NULL DEFAULT '{}', -- host groups new hosts join
    created_by     uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- One row per enrolled agent, 1:1 with a ci of type host.
CREATE TABLE host (
    ci_id               uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    agent_id            uuid NOT NULL UNIQUE,
    cert_serial         text NOT NULL,
    prev_cert_serial    text NOT NULL DEFAULT '', -- still accepted until the agent uses the new one
    cert_not_after      timestamptz NOT NULL,
    revoked             bool NOT NULL DEFAULT false,
    revoked_at          timestamptz,
    machine_id          text NOT NULL DEFAULT '',
    dmi_uuid            text NOT NULL DEFAULT '',
    duplicate_identity  bool NOT NULL DEFAULT false, -- another host reports the same machine-id or DMI UUID
    hostname            text NOT NULL DEFAULT '',
    fqdn                text NOT NULL DEFAULT '',
    os_id               text NOT NULL DEFAULT '',
    os_version          text NOT NULL DEFAULT '',
    os_pretty           text NOT NULL DEFAULT '',
    kernel              text NOT NULL DEFAULT '',
    arch                text NOT NULL DEFAULT '',
    agent_version       text NOT NULL DEFAULT '',
    capabilities        text[] NOT NULL DEFAULT '{}',
    local_policy        jsonb NOT NULL DEFAULT '{}',
    connected           bool NOT NULL DEFAULT false,
    last_connect        timestamptz,
    last_seen           timestamptz,
    boot_id             text NOT NULL DEFAULT '',
    boot_time           timestamptz,
    enrolled_at         timestamptz NOT NULL DEFAULT now(),
    enrollment_token_id uuid REFERENCES enrollment_token(id) ON DELETE SET NULL
);
CREATE INDEX host_machine_id_idx ON host (machine_id) WHERE machine_id <> '';
CREATE INDEX host_dmi_uuid_idx ON host (dmi_uuid) WHERE dmi_uuid <> '';

-- The latest copy of each inventory section, as the agent sent it. Typed
-- tables (host_package...) are projections of it for queries.
CREATE TABLE host_inventory (
    host         uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    section      text NOT NULL,
    content_hash text NOT NULL,
    data         jsonb NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host, section)
);

-- No primary key: rpm can install several versions of one name.arch (kernels).
CREATE TABLE host_package (
    host    uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    manager text NOT NULL,
    name    text NOT NULL,
    epoch   text NOT NULL DEFAULT '',
    version text NOT NULL,
    release text NOT NULL DEFAULT '',
    arch    text NOT NULL DEFAULT '',
    source  text NOT NULL DEFAULT '',
    repo    text NOT NULL DEFAULT '',
    layered bool NOT NULL DEFAULT false
);
CREATE INDEX host_package_host_idx ON host_package (host);
CREATE INDEX host_package_name_idx ON host_package (name);

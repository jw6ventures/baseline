-- M2: available updates, SMART, metrics and agent self-update
-- (docs/data-model.md §2, §5, §7).

-- Self-update is desired state: an admin sets the version a host should run,
-- and the gateway sends it whenever the agent connects on another version.
ALTER TABLE host
    ADD COLUMN agent_arch          text NOT NULL DEFAULT '', -- GOARCH, from Hello
    ADD COLUMN agent_update_target text NOT NULL DEFAULT '', -- '' = no update wanted
    ADD COLUMN agent_update_at     timestamptz,              -- when the target was set
    ADD COLUMN agent_update_error  text NOT NULL DEFAULT ''; -- why the last attempt failed

-- What upgrading would install now: a projection of the "updates" section.
CREATE TABLE host_update (
    host          uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    manager       text NOT NULL,
    name          text NOT NULL,
    arch          text NOT NULL DEFAULT '',
    installed_ver text NOT NULL DEFAULT '',
    candidate_ver text NOT NULL,
    repo          text NOT NULL DEFAULT '',
    security      bool NOT NULL DEFAULT false,
    advisories    text[] NOT NULL DEFAULT '{}',
    image         bool NOT NULL DEFAULT false, -- a whole OS image (rpm-ostree)
    first_seen    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX host_update_host_idx ON host_update (host);
CREATE INDEX host_update_security_idx ON host_update (host) WHERE security;
CREATE INDEX host_update_name_idx ON host_update (name);

-- Drive health: a projection of the "smart" section.
CREATE TABLE host_smart (
    host      uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    device    text NOT NULL,
    model     text NOT NULL DEFAULT '',
    serial    text NOT NULL DEFAULT '',
    passed    bool,                  -- NULL: the drive reports no health status
    degrading bool NOT NULL DEFAULT false,
    attrs     jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (host, device)
);

-- Metrics (docs/data-model.md §5): native range partitioning by day, UTC.
-- The server creates partitions ahead and drops expired ones; there is no
-- default partition, so rows outside the created range are refused.
CREATE TABLE metric_series (
    id       serial PRIMARY KEY,
    host     uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    kind     text NOT NULL,
    name     text NOT NULL,
    instance text NOT NULL DEFAULT '',
    UNIQUE (host, kind, name, instance)
);

-- The key makes a resent batch a no-op.
CREATE TABLE metric_raw (
    ts        timestamptz NOT NULL,
    series_id int NOT NULL,
    value     double precision NOT NULL,
    PRIMARY KEY (series_id, ts)
) PARTITION BY RANGE (ts);

CREATE TABLE metric_5m (
    ts        timestamptz NOT NULL, -- bucket start
    series_id int NOT NULL,
    avg       double precision NOT NULL,
    min       double precision NOT NULL,
    max       double precision NOT NULL,
    count     int NOT NULL,
    PRIMARY KEY (series_id, ts)
) PARTITION BY RANGE (ts);

-- Rollup progress. done_until is the end of the last bucket rolled up;
-- redo_from is set when late samples (an agent flushing its buffer after an
-- outage) land before it, so those buckets are recomputed.
CREATE TABLE metric_rollup (
    id         bool PRIMARY KEY DEFAULT true CHECK (id),
    done_until timestamptz,
    redo_from  timestamptz
);
INSERT INTO metric_rollup DEFAULT VALUES;

-- Signed agent binaries under /data/releases. The server publishes the ones
-- built into its image at startup and keeps a few older versions.
CREATE TABLE agent_release (
    version      text NOT NULL,
    arch         text NOT NULL,
    sha256       text NOT NULL,
    signature    bytea NOT NULL, -- ed25519 over pki.ReleaseStatement
    size         bigint NOT NULL,
    path         text NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (version, arch)
);

-- M4: jobs, the script library and minimal Normal changes
-- (docs/data-model.md §4, docs/change-management.md).

-- The script library. A version is immutable once saved and identified by
-- the SHA-256 of its body; what it runs with (interpreter, parameters, risk)
-- belongs to the version, so editing any of it makes a new one.
CREATE TABLE script (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    archived    bool NOT NULL DEFAULT false,
    created_by  uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE script_version (
    script_id   uuid NOT NULL REFERENCES script(id) ON DELETE CASCADE,
    version     int NOT NULL CHECK (version > 0),
    interpreter text NOT NULL,
    params      jsonb NOT NULL DEFAULT '[]', -- [{name, type, required, pattern, help}]
    risk        text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    body        text NOT NULL,
    sha256      text NOT NULL,
    notes       text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (script_id, version)
);

CREATE FUNCTION script_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'script versions are immutable';
END;
$$;
CREATE TRIGGER script_version_no_update BEFORE UPDATE ON script_version
    FOR EACH ROW EXECUTE FUNCTION script_version_immutable();

-- Change records. M4 uses a minimal Normal change: submitted, approved
-- (self-approval allowed and flagged), then in progress until its jobs end.
-- The states of the full lifecycle (M5) are allowed already.
CREATE TABLE change (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    number          bigserial UNIQUE, -- shown as CHG-000123
    kind            text NOT NULL DEFAULT 'normal' CHECK (kind IN ('standard', 'normal', 'emergency')),
    title           text NOT NULL,
    description     text NOT NULL DEFAULT '',
    justification   text NOT NULL DEFAULT '',
    risk            text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    impact          text NOT NULL DEFAULT 'low' CHECK (impact IN ('low', 'medium', 'high')),
    -- What runs where: [{action, params, hosts}]. The jobs are its expansion.
    implementation_plan jsonb NOT NULL DEFAULT '[]',
    backout_plan    text NOT NULL DEFAULT '',
    test_plan       text NOT NULL DEFAULT '',
    state           text NOT NULL CHECK (state IN ('draft', 'submitted', 'approved', 'scheduled', 'in_progress',
                        'implemented', 'failed', 'rolled_back', 'review', 'closed', 'rejected', 'cancelled')),
    requested_by    uuid REFERENCES app_user(id) ON DELETE SET NULL,
    required_approvals int NOT NULL DEFAULT 1 CHECK (required_approvals > 0),
    concurrency     int NOT NULL DEFAULT 1 CHECK (concurrency > 0), -- hosts at a time
    stop_on_failure bool NOT NULL DEFAULT true,
    planned_start   timestamptz,
    planned_end     timestamptz,
    approved_at     timestamptz,
    actual_start    timestamptz,
    actual_end      timestamptz,
    outcome         text CHECK (outcome IN ('success', 'partial', 'failed', 'rolled_back', 'cancelled')),
    review_notes    text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX change_state_idx ON change (state);

CREATE TABLE change_approval (
    change_id     uuid NOT NULL REFERENCES change(id) ON DELETE CASCADE,
    approver      uuid NOT NULL REFERENCES app_user(id),
    decision      text NOT NULL CHECK (decision IN ('approve', 'reject')),
    comment       text NOT NULL DEFAULT '',
    self_approved bool NOT NULL DEFAULT false,
    at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (change_id, approver)
);

-- Affected CIs, filled from the targets.
CREATE TABLE change_ci (
    change_id uuid NOT NULL REFERENCES change(id) ON DELETE CASCADE,
    ci_id     uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    PRIMARY KEY (change_id, ci_id)
);
CREATE INDEX change_ci_ci_idx ON change_ci (ci_id);

ALTER TABLE ci_history ADD CONSTRAINT ci_history_change_fk
    FOREIGN KEY (change_id) REFERENCES change(id) ON DELETE SET NULL;

-- One action on one host. The id is the idempotency key the agent sees.
CREATE TABLE job (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    change_id      uuid NOT NULL REFERENCES change(id) ON DELETE CASCADE,
    seq            int NOT NULL DEFAULT 0, -- dispatch order within the change
    host           uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    action         text NOT NULL,
    params         jsonb NOT NULL DEFAULT '{}',
    script_id      uuid,
    script_version int,
    timeout_s      int NOT NULL CHECK (timeout_s > 0),
    -- queued: waiting for its turn or its host; dispatched: sent, not yet
    -- acknowledged; running (also while the host reboots).
    state          text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'dispatched', 'running', 'succeeded',
                       'failed', 'cancelled', 'timed_out', 'rejected', 'rolled_back')),
    awaiting_reboot bool NOT NULL DEFAULT false,
    queued_at      timestamptz NOT NULL DEFAULT now(),
    dispatched_at  timestamptz,
    started_at     timestamptz,
    finished_at    timestamptz,
    exit_code      int,
    result         jsonb,
    error          text NOT NULL DEFAULT '',
    output_bytes   int NOT NULL DEFAULT 0,
    requested_by   uuid REFERENCES app_user(id) ON DELETE SET NULL,
    FOREIGN KEY (script_id, script_version) REFERENCES script_version(script_id, version)
);
CREATE INDEX job_change_idx ON job (change_id, seq);
CREATE INDEX job_host_idx ON job (host, queued_at DESC);
CREATE INDEX job_open_idx ON job (state) WHERE state IN ('queued', 'dispatched', 'running');

-- Output as the agent streamed it, capped per job (internal/store).
CREATE TABLE job_output (
    id     bigserial PRIMARY KEY, -- arrival order, which live readers follow
    job_id uuid NOT NULL REFERENCES job(id) ON DELETE CASCADE,
    seq    bigint NOT NULL, -- the agent's chunk number; 0 for notes from the server
    stream text NOT NULL CHECK (stream IN ('stdout', 'stderr', 'info')),
    at     timestamptz NOT NULL DEFAULT now(),
    chunk  text NOT NULL
);
CREATE UNIQUE INDEX job_output_seq_idx ON job_output (job_id, seq) WHERE seq > 0;
CREATE INDEX job_output_id_idx ON job_output (job_id, id);

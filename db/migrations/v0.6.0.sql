-- M5: change management (docs/change-management.md): Standard, Normal and
-- Emergency changes with the full lifecycle, change models, maintenance
-- windows and freezes, patch groups and their cycles, Compose updates.

-- Maintenance windows and freezes: a cron start, a duration and a time
-- zone, global or scoped to host groups. A freeze has the same shape and
-- blocks every change but Emergency ones in its scope.
CREATE TABLE maintenance_window (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    description  text NOT NULL DEFAULT '',
    kind         text NOT NULL CHECK (kind IN ('window', 'freeze')),
    cron         text NOT NULL,
    duration_s   int NOT NULL CHECK (duration_s > 0),
    tz           text NOT NULL DEFAULT 'UTC',
    -- Host groups it applies to; empty means every host. Groups that are
    -- deleted later drop out of the scope (internal/store).
    scope_groups uuid[] NOT NULL DEFAULT '{}',
    active       bool NOT NULL DEFAULT true,
    created_by   uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- A Standard change model: an action, pre-approved once by an approver.
-- Each change made from it is approved automatically. Editing it needs
-- approval again. The targets are chosen per change; for compose.* the
-- stack is too, so params holds only the rest (health_timeout).
CREATE TABLE change_model (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL UNIQUE,
    description    text NOT NULL DEFAULT '',
    action         text NOT NULL,
    params         jsonb NOT NULL DEFAULT '{}',
    script_id      uuid,
    script_version int,
    risk           text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'retired')),
    requested_by   uuid REFERENCES app_user(id) ON DELETE SET NULL,
    approved_by    uuid REFERENCES app_user(id) ON DELETE SET NULL,
    approved_at    timestamptz,
    self_approved  bool NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (script_id, script_version) REFERENCES script_version(script_id, version)
);

ALTER TABLE change
    ADD COLUMN model_id       uuid REFERENCES change_model(id) ON DELETE SET NULL,
    ADD COLUMN window_id      uuid REFERENCES maintenance_window(id) ON DELETE SET NULL,
    -- End of the window opening a change in progress runs in: no job starts
    -- that wouldn't finish before it (action.Expected).
    ADD COLUMN window_ends_at timestamptz,
    -- What happens to hosts left when the window closes: they wait for the
    -- next opening, or the change fails.
    ADD COLUMN on_window_end  text NOT NULL DEFAULT 'carry_over' CHECK (on_window_end IN ('carry_over', 'fail')),
    -- Why an approved change is waiting (a freeze, the next opening).
    ADD COLUMN schedule_note  text NOT NULL DEFAULT '',
    ADD COLUMN submitted_at   timestamptz,
    ADD COLUMN closed_at      timestamptz,
    ADD COLUMN reviewed_by    uuid REFERENCES app_user(id) ON DELETE SET NULL;
CREATE INDEX change_planned_idx ON change (planned_start) WHERE state IN ('approved', 'scheduled');
UPDATE change SET submitted_at = created_at WHERE state <> 'draft';

-- Patch groups: a host group, a schedule and a policy, run as Standard
-- changes from their change model (docs/change-management.md §4).
CREATE TABLE patch_group (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL UNIQUE,
    description       text NOT NULL DEFAULT '',
    host_group_id     uuid NOT NULL REFERENCES host_group(id) ON DELETE RESTRICT,
    schedule_cron     text NOT NULL,
    tz                text NOT NULL DEFAULT 'UTC',
    window_id         uuid REFERENCES maintenance_window(id) ON DELETE SET NULL,
    change_model_id   uuid NOT NULL REFERENCES change_model(id) ON DELETE RESTRICT,
    blocked_by        uuid[] NOT NULL DEFAULT '{}',
    soak_s            int NOT NULL DEFAULT 0 CHECK (soak_s >= 0),
    success_threshold int NOT NULL DEFAULT 100 CHECK (success_threshold BETWEEN 1 AND 100),
    promote_validated bool NOT NULL DEFAULT true,
    concurrency       int NOT NULL DEFAULT 1 CHECK (concurrency > 0),
    stop_on_failure   bool NOT NULL DEFAULT true,
    enabled           bool NOT NULL DEFAULT true,
    -- The scheduled time of the last run the scheduler handled, so a run is
    -- never started twice.
    last_run_at       timestamptz,
    created_by        uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE patch_cycle (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_group_id uuid NOT NULL REFERENCES patch_group(id) ON DELETE CASCADE,
    change_id      uuid REFERENCES change(id) ON DELETE SET NULL,
    scheduled_for  timestamptz NOT NULL,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    result         text NOT NULL DEFAULT 'running' CHECK (result IN ('running', 'success', 'partial', 'failed',
                       'blocked', 'skipped', 'cancelled')),
    reason         text NOT NULL DEFAULT '',
    hosts          int NOT NULL DEFAULT 0, -- hosts with a job
    succeeded      int NOT NULL DEFAULT 0,
    -- What each host was to install: [{host, hostname, os, packages, deferred}].
    planned        jsonb NOT NULL DEFAULT '[]',
    -- package@version pairs that succeeded, for groups this one blocks:
    -- [{os, manager, name, arch, version}].
    validated_set  jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX patch_cycle_group_idx ON patch_cycle (patch_group_id, started_at DESC);
CREATE UNIQUE INDEX patch_cycle_change_idx ON patch_cycle (change_id);

-- Compose stacks: the Standard change model their updates run under (manual
-- ones too, when set; auto-update needs it) and their own window.
ALTER TABLE compose_stack
    ADD COLUMN change_model_id uuid REFERENCES change_model(id) ON DELETE SET NULL,
    ADD COLUMN window_id       uuid REFERENCES maintenance_window(id) ON DELETE SET NULL;

-- SLA policies and clocks on work items (docs/data-model.md §13).
--
-- A policy sets response and resolution targets per priority, in minutes,
-- for a project, a ticket type, both or everything. A new item takes the
-- most specific enabled policy: project and type, then project, then type,
-- then global. Its clocks start when it is created and keep their targets
-- when the policy changes later.
--
-- Triggers keep the clocks in step with the item, whatever changes it (an
-- edit, a transition, a bulk action, a workflow migration):
--   response    met when the item first leaves the To Do category
--   resolution  met when it reaches Done; reopening runs it again
-- A priority change moves the targets of the clocks still running.
-- Pausing (for example while waiting on the customer) is not supported yet.
--
-- Not in db/db.sql: these tables reference project, ticket_type and
-- work_item, which only the migrations create.

CREATE TABLE sla_policy (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    project_id     uuid REFERENCES project(id) ON DELETE CASCADE,     -- NULL: every project
    ticket_type_id uuid REFERENCES ticket_type(id) ON DELETE CASCADE, -- NULL: every type
    -- {"critical": {"response": 15, "resolution": 240}, "high": {...}}; a
    -- missing priority or metric has no clock.
    targets        jsonb NOT NULL DEFAULT '{}',
    enabled        bool NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);
-- One policy per scope, so the most specific match is never a tie.
CREATE UNIQUE INDEX sla_policy_scope_idx ON sla_policy (project_id, ticket_type_id) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX sla_policy_name_idx ON sla_policy (lower(name));

CREATE TABLE sla_clock (
    work_item_id   uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    metric         text NOT NULL CHECK (metric IN ('response', 'resolution')),
    policy_id      uuid REFERENCES sla_policy(id) ON DELETE SET NULL,
    policy_name    text NOT NULL,           -- as it was when the clock started
    target_minutes int NOT NULL CHECK (target_minutes > 0),
    started_at     timestamptz NOT NULL,
    target_at      timestamptz NOT NULL,    -- started_at + target_minutes
    met_at         timestamptz,             -- NULL while running
    PRIMARY KEY (work_item_id, metric)
);
CREATE INDEX sla_clock_running_idx ON sla_clock (target_at) WHERE met_at IS NULL;

-- sla_target is a policy's target in minutes for a priority and metric,
-- NULL when it sets none.
CREATE FUNCTION sla_target(targets jsonb, priority text, metric text) RETURNS int LANGUAGE sql IMMUTABLE AS $$
    SELECT NULLIF((targets -> priority ->> metric)::int, 0)
$$;

CREATE FUNCTION work_item_sla_start() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    pol sla_policy;
    m   text;
    min int;
BEGIN
    SELECT * INTO pol FROM sla_policy p
    WHERE p.enabled AND (p.project_id IS NULL OR p.project_id = NEW.project_id)
      AND (p.ticket_type_id IS NULL OR p.ticket_type_id = NEW.ticket_type_id)
    ORDER BY p.project_id IS NULL, p.ticket_type_id IS NULL LIMIT 1;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    FOREACH m IN ARRAY ARRAY['response', 'resolution'] LOOP
        min := sla_target(pol.targets, NEW.priority, m);
        CONTINUE WHEN min IS NULL;
        INSERT INTO sla_clock (work_item_id, metric, policy_id, policy_name, target_minutes, started_at, target_at, met_at)
        VALUES (NEW.id, m, pol.id, pol.name, min, NEW.created_at, NEW.created_at + make_interval(mins => min),
                CASE WHEN (m = 'response' AND NEW.status_category <> 'todo') OR NEW.status_category = 'done'
                     THEN NEW.created_at END);
    END LOOP;
    RETURN NULL;
END $$;

CREATE TRIGGER work_item_sla_start AFTER INSERT ON work_item
    FOR EACH ROW EXECUTE FUNCTION work_item_sla_start();

CREATE FUNCTION work_item_sla_track() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status_category <> 'todo' THEN
        UPDATE sla_clock SET met_at = now() WHERE work_item_id = NEW.id AND metric = 'response' AND met_at IS NULL;
    END IF;
    IF NEW.status_category = 'done' THEN
        UPDATE sla_clock SET met_at = now() WHERE work_item_id = NEW.id AND metric = 'resolution' AND met_at IS NULL;
    ELSIF OLD.status_category = 'done' THEN
        UPDATE sla_clock SET met_at = NULL WHERE work_item_id = NEW.id AND metric = 'resolution';
    END IF;
    IF NEW.priority IS DISTINCT FROM OLD.priority THEN
        UPDATE sla_clock c SET target_minutes = t.min, target_at = c.started_at + make_interval(mins => t.min)
        FROM (SELECT c2.metric, sla_target(p.targets, NEW.priority, c2.metric) AS min
              FROM sla_clock c2 JOIN sla_policy p ON p.id = c2.policy_id WHERE c2.work_item_id = NEW.id) t
        WHERE c.work_item_id = NEW.id AND c.metric = t.metric AND c.met_at IS NULL AND t.min IS NOT NULL;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER work_item_sla_track AFTER UPDATE ON work_item
    FOR EACH ROW WHEN (OLD.status_category IS DISTINCT FROM NEW.status_category OR OLD.priority IS DISTINCT FROM NEW.priority)
    EXECUTE FUNCTION work_item_sla_track();

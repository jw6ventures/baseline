-- Workflow migration (docs/data-model.md §12): moving work items off a
-- workflow version, or to another project or ticket type, with their
-- statuses mapped. An admin builds a migration as a draft, then runs it as
-- a background job; each item gets a history entry.
--
-- Not in db/db.sql: these tables reference work items and workflows, which
-- only the migrations create.

-- kind 'workflow' moves the items of from_version to the newest published
-- version of to_workflow. kind 'move' moves the items of from_project's
-- from_type to to_project and to_type, onto the newest published version of
-- the workflow that pair uses. Either way the target version is settled
-- when the migration starts (to_version).
--
-- mapping: {"<source wf_status id>": "<target status key>"}. Keys name a
-- status across versions, so a mapping survives a new target version.
-- query: the list engine query that picked the items (internal/list);
-- excluded: ids unticked from it. items: the selection, frozen at start.
CREATE TABLE wf_migration (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          text NOT NULL CHECK (kind IN ('workflow', 'move')),
    from_version  uuid REFERENCES workflow_version(id) ON DELETE CASCADE,
    to_workflow   uuid REFERENCES workflow(id) ON DELETE CASCADE,
    from_project  uuid REFERENCES project(id) ON DELETE CASCADE,
    from_type     uuid REFERENCES ticket_type(id) ON DELETE CASCADE,
    to_project    uuid REFERENCES project(id) ON DELETE CASCADE,
    to_type       uuid REFERENCES ticket_type(id) ON DELETE CASCADE,
    to_version    uuid REFERENCES workflow_version(id) ON DELETE SET NULL,
    mapping       jsonb NOT NULL DEFAULT '{}',
    query         text NOT NULL DEFAULT '',
    excluded      uuid[] NOT NULL DEFAULT '{}',
    items         uuid[] NOT NULL DEFAULT '{}',
    state         text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'running', 'done', 'failed')),
    items_total   int NOT NULL DEFAULT 0,
    items_done    int NOT NULL DEFAULT 0,
    items_skipped int NOT NULL DEFAULT 0, -- left the scope before their turn
    error         text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text NOT NULL, -- user:<uuid> | system
    started_at    timestamptz,
    started_by    text,
    finished_at   timestamptz,
    CHECK (kind <> 'workflow' OR (from_version IS NOT NULL AND to_workflow IS NOT NULL)),
    CHECK (kind <> 'move' OR (from_project IS NOT NULL AND from_type IS NOT NULL AND to_project IS NOT NULL AND to_type IS NOT NULL)),
    CHECK ((state = 'draft') = (started_at IS NULL))
);
CREATE INDEX wf_migration_running_idx ON wf_migration (started_at) WHERE state = 'running';

-- References items had before a move to another project, so OPS-42 still
-- opens the item that is now DEV-7. Numbers are never reused, so an old
-- reference can't collide with a new item.
CREATE TABLE work_item_old_ref (
    project_id   uuid NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    number       int NOT NULL,
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, number)
);
CREATE INDEX work_item_old_ref_item_idx ON work_item_old_ref (work_item_id);

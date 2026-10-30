-- Workflows (docs/data-model.md §9): the statuses a work item moves through
-- and the transitions between them, edited as drafts and published as
-- immutable versions. An item stays on the version it started on until it
-- is migrated (#9).
--
-- work_item.status_category stays, kept in step with the item's status by a
-- trigger, since boards, SLAs and reports key off the category.
--
-- Not in db/db.sql: these tables reference work_item, which only the
-- migrations create.

CREATE TABLE workflow (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_default  bool NOT NULL DEFAULT false, -- what a project's ticket types get unless told otherwise
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX workflow_name_idx ON workflow (lower(name));
CREATE UNIQUE INDEX workflow_default_idx ON workflow ((true)) WHERE is_default;

-- A draft is edited in place; publishing freezes it. New items start on a
-- workflow's newest published version.
CREATE TABLE workflow_version (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id  uuid NOT NULL REFERENCES workflow(id) ON DELETE CASCADE,
    version      int NOT NULL CHECK (version > 0),
    state        text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'retired')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text NOT NULL,          -- user:<uuid> | system
    published_at timestamptz,
    published_by text,
    UNIQUE (workflow_id, version),
    CHECK ((state = 'draft') = (published_at IS NULL))
);
CREATE UNIQUE INDEX workflow_version_draft_idx ON workflow_version (workflow_id) WHERE state = 'draft';

-- key names a status across versions, so a migration maps In review to In
-- review without asking. Exactly one status of a published version is
-- initial: where new items start.
CREATE TABLE wf_status (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id uuid NOT NULL REFERENCES workflow_version(id) ON DELETE CASCADE,
    key        text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,31}$'),
    name       text NOT NULL,
    category   text NOT NULL CHECK (category IN ('todo', 'in_progress', 'done')),
    position   int NOT NULL DEFAULT 0,
    initial    bool NOT NULL DEFAULT false,
    UNIQUE (version_id, key),
    UNIQUE (id, version_id),
    CHECK (NOT (initial AND category = 'done'))
);
CREATE UNIQUE INDEX wf_status_initial_idx ON wf_status (version_id) WHERE initial;

-- from_status NULL: from any status. conditions say who may run it,
-- validators what must be true first, post_functions what happens after,
-- screen what it asks for (internal/store/workflows.go has the shapes).
CREATE TABLE wf_transition (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id     uuid NOT NULL REFERENCES workflow_version(id) ON DELETE CASCADE,
    name           text NOT NULL,
    from_status    uuid,
    to_status      uuid NOT NULL,
    position       int NOT NULL DEFAULT 0,
    conditions     jsonb NOT NULL DEFAULT '[]',
    validators     jsonb NOT NULL DEFAULT '[]',
    post_functions jsonb NOT NULL DEFAULT '[]',
    screen         jsonb NOT NULL DEFAULT '[]',
    FOREIGN KEY (from_status, version_id) REFERENCES wf_status(id, version_id) ON DELETE CASCADE,
    FOREIGN KEY (to_status, version_id) REFERENCES wf_status(id, version_id) ON DELETE CASCADE,
    CHECK (from_status IS DISTINCT FROM to_status)
);
CREATE INDEX wf_transition_version_idx ON wf_transition (version_id, position);

-- The default workflow, which every ticket type of every project starts on
-- and which existing items move to, status by category.
WITH w AS (
    INSERT INTO workflow (name, description, is_default)
    VALUES ('Default', 'To do, In progress, Done. Closing asks for a resolution.', true) RETURNING id),
v AS (
    INSERT INTO workflow_version (workflow_id, version, state, created_by, published_at, published_by)
    SELECT id, 1, 'published', 'system', now(), 'system' FROM w RETURNING id),
s AS (
    INSERT INTO wf_status (version_id, key, name, category, position, initial)
    SELECT v.id, x.key, x.name, x.category, x.position, x.initial FROM v,
        (VALUES ('todo', 'To do', 'todo', 0, true), ('in_progress', 'In progress', 'in_progress', 1, false),
                ('done', 'Done', 'done', 2, false)) AS x(key, name, category, position, initial)
    RETURNING id, version_id, key)
INSERT INTO wf_transition (version_id, name, from_status, to_status, position, screen)
SELECT v.id, x.name, f.id, t.id, x.position, x.screen::jsonb FROM v
    JOIN (VALUES ('Start progress', 'todo', 'in_progress', 0, '[]'),
                 ('Stop progress', 'in_progress', 'todo', 1, '[]'),
                 ('Done', NULL, 'done', 2, '["resolution", "comment"]'),
                 ('Reopen', 'done', 'todo', 3, '["comment"]')) AS x(name, from_key, to_key, position, screen) ON true
    LEFT JOIN s f ON f.key = x.from_key
    JOIN s t ON t.key = x.to_key;

ALTER TABLE project_ticket_type ADD COLUMN workflow_id uuid REFERENCES workflow(id) ON DELETE RESTRICT;
UPDATE project_ticket_type SET workflow_id = (SELECT id FROM workflow WHERE is_default);
ALTER TABLE project_ticket_type ALTER COLUMN workflow_id SET NOT NULL;
CREATE INDEX project_ticket_type_workflow_idx ON project_ticket_type (workflow_id);

ALTER TABLE work_item ADD COLUMN workflow_version_id uuid REFERENCES workflow_version(id) ON DELETE RESTRICT,
                      ADD COLUMN status_id uuid;
UPDATE work_item w SET workflow_version_id = s.version_id, status_id = s.id
FROM wf_status s JOIN workflow_version v ON v.id = s.version_id JOIN workflow f ON f.id = v.workflow_id
WHERE f.is_default AND s.key = w.status_category;
ALTER TABLE work_item ALTER COLUMN workflow_version_id SET NOT NULL,
                      ALTER COLUMN status_id SET NOT NULL,
                      ADD FOREIGN KEY (status_id, workflow_version_id) REFERENCES wf_status(id, version_id) ON DELETE RESTRICT;
CREATE INDEX work_item_version_idx ON work_item (workflow_version_id, status_id);

-- The category follows the status, whatever writes it.
CREATE FUNCTION work_item_status_category() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT category INTO NEW.status_category FROM wf_status WHERE id = NEW.status_id;
    RETURN NEW;
END $$;
CREATE TRIGGER work_item_status_category BEFORE INSERT OR UPDATE OF status_id, status_category ON work_item
    FOR EACH ROW EXECUTE FUNCTION work_item_status_category();

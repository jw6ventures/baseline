-- Work items (docs/data-model.md §8): projects, the ticket types they share,
-- and the work_item every ticket is, with its links to CIs, changes and
-- other items, its history, comments and watchers.
--
-- Workflows and custom field groups arrive in later migrations. Until then
-- an item's status is its status category (To do, In progress, Done); the
-- workflow engine adds workflow_version_id and status_id beside it and keeps
-- the category in step, since boards, SLAs and reports key off it.
--
-- Not in db/db.sql: these tables reference ci and change, which only the
-- migrations create.

CREATE TABLE project (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key           text NOT NULL UNIQUE CHECK (key ~ '^[A-Z][A-Z0-9]{1,9}$'), -- OPS, INFRA; items are OPS-42
    name          text NOT NULL,
    kind          text NOT NULL DEFAULT 'service_desk' CHECK (kind IN ('service_desk', 'software')),
    description   text NOT NULL DEFAULT '',
    host_group_id uuid REFERENCES host_group(id) ON DELETE SET NULL, -- the infra a queue supports
    next_number   int NOT NULL DEFAULT 1,
    archived      bool NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Defined once and shared by projects. base_kind tells built-in features
-- what a type is whatever its name: SLAs and alerts look for incident,
-- parenting for epic.
CREATE TABLE ticket_type (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{0,31}$'),
    name        text NOT NULL,
    icon        text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    base_kind   text NOT NULL CHECK (base_kind IN ('incident', 'request', 'problem', 'epic', 'story', 'task', 'bug', 'generic')),
    created_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO ticket_type (key, name, base_kind, description) VALUES
    ('incident', 'Incident', 'incident', 'Something is broken or degraded.'),
    ('request', 'Service request', 'request', 'Someone needs something done.'),
    ('problem', 'Problem', 'problem', 'The cause behind one or more incidents.'),
    ('epic', 'Epic', 'epic', 'A large piece of work, broken into stories and tasks.'),
    ('story', 'Story', 'story', 'A piece of work described from a user''s side.'),
    ('task', 'Task', 'task', 'A piece of work.'),
    ('bug', 'Bug', 'bug', 'A defect in software.');

-- The types a project offers. The workflow engine adds workflow_id here.
CREATE TABLE project_ticket_type (
    project_id     uuid NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    ticket_type_id uuid NOT NULL REFERENCES ticket_type(id) ON DELETE RESTRICT,
    position       int NOT NULL DEFAULT 0,
    is_default     bool NOT NULL DEFAULT false,
    PRIMARY KEY (project_id, ticket_type_id)
);
CREATE UNIQUE INDEX project_ticket_type_default_idx ON project_ticket_type (project_id) WHERE is_default;

CREATE TABLE work_item (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid NOT NULL REFERENCES project(id) ON DELETE RESTRICT,
    number          int NOT NULL,
    ticket_type_id  uuid NOT NULL REFERENCES ticket_type(id) ON DELETE RESTRICT,
    status_category text NOT NULL DEFAULT 'todo' CHECK (status_category IN ('todo', 'in_progress', 'done')),
    resolution      text, -- set when done
    title           text NOT NULL,
    description     text NOT NULL DEFAULT '', -- markdown
    priority        text NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    impact          text CHECK (impact IN ('high', 'medium', 'low')),
    urgency         text CHECK (urgency IN ('high', 'medium', 'low')),
    reporter        uuid REFERENCES app_user(id) ON DELETE SET NULL, -- NULL: opened by the system
    assignee        uuid REFERENCES app_user(id) ON DELETE SET NULL,
    parent_id       uuid REFERENCES work_item(id) ON DELETE SET NULL,
    estimate        numeric CHECK (estimate >= 0),
    due_at          timestamptz,
    source          text NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'alert', 'unplanned_change', 'email', 'api')),
    source_ref      text NOT NULL DEFAULT '',
    custom          jsonb NOT NULL DEFAULT '{}', -- custom field values
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz,
    UNIQUE (project_id, number),
    CHECK ((status_category = 'done') = (resolution IS NOT NULL))
);
CREATE INDEX work_item_status_idx ON work_item (project_id, status_category);
CREATE INDEX work_item_assignee_idx ON work_item (assignee) WHERE assignee IS NOT NULL;
CREATE INDEX work_item_parent_idx ON work_item (parent_id) WHERE parent_id IS NOT NULL;

-- The bridges that make work items and the CMDB one system.
CREATE TABLE work_item_ci (
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    ci_id        uuid NOT NULL REFERENCES ci(id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role IN ('affected', 'caused_by', 'target')),
    PRIMARY KEY (work_item_id, ci_id, role)
);
CREATE INDEX work_item_ci_ci_idx ON work_item_ci (ci_id);

CREATE TABLE work_item_change (
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    change_id    uuid NOT NULL REFERENCES change(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('fixes', 'implements', 'caused')),
    PRIMARY KEY (work_item_id, change_id, kind)
);
CREATE INDEX work_item_change_change_idx ON work_item_change (change_id);

-- Read "from <kind> to": OPS-1 blocks OPS-2.
CREATE TABLE work_item_link (
    from_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    to_id   uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    kind    text NOT NULL CHECK (kind IN ('blocks', 'relates', 'duplicates', 'caused_by')),
    PRIMARY KEY (from_id, to_id, kind),
    CHECK (from_id <> to_id)
);
CREATE INDEX work_item_link_to_idx ON work_item_link (to_id);

-- Field-level history, shaped like ci_history's diffs.
CREATE TABLE work_item_history (
    id           bigserial PRIMARY KEY,
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    at           timestamptz NOT NULL DEFAULT now(),
    actor        text NOT NULL, -- user:<uuid> | system
    diff         jsonb NOT NULL
);
CREATE INDEX work_item_history_item_idx ON work_item_history (work_item_id, at DESC);

-- internal = a work note, which a future customer portal would not show.
CREATE TABLE comment (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    author       uuid REFERENCES app_user(id) ON DELETE SET NULL,
    body         text NOT NULL,
    internal     bool NOT NULL DEFAULT false,
    at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX comment_item_idx ON comment (work_item_id, at);

CREATE TABLE watcher (
    work_item_id uuid NOT NULL REFERENCES work_item(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    PRIMARY KEY (work_item_id, user_id)
);
CREATE INDEX watcher_user_idx ON watcher (user_id);

-- Custom fields, field groups and form layouts (docs/data-model.md §10).
--
-- Fields are defined once and bundled into reusable groups; a project
-- applies several groups to each ticket type it offers, and a layout orders
-- core fields, groups and single fields on each screen. Values live in
-- work_item.custom, keyed by field_def.key.
--
-- Not in db/db.sql: these tables reference project and ticket_type, which
-- only the migrations create.

CREATE TABLE field_def (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{0,31}$'), -- the key in work_item.custom
    label       text NOT NULL,
    type        text NOT NULL CHECK (type IN ('text', 'textarea', 'number', 'date', 'datetime', 'bool',
                                              'select', 'multiselect', 'user', 'ci_ref', 'item_ref', 'url')),
    options     jsonb NOT NULL DEFAULT '[]', -- select and multiselect: the values, in order
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE field_group (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX field_group_name_idx ON field_group (lower(name));

CREATE TABLE field_group_field (
    group_id      uuid NOT NULL REFERENCES field_group(id) ON DELETE CASCADE,
    field_id      uuid NOT NULL REFERENCES field_def(id) ON DELETE RESTRICT,
    position      int NOT NULL DEFAULT 0,
    required      bool NOT NULL DEFAULT false,
    default_value jsonb, -- NULL: no default
    PRIMARY KEY (group_id, field_id)
);
CREATE INDEX field_group_field_field_idx ON field_group_field (field_id);

-- The groups a project applies to one of its ticket types. A field in two
-- applied groups shows once, required if either group requires it.
CREATE TABLE project_ticket_type_group (
    project_id     uuid NOT NULL,
    ticket_type_id uuid NOT NULL,
    field_group_id uuid NOT NULL REFERENCES field_group(id) ON DELETE CASCADE,
    position       int NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, ticket_type_id, field_group_id),
    FOREIGN KEY (project_id, ticket_type_id) REFERENCES project_ticket_type (project_id, ticket_type_id) ON DELETE CASCADE
);
CREATE INDEX project_ticket_type_group_group_idx ON project_ticket_type_group (field_group_id);

-- A screen's layout. project_id NULL is the ticket type's default; a
-- project stores its own only when it overrides it. transition_id names a
-- workflow transition for screen = 'transition'; transitions belong to one
-- workflow version, so such a layout does too. view_uses_create makes a
-- create layout the view layout too.
--
-- sections: [{"title": "", "columns": 1|2, "collapsed": false, "items": [
--   {"kind": "core",  "field": "priority"},
--   {"kind": "group", "group_id": "<uuid>"},
--   {"kind": "field", "field_id": "<uuid>"}]}]
CREATE TABLE form_layout (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       uuid REFERENCES project(id) ON DELETE CASCADE,
    ticket_type_id   uuid NOT NULL REFERENCES ticket_type(id) ON DELETE CASCADE,
    screen           text NOT NULL CHECK (screen IN ('create', 'view', 'transition')),
    transition_id    uuid REFERENCES wf_transition(id) ON DELETE CASCADE,
    view_uses_create bool NOT NULL DEFAULT false,
    sections         jsonb NOT NULL DEFAULT '[]',
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK ((screen = 'transition') = (transition_id IS NOT NULL)),
    CHECK (NOT view_uses_create OR screen = 'create')
);
CREATE UNIQUE INDEX form_layout_screen_idx ON form_layout (
    COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), ticket_type_id, screen,
    COALESCE(transition_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- Lists filter on custom values; containment queries use this, and a field
-- that is filtered or sorted a lot can get its own expression index.
CREATE INDEX work_item_custom_idx ON work_item USING gin (custom jsonb_path_ops);

-- Boards (docs/data-model.md §11): columns of work items, each a set of
-- status categories and statuses, where dropping a card on a column runs a
-- real transition.
--
-- Not in db/db.sql: board references project, which only the migrations
-- create.

CREATE TABLE board (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid REFERENCES project(id) ON DELETE CASCADE, -- NULL: items of every project
    name       text NOT NULL,
    -- [{name, categories: [todo|in_progress|done], statuses: [status key]}], in order.
    -- An item goes in the first column naming its status's key, else the
    -- first naming its category.
    columns    jsonb NOT NULL DEFAULT '[]',
    -- The list engine's condition groups ([[{field, op, value}]]), ORed.
    filter     jsonb NOT NULL DEFAULT '[]',
    created_by uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX board_name_idx ON board (lower(name));
CREATE INDEX board_project_idx ON board (project_id);

-- Saved lists for the list engine (docs/lists.md): a named filter, column
-- set, sort and grouping over one table. A NULL owner makes it shared:
-- everyone who can open the table sees it in the list picker.
CREATE TABLE saved_list (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    table_key  text NOT NULL,             -- host, ci, change, job (internal/server lists)
    name       text NOT NULL,
    owner      uuid REFERENCES app_user(id) ON DELETE CASCADE,   -- NULL: shared
    created_by uuid REFERENCES app_user(id) ON DELETE SET NULL,
    columns    jsonb NOT NULL DEFAULT '[]',  -- field keys, in order
    conditions jsonb NOT NULL DEFAULT '[]',  -- [[{field, op, value}]]: groups ORed, conditions ANDed
    search     text NOT NULL DEFAULT '',
    sort       jsonb NOT NULL DEFAULT '{}',  -- {field, desc}
    group_by   text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX saved_list_name_idx ON saved_list
    (table_key, COALESCE(owner, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));

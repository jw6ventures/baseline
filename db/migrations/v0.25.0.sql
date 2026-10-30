-- Project categories and tags (docs/data-model.md §16).
--
-- Admins keep both lists. A project sits in at most one category, and
-- categories nest: filtering by a category matches its subcategories too.
-- Tags are picked from their list, any number per project. Colors are
-- #rrggbb, or '' for the plain chip; a category without one shows its
-- nearest ancestor's.

CREATE TABLE project_category (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   uuid REFERENCES project_category(id) ON DELETE RESTRICT,
    name        text NOT NULL CHECK (name <> '' AND strpos(name, '/') = 0),
    color       text NOT NULL DEFAULT '' CHECK (color = '' OR color ~ '^#[0-9a-f]{6}$'),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (parent_id <> id)
);
-- Names are unique among siblings.
CREATE UNIQUE INDEX project_category_name_idx ON project_category
    (COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));

CREATE TABLE project_tag (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL CHECK (name <> ''),
    color       text NOT NULL DEFAULT '' CHECK (color = '' OR color ~ '^#[0-9a-f]{6}$'),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX project_tag_name_idx ON project_tag (lower(name));

ALTER TABLE project ADD COLUMN category_id uuid REFERENCES project_category(id) ON DELETE SET NULL;
CREATE INDEX project_category_id_idx ON project (category_id);

CREATE TABLE project_tag_link (
    project_id uuid NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    tag_id     uuid NOT NULL REFERENCES project_tag(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, tag_id)
);
CREATE INDEX project_tag_link_tag_idx ON project_tag_link (tag_id);

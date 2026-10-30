-- Compose stack management (docs/change-management.md §5, docs/agent.md
-- §5.2): changes that deploy a new stack to a host, or edit a stack's
-- Compose file or .env.
--
-- An admin turns it on per host (manage_compose).

ALTER TABLE host ADD COLUMN IF NOT EXISTS manage_compose       bool NOT NULL DEFAULT false,
                 ADD COLUMN IF NOT EXISTS manage_compose_since timestamptz;

-- What one compose.deploy or compose.edit change writes to one stack. The
-- Compose file is kept whole (it is reviewed, diffed, and later checked for
-- drift against what the host reports). The .env is kept encrypted with
-- BASELINE_SECRET_KEY (env_enc), so the next edit starts from it, beside its
-- variable names and a keyed hash that can be shown.
CREATE TABLE IF NOT EXISTS compose_revision (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host           uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    engine         text NOT NULL,
    project        text NOT NULL,
    action         text NOT NULL CHECK (action IN ('compose.deploy', 'compose.edit')),
    change_id      uuid REFERENCES change(id) ON DELETE CASCADE,
    compose        text,                       -- NULL: the edit leaves it alone
    compose_sha256 text NOT NULL DEFAULT '',
    base_sha256    text NOT NULL DEFAULT '',   -- compose.edit: the file it replaces
    base_compose   text NOT NULL DEFAULT '',   -- that file as inventory showed it (masked), for the diff
    env_enc        text,                       -- NULL: the edit leaves the .env alone
    env_keys       text[] NOT NULL DEFAULT '{}', -- its variable names
    env_hash       text NOT NULL DEFAULT '',   -- HMAC-SHA256 under a key derived from BASELINE_SECRET_KEY
    created_by     uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS compose_revision_stack_idx ON compose_revision (host, engine, project, created_at DESC);
CREATE INDEX IF NOT EXISTS compose_revision_change_idx ON compose_revision (change_id);

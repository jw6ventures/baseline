-- API tokens (docs/architecture.md §5.1): a token lets scripts call
-- /api/v1 as its user, with no more than the roles it names. Only the
-- SHA-256 of the secret is stored. The IdP groups of the session that
-- created it are kept with it, so grants resolve the way they do for a
-- session: from the current role bindings on every request.
--
-- The table is also in db/db.sql, so IF NOT EXISTS keeps a new install
-- (db.sql, then every migration) from tripping over it.
CREATE TABLE IF NOT EXISTS api_token (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    name       text NOT NULL,
    hash       bytea NOT NULL UNIQUE,
    roles      text[] NOT NULL,            -- the user's roles the token may use
    idp_groups text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used  timestamptz,
    expires_at timestamptz,                -- NULL: never
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS api_token_user_idx ON api_token (user_id);

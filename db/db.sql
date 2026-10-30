-- Baseline base schema. Run once, on an empty database, by
-- jw6-go-utils/database, and followed by every db/migrations/vX.Y.Z.sql
-- (the version it records is v0.1.0). A schema change is a migration file
-- for upgrades and, from v0.13.0, also lands here for new installs, so such
-- a migration must be idempotent (IF NOT EXISTS).

-- Users, sessions and role bindings (docs/architecture.md §5) ---------------

CREATE TABLE app_user (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_sub   text NOT NULL UNIQUE,
    email      text NOT NULL DEFAULT '',
    name       text NOT NULL DEFAULT '',
    last_login timestamptz,
    prefs      jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The cookie holds a random session ID; only its SHA-256 is stored, so a
-- database leak doesn't hand out live sessions.
CREATE TABLE session (
    id_hash          bytea PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    idp_groups       text[] NOT NULL DEFAULT '{}', -- from the groups claim at login
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,          -- sliding: last_seen + idle timeout
    absolute_expires timestamptz NOT NULL,          -- hard cap from created_at
    oidc_blob_enc    bytea,                         -- oidc.Session, sealed with BASELINE_SECRET_KEY
    ip               text NOT NULL DEFAULT '',
    user_agent       text NOT NULL DEFAULT ''
);
CREATE INDEX session_user_idx ON session (user_id);
CREATE INDEX session_expires_idx ON session (expires_at);

-- API tokens (v0.13.0): a token lets scripts call /api/v1 as its user with
-- at most the roles it names. Only the SHA-256 of the secret is stored; the
-- creating session's IdP groups are kept so grants resolve like a session's.
CREATE TABLE api_token (
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
CREATE INDEX api_token_user_idx ON api_token (user_id);

-- Static members and/or a dynamic rule. Members arrive with hosts in M1.
CREATE TABLE host_group (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    rule        jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_binding (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_group      text NOT NULL,
    role           text NOT NULL CHECK (role IN ('viewer', 'operator', 'approver', 'admin')),
    scope_group_id uuid REFERENCES host_group(id) ON DELETE CASCADE, -- NULL = global
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (role <> 'admin' OR scope_group_id IS NULL)
);
-- NULLS NOT DISTINCT so the same global binding can't be added twice.
CREATE UNIQUE INDEX role_binding_uniq ON role_binding (idp_group, role, scope_group_id) NULLS NOT DISTINCT;

-- Audit log (docs/architecture.md §5.4) -------------------------------------

-- Append-only and hash chained: hash = SHA-256(prev_hash || canonical row),
-- computed by internal/store. The trigger below rejects UPDATE, DELETE and
-- TRUNCATE for every role, including the owner.
CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL,
    actor       text NOT NULL,              -- user:<uuid> | agent:<uuid> | system
    actor_ip    text NOT NULL DEFAULT '',
    action      text NOT NULL,              -- e.g. auth.login, role_binding.create
    object_type text NOT NULL DEFAULT '',
    object_id   text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL UNIQUE
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_object_idx ON audit_log (object_type, object_id);

CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

INSERT INTO application (key, value) VALUES ('version', 'v0.1.0');

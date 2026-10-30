-- Compose roots (docs/change-management.md §5.1): the directories on a
-- host that compose.deploy puts new stacks under, in <root>/<project>.
-- Admins keep the list on the host's Settings tab; the first is the
-- deploy form's default. Empty: the agent's own compose_root.

ALTER TABLE host ADD COLUMN IF NOT EXISTS compose_roots text[] NOT NULL DEFAULT '{}';

-- A stack found on disk under one of those roots with nothing of it
-- running (the agent reads its Compose file instead of container labels).
ALTER TABLE compose_stack ADD COLUMN IF NOT EXISTS stopped bool NOT NULL DEFAULT false;

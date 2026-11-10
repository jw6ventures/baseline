-- Update groups (docs/change-management.md §5.3): Compose services that
-- update together, in order, such as an identity server and the proxy
-- outposts that must never run ahead of it. A container joins one with the
-- labels baseline.update.group and baseline.update.order; a service can
-- also be put in one on its stack's page, kept here by service like the
-- semver rules. The label wins over the setting.
ALTER TABLE compose_stack ADD COLUMN IF NOT EXISTS update_groups jsonb NOT NULL DEFAULT '{}'; -- service -> {group, order}

-- A job of an update group waits for the jobs of the same group and change
-- with a lower order, and is skipped when one of them didn't succeed.
ALTER TABLE job ADD COLUMN IF NOT EXISTS update_group text NOT NULL DEFAULT '';
ALTER TABLE job ADD COLUMN IF NOT EXISTS update_order int NOT NULL DEFAULT 0;

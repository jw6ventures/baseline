-- Compose patch groups (docs/change-management.md §4): a group whose change
-- model is a compose.update one updates the stacks it lists instead of
-- patching a host group. With promotion on, a stack named for an
-- environment (internal/stackname) takes only the images its Dev, Test or
-- Staging copies of the same app already run.
ALTER TABLE patch_group
    ALTER COLUMN host_group_id DROP NOT NULL,
    ADD COLUMN stacks uuid[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT patch_group_targets CHECK (host_group_id IS NOT NULL OR cardinality(stacks) > 0);

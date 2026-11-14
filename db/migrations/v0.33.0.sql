-- Server-wide settings an admin changes on the Settings pages, by key.
-- stacks.retire_missing_days: Compose stacks missing for longer than this
-- many days are retired (docs/data-model.md §1); absent or 0 is never.
CREATE TABLE IF NOT EXISTS app_setting (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

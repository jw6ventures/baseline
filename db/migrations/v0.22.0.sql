-- Closing alerts and quieter drive alerts (docs/data-model.md §7).
--
-- Closing takes an alert out of sight: a closed alert stays open (so the
-- next pass doesn't raise it again) but shows nowhere and never notifies.
-- It resolves quietly when its condition ends, and when the condition gets
-- worse (its level rises, or its severity does) it resolves and a new alert
-- fires. level is what "worse" compares: for drives, the bad sector count.

ALTER TABLE alert DROP CONSTRAINT alert_state_check,
    ADD CONSTRAINT alert_state_check CHECK (state IN ('pending', 'firing', 'closed', 'resolved')),
    ADD COLUMN level          bigint NOT NULL DEFAULT 0,
    ADD COLUMN closed_by      uuid REFERENCES app_user(id) ON DELETE SET NULL,
    ADD COLUMN closed_at      timestamptz,
    ADD COLUMN closed_level   bigint NOT NULL DEFAULT 0,
    ADD COLUMN closed_severity text NOT NULL DEFAULT '',
    ADD COLUMN close_comment  text NOT NULL DEFAULT '';

-- When a drive's bad sector count (reallocated, pending, uncorrectable and
-- media errors together) last went up. The smart rule alerts on a drive
-- whose count rose within its window, or reached its threshold; a small
-- stable count stays quiet. NULL: not since this migration.
ALTER TABLE host_smart ADD COLUMN rose_at timestamptz;

UPDATE alert_rule SET params = params || '{"days": 7, "sectors": 100}' WHERE kind = 'smart';

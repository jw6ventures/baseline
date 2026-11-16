-- Editing changes and escalating them to Emergency
-- (docs/change-management.md §2.1).
--
-- not_before is the start the requester asked for; planned_start is when
-- the scheduler plans to start the change, which a window or freeze can
-- push later. An edit of the schedule plans again from not_before.
ALTER TABLE change ADD COLUMN IF NOT EXISTS not_before timestamptz;
UPDATE change SET not_before = planned_start
WHERE not_before IS NULL AND planned_start IS NOT NULL AND state IN ('draft', 'submitted', 'approved');

-- An approval an edit or an escalation withdrew: kept for the record, not
-- counted. Approving again clears it.
ALTER TABLE change_approval ADD COLUMN IF NOT EXISTS withdrawn bool NOT NULL DEFAULT false;

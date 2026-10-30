-- High security hosts (docs/data-model.md §7): their agents collect
-- hardware within seconds of the kernel reporting a device or link coming
-- or going (every 5 minutes otherwise), USB devices, displays and NIC link
-- state included, and the hardware_change rule alerts on every unplanned
-- component added, removed or swapped, cable plugged or pulled and display
-- connected or disconnected, reminding every 15 minutes until someone
-- acknowledges it. high_security_since bounds what counts: turning the
-- flag on doesn't alert on changes from before.
ALTER TABLE host
    ADD COLUMN high_security       bool NOT NULL DEFAULT false,
    ADD COLUMN high_security_since timestamptz;

-- Hardware history of flagged hosts, read by the rule every minute.
CREATE INDEX ci_history_hardware_idx ON ci_history (ci_id, at) WHERE section = 'hardware';

INSERT INTO alert_rule (name, kind, params, severity, for_s, repeat_s, enabled) VALUES
    ('Hardware change on a high security host', 'hardware_change', '{}', 'critical', 0, 900, true);

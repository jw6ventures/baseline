-- Compose file drift (docs/data-model.md §7): alert when the Compose file
-- of a stack Baseline deployed or edited is changed on the host, against the
-- file kept in compose_revision.

INSERT INTO alert_rule (name, kind, params, severity, for_s, enabled)
SELECT 'Compose file changed on the host', 'compose_drift', '{}', 'warning', 0, true
WHERE NOT EXISTS (SELECT 1 FROM alert_rule WHERE kind = 'compose_drift');

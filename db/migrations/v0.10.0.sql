-- Compose stacks named <env><category><visibility>-<app> (pii-backup,
-- pwe-proxy) carry that metadata in ci.attrs, read from the name by
-- internal/stackname on every containers snapshot. Other names carry none.
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "environment", "label": "Environment", "type": "text", "discovered": true},
    {"key": "category", "label": "Category", "type": "text", "discovered": true},
    {"key": "visibility", "label": "Visibility", "type": "text", "discovered": true}]}'
WHERE key = 'compose_stack';

-- Stacks already stored get theirs when each host next reports: an unknown
-- hash makes the server project its containers section again, even when
-- nothing in it changed.
UPDATE host_inventory SET content_hash = '' WHERE section = 'containers';

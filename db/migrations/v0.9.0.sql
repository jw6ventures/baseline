-- Hostnames Traefik routes to containers, read from their router labels
-- (docs/data-model.md §1). Each is a CI of type service_endpoint keyed by
-- host and hostname (ci.source_key: <host>/traefik:<hostname>, or
-- <host>/traefik-re:<pattern> for HostRegexp and HostSNIRegexp), related
-- to the containers serving it (hosted_by) and their Compose stacks
-- (member_of). A hostname no container names any more keeps its row with
-- present = false, and its CI turns missing an hour later.
CREATE TABLE traefik_hostname (
    ci_id    uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    host     uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    hostname text NOT NULL,             -- lowercase, or the pattern as written
    regexp   bool NOT NULL DEFAULT false,
    present  bool NOT NULL DEFAULT true,
    UNIQUE (host, regexp, hostname)
);

-- Discovered fields are filled by discovery and left off the form for
-- service endpoints added by hand.
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "url", "label": "URL", "type": "url"},
    {"key": "tls_endpoint", "label": "TLS endpoint to check", "type": "endpoint"},
    {"key": "matchers", "label": "Traefik matchers", "type": "text", "discovered": true},
    {"key": "routers", "label": "Traefik routers", "type": "text", "discovered": true},
    {"key": "entrypoints", "label": "Entry points", "type": "text", "discovered": true},
    {"key": "tls", "label": "TLS", "type": "text", "discovered": true},
    {"key": "ports", "label": "Container ports", "type": "text", "discovered": true}]}'
WHERE key = 'service_endpoint';

-- The Traefik a host's hostnames are routed by when it runs elsewhere: a
-- Traefik container on another host, or a host running it as a service.
-- Traefik containers on the host itself are found by their image.
ALTER TABLE host ADD COLUMN traefik_ci uuid REFERENCES ci(id) ON DELETE SET NULL;

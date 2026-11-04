-- Hostnames Kubernetes Ingresses route, read by the cluster agent
-- (docs/data-model.md §1). Each is a CI of type service_endpoint keyed by
-- cluster and hostname (ci.source 'k8s', source_key
-- <cluster UID>/ingress:<hostname>), member_of the cluster and hosted_by
-- the workloads its backends' Services select. A hostname no
-- Ingress names any more keeps its row with present = false, and its CI
-- turns missing an hour later.
CREATE TABLE IF NOT EXISTS k8s_ingress_host (
    ci_id      uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    cluster_ci uuid NOT NULL REFERENCES k8s_cluster(ci_id) ON DELETE CASCADE,
    hostname   text NOT NULL, -- lowercase; a wildcard as written (*.example.com)
    present    bool NOT NULL DEFAULT true,
    UNIQUE (cluster_ci, hostname)
);

-- What the CI page shows of them: discovered, so not on the form.
UPDATE ci_type SET attr_schema = jsonb_set(attr_schema, '{fields}', (attr_schema->'fields') || '[
    {"key": "cluster", "label": "Kubernetes cluster", "type": "text", "discovered": true},
    {"key": "ingresses", "label": "Ingresses", "type": "text", "discovered": true},
    {"key": "ingress_class", "label": "Ingress class", "type": "text", "discovered": true},
    {"key": "backends", "label": "Backends", "type": "text", "discovered": true},
    {"key": "workloads", "label": "Workloads", "type": "text", "discovered": true}]')
WHERE key = 'service_endpoint'
  AND attr_schema ? 'fields'
  AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(attr_schema->'fields') f WHERE f->>'key' = 'ingresses');

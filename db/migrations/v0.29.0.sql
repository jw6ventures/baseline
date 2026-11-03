-- Kubernetes workload management (docs/agent.md §6.1, docs/change-management.md
-- §5.2): the k8s.* actions a cluster agent runs, and the manifests that
-- k8s.deploy and k8s.edit apply.
--
-- What one k8s.deploy or k8s.edit change applies to a cluster: the whole
-- manifest of a bundle, a set of objects Baseline deployed together (named
-- like a Compose project). The next edit of the bundle starts from the last
-- revision that was applied successfully, and the agent gets that one too,
-- to put it back if the edit fails and to delete what the edit leaves out.
-- Manifests never hold Secrets (the server and the agent refuse them), so
-- they are kept as they are.
CREATE TABLE IF NOT EXISTS k8s_manifest (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_ci      uuid NOT NULL REFERENCES k8s_cluster(ci_id) ON DELETE CASCADE,
    host            uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE, -- the cluster agent that applies it
    bundle          text NOT NULL,
    namespace       text NOT NULL,
    action          text NOT NULL CHECK (action IN ('k8s.deploy', 'k8s.edit')),
    change_id       uuid REFERENCES change(id) ON DELETE CASCADE,
    manifest        text NOT NULL,
    manifest_sha256 text NOT NULL,
    objects         text[] NOT NULL DEFAULT '{}', -- "Deployment shop/web", as parsed
    base_revision   uuid REFERENCES k8s_manifest(id) ON DELETE SET NULL,
    created_by      uuid REFERENCES app_user(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS k8s_manifest_bundle_idx ON k8s_manifest (cluster_ci, bundle, created_at DESC);
CREATE INDEX IF NOT EXISTS k8s_manifest_change_idx ON k8s_manifest (change_id);

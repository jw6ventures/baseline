-- M7: virtualization and Kubernetes (docs/data-model.md §2): hypervisor
-- guests, Kubernetes clusters, their nodes and workloads.

-- Guests of Proxmox and libvirt hosts. A guest is a CI of type vm or lxc
-- keyed by its platform's identity (ci.source_key: <proxmox cluster or
-- node:<name>>/<vmid>, or the libvirt domain UUID), so it keeps its CI when
-- it migrates to another node. A guest that disappears keeps its row with
-- present = false, and its CI turns missing an hour later.
CREATE TABLE vm_guest (
    ci_id     uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    host      uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE, -- the hypervisor running it
    platform  text NOT NULL CHECK (platform IN ('proxmox', 'libvirt')),
    kind      text NOT NULL,                  -- qemu | lxc (Proxmox), kvm | qemu (libvirt)
    guest_id  text NOT NULL,                  -- VMID or domain UUID
    name      text NOT NULL,
    uuid      text NOT NULL DEFAULT '',       -- the SMBIOS UUID the guest sees, lowercase
    macs      text[] NOT NULL DEFAULT '{}',   -- lowercase
    state     text NOT NULL DEFAULT '',
    config    jsonb NOT NULL DEFAULT '{}',    -- the guest as reported
    present   bool NOT NULL DEFAULT true
);
CREATE INDEX vm_guest_host_idx ON vm_guest (host);
CREATE INDEX vm_guest_uuid_idx ON vm_guest (uuid) WHERE uuid <> '';
CREATE INDEX vm_guest_macs_idx ON vm_guest USING gin (macs);

-- A Kubernetes cluster, reported by a cluster-mode agent (host). Its CI is
-- keyed by the kube-system namespace's UID, so a re-enrolled agent takes
-- the cluster over rather than starting a new one.
CREATE TABLE k8s_cluster (
    ci_id    uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    host     uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE,
    uid      text NOT NULL UNIQUE,
    name     text NOT NULL,
    version  text NOT NULL DEFAULT '',
    platform text NOT NULL DEFAULT ''
);
CREATE INDEX k8s_cluster_host_idx ON k8s_cluster (host);

-- Nodes (CI type k8s_node) and workloads (k8s_workload) of a cluster:
-- Deployments, StatefulSets, DaemonSets, CronJobs and bare Pods. Services
-- and ingresses are shown from the section, not kept as CIs.
CREATE TABLE k8s_object (
    ci_id        uuid PRIMARY KEY REFERENCES ci(id) ON DELETE CASCADE,
    cluster_ci   uuid NOT NULL REFERENCES k8s_cluster(ci_id) ON DELETE CASCADE,
    host         uuid NOT NULL REFERENCES host(ci_id) ON DELETE CASCADE, -- the agent reporting it
    kind         text NOT NULL,               -- Node, Deployment, StatefulSet, DaemonSet, CronJob, Pod
    namespace    text NOT NULL DEFAULT '',
    name         text NOT NULL,
    images       text[] NOT NULL DEFAULT '{}',
    spec_summary jsonb NOT NULL DEFAULT '{}', -- the object as reported
    present      bool NOT NULL DEFAULT true,
    UNIQUE (cluster_ci, kind, namespace, name)
);
CREATE INDEX k8s_object_host_idx ON k8s_object (host);

-- What the CI page shows for nodes and workloads (ci.attrs, filled by
-- discovery; these types can't be created by hand).
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "cluster", "label": "Cluster", "type": "text"},
    {"key": "roles", "label": "Roles", "type": "text"},
    {"key": "kubelet", "label": "Kubelet", "type": "text"},
    {"key": "os_image", "label": "OS image", "type": "text"},
    {"key": "runtime", "label": "Container runtime", "type": "text"}]}'
WHERE key = 'k8s_node';
UPDATE ci_type SET attr_schema = '{"fields": [
    {"key": "cluster", "label": "Cluster", "type": "text"},
    {"key": "kind", "label": "Kind", "type": "text"},
    {"key": "namespace", "label": "Namespace", "type": "text"},
    {"key": "images", "label": "Images", "type": "text"}]}'
WHERE key = 'k8s_workload';

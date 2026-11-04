package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// workloadResources maps the API resources a cluster agent lists to the
// workload kinds they hold.
var workloadResources = map[string]string{
	"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
	"cronjobs": "CronJob", "pods": "Pod",
}

// keepFailedResources carries over what the previous snapshot had for
// resources the agent couldn't list this time (RBAC, an API the cluster
// stopped serving), so the gap doesn't read as everything removed.
func keepFailedResources(prev, cur []byte) ([]byte, error) {
	var p, c model.K8s
	if err := json.Unmarshal(cur, &c); err != nil {
		return nil, err
	}
	if len(c.Errors) == 0 || prev == nil {
		return cur, nil
	}
	if err := json.Unmarshal(prev, &p); err != nil {
		return cur, nil
	}
	failed := map[string]bool{}
	for _, e := range c.Errors {
		failed[e.Resource] = true
	}
	if failed["nodes"] {
		c.Nodes = p.Nodes
	}
	if failed["namespaces"] {
		c.Namespaces = p.Namespaces
	}
	if failed["services"] {
		c.Services = p.Services
	}
	if failed["ingresses"] {
		c.Ingresses = p.Ingresses
	}
	for res, kind := range workloadResources {
		if !failed[res] {
			continue
		}
		for _, w := range p.Workloads {
			if w.Kind == kind {
				c.Workloads = append(c.Workloads, w)
			}
		}
	}
	slices.SortFunc(c.Workloads, func(a, b model.K8sWorkload) int { return strings.Compare(a.Key(), b.Key()) })
	return json.Marshal(c)
}

func projectK8s(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var k model.K8s
	if err := json.Unmarshal(payload, &k); err != nil {
		return err
	}
	cl := k.Cluster
	if cl.UID == "" {
		return errors.New("k8s section without a cluster UID")
	}
	name := cl.Name
	if name == "" {
		name = "kubernetes"
	}
	var clusterCI string
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO ci (type, name, source, source_key, status, last_seen)
		VALUES ('k8s_cluster', $2, 'k8s', $1, 'active', now())
		ON CONFLICT (source, source_key) DO UPDATE
		SET status = 'active', last_seen = now(), name = EXCLUDED.name,
		    updated_at = CASE WHEN ci.status <> 'active' OR ci.name <> EXCLUDED.name THEN now() ELSE ci.updated_at END
		RETURNING id`, cl.UID, name).Scan(&clusterCI); err != nil {
		return err
	}
	// A re-enrolled agent takes the cluster over.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO k8s_cluster (ci_id, host, uid, name, version, platform) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (ci_id) DO UPDATE
		SET host = EXCLUDED.host, name = EXCLUDED.name, version = EXCLUDED.version, platform = EXCLUDED.platform`,
		clusterCI, hostID, cl.UID, name, cl.Version, cl.Platform); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE k8s_object SET host = $2 WHERE cluster_ci = $1 AND host <> $2`,
		clusterCI, hostID); err != nil {
		return err
	}
	// The agent's own record is named after the cluster it reports: its
	// pod name changes with every restart.
	if _, err := tx.ExecContext(ctx, `
		UPDATE host SET hostname = $2, os_pretty = $3, arch = $4 WHERE ci_id = $1`,
		hostID, name, "Kubernetes "+cl.Version, strings.TrimPrefix(cl.Platform, "linux/")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ci SET name = $2, updated_at = now() WHERE id = $1 AND name <> $2`,
		hostID, name); err != nil {
		return err
	}

	type object struct {
		ciType, kind, namespace, name string
		images                        []string
		attrs                         map[string]any
		v                             any
	}
	var objs []object
	for _, n := range k.Nodes {
		objs = append(objs, object{"k8s_node", "Node", "", n.Name, nil, map[string]any{
			"cluster": name, "roles": strings.Join(n.Roles, ", "), "kubelet": n.KubeletVersion,
			"os_image": n.OSImage, "runtime": n.ContainerRuntime}, n})
	}
	for _, w := range k.Workloads {
		objs = append(objs, object{"k8s_workload", w.Kind, w.Namespace, w.Name, w.Images, map[string]any{
			"cluster": name, "kind": w.Kind, "namespace": w.Namespace, "images": strings.Join(w.Images, ", ")}, w})
	}
	present := make([]string, 0, len(objs))
	for _, o := range objs {
		ciName := o.name
		if o.namespace != "" {
			ciName = o.namespace + "/" + o.name
		}
		attrs, err := json.Marshal(o.attrs)
		if err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, source, source_key, status, last_seen, attrs)
			VALUES ($1, $2, 'k8s', $3, 'active', now(), $4)
			ON CONFLICT (source, source_key) DO UPDATE
			SET status = 'active', last_seen = now(), attrs = EXCLUDED.attrs,
			    updated_at = CASE WHEN ci.status <> 'active' OR ci.attrs <> EXCLUDED.attrs THEN now() ELSE ci.updated_at END
			RETURNING id`, o.ciType, ciName, cl.UID+"/"+o.kind+"/"+o.namespace+"/"+o.name, string(attrs)).Scan(&id); err != nil {
			return err
		}
		spec, err := json.Marshal(o.v)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO k8s_object (ci_id, cluster_ci, host, kind, namespace, name, images, spec_summary, present)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
			ON CONFLICT (ci_id) DO UPDATE
			SET host = EXCLUDED.host, images = EXCLUDED.images, spec_summary = EXCLUDED.spec_summary, present = true`,
			id, clusterCI, hostID, o.kind, o.namespace, o.name, pq.Array(nonNil(o.images)), string(spec)); err != nil {
			return err
		}
		if err := relate(ctx, tx, id, clusterCI, "member_of"); err != nil {
			return err
		}
		present = append(present, id)
	}
	if _, err := tx.ExecContext(ctx, `
		WITH gone AS (
		    UPDATE k8s_object SET present = false
		    WHERE cluster_ci = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
		UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`,
		clusterCI, pq.Array(present)); err != nil {
		return err
	}
	if err := projectK8sIngresses(ctx, tx, clusterCI, cl.UID, name, k.Ingresses); err != nil {
		return err
	}
	return linkDiscovered(ctx, tx)
}

// Queries ----------------------------------------------------------------------

// Cluster is a Kubernetes cluster and the agent reporting it.
type Cluster struct {
	CIID     string
	Name     string
	UID      string
	Version  string
	Platform string
	Status   string // the CI's
	HostID   string // the cluster agent
	// Connected is whether the cluster agent is connected.
	Connected  bool
	Nodes      int
	NodesReady int
	Workloads  int
	// Degraded counts workloads with fewer ready replicas than desired.
	Degraded int
}

const clusterCols = `k.ci_id, k.name, k.uid, k.version, k.platform, ci.status, k.host, h.connected,
	(SELECT count(*) FROM k8s_object o WHERE o.cluster_ci = k.ci_id AND o.present AND o.kind = 'Node'),
	(SELECT count(*) FROM k8s_object o WHERE o.cluster_ci = k.ci_id AND o.present AND o.kind = 'Node'
	   AND (o.spec_summary->>'ready')::bool),
	(SELECT count(*) FROM k8s_object o WHERE o.cluster_ci = k.ci_id AND o.present AND o.kind <> 'Node'),
	(SELECT count(*) FROM k8s_object o WHERE o.cluster_ci = k.ci_id AND o.present AND o.kind NOT IN ('Node', 'CronJob')
	   AND COALESCE((o.spec_summary->>'ready')::int, 0) < COALESCE((o.spec_summary->>'replicas')::int, 0))`

const clusterFrom = ` FROM k8s_cluster k JOIN host h ON h.ci_id = k.host JOIN ci ON ci.id = k.ci_id `

func scanCluster(row interface{ Scan(...any) error }) (Cluster, error) {
	var c Cluster
	err := row.Scan(&c.CIID, &c.Name, &c.UID, &c.Version, &c.Platform, &c.Status, &c.HostID, &c.Connected,
		&c.Nodes, &c.NodesReady, &c.Workloads, &c.Degraded)
	return c, err
}

// ListClusters returns the clusters the given agents report.
func (s *Store) ListClusters(ctx context.Context, hostIDs []string) ([]Cluster, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clusterCols+clusterFrom+`
		WHERE k.host::text = ANY($1) ORDER BY lower(k.name)`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cluster
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCluster(ctx context.Context, ciID string) (Cluster, error) {
	c, err := scanCluster(s.db.QueryRowContext(ctx, `SELECT `+clusterCols+clusterFrom+` WHERE k.ci_id = $1`, ciID))
	return c, mapErr(err)
}

// ClusterOfAgent returns the cluster a cluster-mode agent reports.
func (s *Store) ClusterOfAgent(ctx context.Context, hostID string) (Cluster, error) {
	c, err := scanCluster(s.db.QueryRowContext(ctx, `SELECT `+clusterCols+clusterFrom+` WHERE k.host = $1
		ORDER BY lower(k.name) LIMIT 1`, hostID))
	return c, mapErr(err)
}

// K8sObject is a node or workload CI of a cluster. Node, Workload: the one
// matching Kind is set.
type K8sObject struct {
	CIID      string
	Kind      string
	Namespace string
	Name      string
	Present   bool
	Status    string
	Node      model.K8sNodeInfo
	Workload  model.K8sWorkload
	// HostID and Hostname are the host agent running on a node, if
	// discovery linked one.
	HostID   string
	Hostname string
}

// ClusterObjects returns a cluster's nodes and workloads, present ones
// first.
func (s *Store) ClusterObjects(ctx context.Context, clusterCI string) ([]K8sObject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.ci_id, o.kind, o.namespace, o.name, o.present, ci.status, o.spec_summary::text,
		       COALESCE(h.ci_id::text, ''), COALESCE(h.hostname, '')
		FROM k8s_object o JOIN ci ON ci.id = o.ci_id
		LEFT JOIN ci_relationship r ON r.from_ci = o.ci_id AND r.kind = 'runs_on' AND r.source = 'discovered'
		LEFT JOIN host h ON h.ci_id = r.to_ci
		WHERE o.cluster_ci = $1 AND ci.status <> 'retired'
		ORDER BY NOT o.present, o.kind, o.namespace, o.name`, clusterCI)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []K8sObject
	for rows.Next() {
		var o K8sObject
		var spec string
		if err := rows.Scan(&o.CIID, &o.Kind, &o.Namespace, &o.Name, &o.Present, &o.Status, &spec, &o.HostID, &o.Hostname); err != nil {
			return nil, err
		}
		var err error
		if o.Kind == "Node" {
			err = json.Unmarshal([]byte(spec), &o.Node)
		} else {
			err = json.Unmarshal([]byte(spec), &o.Workload)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// NodeOf is the Kubernetes node a host is, with its cluster.
type NodeOf struct {
	CIID        string
	Name        string
	ClusterCI   string
	ClusterName string
	Present     bool
}

// HostNode returns the Kubernetes node a host is, if discovery linked one.
func (s *Store) HostNode(ctx context.Context, hostID string) (NodeOf, error) {
	var n NodeOf
	err := s.db.QueryRowContext(ctx, `
		SELECT o.ci_id, o.name, o.cluster_ci, k.name, o.present
		FROM ci_relationship r JOIN k8s_object o ON o.ci_id = r.from_ci JOIN k8s_cluster k ON k.ci_id = o.cluster_ci
		WHERE r.to_ci = $1 AND r.kind = 'runs_on' AND r.source = 'discovered' AND o.kind = 'Node'
		ORDER BY o.present DESC LIMIT 1`, hostID).Scan(&n.CIID, &n.Name, &n.ClusterCI, &n.ClusterName, &n.Present)
	return n, mapErr(err)
}

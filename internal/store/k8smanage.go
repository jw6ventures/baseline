package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// Kubernetes workload management (docs/change-management.md §5.2): the
// workloads the k8s.* actions act on, and the manifests k8s.deploy and
// k8s.edit apply.

// Workload is a workload CI of a cluster, with the cluster agent that
// reports it and runs its actions.
type Workload struct {
	CIID      string
	Kind      string
	Namespace string
	Name      string
	Present   bool
	Status    string
	Workload  model.K8sWorkload
	ClusterCI string
	Cluster   string // its name
	// HostID is the cluster agent; Connected whether it is connected.
	HostID    string
	Connected bool
}

// Ref is the workload as messages name it: "Deployment shop/web".
func (w Workload) Ref() string { return w.Kind + " " + w.Namespace + "/" + w.Name }

const workloadCols = `o.ci_id, o.kind, o.namespace, o.name, o.present, ci.status, o.spec_summary::text,
	o.cluster_ci, k.name, k.host, h.connected`

const workloadFrom = ` FROM k8s_object o JOIN ci ON ci.id = o.ci_id JOIN k8s_cluster k ON k.ci_id = o.cluster_ci
	JOIN host h ON h.ci_id = k.host `

func scanWorkload(row interface{ Scan(...any) error }) (Workload, error) {
	var w Workload
	var spec string
	if err := row.Scan(&w.CIID, &w.Kind, &w.Namespace, &w.Name, &w.Present, &w.Status, &spec, &w.ClusterCI, &w.Cluster,
		&w.HostID, &w.Connected); err != nil {
		return w, err
	}
	return w, json.Unmarshal([]byte(spec), &w.Workload)
}

// GetWorkload returns a workload CI; ErrNotFound for anything else, nodes
// included.
func (s *Store) GetWorkload(ctx context.Context, ciID string) (Workload, error) {
	w, err := scanWorkload(s.db.QueryRowContext(ctx, `SELECT `+workloadCols+workloadFrom+`
		WHERE o.ci_id = $1 AND o.kind <> 'Node'`, ciID))
	return w, mapErr(err)
}

// ListWorkloads returns the present workloads of the clusters the given
// agents report, by cluster, namespace, kind and name.
func (s *Store) ListWorkloads(ctx context.Context, hostIDs []string) ([]Workload, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workloadCols+workloadFrom+`
		WHERE k.host::text = ANY($1) AND o.kind <> 'Node' AND o.present AND ci.status <> 'retired'
		ORDER BY lower(k.name), o.namespace, o.kind, o.name`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workload
	for rows.Next() {
		w, err := scanWorkload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Manifest is what one k8s.deploy or k8s.edit change applies to a bundle.
// Its ID is in the job's parameters; the dispatcher sends the manifest, and
// an edit's base, with the job.
type Manifest struct {
	ID             string
	ClusterCI      string
	HostID         string
	Bundle         string
	Namespace      string
	Action         string
	Manifest       string
	ManifestSHA256 string
	Objects        []string
	BaseRevision   string
	// Read back.
	ChangeID      string
	ChangeNumber  int64
	ChangeState   string
	CreatedBy     string
	CreatedByName string
	CreatedAt     time.Time
	// JobState is the state of the revision's job; "" before the change
	// has one.
	JobState string
}

// ChangeRef is the revision's change as people see it.
func (m Manifest) ChangeRef() string { return ChangeRef(m.ChangeNumber) }

// Applied reports whether the revision's job succeeded.
func (m Manifest) Applied() bool { return m.JobState == "succeeded" }

func insertManifests(ctx context.Context, tx *sql.Tx, changeID string, by sql.NullString, ms []Manifest) error {
	for _, m := range ms {
		base := sql.NullString{String: m.BaseRevision, Valid: m.BaseRevision != ""}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO k8s_manifest (id, cluster_ci, host, bundle, namespace, action, change_id, manifest, manifest_sha256,
			       objects, base_revision, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			m.ID, m.ClusterCI, m.HostID, m.Bundle, m.Namespace, m.Action, changeID, m.Manifest, m.ManifestSHA256,
			pq.Array(nonNil(m.Objects)), base, by); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

const manifestCols = `r.id, r.cluster_ci, r.host, r.bundle, r.namespace, r.action, r.manifest, r.manifest_sha256, r.objects,
	COALESCE(r.base_revision::text, ''), COALESCE(r.change_id::text, ''), COALESCE(c.number, 0), COALESCE(c.state, ''),
	COALESCE(r.created_by::text, ''), COALESCE(NULLIF(u.name, ''), u.email, ''), r.created_at,
	COALESCE((SELECT j.state FROM job j WHERE j.change_id = r.change_id AND j.params->>'revision' = r.id::text
	          ORDER BY j.seq LIMIT 1), '')`

const manifestFrom = ` FROM k8s_manifest r LEFT JOIN change c ON c.id = r.change_id
	LEFT JOIN app_user u ON u.id = r.created_by `

func scanManifest(row interface{ Scan(...any) error }) (Manifest, error) {
	var m Manifest
	err := row.Scan(&m.ID, &m.ClusterCI, &m.HostID, &m.Bundle, &m.Namespace, &m.Action, &m.Manifest, &m.ManifestSHA256,
		pq.Array(&m.Objects), &m.BaseRevision, &m.ChangeID, &m.ChangeNumber, &m.ChangeState, &m.CreatedBy,
		&m.CreatedByName, &m.CreatedAt, &m.JobState)
	return m, err
}

func (s *Store) listManifests(ctx context.Context, where string, args ...any) ([]Manifest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+manifestCols+manifestFrom+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetManifest reads a revision.
func (s *Store) GetManifest(ctx context.Context, id string) (Manifest, error) {
	m, err := scanManifest(s.db.QueryRowContext(ctx, `SELECT `+manifestCols+manifestFrom+`WHERE r.id = $1`, id))
	return m, mapErr(err)
}

// ChangeManifests are a change's manifest revisions.
func (s *Store) ChangeManifests(ctx context.Context, changeID string) ([]Manifest, error) {
	return s.listManifests(ctx, `WHERE r.change_id = $1 ORDER BY r.bundle, r.id`, changeID)
}

// BundleRevisions are the latest revisions of a bundle, newest first.
func (s *Store) BundleRevisions(ctx context.Context, clusterCI, bundle string, limit int) ([]Manifest, error) {
	return s.listManifests(ctx, `WHERE r.cluster_ci = $1 AND r.bundle = $2 ORDER BY r.created_at DESC LIMIT $3`,
		clusterCI, bundle, limit)
}

// CurrentManifest is the revision of a bundle applied last: what the
// cluster has, as far as Baseline knows. ErrNotFound when none was.
func (s *Store) CurrentManifest(ctx context.Context, clusterCI, bundle string) (Manifest, error) {
	m, err := scanManifest(s.db.QueryRowContext(ctx, `SELECT `+manifestCols+manifestFrom+`
		WHERE r.cluster_ci = $1 AND r.bundle = $2
		  AND EXISTS (SELECT 1 FROM job j WHERE j.change_id = r.change_id AND j.params->>'revision' = r.id::text
		              AND j.state = 'succeeded')
		ORDER BY r.created_at DESC LIMIT 1`, clusterCI, bundle))
	return m, mapErr(err)
}

// Bundle is a bundle of a cluster: its latest revision, and the one
// applied last.
type Bundle struct {
	Latest  Manifest
	Current *Manifest // nil when no revision was applied
	// Pending: a revision newer than Current is in an open change.
	Pending bool
}

// ClusterBundles lists a cluster's bundles by name.
func (s *Store) ClusterBundles(ctx context.Context, clusterCI string) ([]Bundle, error) {
	all, err := s.listManifests(ctx, `WHERE r.cluster_ci = $1 ORDER BY r.bundle, r.created_at DESC`, clusterCI)
	if err != nil {
		return nil, err
	}
	var out []Bundle
	for _, m := range all {
		if len(out) == 0 || out[len(out)-1].Latest.Bundle != m.Bundle {
			out = append(out, Bundle{Latest: m})
		}
		b := &out[len(out)-1]
		if b.Current == nil && m.Applied() {
			c := m
			b.Current = &c
		}
		if b.Current == nil && openChangeStates[m.ChangeState] {
			b.Pending = true
		}
	}
	return out, nil
}

// openChangeStates are the states of changes that may still run.
var openChangeStates = map[string]bool{ChangeDraft: true, ChangeSubmitted: true, ChangeApproved: true,
	ChangeScheduled: true, ChangeInProgress: true}

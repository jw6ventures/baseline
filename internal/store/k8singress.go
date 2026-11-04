package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// ingressHost is one hostname the Ingresses of a cluster route, with
// every Ingress that names it.
type ingressHost struct {
	name      string
	ingresses map[string]bool // namespace/name
	classes   map[string]bool
	backends  map[string]bool // "host/path → service:port", this host's only
	services  map[string]bool // namespace/name of the Services it routes to
	workloads map[string]bool // K8sWorkload.Key, through those Services
	tls       bool
}

// backendService is the Service a backend ("host/path → service:port", or
// "* → service:port" for a default backend) routes to, or "" for a
// resource backend ("→ Kind/name").
func backendService(b string) string {
	_, target, ok := strings.Cut(b, " → ")
	if !ok {
		return ""
	}
	svc, _, ok := strings.Cut(target, ":")
	if !ok || strings.Contains(svc, "/") {
		return ""
	}
	return svc
}

// attrs is what the CI page shows. A hostname gets a URL unless it is a
// wildcard: https when an Ingress naming it has a TLS section.
func (h *ingressHost) attrs(cluster string) map[string]string {
	list := func(m map[string]bool) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return strings.Join(keys, ", ")
	}
	a := map[string]string{"cluster": cluster, "ingresses": list(h.ingresses), "tls": "no"}
	if h.tls {
		a["tls"] = "yes"
	}
	if v := list(h.classes); v != "" {
		a["ingress_class"] = v
	}
	if v := list(h.backends); v != "" {
		a["backends"] = v
	}
	if v := list(h.workloads); v != "" {
		a["workloads"] = v
	}
	if !strings.Contains(h.name, "*") {
		scheme := "http"
		if h.tls {
			scheme = "https"
		}
		a["url"] = scheme + "://" + h.name
	}
	return a
}

// ingressHosts groups the hostnames of a cluster's Ingresses, in order,
// with the workloads behind them: each backend's Service, and the
// workloads that Service selects. An Ingress's default backend serves
// every one of its hostnames.
func ingressHosts(ings []model.K8sIngress, svcs []model.K8sService) []*ingressHost {
	selects := map[string][]string{}
	for _, sv := range svcs {
		selects[sv.Namespace+"/"+sv.Name] = sv.Workloads
	}
	byName := map[string]*ingressHost{}
	var out []*ingressHost
	for _, ing := range ings {
		for _, host := range ing.Hosts {
			name := strings.ToLower(strings.TrimSpace(host))
			if name == "" {
				continue
			}
			h := byName[name]
			if h == nil {
				h = &ingressHost{name: name, ingresses: map[string]bool{}, classes: map[string]bool{}, backends: map[string]bool{},
					services: map[string]bool{}, workloads: map[string]bool{}}
				byName[name] = h
				out = append(out, h)
			}
			h.ingresses[ing.Namespace+"/"+ing.Name] = true
			if ing.Class != "" {
				h.classes[ing.Class] = true
			}
			h.tls = h.tls || ing.TLS
			for _, b := range ing.Backends {
				mine := strings.HasPrefix(strings.ToLower(b), name+"/")
				if mine {
					h.backends[b] = true
				}
				if svc := backendService(b); svc != "" && (mine || strings.HasPrefix(b, "* → ")) {
					key := ing.Namespace + "/" + svc
					h.services[key] = true
					for _, w := range selects[key] {
						h.workloads[w] = true
					}
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b *ingressHost) int { return strings.Compare(a.name, b.name) })
	return out
}

// projectK8sIngresses keeps a service_endpoint CI for every hostname the
// cluster's Ingresses route, member_of the cluster and hosted_by the
// workloads serving it, as projectTraefik does for Traefik's router
// labels. workloadCI maps K8sWorkload.Key to the cluster's workload CIs.
func projectK8sIngresses(ctx context.Context, tx *sql.Tx, clusterCI, clusterUID, clusterName string,
	ings []model.K8sIngress, svcs []model.K8sService, workloadCI map[string]string) error {
	var present []string
	for _, h := range ingressHosts(ings, svcs) {
		attrs, err := json.Marshal(h.attrs(clusterName))
		if err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, source, source_key, status, last_seen, attrs)
			VALUES ('service_endpoint', $2, 'k8s', $1, 'active', now(), $3)
			ON CONFLICT (source, source_key) DO UPDATE
			SET status = 'active', last_seen = now(), attrs = EXCLUDED.attrs,
			    updated_at = CASE WHEN ci.status <> 'active' OR ci.attrs <> EXCLUDED.attrs THEN now() ELSE ci.updated_at END
			RETURNING id`, clusterUID+"/ingress:"+h.name, h.name, string(attrs)).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO k8s_ingress_host (ci_id, cluster_ci, hostname, present) VALUES ($1, $2, $3, true)
			ON CONFLICT (ci_id) DO UPDATE SET cluster_ci = EXCLUDED.cluster_ci, present = true`,
			id, clusterCI, h.name); err != nil {
			return err
		}
		if err := relate(ctx, tx, id, clusterCI, "member_of"); err != nil {
			return err
		}
		// Who serves it is rebuilt every time; one that went away keeps
		// its last relationships, like a workload does.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM ci_relationship WHERE from_ci = $1 AND source = 'discovered' AND kind = 'hosted_by'`, id); err != nil {
			return err
		}
		for w := range h.workloads {
			if wid := workloadCI[w]; wid != "" {
				if err := relate(ctx, tx, id, wid, "hosted_by"); err != nil {
					return err
				}
			}
		}
		present = append(present, id)
	}
	// Hostnames that went away: their CI turns missing an hour from now
	// unless an Ingress names them again.
	_, err := tx.ExecContext(ctx, `
		WITH gone AS (
		    UPDATE k8s_ingress_host SET present = false
		    WHERE cluster_ci = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
		UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`,
		clusterCI, pq.Array(nonNil(present)))
	return err
}

// ClusterEndpoints maps the hostnames of a cluster's Ingresses to their
// service_endpoint CIs, for the cluster page to link.
func (s *Store) ClusterEndpoints(ctx context.Context, clusterCI string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT hostname, ci_id FROM k8s_ingress_host WHERE cluster_ci = $1 AND present`, clusterCI)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, id string
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		out[name] = id
	}
	return out, rows.Err()
}

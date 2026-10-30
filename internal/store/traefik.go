package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/traefik"
)

// traefikEndpoint is a hostname, or pattern, the Traefik labels of a host's
// containers route to them.
type traefikEndpoint struct {
	name                                  string
	regexp                                bool
	matchers, routers, entrypoints, ports map[string]bool
	tls, http                             bool
	containers, stacks                    map[string]bool // CI IDs
}

func (e *traefikEndpoint) sourceKey(hostID string) string {
	if e.regexp {
		return hostID + "/traefik-re:" + e.name
	}
	return hostID + "/traefik:" + e.name
}

// attrs is what the CI page shows. A hostname an HTTP router serves gets a
// URL: https when a router for it has TLS or listens on an entry point
// named websecure or https (TLS set on the entry point in Traefik's static
// configuration isn't visible in labels).
func (e *traefikEndpoint) attrs() map[string]string {
	list := func(m map[string]bool) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return strings.Join(keys, ", ")
	}
	a := map[string]string{"matchers": list(e.matchers), "routers": list(e.routers), "tls": "no"}
	if e.tls {
		a["tls"] = "yes"
	}
	if v := list(e.entrypoints); v != "" {
		a["entrypoints"] = v
	}
	if v := list(e.ports); v != "" {
		a["ports"] = v
	}
	if e.http && !e.regexp {
		scheme := "http"
		if e.tls {
			scheme = "https"
		}
		a["url"] = scheme + "://" + e.name
	}
	return a
}

// traefikEndpoints groups the hosts the containers' router labels match.
// ctrCI maps container keys (engine/name) to their CIs, stackCI stacks
// (engine/project) to theirs.
func traefikEndpoints(ctrs []model.Container, ctrCI, stackCI map[string]string) []*traefikEndpoint {
	type key struct {
		regexp bool
		name   string
	}
	byKey := map[key]*traefikEndpoint{}
	var out []*traefikEndpoint
	for _, ct := range ctrs {
		for _, r := range traefik.Routers(ct.Labels) {
			for _, m := range r.Matches {
				k := key{m.Regexp(), m.Value}
				e := byKey[k]
				if e == nil {
					e = &traefikEndpoint{name: m.Value, regexp: m.Regexp(), matchers: map[string]bool{},
						routers: map[string]bool{}, entrypoints: map[string]bool{}, ports: map[string]bool{},
						containers: map[string]bool{}, stacks: map[string]bool{}}
					byKey[k] = e
					out = append(out, e)
				}
				e.matchers[m.Kind] = true
				e.routers[r.Name] = true
				for _, ep := range r.EntryPoints {
					e.entrypoints[ep] = true
					if r.Protocol == "http" && (strings.EqualFold(ep, "websecure") || strings.EqualFold(ep, "https")) {
						e.tls = true
					}
				}
				if r.Port != 0 {
					e.ports[strconv.Itoa(r.Port)] = true
				}
				e.tls = e.tls || r.TLS
				e.http = e.http || r.Protocol == "http"
				if id := ctrCI[ct.Key()]; id != "" {
					e.containers[id] = true
				}
				if id := stackCI[ct.Engine+"/"+ct.ComposeProject]; id != "" && ct.ComposeProject != "" {
					e.stacks[id] = true
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b *traefikEndpoint) int {
		if a.regexp != b.regexp {
			if a.regexp {
				return 1
			}
			return -1
		}
		return strings.Compare(a.name, b.name)
	})
	return out
}

// projectTraefik keeps a service_endpoint CI for every hostname the
// Traefik labels of a host's containers route to them, related to the
// containers serving it (hosted_by) and their stacks (member_of).
func projectTraefik(ctx context.Context, tx *sql.Tx, hostID string, ctrs []model.Container, ctrCI, stackCI map[string]string) error {
	var present []string
	for _, e := range traefikEndpoints(ctrs, ctrCI, stackCI) {
		attrs, err := json.Marshal(e.attrs())
		if err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, source, source_key, status, last_seen, attrs)
			VALUES ('service_endpoint', $2, 'agent', $1, 'active', now(), $3)
			ON CONFLICT (source, source_key) DO UPDATE
			SET status = 'active', last_seen = now(), attrs = EXCLUDED.attrs,
			    updated_at = CASE WHEN ci.status <> 'active' OR ci.attrs <> EXCLUDED.attrs THEN now() ELSE ci.updated_at END
			RETURNING id`, e.sourceKey(hostID), e.name, string(attrs)).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO traefik_hostname (ci_id, host, hostname, regexp, present) VALUES ($1, $2, $3, $4, true)
			ON CONFLICT (ci_id) DO UPDATE SET present = true`, id, hostID, e.name, e.regexp); err != nil {
			return err
		}
		// Who serves it is rebuilt every time; one that went away keeps
		// its last relationships, like a container does.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM ci_relationship WHERE from_ci = $1 AND source = 'discovered' AND kind IN ('hosted_by', 'member_of')`,
			id); err != nil {
			return err
		}
		for c := range e.containers {
			if err := relate(ctx, tx, id, c, "hosted_by"); err != nil {
				return err
			}
		}
		for st := range e.stacks {
			if err := relate(ctx, tx, id, st, "member_of"); err != nil {
				return err
			}
		}
		present = append(present, id)
	}
	if _, err := tx.ExecContext(ctx, `
		WITH gone AS (
		    UPDATE traefik_hostname SET present = false
		    WHERE host = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
		UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`,
		hostID, pq.Array(nonNil(present))); err != nil {
		return err
	}
	return relateTraefikProxies(ctx, tx, hostID)
}

// traefikImage matches the image references of Traefik containers:
// traefik:v3.1, docker.io/library/traefik, ghcr.io/x/traefik@sha256:...
const traefikImage = `(^|/)traefik([:@]|$)`

// traefikProxies are the CIs a host's hostnames are routed by: Traefik
// containers on the host, and the Traefik node set for it.
const traefikProxies = `
	SELECT c.ci_id AS id FROM container c WHERE c.host = $1 AND c.image_ref ~ '` + traefikImage + `'
	UNION SELECT h.traefik_ci FROM host h WHERE h.ci_id = $1 AND h.traefik_ci IS NOT NULL`

// relateTraefikProxies has a host's present hostnames depend_on the
// Traefik that routes them.
func relateTraefikProxies(ctx context.Context, tx *sql.Tx, hostID string) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM ci_relationship r USING traefik_hostname th
		WHERE r.from_ci = th.ci_id AND th.host = $1 AND th.present AND r.source = 'discovered' AND r.kind = 'depends_on'`,
		hostID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ci_relationship (from_ci, to_ci, kind, source)
		SELECT th.ci_id, p.id, 'depends_on', 'discovered' FROM traefik_hostname th CROSS JOIN (`+traefikProxies+`) p
		WHERE th.host = $1 AND th.present
		ON CONFLICT (from_ci, to_ci, kind) DO NOTHING`, hostID)
	return err
}

// TraefikRouting is how a host's hostnames reach Traefik.
type TraefikRouting struct {
	Local []CI // Traefik containers on the host
	Node  *CI  // the Traefik set for it on another node
}

// HostTraefik returns the Traefik a host's hostnames are routed by.
func (s *Store) HostTraefik(ctx context.Context, hostID string) (TraefikRouting, error) {
	var tr TraefikRouting
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+ciCols+`, COALESCE(ci.id = (SELECT traefik_ci FROM host WHERE ci_id = $1), false) FROM ci JOIN ci_type t ON t.key = ci.type
		WHERE ci.id IN (`+traefikProxies+`)
		ORDER BY lower(ci.name)`, hostID)
	if err != nil {
		return tr, err
	}
	defer rows.Close()
	for rows.Next() {
		var c CI
		var attrs string
		var node bool
		if err := rows.Scan(&c.ID, &c.Type, &c.TypeLabel, &c.Name, &c.Status, &c.Source, &c.Owner, &c.Description,
			pq.Array(&c.Tags), &attrs, &c.FirstSeen, &c.LastSeen, &c.UpdatedAt, &c.HostID, &c.Relation, &node); err != nil {
			return tr, err
		}
		json.Unmarshal([]byte(attrs), &c.Attrs)
		if node {
			tr.Node = &c
		} else {
			tr.Local = append(tr.Local, c)
		}
	}
	return tr, rows.Err()
}

// TraefikNodes lists what a host can be routed by: Traefik containers on
// the given hosts, then the hosts themselves (for Traefik run as a
// service), leaving out the host asking.
func (s *Store) TraefikNodes(ctx context.Context, hostID string, hostIDs []string) ([]CI, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+ciCols+` FROM ci JOIN ci_type t ON t.key = ci.type
		WHERE ci.status = 'active' AND (
		    ci.id IN (SELECT c.ci_id FROM container c WHERE c.host::text = ANY($2) AND c.host <> $1
		              AND c.image_ref ~ '`+traefikImage+`')
		    OR (ci.type = 'host' AND ci.id::text = ANY($2) AND ci.id <> $1))
		ORDER BY ci.type <> 'container', lower(ci.name)`, hostID, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CI
	for rows.Next() {
		c, err := scanCI(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetHostTraefik sets ("" clears) the Traefik on another node that routes
// a host's hostnames: a container or a host CI.
func (s *Store) SetHostTraefik(ctx context.Context, actor Actor, hostID, ciID string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if ciID != "" {
			var typ string
			if err := tx.QueryRowContext(ctx, `SELECT type, name FROM ci WHERE id = $1`, ciID).Scan(&typ, &name); err != nil {
				return mapErr(err)
			}
			if (typ != "host" && typ != "container") || ciID == hostID {
				return ErrConflict
			}
		}
		var hostname string
		if err := tx.QueryRowContext(ctx, `UPDATE host SET traefik_ci = $2 WHERE ci_id = $1 RETURNING hostname`,
			hostID, nullString(ciID)).Scan(&hostname); err != nil {
			return mapErr(err)
		}
		if err := relateTraefikProxies(ctx, tx, hostID); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host.traefik", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"hostname": hostname, "traefik": ciID, "traefik_name": name},
		})
	})
}

// ServedHostnames lists the hostnames Traefik routes to a container or a
// Compose stack, as discovery found them: active service_endpoint CIs
// hosted by the container or belonging to the stack.
func (s *Store) ServedHostnames(ctx context.Context, ciID string) ([]CI, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+ciCols+` FROM ci JOIN ci_type t ON t.key = ci.type
		WHERE ci.type = 'service_endpoint' AND ci.source = 'agent' AND ci.status = 'active'
		  AND ci.id IN (SELECT from_ci FROM ci_relationship
		                WHERE to_ci = $1 AND source = 'discovered' AND kind IN ('hosted_by', 'member_of'))
		ORDER BY (SELECT regexp FROM traefik_hostname th WHERE th.ci_id = ci.id), lower(ci.name)`, ciID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CI
	for rows.Next() {
		c, err := scanCI(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

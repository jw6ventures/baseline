package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// ErrNotManual refuses edits to CIs that discovery maintains.
var ErrNotManual = errors.New("only manually created CIs can be edited")

// CIType is a kind of configuration item and, for agentless ones, the
// fields its form has.
type CIType struct {
	Key    string
	Label  string
	Fields []CIField
}

type CIField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Type  string `json:"type"` // text | textarea | date | url | endpoint
	// Discovered fields are filled by discovery, and aren't on the form.
	Discovered bool `json:"discovered,omitempty"`
}

// discoveredTypes are maintained by agents only. VMs and LXC containers are
// discovered on Proxmox and libvirt hosts, and can be added by hand too.
var discoveredTypes = []string{"host", "container", "compose_stack", "k8s_cluster", "k8s_node", "k8s_workload"}

// Manual reports whether CIs of this type can be created by hand.
func (t CIType) Manual() bool { return !slices.Contains(discoveredTypes, t.Key) }

func (s *Store) CITypes(ctx context.Context) ([]CIType, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, label, attr_schema::text FROM ci_type ORDER BY label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CIType
	for rows.Next() {
		var t CIType
		var schema string
		if err := rows.Scan(&t.Key, &t.Label, &schema); err != nil {
			return nil, err
		}
		var sc struct {
			Fields []CIField `json:"fields"`
		}
		json.Unmarshal([]byte(schema), &sc)
		t.Fields = sc.Fields
		out = append(out, t)
	}
	return out, rows.Err()
}

// CI is a configuration item.
type CI struct {
	ID          string
	Type        string
	TypeLabel   string
	Name        string
	Status      string // active | retired | planned | missing
	Source      string // agent | manual | ...
	Owner       string
	Description string
	Tags        []string
	Attrs       map[string]any
	FirstSeen   time.Time
	LastSeen    time.Time
	UpdatedAt   time.Time
	// HostID is the host a discovered CI lives on (the host itself for a
	// host), for permission checks; "" for agentless CIs.
	HostID   string
	Relation int // relationships, in either direction
}

func (c CI) Manual() bool { return c.Source == "manual" }

// Agentless reports whether a CI lives on no host: made by hand, or kept by
// a UniFi console's polls. Every viewer sees agentless CIs.
func (c CI) Agentless() bool { return c.Source == "manual" || c.Source == "unifi" }

// AgentlessSQL is Agentless for a CI aliased ci.
const AgentlessSQL = `ci.source IN ('manual', 'unifi')`

// Attr returns an attribute as text.
func (c CI) Attr(key string) string {
	switch v := c.Attrs[key].(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// CIHostRef is SQL for the host a CI (aliased ci) lives on, as text (empty
// for an agentless one): what permission checks go by.
const CIHostRef = `COALESCE((SELECT h.ci_id::text FROM host h WHERE h.ci_id = ci.id),
	         (SELECT c.host::text FROM container c WHERE c.ci_id = ci.id),
	         (SELECT s.host::text FROM compose_stack s WHERE s.ci_id = ci.id),
	         (SELECT th.host::text FROM traefik_hostname th WHERE th.ci_id = ci.id),
	         (SELECT g.host::text FROM vm_guest g WHERE g.ci_id = ci.id),
	         (SELECT k.host::text FROM k8s_cluster k WHERE k.ci_id = ci.id),
	         (SELECT o.host::text FROM k8s_object o WHERE o.ci_id = ci.id),
	         (SELECT k.host::text FROM k8s_ingress_host ih JOIN k8s_cluster k ON k.ci_id = ih.cluster_ci WHERE ih.ci_id = ci.id),
	         CASE WHEN ci.type IN ('container', 'compose_stack') THEN split_part(ci.source_key, '/', 1) END, '')`

const ciCols = `ci.id, ci.type, t.label, ci.name, ci.status, ci.source, ci.owner, ci.description, ci.tags, ci.attrs::text,
	ci.first_seen, ci.last_seen, ci.updated_at,
	` + CIHostRef + ` AS host_ref,
	(SELECT count(*) FROM ci_relationship r WHERE r.from_ci = ci.id OR r.to_ci = ci.id) AS rels`

func scanCI(row interface{ Scan(...any) error }) (CI, error) {
	var c CI
	var attrs string
	err := row.Scan(&c.ID, &c.Type, &c.TypeLabel, &c.Name, &c.Status, &c.Source, &c.Owner, &c.Description,
		pq.Array(&c.Tags), &attrs, &c.FirstSeen, &c.LastSeen, &c.UpdatedAt, &c.HostID, &c.Relation)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal([]byte(attrs), &c.Attrs)
}

// CIFilter narrows ListCIs. Hosts limits discovered CIs to those living on
// the given hosts; agentless CIs are visible to every viewer.
type CIFilter struct {
	Type    string
	Status  string // "" = everything but retired and missing
	Query   string
	HostIDs []string
	Limit   int
}

func (s *Store) ListCIs(ctx context.Context, f CIFilter) ([]CI, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT * FROM (SELECT `+ciCols+` FROM ci JOIN ci_type t ON t.key = ci.type) x
		WHERE ($1 = '' OR x.type = $1)
		  AND (CASE WHEN $2 = '' THEN x.status IN ('active', 'planned') WHEN $2 = 'all' THEN true ELSE x.status = $2 END)
		  AND ($3 = '' OR strpos(lower(x.name || ' ' || x.description || ' ' || array_to_string(x.tags, ' ')), lower($3)) > 0)
		  AND (x.source IN ('manual', 'unifi') OR x.host_ref = ANY($4))
		ORDER BY x.label, lower(x.name)
		LIMIT $5`, f.Type, f.Status, strings.TrimSpace(f.Query), pq.Array(nonNil(f.HostIDs)), f.Limit)
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

func (s *Store) GetCI(ctx context.Context, id string) (CI, error) {
	c, err := scanCI(s.db.QueryRowContext(ctx, `SELECT `+ciCols+` FROM ci JOIN ci_type t ON t.key = ci.type WHERE ci.id = $1`, id))
	return c, mapErr(err)
}

// CIInput is the editable part of a manual CI.
type CIInput struct {
	Type        string
	Name        string
	Status      string
	Owner       string
	Description string
	Tags        []string
	Attrs       map[string]string
}

func (in CIInput) attrs() map[string]string {
	out := map[string]string{}
	for k, v := range in.Attrs {
		if v = strings.TrimSpace(v); v != "" {
			out[k] = v
		}
	}
	return out
}

// CreateCI adds an agentless CI.
func (s *Store) CreateCI(ctx context.Context, actor Actor, in CIInput) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		attrs, err := json.Marshal(in.attrs())
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, status, source, owner, description, tags, attrs)
			VALUES ($1, $2, $3, 'manual', $4, $5, $6, $7) RETURNING id`,
			in.Type, in.Name, in.Status, in.Owner, in.Description, pq.Array(nonNil(in.Tags)), string(attrs)).Scan(&id); err != nil {
			return mapErr(err)
		}
		if err := addHistory(ctx, tx, id, actor.ID, "ci", map[string]any{"initial": true}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "ci.create", ObjectType: "ci", ObjectID: id,
			Details: map[string]any{"type": in.Type, "name": in.Name},
		})
	})
	return id, err
}

// UpdateCI edits an agentless CI, recording what changed in its history.
func (s *Store) UpdateCI(ctx context.Context, actor Actor, id string, in CIInput) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var source, name, status, owner, desc, attrs string
		var tags []string
		if err := tx.QueryRowContext(ctx, `
			SELECT source, name, status, owner, description, tags, attrs::text FROM ci WHERE id = $1 FOR UPDATE`, id).
			Scan(&source, &name, &status, &owner, &desc, pq.Array(&tags), &attrs); err != nil {
			return mapErr(err)
		}
		if source != "manual" {
			return ErrNotManual
		}
		var before map[string]string
		json.Unmarshal([]byte(attrs), &before)
		after := in.attrs()
		var changes []inventory.Change
		diff := func(field, from, to string) {
			if from != to {
				changes = append(changes, inventory.Change{Field: field, From: from, To: to})
			}
		}
		diff("name", name, in.Name)
		diff("status", status, in.Status)
		diff("owner", owner, in.Owner)
		diff("description", desc, in.Description)
		diff("tags", strings.Join(tags, ", "), strings.Join(in.Tags, ", "))
		keys := map[string]bool{}
		for k := range before {
			keys[k] = true
		}
		for k := range after {
			keys[k] = true
		}
		var sorted []string
		for k := range keys {
			sorted = append(sorted, k)
		}
		slices.Sort(sorted)
		for _, k := range sorted {
			diff("attrs."+k, before[k], after[k])
		}
		if len(changes) == 0 {
			return nil
		}
		b, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE ci SET name = $2, status = $3, owner = $4, description = $5, tags = $6, attrs = $7, updated_at = now()
			WHERE id = $1`, id, in.Name, in.Status, in.Owner, in.Description, pq.Array(nonNil(in.Tags)), string(b)); err != nil {
			return err
		}
		if err := addHistory(ctx, tx, id, actor.ID, "ci", map[string]any{"changed": changes}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "ci.update", ObjectType: "ci", ObjectID: id, Details: map[string]any{"name": in.Name, "changed": changes},
		})
	})
}

// DeleteCI removes a manual CI, or a discovered one that is missing or
// retired. Its relationships and history go with it; the audit log keeps
// the record.
func (s *Store) DeleteCI(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var typ, name, source, status string
		if err := tx.QueryRowContext(ctx, `SELECT type, name, source, status FROM ci WHERE id = $1 FOR UPDATE`, id).
			Scan(&typ, &name, &source, &status); err != nil {
			return mapErr(err)
		}
		if source != "manual" && (typ == "host" || (status != "missing" && status != "retired")) {
			return ErrNotManual
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ci WHERE id = $1`, id); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "ci.delete", ObjectType: "ci", ObjectID: id, Details: map[string]any{"type": typ, "name": name, "source": source},
		})
	})
}

// Relationships ------------------------------------------------------------------

// RelationKinds are the relationship kinds, as "from <kind> to".
var RelationKinds = []string{"runs_on", "hosted_by", "member_of", "depends_on", "connected_to", "contains", "uses"}

type Relationship struct {
	ID     string
	Kind   string
	Source string // discovered | manual
	// Outgoing is true when the CI asked about is the "from" side.
	Outgoing bool
	Other    CI
	// Note qualifies it, e.g. the switch port a wired client is on.
	Note string
}

// CIRelationships lists a CI's relationships in both directions.
func (s *Store) CIRelationships(ctx context.Context, id string) ([]Relationship, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.kind, r.source, r.from_ci = $1, r.attrs::text, `+ciCols+`
		FROM ci_relationship r JOIN ci ON ci.id = CASE WHEN r.from_ci = $1 THEN r.to_ci ELSE r.from_ci END
		JOIN ci_type t ON t.key = ci.type
		WHERE r.from_ci = $1 OR r.to_ci = $1
		ORDER BY r.from_ci <> $1, r.kind, lower(ci.name)`, id)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Relationship
	for rows.Next() {
		var r Relationship
		var c CI
		var attrs, relAttrs string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Source, &r.Outgoing, &relAttrs,
			&c.ID, &c.Type, &c.TypeLabel, &c.Name, &c.Status, &c.Source, &c.Owner, &c.Description,
			pq.Array(&c.Tags), &attrs, &c.FirstSeen, &c.LastSeen, &c.UpdatedAt, &c.HostID, &c.Relation); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(attrs), &c.Attrs)
		var ra map[string]any
		json.Unmarshal([]byte(relAttrs), &ra)
		r.Note = unifiPortLabel(ra)
		r.Other = c
		out = append(out, r)
	}
	return out, rows.Err()
}

// Edge is one relationship as the CI map draws it: from and to are CI IDs.
type Edge struct {
	From, To, Kind, Source string
}

// AllRelationships lists every relationship, for the CI map. The caller
// drops the ones whose ends the user can't see.
func (s *Store) AllRelationships(ctx context.Context) ([]Edge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT from_ci, to_ci, kind, source FROM ci_relationship ORDER BY kind, from_ci, to_ci`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.From, &e.To, &e.Kind, &e.Source); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddRelationship records a manual relationship.
func (s *Store) AddRelationship(ctx context.Context, actor Actor, from, to, kind string) error {
	if from == to {
		return ErrConflict
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci_relationship (from_ci, to_ci, kind, source) VALUES ($1, $2, $3, 'manual') RETURNING id`,
			from, to, kind).Scan(&id); err != nil {
			return mapErr(err)
		}
		for _, ci := range []string{from, to} {
			if err := addHistory(ctx, tx, ci, actor.ID, "relationships", map[string]any{
				"added": []inventory.Change{{Field: kind, To: relLabel(ctx, tx, from, to)}},
			}); err != nil {
				return err
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "ci.relate", ObjectType: "ci", ObjectID: from, Details: map[string]any{"to": to, "kind": kind},
		})
	})
}

// DeleteRelationship removes a manual relationship of the CI ciID.
// Discovered ones follow discovery.
func (s *Store) DeleteRelationship(ctx context.Context, actor Actor, ciID, relID string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var from, to, kind string
		if err := tx.QueryRowContext(ctx, `
			DELETE FROM ci_relationship WHERE id = $1 AND source = 'manual' AND (from_ci = $2 OR to_ci = $2)
			RETURNING from_ci, to_ci, kind`, relID, ciID).Scan(&from, &to, &kind); err != nil {
			return mapErr(err)
		}
		for _, ci := range []string{from, to} {
			if err := addHistory(ctx, tx, ci, actor.ID, "relationships", map[string]any{
				"removed": []inventory.Change{{Field: kind, From: relLabel(ctx, tx, from, to)}},
			}); err != nil {
				return err
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "ci.unrelate", ObjectType: "ci", ObjectID: from, Details: map[string]any{"to": to, "kind": kind},
		})
	})
}

// relLabel describes a relationship for history: "web1 → nas1".
func relLabel(ctx context.Context, tx *sql.Tx, from, to string) string {
	var a, b string
	tx.QueryRowContext(ctx, `SELECT (SELECT name FROM ci WHERE id = $1), (SELECT name FROM ci WHERE id = $2)`, from, to).Scan(&a, &b)
	return a + " → " + b
}

// CIHistory lists a CI's history entries, newest first.
func (s *Store) CIHistory(ctx context.Context, id string, limit int) ([]HistoryEntry, error) {
	return s.HostHistory(ctx, id, limit)
}

// Endpoint probes ------------------------------------------------------------

// Endpoint is an agentless CI's TLS endpoint the server checks itself.
type Endpoint struct {
	CIID    string
	Address string // host:port
}

// TLSEndpoints lists the TLS endpoints configured on active CIs.
func (s *Store) TLSEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, attrs->>'tls_endpoint' FROM ci
		WHERE source = 'manual' AND status = 'active' AND COALESCE(attrs->>'tls_endpoint', '') <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.CIID, &e.Address); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

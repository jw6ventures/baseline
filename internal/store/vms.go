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

// keepFailedPlatforms carries over the guests (and Proxmox storage) of
// hypervisors that couldn't be read this time, like keepFailedEngines does
// for containers: libvirtd restarting shouldn't read as every VM removed.
func keepFailedPlatforms(prev, cur []byte) ([]byte, error) {
	var p, c model.VMs
	if err := json.Unmarshal(cur, &c); err != nil {
		return nil, err
	}
	failed := map[string]bool{}
	for _, h := range c.Hypervisors {
		if h.Error != "" {
			failed[h.Platform] = true
		}
	}
	if len(failed) == 0 || prev == nil {
		return cur, nil
	}
	if err := json.Unmarshal(prev, &p); err != nil {
		return cur, nil
	}
	for _, g := range p.Guests {
		if failed[g.Platform] {
			c.Guests = append(c.Guests, g)
		}
	}
	if failed["proxmox"] && len(c.Storage) == 0 {
		c.Storage = p.Storage
	}
	slices.SortFunc(c.Guests, func(a, b model.Guest) int { return strings.Compare(a.Key(), b.Key()) })
	return json.Marshal(c)
}

// guestSourceKey identifies a guest across the hypervisors that may run it:
// a Proxmox VMID is unique in its cluster (or on a standalone node), and a
// libvirt domain keeps its UUID when it migrates.
func guestSourceKey(hostID string, hv model.Hypervisor, g model.Guest) string {
	if g.Platform != "proxmox" {
		return g.ID
	}
	switch {
	case hv.Cluster != "":
		return hv.Cluster + "/" + g.ID
	case hv.Node != "":
		return "node:" + hv.Node + "/" + g.ID
	}
	return "host:" + hostID + "/" + g.ID
}

func guestType(g model.Guest) string {
	if g.Kind == "lxc" {
		return "lxc"
	}
	return "vm"
}

func projectVMs(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var v model.VMs
	if err := json.Unmarshal(payload, &v); err != nil {
		return err
	}
	hvs := map[string]model.Hypervisor{}
	for _, h := range v.Hypervisors {
		hvs[h.Platform] = h
	}
	var present []string
	for _, g := range v.Guests {
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, source, source_key, status, last_seen)
			VALUES ($1, $2, $3, $4, 'active', now())
			ON CONFLICT (source, source_key) DO UPDATE
			SET status = 'active', last_seen = now(), name = EXCLUDED.name,
			    updated_at = CASE WHEN ci.status <> 'active' OR ci.name <> EXCLUDED.name THEN now() ELSE ci.updated_at END
			RETURNING id`, guestType(g), g.Name, g.Platform, guestSourceKey(hostID, hvs[g.Platform], g)).Scan(&id); err != nil {
			return err
		}
		var macs []string
		for _, n := range g.NICs {
			if n.MAC != "" {
				macs = append(macs, strings.ToLower(n.MAC))
			}
		}
		config, err := json.Marshal(g)
		if err != nil {
			return err
		}
		// A guest that migrated here from another node moves with it.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vm_guest (ci_id, host, platform, kind, guest_id, name, uuid, macs, state, config, present)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
			ON CONFLICT (ci_id) DO UPDATE
			SET host = EXCLUDED.host, kind = EXCLUDED.kind, guest_id = EXCLUDED.guest_id, name = EXCLUDED.name,
			    uuid = EXCLUDED.uuid, macs = EXCLUDED.macs, state = EXCLUDED.state, config = EXCLUDED.config, present = true`,
			id, hostID, g.Platform, g.Kind, g.ID, g.Name, strings.ToLower(g.UUID), pq.Array(nonNil(macs)), g.State,
			string(config)); err != nil {
			return err
		}
		if err := relate(ctx, tx, id, hostID, "runs_on"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM ci_relationship WHERE from_ci = $1 AND kind = 'runs_on' AND source = 'discovered' AND to_ci <> $2`,
			id, hostID); err != nil {
			return err
		}
		present = append(present, id)
	}
	// Guests that went away: their CI turns missing an hour from now
	// unless they come back (or show up on another node).
	if _, err := tx.ExecContext(ctx, `
		WITH gone AS (
		    UPDATE vm_guest SET present = false
		    WHERE host = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
		UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`,
		hostID, pq.Array(nonNil(present))); err != nil {
		return err
	}
	return linkDiscovered(ctx, tx)
}

// linkLockKey serializes linkDiscovered: it rewrites relationships across
// every host, so two ingests doing it at once could deadlock.
const linkLockKey = 0x6a636d6c6b // "jcmlk"

// linkDiscovered joins the records discovery keeps of one machine from two
// sides (docs/agent.md §4): a host whose agent runs inside a VM or LXC
// container runs_on that guest's CI, matched by the DMI product UUID (VMs
// only: an LXC container sees its hypervisor's) or else a NIC MAC; and a
// Kubernetes node runs_on the host whose agent reports its machine-id or
// DMI UUID. It recomputes every such link, which is cheap at homelab scale,
// and drops the ones that no longer hold.
func linkDiscovered(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, linkLockKey); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		WITH hm AS (
		    SELECT h.ci_id, h.dmi_uuid, h.machine_id,
		           ARRAY(SELECT DISTINCT lower(n->>'mac')
		                 FROM host_inventory i, jsonb_array_elements(CASE WHEN jsonb_typeof(i.data->'nics') = 'array'
		                      THEN i.data->'nics' ELSE '[]' END) n
		                 WHERE i.host = h.ci_id AND i.section = 'hardware'
		                   AND COALESCE(n->>'mac', '') NOT IN ('', '00:00:00:00:00:00')) AS macs
		    FROM host h WHERE NOT h.revoked AND NOT $1 = ANY(h.capabilities)
		), want AS (
		    (SELECT DISTINCT ON (hm.ci_id) hm.ci_id AS from_ci, g.ci_id AS to_ci
		     FROM hm JOIN vm_guest g ON g.present AND g.host <> hm.ci_id
		       AND ((g.uuid <> '' AND g.kind <> 'lxc' AND g.uuid = hm.dmi_uuid) OR g.macs && hm.macs)
		     ORDER BY hm.ci_id, (g.uuid <> '' AND g.uuid = hm.dmi_uuid) DESC, g.ci_id)
		    UNION ALL
		    (SELECT DISTINCT ON (o.ci_id) o.ci_id, hm.ci_id
		     FROM k8s_object o JOIN hm
		       ON (o.spec_summary->>'machine_id' <> '' AND o.spec_summary->>'machine_id' = hm.machine_id)
		       OR (o.spec_summary->>'system_uuid' <> '' AND o.spec_summary->>'system_uuid' = hm.dmi_uuid)
		     WHERE o.kind = 'Node' AND o.present
		     ORDER BY o.ci_id, (o.spec_summary->>'machine_id' = hm.machine_id) DESC, hm.ci_id)
		), stale AS (
		    DELETE FROM ci_relationship r
		    WHERE r.source = 'discovered' AND r.kind = 'runs_on'
		      AND ((r.from_ci IN (SELECT ci_id FROM host) AND r.to_ci IN (SELECT ci_id FROM vm_guest))
		        OR (r.from_ci IN (SELECT ci_id FROM k8s_object WHERE kind = 'Node')
		            AND r.to_ci IN (SELECT ci_id FROM host)))
		      AND NOT EXISTS (SELECT 1 FROM want w WHERE w.from_ci = r.from_ci AND w.to_ci = r.to_ci)
		)
		INSERT INTO ci_relationship (from_ci, to_ci, kind, source)
		SELECT from_ci, to_ci, 'runs_on', 'discovered' FROM want
		ON CONFLICT (from_ci, to_ci, kind) DO NOTHING`, model.CapK8sCluster)
	return err
}

// Queries ----------------------------------------------------------------------

// Guest is a hypervisor guest with its hypervisor, and the host its own
// agent reports, if one does.
type Guest struct {
	model.Guest
	CIID     string
	Status   string // the CI's: active | missing | retired
	Present  bool
	HostID   string // the hypervisor
	Hostname string
	// HostConnected is whether the hypervisor's agent is connected.
	HostConnected bool
	// AgentHostID and AgentHostname are the host the guest's own agent
	// reports, linked by DMI UUID or MAC; "" when none does.
	AgentHostID   string
	AgentHostname string
}

const guestCols = `g.ci_id, ci.status, g.present, g.host, h.hostname, h.connected, g.config::text,
	COALESCE((SELECT r.from_ci::text FROM ci_relationship r JOIN host a ON a.ci_id = r.from_ci
	          WHERE r.to_ci = g.ci_id AND r.kind = 'runs_on' AND r.source = 'discovered' ORDER BY a.hostname LIMIT 1), ''),
	COALESCE((SELECT a.hostname FROM ci_relationship r JOIN host a ON a.ci_id = r.from_ci
	          WHERE r.to_ci = g.ci_id AND r.kind = 'runs_on' AND r.source = 'discovered' ORDER BY a.hostname LIMIT 1), '')`

const guestFrom = ` FROM vm_guest g JOIN host h ON h.ci_id = g.host JOIN ci ON ci.id = g.ci_id `

func scanGuest(row interface{ Scan(...any) error }) (Guest, error) {
	var g Guest
	var config string
	err := row.Scan(&g.CIID, &g.Status, &g.Present, &g.HostID, &g.Hostname, &g.HostConnected, &config,
		&g.AgentHostID, &g.AgentHostname)
	if err != nil {
		return g, err
	}
	return g, json.Unmarshal([]byte(config), &g.Guest)
}

// ListGuests returns the guests of the given hypervisors, present ones
// first. Retired guests (their hypervisor was revoked) are left out.
func (s *Store) ListGuests(ctx context.Context, hostIDs []string) ([]Guest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+guestCols+guestFrom+`
		WHERE g.host::text = ANY($1) AND ci.status <> 'retired'
		ORDER BY NOT g.present, lower(g.name), lower(h.hostname)`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Guest
	for rows.Next() {
		g, err := scanGuest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetGuest(ctx context.Context, ciID string) (Guest, error) {
	g, err := scanGuest(s.db.QueryRowContext(ctx, `SELECT `+guestCols+guestFrom+` WHERE g.ci_id = $1`, ciID))
	return g, mapErr(err)
}

// GuestOf is the guest a host's agent runs in, with its hypervisor.
type GuestOf struct {
	CIID       string
	Name       string
	Platform   string
	Kind       string
	HostID     string // the hypervisor
	Hostname   string
	Present    bool
	GuestState string
}

// HostGuest returns the guest a host runs in, if discovery linked one.
func (s *Store) HostGuest(ctx context.Context, hostID string) (GuestOf, error) {
	var g GuestOf
	err := s.db.QueryRowContext(ctx, `
		SELECT g.ci_id, g.name, g.platform, g.kind, g.host, h.hostname, g.present, g.state
		FROM ci_relationship r JOIN vm_guest g ON g.ci_id = r.to_ci JOIN host h ON h.ci_id = g.host
		WHERE r.from_ci = $1 AND r.kind = 'runs_on' AND r.source = 'discovered'
		ORDER BY g.present DESC LIMIT 1`, hostID).
		Scan(&g.CIID, &g.Name, &g.Platform, &g.Kind, &g.HostID, &g.Hostname, &g.Present, &g.GuestState)
	return g, mapErr(err)
}

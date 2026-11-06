package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/unifi"
)

// UniFiController is a UniFi console Baseline polls (docs/integrations.md).
type UniFiController struct {
	ID        string
	Name      string
	Config    unifi.Config
	APIKeyEnc string // sealed with BASELINE_SECRET_KEY; "" on save keeps the stored one
	// RunOn is the host whose agent polls it; "" for the server.
	RunOn          string
	RunOnName      string
	Enabled        bool
	NetworkVersion string
	ProtectVersion string
	LastPoll       time.Time // zero: never
	LastOK         time.Time
	LastError      string
	Notes          string
	CreatedAt      time.Time
	// What its last polls keep, present now.
	Sites, Devices, Clients, Protect int
}

const unifiControllerCols = `u.id, u.name, u.config::text, u.api_key_enc, COALESCE(u.run_on::text, ''), COALESCE(h.hostname, ''),
	u.enabled, u.network_version, u.protect_version, u.last_poll, u.last_ok, u.last_error, u.notes, u.created_at,
	(SELECT count(*) FROM unifi_object o WHERE o.controller = u.id AND o.present AND o.kind = 'site'),
	(SELECT count(*) FROM unifi_object o WHERE o.controller = u.id AND o.present AND o.kind = 'device'),
	(SELECT count(*) FROM unifi_object o WHERE o.controller = u.id AND o.present AND o.kind = 'client'),
	(SELECT count(*) FROM unifi_object o WHERE o.controller = u.id AND o.present AND o.kind = 'protect')`

func scanUniFiController(row interface{ Scan(...any) error }) (UniFiController, error) {
	var c UniFiController
	var cfg string
	var lastPoll, lastOK sql.NullTime
	err := row.Scan(&c.ID, &c.Name, &cfg, &c.APIKeyEnc, &c.RunOn, &c.RunOnName, &c.Enabled, &c.NetworkVersion, &c.ProtectVersion,
		&lastPoll, &lastOK, &c.LastError, &c.Notes, &c.CreatedAt, &c.Sites, &c.Devices, &c.Clients, &c.Protect)
	if err != nil {
		return c, err
	}
	c.LastPoll, c.LastOK = lastPoll.Time, lastOK.Time
	return c, json.Unmarshal([]byte(cfg), &c.Config)
}

func (s *Store) ListUniFiControllers(ctx context.Context) ([]UniFiController, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+unifiControllerCols+`
		FROM unifi_controller u LEFT JOIN host h ON h.ci_id = u.run_on ORDER BY lower(u.name), u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UniFiController
	for rows.Next() {
		c, err := scanUniFiController(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetUniFiController(ctx context.Context, id string) (UniFiController, error) {
	c, err := scanUniFiController(s.db.QueryRowContext(ctx, `SELECT `+unifiControllerCols+`
		FROM unifi_controller u LEFT JOIN host h ON h.ci_id = u.run_on WHERE u.id::text = $1`, id))
	return c, mapErr(err)
}

// SaveUniFiController adds a console (ID "") or changes one. An empty
// APIKeyEnc keeps the stored key; a new console needs one.
func (s *Store) SaveUniFiController(ctx context.Context, actor Actor, c UniFiController) (string, error) {
	cfg, err := json.Marshal(c.Config)
	if err != nil {
		return "", err
	}
	runOn := sql.NullString{String: c.RunOn, Valid: c.RunOn != ""}
	id := c.ID
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if id == "" {
			if c.APIKeyEnc == "" {
				return errors.New("an API key is needed")
			}
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO unifi_controller (name, config, api_key_enc, run_on, enabled) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
				c.Name, string(cfg), c.APIKeyEnc, runOn, c.Enabled).Scan(&id); err != nil {
				return err
			}
		} else {
			res, err := tx.ExecContext(ctx, `
				UPDATE unifi_controller SET name = $2, config = $3, api_key_enc = COALESCE(NULLIF($4, ''), api_key_enc),
				    run_on = $5, enabled = $6, last_poll = NULL
				WHERE id::text = $1`, id, c.Name, string(cfg), c.APIKeyEnc, runOn, c.Enabled)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		runs := "server"
		if c.RunOn != "" {
			runs = "host " + c.RunOn
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "unifi_controller.save", ObjectType: "unifi_controller", ObjectID: id,
			Details: map[string]any{"name": c.Name, "url": c.Config.URL, "sites": c.Config.Sites, "protect": c.Config.Protect,
				"tls_pinned": c.Config.TLSFingerprint != "", "runs_on": runs, "enabled": c.Enabled, "key_changed": c.APIKeyEnc != ""},
		})
	})
	return id, err
}

// DeleteUniFiController removes a console. The CIs its polls kept stay,
// and turn missing an hour later.
func (s *Store) DeleteUniFiController(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE ci SET last_seen = now() FROM unifi_object o WHERE o.ci_id = ci.id AND o.controller::text = $1`, id); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM unifi_controller WHERE id::text = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "unifi_controller.delete", ObjectType: "unifi_controller", ObjectID: id, Details: map[string]any{"name": name},
		})
	})
}

// UniFiPollFailed records a poll that read nothing; what earlier polls
// found stays as it was.
func (s *Store) UniFiPollFailed(ctx context.Context, id string, at time.Time, msg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE unifi_controller SET last_poll = $2, last_error = $3 WHERE id::text = $1`, id, at, msg)
	return err
}

// unifiOffline are the states a device or Protect device is down in.
var unifiOffline = []string{"OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED", "DISCONNECTED"}

// IngestUniFi stores what a poll of a console found: a site CI per site, a
// network_device CI per adopted device (member_of its site, connected_to
// its uplink), a camera or protect_device CI per Protect device, and a
// connected_to relationship from each client to the device it is plugged
// into or, wireless, the access point it is associated with. A client is
// the CI that already has its MAC (a Protect device, a host's NIC, a guest,
// an agentless CI's MAC field) or else, wired only, a network_client CI of
// its own; a network_client whose MAC has since turned up on another CI is
// merged into it. A wireless client no CI has the MAC of is left out:
// phones and laptops come and go, often under random MACs.
func (s *Store) IngestUniFi(ctx context.Context, id string, at time.Time, snap model.UniFi) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM unifi_controller WHERE id::text = $1 FOR UPDATE`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		in := &unifiIngest{tx: tx, ctx: ctx, ctrl: id, ctrlName: name, byMAC: map[string]string{}}
		var notes []string
		for _, site := range snap.Sites {
			if err := in.site(site); err != nil {
				return err
			}
			if site.PortsError != "" {
				notes = append(notes, fmt.Sprintf("Switch ports of %s's clients couldn't be read: %s", site.Name, site.PortsError))
			}
		}
		for _, p := range snap.Protect {
			if err := in.protect(p); err != nil {
				return err
			}
		}
		if snap.ProtectError != "" {
			notes = append(notes, "Protect couldn't be read: "+snap.ProtectError)
		}
		if err := in.clients(snap.Sites); err != nil {
			return err
		}
		// Relationships to this console's sites and devices that no poll
		// found this time are dropped; gone objects start towards missing.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM ci_relationship r USING unifi_object o
			WHERE r.to_ci = o.ci_id AND o.controller::text = $1 AND o.kind IN ('site', 'device')
			  AND r.source = 'discovered' AND r.kind IN ('member_of', 'connected_to') AND NOT r.id::text = ANY($2)`,
			id, pq.Array(nonNil(in.rels))); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			WITH gone AS (
			    UPDATE unifi_object SET present = false
			    WHERE controller::text = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
			UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`, id, pq.Array(nonNil(in.present))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE unifi_controller SET network_version = $2, protect_version = $3, last_poll = $4, last_ok = $4,
			    last_error = '', notes = $5
			WHERE id::text = $1`, id, snap.NetworkVersion, snap.ProtectVersion, at, strings.Join(notes, "\n"))
		return err
	})
}

type unifiIngest struct {
	tx       *sql.Tx
	ctx      context.Context
	ctrl     string
	ctrlName string
	present  []string          // CI IDs of the objects found
	rels     []string          // relationship IDs to keep
	byMAC    map[string]string // MAC -> CI ID of devices and Protect devices found
	devices  map[string]string // site ID + "/" + device ID -> CI ID
}

// upsert keeps one of the console's CIs and its unifi_object row.
func (in *unifiIngest) upsert(typ, kind, key, name, state string, updatable bool, attrs map[string]string) (string, error) {
	attrs["console"] = in.ctrlName
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return "", err
	}
	var id string
	if err := in.tx.QueryRowContext(in.ctx, `
		INSERT INTO ci (type, name, source, source_key, status, last_seen, attrs)
		VALUES ($1, $2, 'unifi', $3, 'active', now(), $4)
		ON CONFLICT (source, source_key) DO UPDATE
		SET type = EXCLUDED.type, name = EXCLUDED.name, status = 'active', last_seen = now(), attrs = EXCLUDED.attrs,
		    updated_at = CASE WHEN ci.status <> 'active' OR ci.attrs <> EXCLUDED.attrs OR ci.name <> EXCLUDED.name OR ci.type <> EXCLUDED.type
		                      THEN now() ELSE ci.updated_at END
		RETURNING id`, typ, name, in.ctrl+"/"+key, string(b)).Scan(&id); err != nil {
		return "", err
	}
	if _, err := in.tx.ExecContext(in.ctx, `
		INSERT INTO unifi_object (ci_id, controller, kind, key, state, firmware_updatable, present)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		ON CONFLICT (ci_id) DO UPDATE
		SET controller = EXCLUDED.controller, kind = EXCLUDED.kind, key = EXCLUDED.key, present = true,
		    state_since = CASE WHEN unifi_object.state <> EXCLUDED.state THEN now() ELSE unifi_object.state_since END,
		    state = EXCLUDED.state, firmware_updatable = EXCLUDED.firmware_updatable`,
		id, in.ctrl, kind, key, state, updatable); err != nil {
		return "", err
	}
	in.present = append(in.present, id)
	return id, nil
}

// relate keeps a discovered relationship, with attrs (a client's port).
func (in *unifiIngest) relate(from, to, kind string, attrs map[string]any) error {
	if from == to {
		return nil
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	var id string
	if err := in.tx.QueryRowContext(in.ctx, `
		INSERT INTO ci_relationship (from_ci, to_ci, kind, source, attrs) VALUES ($1, $2, $3, 'discovered', $4)
		ON CONFLICT (from_ci, to_ci, kind) DO UPDATE SET attrs = EXCLUDED.attrs
		RETURNING id`, from, to, kind, string(b)).Scan(&id); err != nil {
		return err
	}
	in.rels = append(in.rels, id)
	return nil
}

func (in *unifiIngest) site(site model.UniFiSite) error {
	siteCI, err := in.upsert("site", "site", "site:"+site.ID, first(site.Name, site.Ref, "UniFi site"), "", false,
		map[string]string{"unifi_site": site.Ref})
	if err != nil {
		return err
	}
	if in.devices == nil {
		in.devices = map[string]string{}
	}
	for _, d := range site.Devices {
		if _, dup := in.byMAC[d.MAC]; dup {
			continue
		}
		attrs := map[string]string{"vendor": "Ubiquiti", "model": d.Model, "mac": d.MAC, "address": d.IP,
			"firmware": d.Firmware, "state": d.State, "features": strings.Join(d.Features, ", ")}
		if d.FirmwareUpdatable {
			attrs["firmware_update"] = "available"
		}
		ciID, err := in.upsert("network_device", "device", "mac:"+d.MAC, first(d.Name, d.Model, d.MAC), d.State, d.FirmwareUpdatable, attrs)
		if err != nil {
			return err
		}
		in.byMAC[d.MAC] = ciID
		in.devices[site.ID+"/"+d.ID] = ciID
		if err := in.relate(ciID, siteCI, "member_of", nil); err != nil {
			return err
		}
	}
	for _, d := range site.Devices {
		from, to := in.devices[site.ID+"/"+d.ID], in.devices[site.ID+"/"+d.UplinkID]
		if from != "" && to != "" {
			if err := in.relate(from, to, "connected_to", map[string]any{"via": "uplink"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (in *unifiIngest) protect(p model.UniFiCamera) error {
	if p.MAC != "" {
		if _, dup := in.byMAC[p.MAC]; dup {
			return nil
		}
	}
	typ := "protect_device"
	if p.Kind == "camera" {
		typ = "camera"
	}
	key := "mac:" + p.MAC
	if p.MAC == "" {
		key = "protect:" + p.ID
	}
	ciID, err := in.upsert(typ, "protect", key, first(p.Name, p.Model, p.MAC, p.ID), p.State, false,
		map[string]string{"vendor": "Ubiquiti", "model": p.Model, "mac": p.MAC, "protect_kind": p.Kind, "state": p.State})
	if err != nil {
		return err
	}
	if p.MAC != "" {
		in.byMAC[p.MAC] = ciID
	}
	return nil
}

// clients relates every client to the device it is plugged into, or the
// access point it is associated with.
func (in *unifiIngest) clients(sites []model.UniFiSite) error {
	var macs []string
	for _, site := range sites {
		for _, c := range site.Clients {
			if in.byMAC[c.MAC] == "" {
				macs = append(macs, macHex(c.MAC))
			}
		}
	}
	known, err := in.matchMACs(macs)
	if err != nil {
		return err
	}
	if err := in.fold(sites, known); err != nil {
		return err
	}
	for _, site := range sites {
		for _, c := range site.Clients {
			ciID := in.byMAC[c.MAC]
			if ciID == "" {
				ciID = known[macHex(c.MAC)]
			}
			if ciID == "" && c.Wireless {
				continue
			}
			if ciID == "" {
				ciID, err = in.upsert("network_client", "client", "mac:"+c.MAC, first(c.Name, c.MAC), "", false,
					map[string]string{"mac": c.MAC, "address": c.IP, "unifi_site": site.Name})
				if err != nil {
					return err
				}
				in.byMAC[c.MAC] = ciID
			}
			to := in.devices[site.ID+"/"+c.UplinkID]
			if to == "" {
				continue
			}
			attrs := map[string]any{"via": "wired"}
			if c.Wireless {
				attrs["via"] = "wireless"
			}
			if c.Port > 0 && !c.Wireless {
				attrs["port"] = c.Port
			}
			if c.IP != "" {
				attrs["address"] = c.IP
			}
			if err := in.relate(ciID, to, "connected_to", attrs); err != nil {
				return err
			}
		}
	}
	return nil
}

// fold merges this console's network_client CIs whose MAC now belongs to
// another CI (a host enrolled, a CI given the MAC after the client was
// found) into that CI: their manual relationships, changes, work items and
// silences move to it, and the network_client is deleted.
func (in *unifiIngest) fold(sites []model.UniFiSite, known map[string]string) error {
	into := map[string]string{} // unifi_object key -> CI it now is
	for _, site := range sites {
		for _, c := range site.Clients {
			if id := known[macHex(c.MAC)]; id != "" && in.byMAC[c.MAC] == "" {
				into["mac:"+c.MAC] = id
			}
		}
	}
	if len(into) == 0 {
		return nil
	}
	keys := make([]string, 0, len(into))
	for k := range into {
		keys = append(keys, k)
	}
	rows, err := in.tx.QueryContext(in.ctx, `
		SELECT o.ci_id, o.key, c.name FROM unifi_object o JOIN ci c ON c.id = o.ci_id
		WHERE o.controller::text = $1 AND o.kind = 'client' AND o.key = ANY($2)`, in.ctrl, pq.Array(keys))
	if err != nil {
		return err
	}
	type stale struct{ id, key, name string }
	var olds []stale
	for rows.Next() {
		var o stale
		if err := rows.Scan(&o.id, &o.key, &o.name); err != nil {
			rows.Close()
			return err
		}
		olds = append(olds, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range olds {
		to := into[o.key]
		for _, q := range []string{
			// Discovered relationships are rebuilt by this poll; manual ones
			// move unless the CI already has them.
			`UPDATE ci_relationship r SET from_ci = $2 WHERE r.from_ci = $1 AND r.source = 'manual' AND r.to_ci <> $2
			   AND NOT EXISTS (SELECT 1 FROM ci_relationship x WHERE x.from_ci = $2 AND x.to_ci = r.to_ci AND x.kind = r.kind)`,
			`UPDATE ci_relationship r SET to_ci = $2 WHERE r.to_ci = $1 AND r.source = 'manual' AND r.from_ci <> $2
			   AND NOT EXISTS (SELECT 1 FROM ci_relationship x WHERE x.to_ci = $2 AND x.from_ci = r.from_ci AND x.kind = r.kind)`,
			`INSERT INTO change_ci (change_id, ci_id) SELECT change_id, $2 FROM change_ci WHERE ci_id = $1 ON CONFLICT DO NOTHING`,
			`INSERT INTO work_item_ci (work_item_id, ci_id, role) SELECT work_item_id, $2, role FROM work_item_ci WHERE ci_id = $1
			   ON CONFLICT DO NOTHING`,
			`UPDATE silence SET ci_id = $2 WHERE ci_id = $1`,
		} {
			if _, err := in.tx.ExecContext(in.ctx, q, o.id, to); err != nil {
				return err
			}
		}
		if _, err := in.tx.ExecContext(in.ctx, `DELETE FROM ci WHERE id = $1`, o.id); err != nil {
			return err
		}
		if err := appendAudit(in.ctx, in.tx, System, AuditEvent{
			Action: "ci.merge", ObjectType: "ci", ObjectID: to,
			Details: map[string]any{"merged": o.id, "name": o.name, "type": "network_client", "console": in.ctrlName},
		}); err != nil {
			return err
		}
	}
	return nil
}

// matchMACs finds the CIs that already have these MACs (12 hex digits):
// a host by a NIC in its hardware section, then a hypervisor guest, then
// any CI but the consoles' own with a mac attribute.
func (in *unifiIngest) matchMACs(macs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(macs) == 0 {
		return out, nil
	}
	rows, err := in.tx.QueryContext(in.ctx, `
		SELECT DISTINCT ON (mac) mac, id FROM (
		    SELECT regexp_replace(lower(n->>'mac'), '[^0-9a-f]', '', 'g') AS mac, h.ci_id AS id, 1 AS rank
		    FROM host h JOIN host_inventory i ON i.host = h.ci_id AND i.section = 'hardware',
		         jsonb_array_elements(CASE WHEN jsonb_typeof(i.data->'nics') = 'array' THEN i.data->'nics' ELSE '[]' END) n
		    WHERE NOT h.revoked
		    UNION ALL
		    SELECT regexp_replace(lower(m), '[^0-9a-f]', '', 'g'), g.ci_id, 2 FROM vm_guest g, unnest(g.macs) m WHERE g.present
		    UNION ALL
		    SELECT regexp_replace(lower(c.attrs->>'mac'), '[^0-9a-f]', '', 'g'), c.id, 3 FROM ci c
		    WHERE c.source <> 'unifi' AND c.status <> 'retired' AND COALESCE(c.attrs->>'mac', '') <> ''
		) m
		WHERE mac = ANY($1)
		ORDER BY mac, rank, id`, pq.Array(macs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var mac, id string
		if err := rows.Scan(&mac, &id); err != nil {
			return nil, err
		}
		out[mac] = id
	}
	return out, rows.Err()
}

func macHex(mac string) string { return strings.ReplaceAll(mac, ":", "") }

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// UniFiDevicesOffline: devices and Protect devices of enabled consoles that
// have been down for at least d, and consoles that couldn't be read for
// that long.
func (s *Store) UniFiDevicesOffline(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.ci_id, c.name, c.type, o.state, o.state_since, u.name
		FROM unifi_object o JOIN ci c ON c.id = o.ci_id JOIN unifi_controller u ON u.id = o.controller
		WHERE u.enabled AND o.present AND o.kind IN ('device', 'protect') AND upper(o.state) = ANY($1)
		  AND o.state_since < now() - $2 * interval '1 second'
		ORDER BY c.name, o.ci_id`, pq.Array(unifiOffline), d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var typ, state, console string
		var since time.Time
		if err := rows.Scan(&c.CIID, &c.Subject, &typ, &state, &since, &console); err != nil {
			return nil, err
		}
		c.Link = "/cis/" + c.CIID
		c.Summary = fmt.Sprintf("%s is %s on %s since %s", c.Subject, strings.ToLower(state), console, when(since))
		c.Details = map[string]any{"state": state, "since": since, "console": console}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `
		SELECT id, name, last_error, COALESCE(last_ok, created_at) FROM unifi_controller
		WHERE enabled AND last_error <> '' AND COALESCE(last_ok, created_at) < now() - $1 * interval '1 second'
		ORDER BY name, id`, d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Condition
		var id, msg string
		var since time.Time
		if err := rows.Scan(&id, &c.Subject, &msg, &since); err != nil {
			return nil, err
		}
		c.Key, c.Link = "console:"+id, "/settings/unifi"
		c.Summary = fmt.Sprintf("UniFi console %s couldn't be read since %s: %s", c.Subject, when(since), msg)
		c.Details = map[string]any{"error": msg, "last_ok": since}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UniFiFirmware: devices whose console offers a firmware update.
func (s *Store) UniFiFirmware(ctx context.Context) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.ci_id, c.name, COALESCE(c.attrs->>'model', ''), COALESCE(c.attrs->>'firmware', '')
		FROM unifi_object o JOIN ci c ON c.id = o.ci_id JOIN unifi_controller u ON u.id = o.controller
		WHERE u.enabled AND o.present AND o.kind = 'device' AND o.firmware_updatable
		ORDER BY c.name, o.ci_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var model, fw string
		if err := rows.Scan(&c.CIID, &c.Subject, &model, &fw); err != nil {
			return nil, err
		}
		c.Link = "/cis/" + c.CIID
		c.Summary = fmt.Sprintf("%s has a firmware update (running %s)", c.Subject, first(fw, "unknown firmware"))
		if model != "" {
			c.Summary = fmt.Sprintf("%s (%s) has a firmware update (running %s)", c.Subject, model, first(fw, "unknown firmware"))
		}
		c.Details = map[string]any{"model": model, "firmware": fw}
		out = append(out, c)
	}
	return out, rows.Err()
}

// unifiPortLabel is how a client's relationship names its switch port, or
// says it is wireless.
func unifiPortLabel(attrs map[string]any) string {
	if attrs["via"] == "wireless" {
		return "wireless"
	}
	switch p := attrs["port"].(type) {
	case float64:
		return "port " + strconv.Itoa(int(p))
	case int:
		return "port " + strconv.Itoa(p)
	}
	return ""
}

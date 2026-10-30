package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/inventory"
	"github.com/jw6ventures/baseline/internal/model"
)

var (
	ErrRevoked     = errors.New("host is revoked")
	ErrUnknownCert = errors.New("certificate is not the host's current one")
)

// AgentHost is what the gateway knows about a connected agent.
type AgentHost struct {
	HostID   string
	AgentID  string
	Hostname string
}

// AuthenticateAgent checks a client cert presented on Connect. The previous
// serial stays valid until the agent first uses its renewed cert, so a lost
// renewal response can't lock an agent out.
func (s *Store) AuthenticateAgent(ctx context.Context, agentID, serial string) (AgentHost, error) {
	h := AgentHost{AgentID: agentID}
	var cur, prev string
	var revoked bool
	err := s.db.QueryRowContext(ctx,
		`SELECT ci_id, hostname, cert_serial, prev_cert_serial, revoked FROM host WHERE agent_id = $1`, agentID).
		Scan(&h.HostID, &h.Hostname, &cur, &prev, &revoked)
	if err != nil {
		return h, mapErr(err)
	}
	switch {
	case revoked:
		return h, ErrRevoked
	case serial == cur:
		if prev != "" {
			_, err = s.db.ExecContext(ctx, `UPDATE host SET prev_cert_serial = '' WHERE ci_id = $1`, h.HostID)
		}
		return h, err
	case serial == prev && prev != "":
		return h, nil
	}
	return h, ErrUnknownCert
}

// Hello is the identity and capability report an agent sends on connect.
type Hello struct {
	AgentVersion string
	MachineID    string
	DMIUUID      string
	Hostname     string
	BootID       string
	BootTime     time.Time
	Capabilities []string
	Arch         string
	IP           string
	// Policy is the agent's local policy; nil for agents that predate jobs.
	Policy *action.Policy
}

// Connected is what the gateway needs after a Hello.
type Connected struct {
	// Hashes are the content hashes of the sections the server holds, so
	// the gateway can ask for stale ones.
	Hashes map[string]string
	// UpdateTarget is the agent version an admin asked for; "" when the
	// agent is where it should be.
	UpdateTarget string
	// Settings change what the agent is told to collect.
	Settings AgentSettings
}

// AgentSettings are the host's settings its agent is told in Config.
type AgentSettings struct {
	HighSecurity bool
	// ComposeRoots are where the agent looks for stacks that aren't
	// running; none while Compose stack management is off.
	ComposeRoots []string
}

// AgentSettings are the settings the host's agent is told.
func (h Host) AgentSettings() AgentSettings {
	a := AgentSettings{HighSecurity: h.HighSecurity}
	if h.ManageCompose {
		a.ComposeRoots = h.ComposeRoots
	}
	return a
}

// AgentConnected records a Hello. An agent arriving on its target version
// completes a self-update.
func (s *Store) AgentConnected(ctx context.Context, hostID, agentID string, h Hello) (Connected, error) {
	c := Connected{Hashes: map[string]string{}}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var bootTime sql.NullTime
		if !h.BootTime.IsZero() {
			bootTime = sql.NullTime{Time: h.BootTime, Valid: true}
		}
		if err := lockIdentities(ctx, tx); err != nil {
			return err
		}
		// Re-checked under the row lock: a revocation between the cert
		// check and here must still keep the agent out.
		var prevBoot, prevVersion, target string
		var revoked, manageCompose bool
		var roots []string
		if err := tx.QueryRowContext(ctx, `
			SELECT boot_id, agent_version, agent_update_target, revoked, high_security, manage_compose, compose_roots
			FROM host WHERE ci_id = $1 FOR UPDATE`, hostID).
			Scan(&prevBoot, &prevVersion, &target, &revoked, &c.Settings.HighSecurity, &manageCompose, pq.Array(&roots)); err != nil {
			return mapErr(err)
		}
		if manageCompose {
			c.Settings.ComposeRoots = roots
		}
		if revoked {
			return ErrRevoked
		}
		if target == h.AgentVersion {
			target = ""
		}
		policy := action.Policy{}
		if h.Policy != nil {
			policy = *h.Policy
		}
		pj, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE host SET agent_version = $2, machine_id = $3, dmi_uuid = $4, boot_id = $5, boot_time = $6,
			       capabilities = $7, agent_arch = $8, connected = true, last_connect = now(), last_seen = now(),
			       agent_update_target = $9,
			       agent_update_error = CASE WHEN $9 = '' AND agent_update_target <> '' THEN '' ELSE agent_update_error END,
			       local_policy = $10
			WHERE ci_id = $1`,
			hostID, h.AgentVersion, h.MachineID, h.DMIUUID, h.BootID, bootTime, pq.Array(nonNil(h.Capabilities)), h.Arch, target,
			string(pj)); err != nil {
			return err
		}
		c.UpdateTarget = target
		if prevVersion != "" && prevVersion != h.AgentVersion {
			if err := addHistory(ctx, tx, hostID, "agent:"+agentID, "agent", map[string]any{
				"changed": []inventory.Change{{Field: "agent_version", From: prevVersion, To: h.AgentVersion}},
			}); err != nil {
				return err
			}
			if err := appendAudit(ctx, tx, Actor{ID: "agent:" + agentID, IP: h.IP}, AuditEvent{
				Action: "host.agent_version", ObjectType: "host", ObjectID: hostID,
				Details: map[string]any{"from": prevVersion, "to": h.AgentVersion},
			}); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ci SET last_seen = now() WHERE id = $1`, hostID); err != nil {
			return err
		}
		if prevBoot != "" && h.BootID != "" && prevBoot != h.BootID {
			if err := addHistory(ctx, tx, hostID, "agent", "boot", map[string]any{
				"changed": []inventory.Change{{Field: "boot_time", To: h.BootTime.UTC()}},
			}); err != nil {
				return err
			}
		}
		if err := flagDuplicates(ctx, tx, hostID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT section, content_hash FROM host_inventory WHERE host = $1`, hostID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sec, hash string
			if err := rows.Scan(&sec, &hash); err != nil {
				return err
			}
			c.Hashes[sec] = hash
		}
		return rows.Err()
	})
	return c, err
}

// FlagIdentityConflict records a second machine presenting a host's cert.
func (s *Store) FlagIdentityConflict(ctx context.Context, hostID, agentID, ip, bootID, machineID, hostname string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var already bool
		if err := tx.QueryRowContext(ctx,
			`SELECT duplicate_identity FROM host WHERE ci_id = $1 FOR UPDATE`, hostID).Scan(&already); err != nil {
			return mapErr(err)
		}
		if already {
			return nil // audited the first time; the agent retries every minute
		}
		if _, err := tx.ExecContext(ctx, `UPDATE host SET duplicate_identity = true WHERE ci_id = $1`, hostID); err != nil {
			return err
		}
		return appendAudit(ctx, tx, Actor{ID: "agent:" + agentID, IP: ip}, AuditEvent{
			Action: "host.identity_conflict", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"boot_id": bootID, "machine_id": machineID, "hostname": hostname},
		})
	})
}

func (s *Store) AgentSeen(ctx context.Context, hostID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE host SET last_seen = now() WHERE ci_id = $1`, hostID)
	return err
}

func (s *Store) AgentDisconnected(ctx context.Context, hostID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE host SET connected = false, last_seen = now() WHERE ci_id = $1`, hostID)
	return err
}

// ResetConnections clears stale connected flags after a server restart.
func (s *Store) ResetConnections(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE host SET connected = false WHERE connected`)
	return err
}

// RenewCert records a renewed client cert. usedSerial, the cert the agent
// is connected with, stays valid until the agent reconnects with the new
// one; recording that (not the previous "current" serial) means repeated
// lost renewal responses can't strand the agent.
func (s *Store) RenewCert(ctx context.Context, hostID, agentID, usedSerial, serial string, notAfter time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE host SET prev_cert_serial = $4, cert_serial = $2, cert_not_after = $3
			WHERE ci_id = $1 AND NOT revoked`, hostID, serial, notAfter, usedSerial)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrRevoked
		}
		return appendAudit(ctx, tx, Actor{ID: "agent:" + agentID}, AuditEvent{
			Action: "host.cert_renew", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"cert_serial": serial, "not_after": notAfter.UTC()},
		})
	})
}

func (s *Store) RevokeHost(ctx context.Context, actor Actor, hostID string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `
			UPDATE host SET revoked = true, revoked_at = now(), connected = false
			WHERE ci_id = $1 AND NOT revoked RETURNING hostname`, hostID).Scan(&name); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE ci SET status = 'retired', updated_at = now()
			WHERE id = $1 OR id IN (SELECT ci_id FROM container WHERE host = $1 UNION SELECT ci_id FROM compose_stack WHERE host = $1
			    UNION SELECT ci_id FROM traefik_hostname WHERE host = $1
			    UNION SELECT ci_id FROM vm_guest WHERE host = $1 AND present
			    UNION SELECT ci_id FROM k8s_cluster WHERE host = $1 UNION SELECT ci_id FROM k8s_object WHERE host = $1)`,
			hostID); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host.revoke", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"hostname": name},
		})
	})
}

// IngestSection stores one inventory snapshot: it records a history entry
// when the section changed, keeps the latest copy, and refreshes the typed
// projections (host columns, host_package).
//
// jobID is set when the agent collected the section again after a job; the
// history entry is then tagged with the job's change. Without it, a change
// whose job is running on the host (or just rebooted it) is assumed to be
// the cause, if its action can change the section. Everything else is an
// unplanned change.
func (s *Store) IngestSection(ctx context.Context, hostID, agentID, section, hash string, payload []byte, jobID string) (changed bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var prevHash, prevData string
		err := tx.QueryRowContext(ctx, `
			SELECT content_hash, data::text FROM host_inventory WHERE host = $1 AND section = $2 FOR UPDATE`,
			hostID, section).Scan(&prevHash, &prevData)
		first := errors.Is(err, sql.ErrNoRows)
		if err != nil && !first {
			return err
		}
		if !first && prevHash == hash {
			_, err := tx.ExecContext(ctx,
				`UPDATE host_inventory SET received_at = now() WHERE host = $1 AND section = $2`, hostID, section)
			return err
		}
		changed = true
		// A part of the section that couldn't be read this time keeps its
		// earlier copy.
		if keep := keepFailed[section]; keep != nil {
			var prev []byte
			if !first {
				prev = []byte(prevData)
			}
			if payload, err = keep(prev, payload); err != nil {
				return err
			}
		}

		var entry any
		switch {
		case !model.Tracked(section):
		case first:
			entry = map[string]any{"initial": true}
		default:
			d, err := inventory.Compare(section, []byte(prevData), payload)
			if err != nil {
				return fmt.Errorf("diff %s: %w", section, err)
			}
			if d != nil {
				entry = d
			}
		}
		if entry != nil {
			var changeID sql.NullString
			if !first { // a first inventory isn't a change anyone made
				if changeID, err = jobChange(ctx, tx, hostID, jobID, section); err != nil {
					return err
				}
			}
			if err := addChangeHistory(ctx, tx, hostID, "agent:"+agentID, changeID, section, entry); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO host_inventory (host, section, content_hash, data, received_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (host, section) DO UPDATE
			SET content_hash = EXCLUDED.content_hash, data = EXCLUDED.data, received_at = now()`,
			hostID, section, hash, string(payload)); err != nil {
			return err
		}
		switch section {
		case model.SectionOS:
			return projectOS(ctx, tx, hostID, payload)
		case model.SectionPackages:
			return projectPackages(ctx, tx, hostID, payload)
		case model.SectionUpdates:
			return projectUpdates(ctx, tx, hostID, payload)
		case model.SectionSmart:
			return projectSmart(ctx, tx, hostID, payload)
		case model.SectionContainers:
			return projectContainers(ctx, tx, hostID, payload)
		case model.SectionServices:
			return projectServices(ctx, tx, hostID, payload)
		case model.SectionPorts:
			return projectPorts(ctx, tx, hostID, payload)
		case model.SectionReboot:
			return projectReboot(ctx, tx, hostID, payload)
		case model.SectionCerts:
			return projectCerts(ctx, tx, hostID, payload)
		case model.SectionVMs:
			return projectVMs(ctx, tx, hostID, payload)
		case model.SectionK8s:
			return projectK8s(ctx, tx, hostID, payload)
		case model.SectionHardware:
			// A guest's or a Kubernetes node's agent is linked by its NICs.
			return linkDiscovered(ctx, tx)
		}
		return nil
	})
	return changed, err
}

var keepFailed = map[string]func(prev, cur []byte) ([]byte, error){
	model.SectionContainers: keepFailedEngines,
	model.SectionVMs:        keepFailedPlatforms,
	model.SectionK8s:        keepFailedResources,
}

func addHistory(ctx context.Context, tx *sql.Tx, hostID, actor, section string, diff any) error {
	return addChangeHistory(ctx, tx, hostID, actor, sql.NullString{}, section, diff)
}

func addChangeHistory(ctx context.Context, tx *sql.Tx, ciID, actor string, changeID sql.NullString, section string, diff any) error {
	b, err := json.Marshal(diff)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO ci_history (ci_id, actor, change_id, section, diff) VALUES ($1, $2, $3, $4, $5)`,
		ciID, actor, changeID, section, string(b))
	return err
}

func projectOS(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var o model.OS
	if err := json.Unmarshal(payload, &o); err != nil {
		return err
	}
	version := o.VersionID
	if o.Image != nil && o.Image.Version != "" {
		version = o.Image.Version
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE host SET hostname = $2, fqdn = $3, os_id = $4, os_version = $5, os_pretty = $6, kernel = $7, arch = $8
		WHERE ci_id = $1`, hostID, o.Hostname, o.FQDN, o.ID, version, o.PrettyName, o.Kernel, o.Arch); err != nil {
		return err
	}
	if o.Hostname != "" {
		_, err := tx.ExecContext(ctx, `UPDATE ci SET name = $2, updated_at = now() WHERE id = $1 AND name <> $2`, hostID, o.Hostname)
		return err
	}
	return nil
}

func projectPackages(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var p model.Packages
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_package WHERE host = $1`, hostID); err != nil {
		return err
	}
	n := len(p.Packages)
	cols := make([][]string, 9)
	for i := range cols {
		cols[i] = make([]string, n)
	}
	layered := make([]bool, n)
	for i, pk := range p.Packages {
		for j, v := range []string{pk.Manager, pk.Name, pk.Epoch, pk.Version, pk.Release, pk.Arch, pk.Source, pk.Repo} {
			cols[j][i] = v
		}
		layered[i] = pk.Layered
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO host_package (host, manager, name, epoch, version, release, arch, source, repo, layered)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::bool[])`,
		hostID, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]),
		pq.Array(cols[4]), pq.Array(cols[5]), pq.Array(cols[6]), pq.Array(cols[7]), pq.Array(layered))
	return err
}

// Host listing and detail ------------------------------------------------------

type Host struct {
	ID                string
	AgentID           string
	Hostname          string
	FQDN              string
	OSID              string
	OSVersion         string
	OSPretty          string
	Kernel            string
	Arch              string
	AgentVersion      string
	Connected         bool
	LastSeen          time.Time
	LastConnect       time.Time
	Revoked           bool
	DuplicateIdentity bool
	EnrolledAt        time.Time
	PackageCount      int
	GroupIDs          []string
	GroupNames        []string

	Updates         int       // available updates
	SecurityUpdates int       // of which security
	UpdatesAt       time.Time // when updates were last checked
	DisksFailing    int       // drives whose SMART status failed
	DisksDegrading  int       // drives with early warning signs

	AgentArch         string
	AgentUpdateTarget string // version an admin asked for, until the agent arrives on it
	AgentUpdateAt     time.Time
	AgentUpdateError  string

	RebootRequired   bool
	RebootReasons    []string
	FailedServices   int
	Containers       int
	ContainersUp     int // running
	ContainerUpdates int // containers whose image tag moved on (digest drift)
	CertsExpiring    int // within CertWarning

	// Policy is the agent's local policy (agent.conf), as last reported.
	Policy   action.Policy
	OpenJobs int // jobs queued, sent or running

	// VulnEcosystem is the OSV ecosystem the host was matched in; "" when
	// its distro isn't covered (or before the first match, VulnsAt zero).
	VulnEcosystem string
	VulnsAt       time.Time
	FixableVulns  int // vulnerabilities patching fixes now

	// HighSecurity hosts collect hardware every few minutes, USB devices
	// included, and alert on every hardware change made since
	// HighSecuritySince (the hardware_change rule kind).
	HighSecurity      bool
	HighSecuritySince time.Time
	// ManageCompose hosts take changes that deploy Compose stacks and edit
	// stacks' Compose files and .env files; an admin turns it on.
	ManageCompose      bool
	ManageComposeSince time.Time
	// ComposeRoots are the directories compose.deploy puts new stacks
	// under on the host, the first the default; none is the agent's own
	// compose_root.
	ComposeRoots []string

	// Detail only.
	MachineID    string
	DMIUUID      string
	BootID       string
	BootTime     time.Time
	Capabilities []string
	CertNotAfter time.Time
}

// ClusterAgent reports whether the host is a Kubernetes cluster agent
// rather than a machine.
func (h Host) ClusterAgent() bool { return slices.Contains(h.Capabilities, model.CapK8sCluster) }

// DisplayName is the hostname, or the CI name before the first inventory.
func (h Host) DisplayName() string {
	if h.Hostname != "" {
		return h.Hostname
	}
	return "host " + h.ID[:8]
}

const hostCols = `h.ci_id, h.agent_id, h.hostname, h.fqdn, h.os_id, h.os_version, h.os_pretty, h.kernel, h.arch,
	h.agent_version, h.connected, COALESCE(h.last_seen, 'epoch'), COALESCE(h.last_connect, 'epoch'),
	h.revoked, h.duplicate_identity, h.enrolled_at,
	(SELECT count(*) FROM host_package p WHERE p.host = h.ci_id),
	ARRAY(SELECT m.group_id::text FROM host_group_member m JOIN host_group g ON g.id = m.group_id
	      WHERE m.ci_id = h.ci_id ORDER BY g.name),
	ARRAY(SELECT g.name FROM host_group_member m JOIN host_group g ON g.id = m.group_id
	      WHERE m.ci_id = h.ci_id ORDER BY g.name),
	h.machine_id, h.dmi_uuid, h.boot_id, COALESCE(h.boot_time, 'epoch'), h.capabilities, h.cert_not_after,
	(SELECT count(*) FROM host_update u WHERE u.host = h.ci_id),
	(SELECT count(*) FROM host_update u WHERE u.host = h.ci_id AND u.security),
	COALESCE((SELECT received_at FROM host_inventory i WHERE i.host = h.ci_id AND i.section = 'updates'), 'epoch'),
	(SELECT count(*) FROM host_smart d WHERE d.host = h.ci_id AND d.passed = false),
	(SELECT count(*) FROM host_smart d WHERE d.host = h.ci_id AND d.degrading),
	h.agent_arch, h.agent_update_target, COALESCE(h.agent_update_at, 'epoch'), h.agent_update_error,
	h.reboot_required, h.reboot_reasons,
	(SELECT count(*) FROM host_service v WHERE v.host = h.ci_id AND v.active = 'failed'),
	(SELECT count(*) FROM container c WHERE c.host = h.ci_id),
	(SELECT count(*) FROM container c WHERE c.host = h.ci_id AND c.state = 'running'),
	(SELECT count(*) FROM container_update u WHERE u.host = h.ci_id AND u.drift AND NOT u.pinned),
	(SELECT count(*) FROM ci_cert x WHERE x.ci_id = h.ci_id AND x.not_after < now() + interval '` + certWarningSQL + `'),
	h.local_policy::text,
	(SELECT count(*) FROM job j WHERE j.host = h.ci_id AND j.state IN ('queued', 'dispatched', 'running')),
	h.vuln_ecosystem, COALESCE(h.vulns_at, 'epoch'),
	(SELECT count(DISTINCT v.vuln_id) FROM host_vuln v WHERE v.host = h.ci_id AND v.fix_available),
	h.high_security, COALESCE(h.high_security_since, 'epoch'),
	h.manage_compose, COALESCE(h.manage_compose_since, 'epoch'), h.compose_roots`

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var policy string
	err := row.Scan(&h.ID, &h.AgentID, &h.Hostname, &h.FQDN, &h.OSID, &h.OSVersion, &h.OSPretty, &h.Kernel, &h.Arch,
		&h.AgentVersion, &h.Connected, &h.LastSeen, &h.LastConnect, &h.Revoked, &h.DuplicateIdentity, &h.EnrolledAt,
		&h.PackageCount, pq.Array(&h.GroupIDs), pq.Array(&h.GroupNames),
		&h.MachineID, &h.DMIUUID, &h.BootID, &h.BootTime, pq.Array(&h.Capabilities), &h.CertNotAfter,
		&h.Updates, &h.SecurityUpdates, &h.UpdatesAt, &h.DisksFailing, &h.DisksDegrading,
		&h.AgentArch, &h.AgentUpdateTarget, &h.AgentUpdateAt, &h.AgentUpdateError,
		&h.RebootRequired, pq.Array(&h.RebootReasons), &h.FailedServices, &h.Containers, &h.ContainersUp,
		&h.ContainerUpdates, &h.CertsExpiring, &policy, &h.OpenJobs, &h.VulnEcosystem, &h.VulnsAt, &h.FixableVulns,
		&h.HighSecurity, &h.HighSecuritySince, &h.ManageCompose, &h.ManageComposeSince, pq.Array(&h.ComposeRoots))
	if err == nil {
		err = json.Unmarshal([]byte(policy), &h.Policy)
	}
	for _, t := range []*time.Time{&h.LastSeen, &h.LastConnect, &h.BootTime, &h.UpdatesAt, &h.AgentUpdateAt, &h.VulnsAt, &h.HighSecuritySince,
		&h.ManageComposeSince} {
		if t.Unix() == 0 {
			*t = time.Time{}
		}
	}
	return h, err
}

// CertWarning is how close to expiry a certificate is flagged.
const (
	CertWarning    = 30 * 24 * time.Hour
	certWarningSQL = "30 days"
)

// ListHosts returns every host, revoked ones last.
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostCols+` FROM host h ORDER BY h.revoked, lower(h.hostname), h.ci_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(ctx context.Context, id string) (Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostCols+` FROM host h WHERE h.ci_id = $1`, id))
	return h, mapErr(err)
}

// HostSection returns the stored JSON of one section, or ErrNotFound.
func (s *Store) HostSection(ctx context.Context, hostID, section string) ([]byte, time.Time, error) {
	var data string
	var at time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT data::text, received_at FROM host_inventory WHERE host = $1 AND section = $2`, hostID, section).
		Scan(&data, &at)
	return []byte(data), at, mapErr(err)
}

// HostPackages lists a host's packages whose name contains query.
// HostSectionNames lists the inventory sections a host has sent.
func (s *Store) HostSectionNames(ctx context.Context, hostID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT section FROM host_inventory WHERE host = $1 ORDER BY section`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sec string
		if err := rows.Scan(&sec); err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

func (s *Store) HostPackages(ctx context.Context, hostID, query string) ([]model.Package, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT manager, name, epoch, version, release, arch, source, repo, layered FROM host_package
		WHERE host = $1 AND ($2 = '' OR strpos(lower(name), lower($2)) > 0)
		ORDER BY manager, name, version`, hostID, strings.TrimSpace(query))
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []model.Package
	for rows.Next() {
		var p model.Package
		if err := rows.Scan(&p.Manager, &p.Name, &p.Epoch, &p.Version, &p.Release, &p.Arch, &p.Source, &p.Repo, &p.Layered); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type HistoryEntry struct {
	ID           int64
	At           time.Time
	Actor        string
	ChangeID     string // "" for an unplanned change
	ChangeNumber int64
	Section      string
	Diff         json.RawMessage
}

// ChangeRef is the change behind the entry, CHG-000123.
func (e HistoryEntry) ChangeRef() string { return ChangeRef(e.ChangeNumber) }

func (s *Store) HostHistory(ctx context.Context, hostID string, limit int) ([]HistoryEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT x.id, x.at, x.actor, COALESCE(x.change_id::text, ''), COALESCE(c.number, 0), x.section, x.diff::text
		FROM ci_history x LEFT JOIN change c ON c.id = x.change_id
		WHERE x.ci_id = $1 ORDER BY x.at DESC, x.id DESC LIMIT $2`, hostID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var diff string
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.ChangeID, &e.ChangeNumber, &e.Section, &diff); err != nil {
			return nil, err
		}
		e.Diff = json.RawMessage(diff)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetHostGroups replaces a host's static group memberships.
func (s *Store) SetHostGroups(ctx context.Context, actor Actor, hostID string, groupIDs []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var before []string
		if err := tx.QueryRowContext(ctx, `
			SELECT ARRAY(SELECT g.name FROM host_group_member m JOIN host_group g ON g.id = m.group_id
			             WHERE m.ci_id = $1 ORDER BY g.name)
			FROM host WHERE ci_id = $1`, hostID).Scan(pq.Array(&before)); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_group_member WHERE ci_id = $1`, hostID); err != nil {
			return err
		}
		var after []string
		if err := tx.QueryRowContext(ctx, `
			WITH ins AS (
			    INSERT INTO host_group_member (group_id, ci_id)
			    SELECT g.id, $2 FROM host_group g WHERE g.id::text = ANY($1::text[])
			    RETURNING group_id)
			SELECT ARRAY(SELECT g.name FROM ins JOIN host_group g ON g.id = ins.group_id ORDER BY g.name)`,
			pq.Array(nonNil(groupIDs)), hostID).Scan(pq.Array(&after)); err != nil {
			return err
		}
		if slices.Equal(before, after) {
			return nil
		}
		if err := addHistory(ctx, tx, hostID, actor.ID, "groups", map[string]any{
			"changed": []inventory.Change{{Field: "groups", From: strings.Join(before, ", "), To: strings.Join(after, ", ")}},
		}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host.groups", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"before": before, "after": after},
		})
	})
}

// SetHostHighSecurity turns a host's high security flag on or off. It
// reports whether that changed anything.
func (s *Store) SetHostHighSecurity(ctx context.Context, actor Actor, hostID string, on bool) (bool, error) {
	changed := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var before bool
		if err := tx.QueryRowContext(ctx, `SELECT high_security FROM host WHERE ci_id = $1 FOR UPDATE`, hostID).
			Scan(&before); err != nil {
			return mapErr(err)
		}
		if before == on {
			return nil
		}
		changed = true
		if _, err := tx.ExecContext(ctx, `
			UPDATE host SET high_security = $2, high_security_since = CASE WHEN $2 THEN now() END WHERE ci_id = $1`,
			hostID, on); err != nil {
			return err
		}
		if err := addHistory(ctx, tx, hostID, actor.ID, "settings", map[string]any{
			"changed": []inventory.Change{{Field: "high_security", From: before, To: on}},
		}); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "host.high_security", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"high_security": on},
		})
	})
	return changed, err
}

// FleetCounts is the dashboard's host summary.
type FleetCounts struct {
	Total, Online, Offline, Duplicate int
}

func (s *Store) FleetCounts(ctx context.Context) (FleetCounts, error) {
	var c FleetCounts
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE connected), count(*) FILTER (WHERE NOT connected),
		       count(*) FILTER (WHERE duplicate_identity)
		FROM host WHERE NOT revoked`).Scan(&c.Total, &c.Online, &c.Offline, &c.Duplicate)
	return c, err
}

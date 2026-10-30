package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

func projectServices(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var sv model.Services
	if err := json.Unmarshal(payload, &sv); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_service WHERE host = $1`, hostID); err != nil {
		return err
	}
	n := len(sv.Units)
	cols := make([][]string, 6)
	for i := range cols {
		cols[i] = make([]string, n)
	}
	for i, u := range sv.Units {
		for j, v := range []string{u.Name, u.Description, u.Load, u.Active, u.Sub, u.Enabled} {
			cols[j][i] = v
		}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO host_service (host, unit, description, load, active, sub, enabled)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
		ON CONFLICT DO NOTHING`,
		hostID, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]), pq.Array(cols[4]), pq.Array(cols[5]))
	return err
}

func projectPorts(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var p model.Ports
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_port WHERE host = $1`, hostID); err != nil {
		return err
	}
	n := len(p.Listeners)
	proto, addr, process, unit := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	port := make([]int64, n)
	for i, l := range p.Listeners {
		proto[i], addr[i], port[i], process[i], unit[i] = l.Proto, l.Addr, int64(l.Port), l.Process, l.Unit
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO host_port (host, proto, addr, port, process, unit)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::int[], $5::text[], $6::text[])
		ON CONFLICT DO NOTHING`,
		hostID, pq.Array(proto), pq.Array(addr), pq.Array(port), pq.Array(process), pq.Array(unit))
	return err
}

func projectReboot(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var r model.Reboot
	if err := json.Unmarshal(payload, &r); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE host SET reboot_required = $2, reboot_reasons = $3,
		       reboot_required_since = CASE WHEN NOT $2 THEN NULL ELSE COALESCE(reboot_required_since, now()) END
		WHERE ci_id = $1`,
		hostID, r.Required, pq.Array(nonNil(r.Reasons)))
	return err
}

func projectCerts(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var c model.Certs
	if err := json.Unmarshal(payload, &c); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ci_cert WHERE ci_id = $1 AND source = 'agent'`, hostID); err != nil {
		return err
	}
	for _, ct := range c.Certs {
		if err := insertCert(ctx, tx, hostID, "agent", ct, ""); err != nil {
			return err
		}
	}
	return nil
}

func insertCert(ctx context.Context, tx *sql.Tx, ciID, source string, c model.Cert, probeErr string) error {
	parse := func(s string) sql.NullTime {
		t, err := time.Parse(time.RFC3339, s)
		return sql.NullTime{Time: t, Valid: err == nil}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ci_cert (ci_id, location, source, subject, sans, issuer, not_before, not_after, serial, fingerprint,
		                     self_signed, error, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
		ON CONFLICT (ci_id, location) DO UPDATE
		SET source = EXCLUDED.source, subject = EXCLUDED.subject, sans = EXCLUDED.sans, issuer = EXCLUDED.issuer,
		    not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after, serial = EXCLUDED.serial,
		    fingerprint = EXCLUDED.fingerprint, self_signed = EXCLUDED.self_signed, error = EXCLUDED.error,
		    checked_at = now()`,
		ciID, c.Location, source, c.Subject, pq.Array(nonNil(c.SANs)), c.Issuer, parse(c.NotBefore), parse(c.NotAfter),
		c.Serial, c.Fingerprint, c.SelfSigned, probeErr)
	return err
}

// HostServices lists a host's services, failed ones first.
func (s *Store) HostServices(ctx context.Context, hostID string) ([]model.Service, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT unit, description, load, active, sub, enabled FROM host_service WHERE host = $1
		ORDER BY active <> 'failed', unit`, hostID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []model.Service
	for rows.Next() {
		var u model.Service
		if err := rows.Scan(&u.Name, &u.Description, &u.Load, &u.Active, &u.Sub, &u.Enabled); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// HostPorts lists a host's listening sockets by port.
func (s *Store) HostPorts(ctx context.Context, hostID string) ([]model.Listener, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT proto, addr, port, process, unit FROM host_port WHERE host = $1 ORDER BY port, proto, addr`, hostID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []model.Listener
	for rows.Next() {
		var l model.Listener
		if err := rows.Scan(&l.Proto, &l.Addr, &l.Port, &l.Process, &l.Unit); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// CertRow is a certificate found on a host or probed on an endpoint.
type CertRow struct {
	CIID        string
	CIName      string
	CIType      string
	Location    string
	Source      string
	Subject     string
	SANs        []string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Serial      string
	Fingerprint string
	SelfSigned  bool
	Error       string
	CheckedAt   time.Time
}

// DaysLeft is how many whole days the certificate has left; negative once
// it has expired.
func (c CertRow) DaysLeft() int {
	return int(time.Until(c.NotAfter).Hours() / 24)
}

const certCols = `c.ci_id, ci.name, ci.type, c.location, c.source, c.subject, c.sans, c.issuer,
	COALESCE(c.not_before, 'epoch'), COALESCE(c.not_after, 'epoch'), c.serial, c.fingerprint, c.self_signed, c.error, c.checked_at`

func scanCerts(rows *sql.Rows) ([]CertRow, error) {
	defer rows.Close()
	var out []CertRow
	for rows.Next() {
		var c CertRow
		if err := rows.Scan(&c.CIID, &c.CIName, &c.CIType, &c.Location, &c.Source, &c.Subject, pq.Array(&c.SANs), &c.Issuer,
			&c.NotBefore, &c.NotAfter, &c.Serial, &c.Fingerprint, &c.SelfSigned, &c.Error, &c.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CICerts lists the certificates of one CI, soonest to expire first.
func (s *Store) CICerts(ctx context.Context, ciID string) ([]CertRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+certCols+` FROM ci_cert c JOIN ci ON ci.id = c.ci_id
		WHERE c.ci_id = $1 ORDER BY c.not_after NULLS LAST, c.location`, ciID)
	if err != nil {
		return nil, mapErr(err)
	}
	return scanCerts(rows)
}

// ExpiringCerts lists certificates expiring before a time on the given hosts,
// plus those of CIs that aren't hosts (probed endpoints), which every viewer
// may see.
func (s *Store) ExpiringCerts(ctx context.Context, hostIDs []string, before time.Time) ([]CertRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+certCols+` FROM ci_cert c JOIN ci ON ci.id = c.ci_id
		WHERE c.not_after < $2 AND ci.status = 'active'
		  AND (c.ci_id::text = ANY($1) OR ci.type <> 'host')
		ORDER BY c.not_after, ci.name, c.location`, pq.Array(nonNil(hostIDs)), before)
	if err != nil {
		return nil, err
	}
	return scanCerts(rows)
}

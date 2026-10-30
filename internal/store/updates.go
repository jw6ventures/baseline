package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// projectUpdates replaces a host's host_update rows, keeping first_seen for
// updates that were already pending: "available for 12 days" is the point.
func projectUpdates(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var u model.Updates
	if err := json.Unmarshal(payload, &u); err != nil {
		return err
	}
	seen := map[string]time.Time{}
	rows, err := tx.QueryContext(ctx, `
		DELETE FROM host_update WHERE host = $1 RETURNING manager, name, arch, candidate_ver, first_seen`, hostID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var m, n, a, c string
		var at time.Time
		if err := rows.Scan(&m, &n, &a, &c, &at); err != nil {
			rows.Close()
			return err
		}
		seen[m+"\x00"+n+"\x00"+a+"\x00"+c] = at
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	n := len(u.Updates)
	if n == 0 {
		return nil
	}
	cols := make([][]string, 7)
	for i := range cols {
		cols[i] = make([]string, n)
	}
	security, image := make([]bool, n), make([]bool, n)
	advisories := make([]string, n)
	firstSeen := make([]time.Time, n)
	now := time.Now()
	for i, up := range u.Updates {
		for j, v := range []string{up.Manager, up.Name, up.Arch, up.Installed, up.Candidate, up.Repo} {
			cols[j][i] = v
		}
		security[i], image[i] = up.Security, up.Image
		// A text array can't hold arrays, so advisories travel joined.
		advisories[i] = strings.Join(up.Advisories, " ")
		firstSeen[i] = now
		if at, ok := seen[up.Manager+"\x00"+up.Name+"\x00"+up.Arch+"\x00"+up.Candidate]; ok {
			firstSeen[i] = at
		}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO host_update (host, manager, name, arch, installed_ver, candidate_ver, repo, security, image, advisories, first_seen)
		SELECT $1, m, n, a, i, c, r, s, img, string_to_array(adv, ' '), fs
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::bool[], $9::bool[], $10::text[], $11::timestamptz[])
		     AS t(m, n, a, i, c, r, s, img, adv, fs)`,
		hostID, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]), pq.Array(cols[4]),
		pq.Array(cols[5]), pq.Array(security), pq.Array(image), pq.Array(advisories), pq.Array(firstSeen))
	return err
}

func projectSmart(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var sm model.Smart
	if err := json.Unmarshal(payload, &sm); err != nil {
		return err
	}
	// When each drive's bad sector count last rose, carried across the
	// rewrite: a drive seen for the first time with bad sectors rose now.
	type before struct {
		bad  int64
		rose sql.NullTime
	}
	prev := map[string]before{}
	rows, err := tx.QueryContext(ctx, `SELECT device, `+smartBadSQL+`, rose_at FROM host_smart d WHERE host = $1`, hostID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev string
		var b before
		if err := rows.Scan(&dev, &b.bad, &b.rose); err != nil {
			rows.Close()
			return err
		}
		prev[dev] = b
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Older agents list a drive behind a RAID HBA twice; this also clears
	// their duplicate rows on the next report.
	sm.Devices = model.DedupeSmart(sm.Devices)
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_smart WHERE host = $1`, hostID); err != nil {
		return err
	}
	for _, d := range sm.Devices {
		attrs, err := json.Marshal(d)
		if err != nil {
			return err
		}
		rose := prev[d.Name].rose
		if d.BadSectors() > prev[d.Name].bad {
			rose = sql.NullTime{Time: time.Now(), Valid: true}
		}
		var passed sql.NullBool
		if d.Passed != nil {
			passed = sql.NullBool{Bool: *d.Passed, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO host_smart (host, device, model, serial, passed, degrading, attrs, rose_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (host, device) DO NOTHING`,
			hostID, d.Name, d.Model, d.Serial, passed, d.Degrading(), string(attrs), rose); err != nil {
			return err
		}
	}
	return nil
}

// HostUpdate is a pending update with when it first appeared.
type HostUpdate struct {
	model.Update
	FirstSeen time.Time
}

// HostUpdates lists a host's pending updates, security ones first.
func (s *Store) HostUpdates(ctx context.Context, hostID string) ([]HostUpdate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT manager, name, arch, installed_ver, candidate_ver, repo, security, image, advisories, first_seen
		FROM host_update WHERE host = $1 ORDER BY image DESC, security DESC, manager, name, arch`, hostID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []HostUpdate
	for rows.Next() {
		var u HostUpdate
		if err := rows.Scan(&u.Manager, &u.Name, &u.Arch, &u.Installed, &u.Candidate, &u.Repo, &u.Security, &u.Image,
			pq.Array(&u.Advisories), &u.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PackageUpdate is one package pending on one or more hosts.
type PackageUpdate struct {
	Manager    string
	Name       string
	Candidates []string
	Security   bool
	Image      bool
	HostIDs    []string
	Hosts      []string // hostnames, in HostIDs order
	FirstSeen  time.Time
}

// UpdatesByPackage groups the pending updates of the given hosts by package.
// query filters by name; securityOnly keeps security updates.
func (s *Store) UpdatesByPackage(ctx context.Context, hostIDs []string, query string, securityOnly bool) ([]PackageUpdate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.manager, u.name, array_agg(DISTINCT u.candidate_ver ORDER BY u.candidate_ver), bool_or(u.security), bool_or(u.image),
		       array_agg(h.ci_id::text ORDER BY lower(h.hostname)), array_agg(h.hostname ORDER BY lower(h.hostname)), min(u.first_seen)
		FROM host_update u JOIN host h ON h.ci_id = u.host
		WHERE u.host::text = ANY($1) AND ($2 = '' OR strpos(lower(u.name), lower($2)) > 0) AND (NOT $3 OR u.security)
		GROUP BY u.manager, u.name
		ORDER BY bool_or(u.security) DESC, count(*) DESC, u.name`,
		pq.Array(nonNil(hostIDs)), strings.TrimSpace(query), securityOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageUpdate
	for rows.Next() {
		var p PackageUpdate
		if err := rows.Scan(&p.Manager, &p.Name, pq.Array(&p.Candidates), &p.Security, &p.Image,
			pq.Array(&p.HostIDs), pq.Array(&p.Hosts), &p.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

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

// Vuln is one OSV record, trimmed to what the UI shows.
type Vuln struct {
	ID         string
	Aliases    []string // upstream CVE IDs
	Summary    string
	Details    string
	Severity   string // unknown | negligible | low | medium | high | critical
	CVSSScore  *float64
	CVSSVector string
	Published  time.Time
	Modified   time.Time
	Refs       []VulnRef
}

type VulnRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// VulnAffected is a source package a vulnerability affects in one
// ecosystem.
type VulnAffected struct {
	VulnID    string
	Ecosystem string
	Package   string
	Severity  string            // the ecosystem's own rating, if it has one
	Ranges    json.RawMessage   // [[{"introduced": "0"}, {"fixed": "1.2-3"}]]
	Binaries  map[string]string // binary package -> fixed version (Ubuntu)
	// VulnSeverity is the record's rating, filled when read for matching.
	VulnSeverity string
}

// VulnSource is the sync state of one ecosystem.
type VulnSource struct {
	Ecosystem string
	Dump      string
	ETag      string
	Cursor    time.Time
	FullAt    time.Time
	SyncedAt  time.Time
	TriedAt   time.Time
	Error     string
	Vulns     int
}

func (s *Store) VulnSources(ctx context.Context) ([]VulnSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ecosystem, dump, etag, COALESCE(cursor, 'epoch'), COALESCE(full_at, 'epoch'), COALESCE(synced_at, 'epoch'),
		       COALESCE(tried_at, 'epoch'), error, vulns
		FROM vuln_source ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnSource
	for rows.Next() {
		var v VulnSource
		if err := rows.Scan(&v.Ecosystem, &v.Dump, &v.ETag, &v.Cursor, &v.FullAt, &v.SyncedAt, &v.TriedAt, &v.Error, &v.Vulns); err != nil {
			return nil, err
		}
		for _, t := range []*time.Time{&v.Cursor, &v.FullAt, &v.SyncedAt, &v.TriedAt} {
			if t.Unix() == 0 {
				*t = time.Time{}
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveVulnSource stores an ecosystem's sync state; the vulnerability count
// is recomputed.
func (s *Store) SaveVulnSource(ctx context.Context, v VulnSource) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vuln_source (ecosystem, dump, etag, cursor, full_at, synced_at, tried_at, error, vulns)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
		        (SELECT count(DISTINCT vuln_id) FROM vuln_affected WHERE ecosystem = $1))
		ON CONFLICT (ecosystem) DO UPDATE SET dump = EXCLUDED.dump, etag = EXCLUDED.etag, cursor = EXCLUDED.cursor,
		    full_at = EXCLUDED.full_at, synced_at = EXCLUDED.synced_at, tried_at = EXCLUDED.tried_at,
		    error = EXCLUDED.error, vulns = EXCLUDED.vulns`,
		v.Ecosystem, v.Dump, v.ETag, nullTime(v.Cursor), nullTime(v.FullAt), nullTime(v.SyncedAt), nullTime(v.TriedAt),
		v.Error)
	return err
}

// ReplaceVulns replaces everything known about an ecosystem with a full
// dump's contents.
func (s *Store) ReplaceVulns(ctx context.Context, ecosystem string, vulns []Vuln, affected []VulnAffected) error {
	w, err := s.ReplaceVulnsStream(ctx, ecosystem)
	if err != nil {
		return err
	}
	if err := w.add(vulns, affected); err != nil {
		w.Rollback()
		return err
	}
	return w.Commit()
}

// VulnWriter replaces an ecosystem's data as a dump is read, in one
// transaction, so only a batch is held in memory at a time. Readers see
// the old data until Commit.
type VulnWriter struct {
	ctx      context.Context
	tx       *sql.Tx
	vulns    []Vuln
	affected []VulnAffected
	Count    int // records added
}

// ReplaceVulnsStream starts replacing an ecosystem's data.
func (s *Store) ReplaceVulnsStream(ctx context.Context, ecosystem string) (*VulnWriter, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_affected WHERE ecosystem = $1`, ecosystem); err != nil {
		tx.Rollback()
		return nil, err
	}
	return &VulnWriter{ctx: ctx, tx: tx}, nil
}

// Add queues a record and its entries, writing a batch when one is full.
func (w *VulnWriter) Add(v Vuln, affected []VulnAffected) error {
	w.Count++
	w.vulns = append(w.vulns, v)
	w.affected = append(w.affected, affected...)
	if len(w.vulns) >= vulnBatch || len(w.affected) >= vulnBatch {
		return w.flush()
	}
	return nil
}

func (w *VulnWriter) add(vulns []Vuln, affected []VulnAffected) error {
	w.Count += len(vulns)
	w.vulns, w.affected = append(w.vulns, vulns...), append(w.affected, affected...)
	return w.flush()
}

func (w *VulnWriter) flush() error {
	if err := upsertVulns(w.ctx, w.tx, w.vulns); err != nil {
		return err
	}
	if err := insertAffected(w.ctx, w.tx, w.affected); err != nil {
		return err
	}
	w.vulns, w.affected = w.vulns[:0], w.affected[:0]
	return nil
}

// Commit writes what is left and drops records nothing refers to any more.
func (w *VulnWriter) Commit() error {
	if err := w.flush(); err != nil {
		w.tx.Rollback()
		return err
	}
	if err := pruneVulns(w.ctx, w.tx, nil); err != nil {
		w.tx.Rollback()
		return err
	}
	return w.tx.Commit()
}

// Rollback abandons the replacement.
func (w *VulnWriter) Rollback() { w.tx.Rollback() }

// UpdateVulns applies changed records to an ecosystem: ids are every record
// that changed, vulns and affected what of them still applies.
func (s *Store) UpdateVulns(ctx context.Context, ecosystem string, ids []string, vulns []Vuln, affected []VulnAffected) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := upsertVulns(ctx, tx, vulns); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_affected WHERE ecosystem = $1 AND vuln_id = ANY($2)`,
			ecosystem, pq.Array(nonNil(ids))); err != nil {
			return err
		}
		if err := insertAffected(ctx, tx, affected); err != nil {
			return err
		}
		return pruneVulns(ctx, tx, ids)
	})
}

// pruneVulns deletes records no ecosystem refers to any more, among ids
// (nil: all).
func pruneVulns(ctx context.Context, tx *sql.Tx, ids []string) error {
	_, err := tx.ExecContext(ctx, `
		DELETE FROM vuln v WHERE ($1::text[] IS NULL OR v.id = ANY($1))
		AND NOT EXISTS (SELECT 1 FROM vuln_affected a WHERE a.vuln_id = v.id)`, pq.Array(ids))
	return err
}

const vulnBatch = 2000

func upsertVulns(ctx context.Context, tx *sql.Tx, vulns []Vuln) error {
	for len(vulns) > 0 {
		n := min(len(vulns), vulnBatch)
		batch := vulns[:n]
		vulns = vulns[n:]
		var ids, aliases, summaries, details, sevs, vectors, refs []string
		var scores []sql.NullFloat64
		var published, modified []sql.NullTime
		for _, v := range batch {
			ids = append(ids, v.ID)
			a, _ := json.Marshal(nonNil(v.Aliases))
			aliases = append(aliases, string(a))
			summaries = append(summaries, v.Summary)
			details = append(details, v.Details)
			sevs = append(sevs, v.Severity)
			vectors = append(vectors, v.CVSSVector)
			r, _ := json.Marshal(nonNilSlice(v.Refs))
			refs = append(refs, string(r))
			sc := sql.NullFloat64{}
			if v.CVSSScore != nil {
				sc = sql.NullFloat64{Float64: *v.CVSSScore, Valid: true}
			}
			scores = append(scores, sc)
			published = append(published, nullTime(v.Published))
			modified = append(modified, nullTime(v.Modified))
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln (id, aliases, summary, details, severity, cvss_score, cvss_vector, published, modified, refs)
			SELECT u.id, ARRAY(SELECT jsonb_array_elements_text(u.aliases::jsonb)), u.summary, u.details, u.severity,
			       u.score, u.vector, u.published, u.modified, u.refs::jsonb
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::float8[], $7::text[],
			            $8::timestamptz[], $9::timestamptz[], $10::text[])
			     AS u(id, aliases, summary, details, severity, score, vector, published, modified, refs)
			ON CONFLICT (id) DO UPDATE SET aliases = EXCLUDED.aliases, summary = EXCLUDED.summary,
			    details = EXCLUDED.details, severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score,
			    cvss_vector = EXCLUDED.cvss_vector, published = EXCLUDED.published, modified = EXCLUDED.modified,
			    refs = EXCLUDED.refs`,
			pq.Array(ids), pq.Array(aliases), pq.Array(summaries), pq.Array(details), pq.Array(sevs),
			pq.Array(scores), pq.Array(vectors), pq.Array(published), pq.Array(modified), pq.Array(refs)); err != nil {
			return err
		}
	}
	return nil
}

func insertAffected(ctx context.Context, tx *sql.Tx, affected []VulnAffected) error {
	for len(affected) > 0 {
		n := min(len(affected), vulnBatch)
		batch := affected[:n]
		affected = affected[n:]
		cols := make([][]string, 6)
		for _, a := range batch {
			b, _ := json.Marshal(nonNilMap(a.Binaries))
			for i, v := range []string{a.VulnID, a.Ecosystem, a.Package, a.Severity, string(a.Ranges), string(b)} {
				cols[i] = append(cols[i], v)
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_affected (vuln_id, ecosystem, package, severity, ranges, binaries)
			SELECT u.v, u.e, u.p, u.s, u.r::jsonb, u.b::jsonb
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS u(v, e, p, s, r, b)
			ON CONFLICT (vuln_id, ecosystem, package) DO UPDATE SET severity = EXCLUDED.severity,
			    ranges = EXCLUDED.ranges, binaries = EXCLUDED.binaries`,
			pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]), pq.Array(cols[4]),
			pq.Array(cols[5])); err != nil {
			return err
		}
	}
	return nil
}

// VulnHostRef is what matching needs to know about a host.
type VulnHostRef struct {
	ID        string
	OSID      string
	OSVersion string
	Ecosystem string // as last matched
}

// VulnHosts lists hosts that aren't revoked, by their OS.
func (s *Store) VulnHosts(ctx context.Context) ([]VulnHostRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.os_id, COALESCE((SELECT data->>'version_id' FROM host_inventory i
		                                   WHERE i.host = h.ci_id AND i.section = 'os'), h.os_version), h.vuln_ecosystem
		FROM host h WHERE NOT h.revoked ORDER BY h.ci_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnHostRef
	for rows.Next() {
		var h VulnHostRef
		if err := rows.Scan(&h.ID, &h.OSID, &h.OSVersion, &h.Ecosystem); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// MatchInput is a host's installed packages and the versions its pending
// updates would install.
func (s *Store) MatchInput(ctx context.Context, hostID string) ([]model.Package, []model.Update, error) {
	pkgs, err := s.HostPackages(ctx, hostID, "")
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT manager, name, arch, candidate_ver FROM host_update WHERE host = $1 AND NOT image`, hostID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var ups []model.Update
	for rows.Next() {
		var u model.Update
		if err := rows.Scan(&u.Manager, &u.Name, &u.Arch, &u.Candidate); err != nil {
			return nil, nil, err
		}
		ups = append(ups, u)
	}
	return pkgs, ups, rows.Err()
}

// AffectedFor returns the entries of an ecosystem for the named source
// packages, with each record's own severity.
func (s *Store) AffectedFor(ctx context.Context, ecosystem string, packages []string) ([]VulnAffected, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.vuln_id, a.package, a.severity, a.ranges::text, a.binaries::text, v.severity
		FROM vuln_affected a JOIN vuln v ON v.id = a.vuln_id
		WHERE a.ecosystem = $1 AND a.package = ANY($2)`, ecosystem, pq.Array(nonNil(packages)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnAffected
	for rows.Next() {
		a := VulnAffected{Ecosystem: ecosystem}
		var ranges, bins string
		if err := rows.Scan(&a.VulnID, &a.Package, &a.Severity, &ranges, &bins, &a.VulnSeverity); err != nil {
			return nil, err
		}
		a.Ranges = json.RawMessage(ranges)
		if bins != "{}" {
			json.Unmarshal([]byte(bins), &a.Binaries)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// HostVuln is an installed package a vulnerability affects.
type HostVuln struct {
	HostID       string
	Hostname     string
	VulnID       string
	Package      string
	Arch         string
	Source       string
	Installed    string
	Fixed        string // "" when there is no fix yet
	Candidate    string // what the host would upgrade to now
	FixAvailable bool
	Severity     string
	FirstSeen    time.Time

	// Listings fill these from the record.
	Summary   string
	Aliases   []string
	CVSSScore *float64
}

// SaveHostVulns replaces a host's matches, keeping when each was first
// seen, and records the ecosystem they came from ("" when the host's distro
// isn't covered).
func (s *Store) SaveHostVulns(ctx context.Context, hostID, ecosystem string, matches []HostVuln) error {
	cols := make([][]string, 8)
	var fixable []bool
	for _, m := range matches {
		for i, v := range []string{m.VulnID, m.Package, m.Arch, m.Source, m.Installed, m.Fixed, m.Candidate, m.Severity} {
			cols[i] = append(cols[i], v)
		}
		fixable = append(fixable, m.FixAvailable)
	}
	for i := range cols {
		cols[i] = nonNil(cols[i])
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM host_vuln WHERE host = $1
			AND (vuln_id, package, arch) NOT IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))`,
			hostID, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2])); err != nil {
			return err
		}
		if len(matches) > 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO host_vuln (host, vuln_id, package, arch, source, installed_ver, fixed_ver, candidate_ver,
				                       severity, fix_available)
				SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
				                         $8::text[], $9::text[], $10::bool[])
				ON CONFLICT (host, vuln_id, package, arch) DO UPDATE SET source = EXCLUDED.source,
				    installed_ver = EXCLUDED.installed_ver, fixed_ver = EXCLUDED.fixed_ver,
				    candidate_ver = EXCLUDED.candidate_ver, severity = EXCLUDED.severity,
				    fix_available = EXCLUDED.fix_available`,
				hostID, pq.Array(cols[0]), pq.Array(cols[1]), pq.Array(cols[2]), pq.Array(cols[3]), pq.Array(cols[4]),
				pq.Array(cols[5]), pq.Array(cols[6]), pq.Array(cols[7]), pq.Array(fixable)); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE host SET vuln_ecosystem = $2, vulns_at = now() WHERE ci_id = $1`, hostID, ecosystem)
		return err
	})
}

// severityRank orders severities in SQL, matching vuln.Severities.
const severityRank = `array_position(ARRAY['unknown','negligible','low','medium','high','critical'], %s)`

func sevRank(col string) string { return strings.Replace(severityRank, "%s", col, 1) }

// VulnFilter narrows vulnerability listings.
type VulnFilter struct {
	HostIDs     []string // hosts the user can see
	FixableOnly bool
	MinSeverity string // "" for any
	Query       string // ID, CVE, package or summary
	Limit       int
}

func (f VulnFilter) where(alias string) (string, []any) {
	args := []any{pq.Array(nonNil(f.HostIDs)), f.FixableOnly, f.MinSeverity, strings.TrimSpace(f.Query)}
	w := alias + `.host = ANY($1::uuid[]) AND (NOT $2 OR ` + alias + `.fix_available)
		AND ($3 = '' OR ` + sevRank(alias+".severity") + ` >= ` + sevRank("$3") + `)
		AND ($4 = '' OR strpos(lower(` + alias + `.vuln_id), lower($4)) > 0 OR strpos(lower(` + alias + `.package), lower($4)) > 0
		     OR strpos(lower(` + alias + `.source), lower($4)) > 0
		     OR EXISTS (SELECT 1 FROM vuln q WHERE q.id = ` + alias + `.vuln_id
		                AND (strpos(lower(q.summary), lower($4)) > 0 OR upper($4) = ANY(q.aliases))))`
	return w, args
}

// VulnRow is one vulnerability across the hosts it affects.
type VulnRow struct {
	ID           string
	Aliases      []string
	Summary      string
	Severity     string // the worst among its matches
	CVSSScore    *float64
	Published    time.Time
	Hosts        int
	FixableHosts int
	Packages     []string
	FirstSeen    time.Time
}

// ListVulns groups matches by vulnerability, worst and most widespread
// first.
func (s *Store) ListVulns(ctx context.Context, f VulnFilter) ([]VulnRow, error) {
	where, args := f.where("hv")
	if f.Limit <= 0 {
		f.Limit = 500
	}
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.aliases, v.summary, (array_agg(hv.severity ORDER BY `+sevRank("hv.severity")+` DESC))[1],
		       v.cvss_score, COALESCE(v.published, 'epoch'),
		       count(DISTINCT hv.host), count(DISTINCT hv.host) FILTER (WHERE hv.fix_available),
		       array_agg(DISTINCT hv.package ORDER BY hv.package), min(hv.first_seen)
		FROM host_vuln hv JOIN vuln v ON v.id = hv.vuln_id
		WHERE `+where+`
		GROUP BY v.id
		ORDER BY max(`+sevRank("hv.severity")+`) DESC, count(DISTINCT hv.host) FILTER (WHERE hv.fix_available) DESC,
		         count(DISTINCT hv.host) DESC, v.id DESC
		LIMIT $5`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnRow
	for rows.Next() {
		var r VulnRow
		var score sql.NullFloat64
		if err := rows.Scan(&r.ID, pq.Array(&r.Aliases), &r.Summary, &r.Severity, &score, &r.Published,
			&r.Hosts, &r.FixableHosts, pq.Array(&r.Packages), &r.FirstSeen); err != nil {
			return nil, err
		}
		if score.Valid {
			r.CVSSScore = &score.Float64
		}
		if r.Published.Unix() == 0 {
			r.Published = time.Time{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// VulnCounts summarizes a host's matches.
type VulnCounts struct {
	HostID   string
	Total    int // distinct vulnerabilities
	Fixable  int // of which patching fixes now
	Critical int // fixable, by severity
	High     int
	Medium   int
	Low      int // low, negligible and unknown
}

// VulnTotals counts distinct vulnerabilities on hosts: all of them, those
// pending updates fix, and of those the high and critical ones.
func (s *Store) VulnTotals(ctx context.Context, hostIDs []string) (total, fixable, severe int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT count(DISTINCT vuln_id), count(DISTINCT vuln_id) FILTER (WHERE fix_available),
		       count(DISTINCT vuln_id) FILTER (WHERE fix_available AND severity IN ('high', 'critical'))
		FROM host_vuln WHERE host = ANY($1::uuid[])`, pq.Array(nonNil(hostIDs))).Scan(&total, &fixable, &severe)
	return total, fixable, severe, err
}

// HostVulnCounts counts the matches of each host in hostIDs that has any.
func (s *Store) HostVulnCounts(ctx context.Context, hostIDs []string) (map[string]VulnCounts, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, count(DISTINCT vuln_id), count(DISTINCT vuln_id) FILTER (WHERE fix_available),
		       count(DISTINCT vuln_id) FILTER (WHERE fix_available AND severity = 'critical'),
		       count(DISTINCT vuln_id) FILTER (WHERE fix_available AND severity = 'high'),
		       count(DISTINCT vuln_id) FILTER (WHERE fix_available AND severity = 'medium'),
		       count(DISTINCT vuln_id) FILTER (WHERE fix_available AND severity NOT IN ('critical', 'high', 'medium'))
		FROM host_vuln WHERE host = ANY($1::uuid[]) GROUP BY host`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VulnCounts{}
	for rows.Next() {
		var c VulnCounts
		if err := rows.Scan(&c.HostID, &c.Total, &c.Fixable, &c.Critical, &c.High, &c.Medium, &c.Low); err != nil {
			return nil, err
		}
		out[c.HostID] = c
	}
	return out, rows.Err()
}

// HostVulns lists the matches on f.HostIDs with their records: fixable
// ones first, then the worst.
func (s *Store) HostVulns(ctx context.Context, f VulnFilter) ([]HostVuln, error) {
	where, args := f.where("hv")
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, `
		SELECT hv.host, h.hostname, hv.vuln_id, hv.package, hv.arch, hv.source, hv.installed_ver, hv.fixed_ver,
		       hv.candidate_ver, hv.fix_available, hv.severity, hv.first_seen, v.summary, v.aliases, v.cvss_score
		FROM host_vuln hv JOIN vuln v ON v.id = hv.vuln_id JOIN host h ON h.ci_id = hv.host
		WHERE `+where+`
		ORDER BY hv.fix_available DESC, `+sevRank("hv.severity")+` DESC, v.cvss_score DESC NULLS LAST,
		         lower(h.hostname), hv.vuln_id DESC, hv.package
		LIMIT $5`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostVuln
	for rows.Next() {
		var m HostVuln
		var score sql.NullFloat64
		if err := rows.Scan(&m.HostID, &m.Hostname, &m.VulnID, &m.Package, &m.Arch, &m.Source, &m.Installed, &m.Fixed,
			&m.Candidate, &m.FixAvailable, &m.Severity, &m.FirstSeen, &m.Summary, pq.Array(&m.Aliases), &score); err != nil {
			return nil, err
		}
		if score.Valid {
			m.CVSSScore = &score.Float64
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetVuln returns a record and the entries it has in synced ecosystems.
func (s *Store) GetVuln(ctx context.Context, id string) (Vuln, []VulnAffected, error) {
	var v Vuln
	var score sql.NullFloat64
	var refs string
	var published, modified sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, aliases, summary, details, severity, cvss_score, cvss_vector, published, modified, refs::text
		FROM vuln WHERE id = $1`, id).
		Scan(&v.ID, pq.Array(&v.Aliases), &v.Summary, &v.Details, &v.Severity, &score, &v.CVSSVector, &published,
			&modified, &refs)
	if err != nil {
		return v, nil, mapErr(err)
	}
	if score.Valid {
		v.CVSSScore = &score.Float64
	}
	v.Published, v.Modified = published.Time, modified.Time
	json.Unmarshal([]byte(refs), &v.Refs)
	rows, err := s.db.QueryContext(ctx, `
		SELECT ecosystem, package, severity, ranges::text FROM vuln_affected WHERE vuln_id = $1
		ORDER BY ecosystem, package`, id)
	if err != nil {
		return v, nil, err
	}
	defer rows.Close()
	var aff []VulnAffected
	for rows.Next() {
		a := VulnAffected{VulnID: id}
		var ranges string
		if err := rows.Scan(&a.Ecosystem, &a.Package, &a.Severity, &ranges); err != nil {
			return v, nil, err
		}
		a.Ranges = json.RawMessage(ranges)
		aff = append(aff, a)
	}
	return v, aff, rows.Err()
}

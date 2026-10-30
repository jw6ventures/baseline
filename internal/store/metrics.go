package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Metrics retention (docs/data-model.md §5): raw samples for 14 days, and
// 5-minute rollups for 45, which covers the raw window plus a month.
const (
	RawRetention    = 14 * 24 * time.Hour
	RollupRetention = 45 * 24 * time.Hour
	RollupStep      = 5 * time.Minute
	partitionsAhead = 3 // days of partitions created in advance
	// rollupGrace leaves the newest samples alone until they have arrived.
	rollupGrace = 2 * time.Minute
)

// binOrigin aligns buckets; any fixed instant on a 5-minute boundary does.
const binOrigin = `TIMESTAMPTZ '2000-01-01 00:00:00+00'`

// MetricSample is one reading in a batch.
type MetricSample struct {
	Kind     string
	Name     string
	Instance string
	Value    float64
}

// IngestMetrics stores a batch taken at ts. Re-sending a batch is harmless.
// Samples that land in an already rolled-up bucket (an agent flushing its
// buffer after an outage) mark that bucket for recomputation.
func (s *Store) IngestMetrics(ctx context.Context, hostID string, ts time.Time, samples []MetricSample) error {
	if len(samples) == 0 {
		return nil
	}
	ids, err := s.seriesIDs(ctx, hostID, samples)
	if err != nil {
		return err
	}
	vals := make([]float64, len(samples))
	for i, m := range samples {
		vals[i] = m.Value
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metric_raw (ts, series_id, value)
			SELECT $1, * FROM unnest($2::int[], $3::float8[])
			ON CONFLICT DO NOTHING`, ts, pq.Array(ids), pq.Array(vals)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE metric_rollup SET redo_from = LEAST(COALESCE(redo_from, $1), $1)
			WHERE done_until > $2`, ts.Truncate(RollupStep), ts)
		return err
	})
}

// seriesIDs maps samples to metric_series IDs, creating series on first
// sight. IDs are cached: series are never deleted while their host exists.
func (s *Store) seriesIDs(ctx context.Context, hostID string, samples []MetricSample) ([]int64, error) {
	key := func(kind, name, inst string) string { return hostID + "\x00" + kind + "\x00" + name + "\x00" + inst }
	ids := make([]int64, len(samples))
	s.seriesMu.Lock()
	defer s.seriesMu.Unlock()
	if s.series == nil {
		s.series = map[string]int64{}
	}
	var missing []int
	for i, m := range samples {
		id, ok := s.series[key(m.Kind, m.Name, m.Instance)]
		if !ok {
			missing = append(missing, i)
		}
		ids[i] = id
	}
	if len(missing) == 0 {
		return ids, nil
	}
	kinds, names, insts := make([]string, len(missing)), make([]string, len(missing)), make([]string, len(missing))
	for j, i := range missing {
		kinds[j], names[j], insts[j] = samples[i].Kind, samples[i].Name, samples[i].Instance
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO metric_series (host, kind, name, instance)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[])
		ON CONFLICT DO NOTHING`, hostID, pq.Array(kinds), pq.Array(names), pq.Array(insts)); err != nil {
		return nil, mapErr(err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, name, instance FROM metric_series WHERE host = $1`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var k, n, inst string
		if err := rows.Scan(&id, &k, &n, &inst); err != nil {
			return nil, err
		}
		s.series[key(k, n, inst)] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, i := range missing {
		ids[i] = s.series[key(samples[i].Kind, samples[i].Name, samples[i].Instance)]
	}
	return ids, nil
}

// MaintainMetrics creates the daily partitions from yesterday to a few days
// ahead and drops those past retention. Dropping a partition is instant,
// unlike deleting its rows.
func (s *Store) MaintainMetrics(ctx context.Context, now time.Time) error {
	today := now.UTC().Truncate(24 * time.Hour)
	for _, t := range []struct {
		table string
		keep  time.Duration
	}{{"metric_raw", RawRetention}, {"metric_5m", RollupRetention}} {
		for d := -1; d <= partitionsAhead; d++ {
			from := today.AddDate(0, 0, d)
			if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
				`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
				partitionName(t.table, from), t.table, from.Format(time.RFC3339), from.AddDate(0, 0, 1).Format(time.RFC3339))); err != nil {
				return fmt.Errorf("create partition: %w", err)
			}
		}
		parts, err := s.partitions(ctx, t.table)
		if err != nil {
			return err
		}
		for name, day := range parts {
			if day.AddDate(0, 0, 1).Before(now.Add(-t.keep)) {
				if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+pq.QuoteIdentifier(name)); err != nil {
					return fmt.Errorf("drop partition: %w", err)
				}
			}
		}
	}
	return nil
}

func partitionName(table string, day time.Time) string { return table + "_p" + day.Format("20060102") }

// partitions lists a table's daily partitions by the day they start.
func (s *Store) partitions(ctx context.Context, table string) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = $1`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if day, err := time.Parse("20060102", strings.TrimPrefix(name, table+"_p")); err == nil {
			out[name] = day
		}
	}
	return out, rows.Err()
}

// RollupMetrics aggregates complete 5-minute buckets of raw samples into
// metric_5m, from where it left off (or from the earliest late sample). It
// recomputes whole buckets, so running it twice changes nothing.
func (s *Store) RollupMetrics(ctx context.Context, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var done, redo sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT done_until, redo_from FROM metric_rollup FOR UPDATE`).Scan(&done, &redo); err != nil {
			return err
		}
		to := now.Add(-rollupGrace).Truncate(RollupStep)
		from := now.Add(-24 * time.Hour).Truncate(RollupStep)
		if done.Valid {
			from = done.Time
		}
		if redo.Valid && redo.Time.Before(from) {
			from = redo.Time
		}
		if oldest := now.Add(-RawRetention); from.Before(oldest) {
			from = oldest.Truncate(RollupStep)
		}
		if !to.After(from) {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metric_5m (ts, series_id, avg, min, max, count)
			SELECT date_bin('5 minutes', ts, `+binOrigin+`), series_id, avg(value), min(value), max(value), count(*)
			FROM metric_raw WHERE ts >= $1 AND ts < $2
			GROUP BY 1, 2
			ON CONFLICT (series_id, ts) DO UPDATE
			SET avg = EXCLUDED.avg, min = EXCLUDED.min, max = EXCLUDED.max, count = EXCLUDED.count`, from, to); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE metric_rollup SET done_until = $1, redo_from = NULL`, to)
		return err
	})
}

// MetricQuery selects one kind of metric on one host, averaged into buckets
// of Step. Rollup reads the 5-minute table (for ranges beyond raw retention
// or too long to chart sample by sample).
type MetricQuery struct {
	HostID   string
	Kind     string
	Names    []string
	From, To time.Time
	Step     time.Duration
	Rollup   bool
}

// MetricLine is one series; Values has a NaN where there is no data.
type MetricLine struct {
	Name     string
	Instance string
	Values   []float64
}

// MetricData is aligned for charting: every line has a value per time.
type MetricData struct {
	Times []time.Time
	Lines []MetricLine
}

func (s *Store) QueryMetrics(ctx context.Context, q MetricQuery) (MetricData, error) {
	var d MetricData
	step := fmt.Sprintf("%d seconds", int(q.Step.Seconds()))
	query := `
		SELECT s.name, s.instance, date_bin($6::interval, r.ts, ` + binOrigin + `) AS b, avg(r.value)
		FROM metric_series s JOIN metric_raw r ON r.series_id = s.id
		WHERE s.host = $1 AND s.kind = $2 AND s.name = ANY($3) AND r.ts >= $4 AND r.ts < $5
		GROUP BY 1, 2, 3`
	if q.Rollup {
		query = `
		SELECT s.name, s.instance, date_bin($6::interval, r.ts, ` + binOrigin + `) AS b, sum(r.avg * r.count) / sum(r.count)
		FROM metric_series s JOIN metric_5m r ON r.series_id = s.id
		WHERE s.host = $1 AND s.kind = $2 AND s.name = ANY($3) AND r.ts >= $4 AND r.ts < $5
		GROUP BY 1, 2, 3`
	}
	rows, err := s.db.QueryContext(ctx, query, q.HostID, q.Kind, pq.Array(q.Names), q.From, q.To, step)
	if err != nil {
		return d, mapErr(err)
	}
	defer rows.Close()
	type point struct {
		line int
		at   time.Time
		v    float64
	}
	lineIdx := map[string]int{}
	var points []point
	times := map[time.Time]bool{}
	for rows.Next() {
		var name, inst string
		var at time.Time
		var v float64
		if err := rows.Scan(&name, &inst, &at, &v); err != nil {
			return d, err
		}
		k := inst + "\x00" + name
		i, ok := lineIdx[k]
		if !ok {
			i = len(d.Lines)
			lineIdx[k] = i
			d.Lines = append(d.Lines, MetricLine{Name: name, Instance: inst})
		}
		points = append(points, point{i, at.UTC(), v})
		times[at.UTC()] = true
	}
	if err := rows.Err(); err != nil {
		return d, err
	}

	// Times that have data, plus a gap marker wherever several buckets in a
	// row are missing (the agent was offline), so lines break there instead
	// of bridging the outage. Single missing buckets are sampling jitter.
	var ts []time.Time
	for t := range times {
		ts = append(ts, t)
	}
	slices.SortFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
	for i, t := range ts {
		if i > 0 && t.Sub(ts[i-1]) > 3*q.Step {
			d.Times = append(d.Times, ts[i-1].Add(q.Step))
		}
		d.Times = append(d.Times, t)
	}
	pos := make(map[time.Time]int, len(d.Times))
	for i, t := range d.Times {
		pos[t] = i
	}
	for i := range d.Lines {
		d.Lines[i].Values = make([]float64, len(d.Times))
		for j := range d.Lines[i].Values {
			d.Lines[i].Values[j] = math.NaN()
		}
	}
	for _, p := range points {
		d.Lines[p.line].Values[pos[p.at]] = p.v
	}
	// Instances alphabetically, then names in the order asked for.
	order := map[string]int{}
	for i, n := range q.Names {
		order[n] = i
	}
	sort.SliceStable(d.Lines, func(i, j int) bool {
		a, b := d.Lines[i], d.Lines[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return order[a.Name] < order[b.Name]
	})
	return d, nil
}

// MetricInstances lists the instances (devices, mounts, interfaces) a host
// has recorded for a kind.
func (s *Store) MetricInstances(ctx context.Context, hostID, kind string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT instance FROM metric_series WHERE host = $1 AND kind = $2 ORDER BY 1`, hostID, kind)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var i string
		if err := rows.Scan(&i); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

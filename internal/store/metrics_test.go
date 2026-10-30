package store_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

func partitionCount(t *testing.T, s *store.Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`
		SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = $1`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMetricPartitions(t *testing.T) {
	s := newTestStore(t)
	now := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
	if err := s.MaintainMetrics(ctx, now); err != nil {
		t.Fatal(err)
	}
	// Yesterday through three days ahead.
	if n := partitionCount(t, s, "metric_raw"); n != 5 {
		t.Fatalf("raw partitions = %d", n)
	}
	// Running again is a no-op.
	if err := s.MaintainMetrics(ctx, now); err != nil {
		t.Fatal(err)
	}
	// Twenty days later the first raw partitions are past 14 days and go;
	// the rollups (45 days) stay.
	later := now.Add(20 * 24 * time.Hour)
	if err := s.MaintainMetrics(ctx, later); err != nil {
		t.Fatal(err)
	}
	if n := partitionCount(t, s, "metric_raw"); n != 5 {
		t.Fatalf("raw partitions after 20 days = %d, want only the new window", n)
	}
	if n := partitionCount(t, s, "metric_5m"); n != 10 {
		t.Fatalf("rollup partitions after 20 days = %d", n)
	}
}

func TestMetricsIngestRollupAndQuery(t *testing.T) {
	s := newTestStore(t)
	res := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	now := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour) // an hour of history ending at a clean boundary
	if err := s.MaintainMetrics(ctx, now); err != nil {
		t.Fatal(err)
	}
	// 30 minutes of per-minute CPU samples, with a 10-minute outage.
	for i := range 30 {
		if i >= 10 && i < 20 {
			continue
		}
		ts := now.Add(time.Duration(i) * time.Minute)
		if err := s.IngestMetrics(ctx, res.HostID, ts, []store.MetricSample{
			{Kind: "cpu", Name: "user", Value: float64(i)},
			{Kind: "cpu", Name: "system", Value: 1},
			{Kind: "disk", Name: "util", Instance: "sda", Value: 50},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A resent batch is ignored.
	if err := s.IngestMetrics(ctx, res.HostID, now, []store.MetricSample{{Kind: "cpu", Name: "user", Value: 99}}); err != nil {
		t.Fatal(err)
	}

	d, err := s.QueryMetrics(ctx, store.MetricQuery{HostID: res.HostID, Kind: "cpu", Names: []string{"user", "system"},
		From: now, To: now.Add(time.Hour), Step: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Lines) != 2 || d.Lines[0].Name != "user" || d.Lines[1].Name != "system" {
		t.Fatalf("lines = %+v", d.Lines)
	}
	// 20 points plus one gap marker for the outage.
	if len(d.Times) != 21 || !math.IsNaN(d.Lines[0].Values[10]) || d.Lines[0].Values[0] != 0 || d.Lines[0].Values[11] != 20 {
		t.Fatalf("times = %d, values = %v", len(d.Times), d.Lines[0].Values)
	}

	// Roll up the first 30 minutes: six 5-minute buckets, four with data.
	if err := s.RollupMetrics(ctx, now.Add(32*time.Minute+30*time.Second)); err != nil {
		t.Fatal(err)
	}
	var n int
	var avg float64
	s.DB().QueryRow(`SELECT count(*) FROM metric_5m m JOIN metric_series s ON s.id = m.series_id WHERE s.name = 'user'`).Scan(&n)
	s.DB().QueryRow(`SELECT m.avg FROM metric_5m m JOIN metric_series s ON s.id = m.series_id WHERE s.name = 'user' AND m.ts = $1`, now).Scan(&avg)
	if n != 4 || avg != 2 {
		t.Fatalf("rollups = %d, first avg = %v", n, avg)
	}

	// An agent flushing its buffer after an outage: the late samples land in
	// rolled-up buckets, which the next run recomputes.
	for i := 10; i < 15; i++ {
		s.IngestMetrics(ctx, res.HostID, now.Add(time.Duration(i)*time.Minute), []store.MetricSample{{Kind: "cpu", Name: "user", Value: 100}})
	}
	if err := s.RollupMetrics(ctx, now.Add(33*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.DB().QueryRow(`SELECT count(*) FROM metric_5m m JOIN metric_series s ON s.id = m.series_id WHERE s.name = 'user'`).Scan(&n)
	s.DB().QueryRow(`SELECT m.avg FROM metric_5m m JOIN metric_series s ON s.id = m.series_id WHERE s.name = 'user' AND m.ts = $1`, now.Add(10*time.Minute)).Scan(&avg)
	if n != 5 || avg != 100 {
		t.Fatalf("after late data: rollups = %d, avg = %v", n, avg)
	}

	// Reading the rollups, averaged over 15 minutes and weighted by count.
	d, err = s.QueryMetrics(ctx, store.MetricQuery{HostID: res.HostID, Kind: "disk", Names: []string{"util"},
		From: now, To: now.Add(time.Hour), Step: 15 * time.Minute, Rollup: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Lines) != 1 || d.Lines[0].Instance != "sda" || len(d.Times) != 2 || d.Lines[0].Values[0] != 50 {
		t.Fatalf("rollup query = %+v %v", d.Lines, d.Times)
	}
	if inst, _ := s.MetricInstances(ctx, res.HostID, "disk"); strings.Join(inst, ",") != "sda" {
		t.Fatalf("instances = %v", inst)
	}
}

package scheduler

import (
	"strings"
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNext(t *testing.T) {
	chicago := mustLoc(t, "America/Chicago")
	for _, tc := range []struct {
		expr, after, want string
		loc               *time.Location
	}{
		{"* * * * *", "2026-10-13T10:00:30Z", "2026-10-13T10:01:00Z", nil},
		{"0 2 * * *", "2026-10-13T10:00:00Z", "2026-10-14T02:00:00Z", nil},
		{"0 2 * * *", "2026-10-13T01:59:00Z", "2026-10-13T02:00:00Z", nil},
		{"0 2 * * *", "2026-10-13T02:00:00Z", "2026-10-14T02:00:00Z", nil}, // strictly after
		{"*/15 * * * *", "2026-10-13T10:07:00Z", "2026-10-13T10:15:00Z", nil},
		{"0-30/10 9 * * *", "2026-10-13T09:21:00Z", "2026-10-13T09:30:00Z", nil},
		{"5/20 * * * *", "2026-10-13T09:26:00Z", "2026-10-13T09:45:00Z", nil},
		{"0 2 * * SUN", "2026-10-13T00:00:00Z", "2026-10-18T02:00:00Z", nil}, // a Tuesday
		{"0 2 * * 7", "2026-10-13T00:00:00Z", "2026-10-18T02:00:00Z", nil},
		{"0 2 * * mon-fri", "2026-10-16T03:00:00Z", "2026-10-19T02:00:00Z", nil},
		{"0 0 1 jan *", "2026-10-13T00:00:00Z", "2027-01-01T00:00:00Z", nil},
		{"0 0 29 2 *", "2026-10-13T00:00:00Z", "2028-02-29T00:00:00Z", nil},
		{"0 0 31 * *", "2026-11-01T00:00:00Z", "2026-12-31T00:00:00Z", nil},
		// Both day fields restricted: either matches.
		{"0 0 13 * fri", "2026-10-13T01:00:00Z", "2026-10-16T00:00:00Z", nil},
		{"@daily", "2026-10-13T10:00:00Z", "2026-10-14T00:00:00Z", nil},
		{"@hourly", "2026-10-13T10:00:00Z", "2026-10-13T11:00:00Z", nil},
		// Time zones: 02:00 in Chicago is 07:00 UTC in October (CDT).
		{"0 2 * * SUN", "2026-10-13T00:00:00Z", "2026-10-18T07:00:00Z", chicago},
		// 2027-03-14 02:30 doesn't exist in Chicago (spring forward).
		{"30 2 * * *", "2027-03-13T12:00:00Z", "2027-03-15T07:30:00Z", chicago},
		// 2026-11-01 01:30 happens twice; the first is CDT (06:30 UTC).
		{"30 1 * * *", "2026-10-31T12:00:00Z", "2026-11-01T06:30:00Z", chicago},
		{"0 0 30 2 *", "2026-10-13T00:00:00Z", "", nil}, // never
	} {
		s, err := Parse(tc.expr)
		if err != nil {
			t.Errorf("%s: %v", tc.expr, err)
			continue
		}
		after, _ := time.Parse(time.RFC3339, tc.after)
		got := s.Next(after, tc.loc)
		if tc.want == "" {
			if !got.IsZero() {
				t.Errorf("%s after %s = %v, want none", tc.expr, tc.after, got)
			}
			continue
		}
		want, _ := time.Parse(time.RFC3339, tc.want)
		if !got.Equal(want) {
			t.Errorf("%s after %s = %v, want %v", tc.expr, tc.after, got.UTC(), want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, expr := range []string{"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *",
		"* * * 13 *", "* * * * 8", "5-1 * * * *", "*/0 * * * *", "a * * * *", "* * * * funday", "1,,2 * * * *"} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) accepted", expr)
		}
	}
	if _, err := Parse("0 2 * * SUN"); err != nil {
		t.Error(err)
	}
	if s := MustParse(" 0 2 * * SUN "); s.String() != "0 2 * * SUN" {
		t.Errorf("String() = %q", s.String())
	}
	_, err := Parse("61 * * * *")
	if err == nil || !strings.Contains(err.Error(), "minute") {
		t.Errorf("error names the field: %v", err)
	}
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestWindow(t *testing.T) {
	w := Window{Schedule: MustParse("0 2 * * SUN"), Duration: 3 * time.Hour, Location: time.UTC}
	if o, ok := w.At(at("2026-10-18T03:00:00Z")); !ok || !o.Start.Equal(at("2026-10-18T02:00:00Z")) || !o.End.Equal(at("2026-10-18T05:00:00Z")) {
		t.Errorf("At inside = %+v %v", o, ok)
	}
	if _, ok := w.At(at("2026-10-18T05:00:00Z")); ok {
		t.Error("the end isn't inside")
	}
	if _, ok := w.At(at("2026-10-18T02:00:00Z")); !ok {
		t.Error("the start is inside")
	}
	if o := w.NextOpening(at("2026-10-13T00:00:00Z")); !o.Start.Equal(at("2026-10-18T02:00:00Z")) {
		t.Errorf("NextOpening = %+v", o)
	}
	if o := w.NextOpening(at("2026-10-18T04:00:00Z")); !o.Start.Equal(at("2026-10-18T02:00:00Z")) {
		t.Errorf("NextOpening inside = %+v", o)
	}
	if o := w.NextOpening(at("2026-10-18T05:00:00Z")); !o.Start.Equal(at("2026-10-25T02:00:00Z")) {
		t.Errorf("NextOpening after = %+v", o)
	}
	if got := w.Openings(at("2026-10-01T00:00:00Z"), at("2026-11-01T00:00:00Z"), 10); len(got) != 4 {
		t.Errorf("Openings in October = %d", len(got))
	}
	o := w.NextOpening(at("2026-10-13T00:00:00Z"))
	if !o.Spans(at("2026-10-18T02:00:00Z"), at("2026-10-18T05:00:00Z")) || o.Spans(at("2026-10-18T04:00:00Z"), at("2026-10-18T05:01:00Z")) {
		t.Error("Spans")
	}

	// Openings that overlap or touch merge: hourly, two hours long.
	h := Window{Schedule: MustParse("0 * * * *"), Duration: 2 * time.Hour}
	if o, ok := h.At(at("2026-10-13T10:30:00Z")); !ok || o.End.Sub(o.Start) < 4*time.Hour {
		t.Errorf("merged = %+v %v", o, ok)
	}
	// Back to back: every day at midnight for 24h is always open.
	d := Window{Schedule: MustParse("0 0 * * *"), Duration: 24 * time.Hour}
	if o, ok := d.At(at("2026-10-13T23:59:00Z")); !ok || !o.End.After(at("2026-10-14T00:00:00Z")) {
		t.Errorf("touching = %+v %v", o, ok)
	}
	if got := d.Openings(at("2026-10-01T00:00:00Z"), at("2026-11-01T00:00:00Z"), 10); len(got) != 1 {
		t.Errorf("one long opening, got %d", len(got))
	}
	// Every minute for ten minutes: open throughout, found cheaply.
	m := Window{Schedule: MustParse("* * * * *"), Duration: 10 * time.Minute}
	if o, ok := m.At(at("2026-10-13T10:00:30Z")); !ok || o.End.Before(at("2026-10-13T10:10:00Z")) {
		t.Errorf("every minute = %+v %v", o, ok)
	}
	if o, _ := d.At(at("2026-10-13T12:00:00Z")); !o.Endless() {
		t.Errorf("a window that never closes isn't endless: %+v", o)
	}
	if o := w.NextOpening(at("2026-10-13T00:00:00Z")); o.Endless() {
		t.Error("a 3h window is endless")
	}
	if _, ok := (Window{Schedule: MustParse("* * * * *")}).At(at("2026-10-13T00:00:00Z")); ok {
		t.Error("zero duration is never open")
	}
}

// Package scheduler parses the five-field cron expressions that maintenance
// windows and patch groups are written in (docs/change-management.md §3,
// §4), and finds their next occurrences in a time zone.
package scheduler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed cron expression: minute, hour, day of month, month
// and day of week, each a set of allowed values.
type Schedule struct {
	expr                     string
	minute, hour, dom, month uint64 // bit n set: value n allowed
	dow                      uint64 // 0 = Sunday
	// As in Vixie cron, when both day fields are restricted a day matches
	// if either does.
	domStar, dowStar bool
}

type field struct {
	name     string
	min, max int
	names    []string // names[i] is value min+i
}

var fields = []field{
	{name: "minute", min: 0, max: 59},
	{name: "hour", min: 0, max: 23},
	{name: "day of month", min: 1, max: 31},
	{name: "month", min: 1, max: 12, names: []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}},
	// 7 is Sunday too.
	{name: "day of week", min: 0, max: 7, names: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}},
}

var macros = map[string]string{
	"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
	"@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}

// Parse reads "min hour dom month dow": lists (1,15), ranges (1-5), steps
// (*/15, 0-30/10), names (MON-FRI, JAN) and the @daily-style macros.
func Parse(expr string) (Schedule, error) {
	expr = strings.TrimSpace(expr)
	s := Schedule{expr: expr}
	if m, ok := macros[strings.ToLower(expr)]; ok {
		expr = m
	}
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return s, errors.New("a cron expression has five fields: minute hour day-of-month month day-of-week")
	}
	sets := []*uint64{&s.minute, &s.hour, &s.dom, &s.month, &s.dow}
	for i, p := range parts {
		bits, err := fields[i].parse(p)
		if err != nil {
			return s, err
		}
		*sets[i] = bits
	}
	if s.dow&(1<<7) != 0 {
		s.dow |= 1
		s.dow &^= 1 << 7
	}
	s.domStar = strings.HasPrefix(parts[2], "*")
	s.dowStar = strings.HasPrefix(parts[4], "*")
	return s, nil
}

// MustParse is Parse for expressions known to be valid.
func MustParse(expr string) Schedule {
	s, err := Parse(expr)
	if err != nil {
		panic(err)
	}
	return s
}

func (f field) parse(s string) (uint64, error) {
	var bits uint64
	for _, item := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 || n > f.max {
				return 0, fmt.Errorf("%s: bad step %q", f.name, stepStr)
			}
			step = n
		}
		lo, hi := f.min, f.max
		switch {
		case rng == "*":
			if f.name == "day of week" {
				hi = 6
			}
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if lo, err = f.value(a); err != nil {
				return 0, err
			}
			if hi, err = f.value(b); err != nil {
				return 0, err
			}
			if lo > hi {
				return 0, fmt.Errorf("%s: range %q runs backwards", f.name, rng)
			}
		default:
			v, err := f.value(rng)
			if err != nil {
				return 0, err
			}
			lo = v
			hi = v
			if hasStep {
				hi = f.max
			}
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func (f field) value(s string) (int, error) {
	for i, n := range f.names {
		if strings.EqualFold(s, n) {
			return f.min + i, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < f.min || v > f.max {
		return 0, fmt.Errorf("%s: %q isn't between %d and %d", f.name, s, f.min, f.max)
	}
	return v, nil
}

func (s Schedule) String() string { return s.expr }

// horizon bounds the search for the next occurrence: an expression such as
// "0 0 30 2 *" never matches.
const horizon = 5 * 366

// Next is the first time strictly after t that the schedule matches, read
// in loc; zero if there is none within five years. A time that doesn't
// exist in loc (skipped by a daylight-saving change) is skipped too; one
// that occurs twice matches the first time.
func (s Schedule) Next(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc).Truncate(time.Minute).Add(time.Minute)
	y, mo, d := t.Date()
	day := time.Date(y, mo, d, 0, 0, 0, 0, time.UTC) // calendar arithmetic only
	first := true
	for i := 0; i < horizon; i++ {
		if s.matchDay(day) {
			h0, m0 := 0, 0
			if first {
				h0, m0 = t.Hour(), t.Minute()
			}
			for h := h0; h < 24; h++ {
				if s.hour&(1<<uint(h)) == 0 {
					continue
				}
				start := 0
				if h == h0 {
					start = m0
				}
				for m := start; m < 60; m++ {
					if s.minute&(1<<uint(m)) == 0 {
						continue
					}
					c := time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, loc)
					if c.Hour() != h || c.Minute() != m || c.Day() != day.Day() {
						continue // not a wall-clock time on this day
					}
					if c.After(t) || c.Equal(t) {
						return c
					}
				}
			}
		}
		first = false
		day = day.AddDate(0, 0, 1)
	}
	return time.Time{}
}

func (s Schedule) matchDay(d time.Time) bool {
	if s.month&(1<<uint(d.Month())) == 0 {
		return false
	}
	domOK := s.dom&(1<<uint(d.Day())) != 0
	dowOK := s.dow&(1<<uint(d.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dowOK
	case s.dowStar:
		return domOK
	}
	return domOK || dowOK
}

// Opening is one occurrence of a window: [Start, End).
type Opening struct {
	Start, End time.Time
}

// Contains reports whether t falls inside the opening.
func (o Opening) Contains(t time.Time) bool { return !t.Before(o.Start) && t.Before(o.End) }

// Spans reports whether the opening covers all of [from, to).
func (o Opening) Spans(from, to time.Time) bool { return !from.Before(o.Start) && !to.After(o.End) }

func (o Opening) IsZero() bool { return o.Start.IsZero() }

// Window is a schedule that opens for a duration each time it fires.
type Window struct {
	Schedule Schedule
	Duration time.Duration
	Location *time.Location
}

// MaxOpening bounds openings that merge: a window that never closes ("0 0
// * * *" for 24h) is reported in stretches of this length.
const MaxOpening = 31 * 24 * time.Hour

// maxMerge bounds the starts At looks at. A schedule firing that often
// within one opening ("* * * * *" for an hour) is open throughout, and is
// reported as one MaxOpening stretch.
const maxMerge = 2000

// At returns the opening that contains t, if any. Openings that overlap or
// touch (a schedule firing more often than the window lasts) merge; Start
// is then the earliest start within one duration of t.
func (w Window) At(t time.Time) (Opening, bool) {
	if w.Duration <= 0 {
		return Opening{}, false
	}
	var o Opening
	n := 0
	for s := w.Schedule.Next(t.Add(-w.Duration), w.Location); !s.IsZero() && !s.After(t); s = w.Schedule.Next(s, w.Location) {
		if o.IsZero() {
			o.Start = s
		}
		o.End = s.Add(w.Duration)
		if n++; n > maxMerge {
			o.End = o.Start.Add(MaxOpening)
			return o, true
		}
	}
	if o.IsZero() || !o.Contains(t) {
		return Opening{}, false
	}
	// A later start inside the merged opening extends it.
	for s := w.Schedule.Next(t, w.Location); !s.IsZero() && !s.After(o.End); s = w.Schedule.Next(s, w.Location) {
		o.End = s.Add(w.Duration)
		if n++; n > maxMerge || o.End.Sub(o.Start) >= MaxOpening {
			o.End = o.Start.Add(MaxOpening)
			break
		}
	}
	return o, true
}

// Endless reports whether the opening is a stretch of a window that never
// closes.
func (o Opening) Endless() bool { return o.End.Sub(o.Start) >= MaxOpening }

// NextOpening returns the opening in effect at t, or else the next one to
// start after t; zero if there is none.
func (w Window) NextOpening(t time.Time) Opening {
	if o, ok := w.At(t); ok {
		return o
	}
	s := w.Schedule.Next(t, w.Location)
	if s.IsZero() || w.Duration <= 0 {
		return Opening{}
	}
	o, _ := w.At(s)
	return o
}

// Openings lists the openings that overlap [from, to), at most max of them.
func (w Window) Openings(from, to time.Time, max int) []Opening {
	var out []Opening
	o := w.NextOpening(from)
	for !o.IsZero() && o.Start.Before(to) && len(out) < max {
		out = append(out, o)
		o = w.NextOpening(o.End)
		if len(out) > 0 && !o.IsZero() && !o.Start.After(out[len(out)-1].Start) {
			break
		}
	}
	return out
}

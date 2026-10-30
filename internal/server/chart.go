package server

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
	"time"
)

// Charts are drawn here as SVG, so they work without JavaScript; uPlot
// replaces them with interactive ones when it can (web/static/metrics.js).
// Colours come from CSS classes (.s0 ... .s7), which also keeps the markup
// free of inline styles the CSP would block.

const (
	chartW, chartH = 800, 220
	padL, padR     = 64, 12
	padT, padB     = 10, 24
	chartColors    = 8
)

type chartLine struct {
	Label  string
	Values []float64 // NaN = no data
}

type chartSpec struct {
	Title    string
	Unit     string
	Max      float64 // fixed top of the y axis; 0 = from the data
	Times    []time.Time
	Lines    []chartLine
	From, To time.Time
	Loc      *time.Location
}

// svgChart renders a line chart. Every string that reaches the markup is
// escaped, so the result is safe to embed.
func svgChart(c chartSpec) template.HTML {
	plotW, plotH := float64(chartW-padL-padR), float64(chartH-padT-padB)
	top := c.Max
	if top == 0 {
		for _, l := range c.Lines {
			for _, v := range l.Values {
				if !math.IsNaN(v) && v > top {
					top = v
				}
			}
		}
	}
	yStep, top := niceScale(top)
	if c.Unit == "bytes" || c.Unit == "bytes/s" {
		// Steps in whole KiB, MiB, GiB...: "2.5 GiB" rather than "2.3 GiB".
		unit := math.Pow(1024, math.Max(0, math.Floor(math.Log(math.Max(top, 1))/math.Log(1024))))
		yStep, top = niceScale(top / unit)
		yStep, top = yStep*unit, top*unit
	}
	span := c.To.Sub(c.From).Seconds()
	if span <= 0 {
		span = 1
	}
	x := func(t time.Time) float64 { return padL + plotW*t.Sub(c.From).Seconds()/span }
	y := func(v float64) float64 { return padT + plotH*(1-v/top) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart-svg" viewBox="0 0 %d %d" role="img" aria-label="%s">`, chartW, chartH, html.EscapeString(c.Title))
	b.WriteString(`<g class="grid">`)
	for v := 0.0; v <= top+yStep/2; v += yStep {
		fmt.Fprintf(&b, `<line x1="%d" x2="%d" y1="%.1f" y2="%.1f"/>`, padL, chartW-padR, y(v), y(v))
	}
	b.WriteString(`</g><g class="axis">`)
	for v := 0.0; v <= top+yStep/2; v += yStep {
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" text-anchor="end" dominant-baseline="middle">%s</text>`,
			padL-6, y(v), html.EscapeString(formatValue(v, c.Unit)))
	}
	every, layout := timeTicks(c.To.Sub(c.From))
	for t := c.From.In(c.Loc).Truncate(time.Minute); !t.After(c.To); t = t.Add(time.Minute) {
		if !onTick(t, every) || t.Before(c.From) {
			continue
		}
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" text-anchor="middle">%s</text>`, x(t), chartH-6, t.Format(layout))
		if every >= time.Hour {
			t = t.Add(every - time.Minute) // skip ahead; ticks are far apart
		}
	}
	b.WriteString(`</g>`)
	for i, l := range c.Lines {
		var d strings.Builder
		pen := false
		for j, v := range l.Values {
			if math.IsNaN(v) || j >= len(c.Times) {
				pen = false
				continue
			}
			cmd := 'L'
			if !pen {
				cmd, pen = 'M', true
			}
			fmt.Fprintf(&d, "%c%.1f %.1f", cmd, x(c.Times[j]), y(math.Min(v, top)))
		}
		if d.Len() > 0 {
			fmt.Fprintf(&b, `<path class="line s%d" d="%s" vector-effect="non-scaling-stroke"/>`, i%chartColors, d.String())
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// niceScale picks a tick step of 1, 2, 2.5 or 5 times a power of ten so that
// about four steps cover max, and returns the step and the rounded top.
func niceScale(max float64) (step, top float64) {
	if max <= 0 || math.IsNaN(max) {
		return 0.25, 1
	}
	raw := max / 4
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	switch n := raw / mag; {
	case n <= 1:
		step = mag
	case n <= 2:
		step = 2 * mag
	case n <= 2.5:
		step = 2.5 * mag
	case n <= 5:
		step = 5 * mag
	default:
		step = 10 * mag
	}
	return step, math.Ceil(max/step-1e-9) * step
}

// timeTicks chooses the spacing and format of time labels for a span.
func timeTicks(span time.Duration) (time.Duration, string) {
	for _, t := range []struct {
		every  time.Duration
		layout string
	}{
		{10 * time.Minute, "15:04"}, {30 * time.Minute, "15:04"}, {time.Hour, "15:04"}, {3 * time.Hour, "15:04"},
		{6 * time.Hour, "15:04"}, {24 * time.Hour, "Jan 2"}, {2 * 24 * time.Hour, "Jan 2"}, {7 * 24 * time.Hour, "Jan 2"},
	} {
		if span/t.every <= 7 {
			return t.every, t.layout
		}
	}
	return 14 * 24 * time.Hour, "Jan 2"
}

// onTick reports whether t (in the display zone) falls on a tick.
func onTick(t time.Time, every time.Duration) bool {
	if every >= 24*time.Hour {
		days := int(every / (24 * time.Hour))
		return t.Hour() == 0 && t.Minute() == 0 && t.YearDay()%days == 0
	}
	mins := t.Hour()*60 + t.Minute()
	return mins%int(every/time.Minute) == 0
}

// formatValue renders an axis or table value in a unit.
func formatValue(v float64, unit string) string {
	switch unit {
	case "%":
		return fmt.Sprintf("%.0f%%", v)
	case "bytes":
		return humanBytes(uint64(v))
	case "bytes/s":
		return humanBytes(uint64(v)) + "/s"
	case "°C":
		return fmt.Sprintf("%.0f°C", v)
	case "/s":
		return compact(v) + "/s"
	}
	return compact(v)
}

// compact shortens large numbers: 1500 → 1.5k.
func compact(v float64) string {
	switch a := math.Abs(v); {
	case a >= 1e9:
		return trimZero(fmt.Sprintf("%.1f", v/1e9)) + "G"
	case a >= 1e6:
		return trimZero(fmt.Sprintf("%.1f", v/1e6)) + "M"
	case a >= 1e3:
		return trimZero(fmt.Sprintf("%.1f", v/1e3)) + "k"
	case a == math.Trunc(a):
		return fmt.Sprintf("%.0f", v)
	case a >= 10:
		return fmt.Sprintf("%.1f", v)
	}
	return trimZero(fmt.Sprintf("%.2f", v))
}

func trimZero(s string) string {
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

package server

import (
	"encoding/json"
	"html/template"
	"math"
	"net/http"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// metricPanel is one chart on a host's Metrics tab.
type metricPanel struct {
	ID    string
	Title string
	Kind  string
	Names []string
	Unit  string
	Max   float64 // fixed top of the y axis (percentages)
}

var metricPanels = []metricPanel{
	{"cpu", "CPU", "cpu", []string{"user", "system", "iowait", "steal"}, "%", 100},
	{"load", "Load average", "load", []string{"load1", "load5", "load15"}, "", 0},
	{"memory", "Memory", "mem", []string{"used", "cached", "swap_used"}, "bytes", 0},
	{"disk-throughput", "Disk throughput", "disk", []string{"read_bps", "write_bps"}, "bytes/s", 0},
	{"disk-iops", "Disk operations", "disk", []string{"read_iops", "write_iops"}, "/s", 0},
	{"disk-busy", "Disk busy", "disk", []string{"util"}, "%", 100},
	{"network", "Network", "net", []string{"rx_bps", "tx_bps"}, "bytes/s", 0},
	{"filesystems", "Filesystem used", "fs", []string{"used_pct"}, "%", 100},
	{"drive-temperature", "Drive temperature", "smart", []string{"temperature_c"}, "°C", 0},
	// 100% is one full CPU core, as docker stats shows it.
	{"container-cpu", "Container CPU", "container", []string{"cpu_pct"}, "%", 0},
	{"container-memory", "Container memory", "container", []string{"mem_used"}, "bytes", 0},
}

var metricLabels = map[string]string{
	"iowait": "I/O wait", "load1": "1 min", "load5": "5 min", "load15": "15 min", "cached": "cache", "swap_used": "swap",
	"read_bps": "read", "write_bps": "write", "read_iops": "read", "write_iops": "write", "util": "busy",
	"rx_bps": "in", "tx_bps": "out", "used_pct": "used", "temperature_c": "temperature",
}

// metricRange is a time window offered on the Metrics tab. Up to two days
// come from raw samples; longer ones from the 5-minute rollups. Steps keep
// each line to a few hundred points.
type metricRange struct {
	Key    string
	Label  string
	Span   time.Duration
	Step   time.Duration
	Rollup bool
}

var metricRanges = []metricRange{
	{"1h", "1 hour", time.Hour, time.Minute, false},
	{"6h", "6 hours", 6 * time.Hour, time.Minute, false},
	{"24h", "24 hours", 24 * time.Hour, 2 * time.Minute, false},
	{"7d", "7 days", 7 * 24 * time.Hour, 15 * time.Minute, true},
	{"30d", "30 days", 30 * 24 * time.Hour, time.Hour, true},
}

func findRange(key string) metricRange {
	for _, r := range metricRanges {
		if r.Key == key {
			return r
		}
	}
	return metricRanges[1]
}

func findPanel(id string) (metricPanel, bool) {
	for _, p := range metricPanels {
		if p.ID == id {
			return p, true
		}
	}
	return metricPanel{}, false
}

func (p metricPanel) label(l store.MetricLine) string {
	name := l.Name
	if v, ok := metricLabels[name]; ok {
		name = v
	}
	switch {
	case l.Instance == "":
		return name
	case len(p.Names) == 1:
		return l.Instance
	}
	return l.Instance + " " + name
}

// panelData queries one panel's lines for a range ending now.
func (s *Server) panelData(r *http.Request, hostID string, p metricPanel, rg metricRange) (chartSpec, error) {
	to := time.Now()
	from := to.Add(-rg.Span)
	d, err := s.store.QueryMetrics(r.Context(), store.MetricQuery{
		HostID: hostID, Kind: p.Kind, Names: p.Names, From: from, To: to, Step: rg.Step, Rollup: rg.Rollup,
	})
	if err != nil {
		return chartSpec{}, err
	}
	c := chartSpec{Title: p.Title, Unit: p.Unit, Max: p.Max, Times: d.Times, From: from, To: to, Loc: s.cfg.Location}
	for _, l := range d.Lines {
		c.Lines = append(c.Lines, chartLine{Label: p.label(l), Values: l.Values})
	}
	return c, nil
}

// metricsChart is a rendered panel on the Metrics tab.
type metricsChart struct {
	Panel  metricPanel
	SVG    template.HTML
	Labels []string
	Latest []string // each line's most recent value, formatted
}

type metricsView struct {
	Range  metricRange
	Ranges []metricRange
	Charts []metricsChart
	TZ     string
}

func (s *Server) metricsView(r *http.Request, hostID string) (metricsView, error) {
	v := metricsView{Range: findRange(r.URL.Query().Get("range")), Ranges: metricRanges, TZ: s.cfg.Location.String()}
	for _, p := range metricPanels {
		c, err := s.panelData(r, hostID, p, v.Range)
		if err != nil {
			return v, err
		}
		if len(c.Lines) == 0 {
			continue // nothing recorded, e.g. no SMART on a VM
		}
		mc := metricsChart{Panel: p, SVG: svgChart(c)}
		for _, l := range c.Lines {
			mc.Labels = append(mc.Labels, l.Label)
			latest := "—"
			for i := len(l.Values) - 1; i >= 0; i-- {
				if !math.IsNaN(l.Values[i]) {
					latest = formatValue(l.Values[i], p.Unit)
					break
				}
			}
			mc.Latest = append(mc.Latest, latest)
		}
		v.Charts = append(v.Charts, mc)
	}
	return v, nil
}

// hostMetricsJSON serves one panel's data in the column layout uPlot takes:
// times in seconds, then one array per line, null where there's no data.
func (s *Server) hostMetricsJSON(w http.ResponseWriter, r *http.Request) {
	h, ok := s.loadHost(w, r, rbac.Viewer)
	if !ok {
		return
	}
	p, ok := findPanel(strings.TrimSuffix(r.PathValue("panel"), ".json"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c, err := s.panelData(r, h.ID, p, findRange(r.URL.Query().Get("range")))
	if err != nil {
		s.log.Log("Server", "metrics", jw6_utils.Error, err.Error())
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	out := chartJSON(c, s.cfg.Location.String())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

// chartJSONOut is a panel's data as the Metrics tab's script and the API
// get it: epoch seconds and one series of values (null for gaps) per line.
type chartJSONOut struct {
	Title  string       `json:"title"`
	Unit   string       `json:"unit"`
	Max    float64      `json:"max,omitempty"`
	From   int64        `json:"from"`
	To     int64        `json:"to"`
	TZ     string       `json:"tz"`
	Labels []string     `json:"labels"`
	Times  []int64      `json:"times"`
	Values [][]*float64 `json:"values"`
}

func chartJSON(c chartSpec, tz string) chartJSONOut {
	out := chartJSONOut{Title: c.Title, Unit: c.Unit, Max: c.Max, From: c.From.Unix(), To: c.To.Unix(), TZ: tz,
		Labels: []string{}, Times: make([]int64, len(c.Times)), Values: [][]*float64{}}
	for i, t := range c.Times {
		out.Times[i] = t.Unix()
	}
	for _, l := range c.Lines {
		out.Labels = append(out.Labels, l.Label)
		vals := make([]*float64, len(l.Values))
		for i := range l.Values {
			if !math.IsNaN(l.Values[i]) {
				vals[i] = &l.Values[i]
			}
		}
		out.Values = append(out.Values, vals)
	}
	return out
}

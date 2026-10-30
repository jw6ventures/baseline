package collect

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Sample is one metric reading (docs/agent.md §1.2).
type Sample struct {
	Kind     string // cpu | load | mem | disk | fs | net | smart
	Name     string
	Instance string // device, mount or interface; "" for host-level
	Value    float64
}

// Sampler reads host metrics. Counters (CPU time, disk and network) become
// rates from the difference between two readings, so the first Sample after
// start has gauges only.
type Sampler struct {
	Env *Env

	mu      sync.Mutex
	at      time.Time
	cpu     []uint64
	disks   map[string][]uint64
	nets    map[string][]uint64
	pending []Sample // SMART readings waiting for the next batch
}

// AddSMART queues readings taken by the SMART collector, which runs far less
// often than the sampler; they go out with the next batch.
func (s *Sampler) AddSMART(samples []Sample) {
	s.mu.Lock()
	s.pending = append(s.pending, samples...)
	s.mu.Unlock()
}

// Sample takes one reading of everything.
func (s *Sampler) Sample(now time.Time) []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.Env
	var out []Sample
	add := func(kind, name, inst string, v float64) {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			out = append(out, Sample{kind, name, inst, v})
		}
	}
	dt := now.Sub(s.at).Seconds()
	havePrev := !s.at.IsZero() && dt > 0

	// CPU: /proc/stat's first line, in clock ticks since boot.
	if f := strings.Fields(firstLineOf(e.Read("/proc/stat"))); len(f) >= 9 && f[0] == "cpu" {
		cur := parseUints(f[1:9]) // user nice system idle iowait irq softirq steal
		if havePrev && len(s.cpu) == len(cur) {
			d := make([]float64, len(cur))
			var total float64
			ok := true
			for i := range cur {
				if cur[i] < s.cpu[i] {
					ok = false
				}
				d[i] = float64(cur[i] - s.cpu[i])
				total += d[i]
			}
			if ok && total > 0 {
				pct := func(v float64) float64 { return 100 * v / total }
				add("cpu", "user", "", pct(d[0]+d[1]))
				add("cpu", "system", "", pct(d[2]+d[5]+d[6]))
				add("cpu", "iowait", "", pct(d[4]))
				add("cpu", "steal", "", pct(d[7]))
				add("cpu", "idle", "", pct(d[3]))
			}
		}
		s.cpu = cur
	}

	if f := strings.Fields(e.Read("/proc/loadavg")); len(f) >= 3 {
		for i, name := range []string{"load1", "load5", "load15"} {
			if v, err := strconv.ParseFloat(f[i], 64); err == nil {
				add("load", name, "", v)
			}
		}
	}

	mem := map[string]float64{}
	for _, line := range strings.Split(e.Read("/proc/meminfo"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if f := strings.Fields(v); ok && len(f) > 0 {
			if n, err := strconv.ParseFloat(f[0], 64); err == nil {
				mem[k] = n * 1024
			}
		}
	}
	if total := mem["MemTotal"]; total > 0 {
		add("mem", "total", "", total)
		add("mem", "used", "", total-mem["MemAvailable"])
		add("mem", "available", "", mem["MemAvailable"])
		add("mem", "cached", "", mem["Cached"]+mem["SReclaimable"])
		add("mem", "swap_used", "", mem["SwapTotal"]-mem["SwapFree"])
	}

	// Disks: whole devices only (partitions would count twice).
	wholeDisk := map[string]bool{}
	for _, name := range e.ReadDir("/sys/block") {
		wholeDisk[name] = !skipBlock(name)
	}
	disks := map[string][]uint64{}
	for _, line := range strings.Split(e.Read("/proc/diskstats"), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || !wholeDisk[f[2]] {
			continue
		}
		// reads, sectors read, writes, sectors written, ms doing I/O, weighted ms
		cur := parseUints([]string{f[3], f[5], f[7], f[9], f[12], f[13]})
		disks[f[2]] = cur
		prev, ok := s.disks[f[2]]
		if !havePrev || !ok || !increasing(prev, cur) {
			continue
		}
		rate := func(i int) float64 { return float64(cur[i]-prev[i]) / dt }
		add("disk", "read_iops", f[2], rate(0))
		add("disk", "write_iops", f[2], rate(2))
		add("disk", "read_bps", f[2], rate(1)*512)
		add("disk", "write_bps", f[2], rate(3)*512)
		add("disk", "util", f[2], math.Min(100, rate(4)/10)) // ms per s → %
		add("disk", "queue", f[2], rate(5)/1000)
	}
	s.disks = disks

	for _, fs := range e.filesystems() {
		var st syscall.Statfs_t
		if e.statfs(fs.Mountpoint, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := float64(st.Bsize)
		used, avail := float64(st.Blocks-st.Bfree)*bs, float64(st.Bavail)*bs
		add("fs", "used_bytes", fs.Mountpoint, used)
		add("fs", "avail_bytes", fs.Mountpoint, avail)
		if used+avail > 0 {
			add("fs", "used_pct", fs.Mountpoint, 100*used/(used+avail)) // as df shows it
		}
		if st.Files > 0 {
			add("fs", "inodes_used_pct", fs.Mountpoint, 100*float64(st.Files-st.Ffree)/float64(st.Files))
		}
	}

	nets := map[string][]uint64{}
	for _, line := range strings.Split(e.Read("/proc/net/dev"), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if !ok || len(f) < 12 || name == "lo" || isEphemeralNIC(name) {
			continue
		}
		// rx bytes packets errs drop, tx bytes packets errs drop
		cur := parseUints([]string{f[0], f[1], f[2], f[3], f[8], f[9], f[10], f[11]})
		nets[name] = cur
		prev, ok := s.nets[name]
		if !havePrev || !ok || !increasing(prev, cur) {
			continue
		}
		for i, m := range []string{"rx_bps", "rx_pps", "rx_errors", "rx_drops", "tx_bps", "tx_pps", "tx_errors", "tx_drops"} {
			add("net", m, name, float64(cur[i]-prev[i])/dt)
		}
	}
	s.nets = nets

	out = append(out, s.pending...)
	s.pending = nil
	s.at = now
	return out
}

func parseUints(f []string) []uint64 {
	out := make([]uint64, len(f))
	for i, v := range f {
		out[i], _ = strconv.ParseUint(v, 10, 64)
	}
	return out
}

// increasing is false after a counter reset (device re-added, wrap).
func increasing(prev, cur []uint64) bool {
	if len(prev) != len(cur) {
		return false
	}
	for i := range cur {
		if cur[i] < prev[i] {
			return false
		}
	}
	return true
}

func firstLineOf(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

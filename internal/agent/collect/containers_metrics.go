package collect

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/agent/container"
)

// ctrMetrics is what Sample remembers about a running container.
type ctrMetrics struct {
	engine string
	cgroup string // cgroup v2 path, found through the main PID
	usage  float64
	at     time.Time // when usage was read; zero before the first reading
}

// ctrReading is one reading of a container's resource use.
type ctrReading struct {
	usageUsec float64 // CPU time since the container started
	memUsed   float64
	memLimit  float64 // 0: unlimited
}

// Sample reads CPU and memory use of every running container (docs/agent.md
// §1.2). CPU is a rate between two readings of the same container, so a
// container's first sample has memory only. cpu_pct is a percentage of one
// CPU: 100 is a full core.
func (c *ContainerCollector) Sample(ctx context.Context, now time.Time) []Sample {
	c.smu.Lock()
	defer c.smu.Unlock()
	c.mu.Lock()
	engines, discovered := c.engines, c.discovered
	c.mu.Unlock()
	if !discovered {
		engines = c.discover(ctx)
	}
	if c.stats == nil {
		c.stats = map[string]*ctrMetrics{}
	}
	e := c.Env
	v2 := e.Exists("/sys/fs/cgroup/cgroup.controllers")

	var out []Sample
	running := map[string]bool{}
	unread := map[string]bool{} // engines not listed this time keep their state
	for _, eng := range engines {
		if eng.Error != "" {
			unread[eng.Name] = true
			continue
		}
		// Sampling mustn't hold up the next tick when an engine hangs.
		ectx, cancel := context.WithTimeout(ctx, 10*time.Second)
		list, err := eng.client.ListContainers(ectx)
		if err != nil {
			unread[eng.Name] = true
			cancel()
			continue
		}
		for _, s := range list {
			if s.State != "running" {
				continue
			}
			running[s.ID] = true
			st := c.stats[s.ID]
			if st == nil {
				st = &ctrMetrics{engine: eng.Name}
				c.stats[s.ID] = st
			}
			var r ctrReading
			ok := v2 && c.readCgroup(ectx, eng.client, s.ID, st, &r)
			if !ok {
				ok = c.readEngineStats(ectx, eng.client, s.ID, &r)
			}
			if !ok {
				continue
			}
			inst := s.Name()
			if eng.Name != "docker" {
				inst = eng.Name + "/" + inst
			}
			if dt := now.Sub(st.at).Seconds(); !st.at.IsZero() && dt > 0 && r.usageUsec >= st.usage {
				out = append(out, Sample{"container", "cpu_pct", inst, 100 * (r.usageUsec - st.usage) / (dt * 1e6)})
			}
			st.usage, st.at = r.usageUsec, now
			out = append(out, Sample{"container", "mem_used", inst, r.memUsed})
			if r.memLimit > 0 {
				out = append(out, Sample{"container", "mem_limit", inst, r.memLimit})
			}
		}
		cancel()
	}
	for id, st := range c.stats {
		if !running[id] && !unread[st.engine] {
			delete(c.stats, id)
		}
	}
	return out
}

// readCgroup reads a container's cgroup v2 files. The path is found once
// through the container's main PID and kept until the files disappear.
func (c *ContainerCollector) readCgroup(ctx context.Context, cl *container.Client, id string, st *ctrMetrics, r *ctrReading) bool {
	e := c.Env
	if st.cgroup == "" {
		in, err := cl.Inspect(ctx, id)
		if err != nil || in.State.Pid <= 0 {
			return false
		}
		p := e.procCgroup(in.State.Pid)
		if p == "" || p == "/" {
			return false
		}
		st.cgroup = ctrCgroupScope(p, id)
	}
	dir := "/sys/fs/cgroup" + st.cgroup
	usage, okCPU := cgroupStatValue(e.Read(dir+"/cpu.stat"), "usage_usec")
	current, err := strconv.ParseFloat(e.Read(dir+"/memory.current"), 64)
	if !okCPU || err != nil {
		st.cgroup = "" // the container moved (restarted elsewhere); look again next time
		return false
	}
	inactive, _ := cgroupStatValue(e.Read(dir+"/memory.stat"), "inactive_file")
	r.usageUsec = usage
	r.memUsed = max(0, current-inactive) // as docker stats shows it
	if lim, err := strconv.ParseFloat(e.Read(dir+"/memory.max"), 64); err == nil {
		r.memLimit = lim // "max" doesn't parse: unlimited
	}
	return true
}

// readEngineStats is the cgroup v1 fallback: one reading from the Engine's
// stats endpoint.
func (c *ContainerCollector) readEngineStats(ctx context.Context, cl *container.Client, id string, r *ctrReading) bool {
	st, err := cl.Stats(ctx, id)
	if err != nil {
		return false
	}
	m := st.MemoryStats
	inactive, ok := m.Stats["inactive_file"]
	if !ok {
		inactive = m.Stats["total_inactive_file"] // cgroup v1
	}
	r.usageUsec = float64(st.CPUStats.CPUUsage.TotalUsage) / 1000
	r.memUsed = float64(m.Usage) - float64(min(inactive, m.Usage))
	// Without a limit the engine reports the host's memory (or a huge
	// number on cgroup v1), which isn't a limit at all.
	if total := c.memTotal(); m.Limit > 0 && m.Limit < 1<<60 && (total == 0 || float64(m.Limit) < total) {
		r.memLimit = float64(m.Limit)
	}
	return true
}

func (c *ContainerCollector) memTotal() float64 {
	for _, line := range strings.Split(c.Env.Read("/proc/meminfo"), "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				n, _ := strconv.ParseFloat(f[0], 64)
				return n * 1024
			}
		}
	}
	return 0
}

// ctrCgroupScope is the cgroup holding the whole container. Podman can run
// the main process in a child ("libpod-<id>.scope/container"), which would
// undercount; the container's own cgroup is the one named after its ID.
func ctrCgroupScope(path, id string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i > 0; i-- {
		if id != "" && strings.Contains(segs[i], id) {
			return strings.Join(segs[:i+1], "/")
		}
	}
	return path
}

// cgroupStatValue reads one "key value" line of a cgroup stat file.
func cgroupStatValue(stat, key string) (float64, bool) {
	for _, line := range strings.Split(stat, "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == key {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return n, err == nil
		}
	}
	return 0, false
}

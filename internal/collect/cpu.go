package collect

import "github.com/xyfu/xnux-shared/proto"

// cpuTimes is the aggregate "cpu" line of /proc/stat. guest and guest_nice
// are already included in user and nice and are not added again.
type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// parseCPULine parses the first line of /proc/stat.
func parseCPULine(b []byte) (cpuTimes, bool) {
	line, _ := nextLine(b)
	name, rest := nextField(line)
	if string(name) != "cpu" {
		return cpuTimes{}, false
	}
	var v [8]uint64
	for i := range v {
		var f []byte
		f, rest = nextField(rest)
		n, ok := parseUint(f)
		if !ok {
			if i >= 4 { // very old kernels lack iowait and later columns
				break
			}
			return cpuTimes{}, false
		}
		v[i] = n
	}
	return cpuTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}, true
}

// countCPUs counts the "cpuN" lines of a full /proc/stat.
func countCPUs(b []byte) int {
	n := 0
	for len(b) > 0 {
		var line []byte
		line, b = nextLine(b)
		if hasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	return n
}

// cpuDelta turns two readings into percentages. It reports false for the
// first reading, a zero interval or a counter that went backwards; the caller
// then keeps cur as the new baseline.
func cpuDelta(prev, cur cpuTimes) (proto.CPU, bool) {
	if cur.total() <= prev.total() || cur.idle < prev.idle || cur.iowait < prev.iowait || cur.steal < prev.steal {
		return proto.CPU{}, false
	}
	dt := float64(cur.total() - prev.total())
	didle := float64(cur.idle - prev.idle)
	diow := float64(cur.iowait - prev.iowait)
	dsteal := float64(cur.steal - prev.steal)
	return proto.CPU{
		TotalPct:  pct((dt - didle - diow) / dt * 100),
		IOWaitPct: pct(diow / dt * 100),
		StealPct:  pct(dsteal / dt * 100),
	}, true
}

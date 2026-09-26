package collect

import "github.com/xyfu/xnux-shared/proto"

type meminfo struct {
	memTotal, memAvailable, swapTotal, swapFree uint64 // kB
}

// parseMeminfo reads only the four keys it needs and stops once all are found.
func parseMeminfo(b []byte) (meminfo, bool) {
	var m meminfo
	found := 0
	for len(b) > 0 && found < 4 {
		var line []byte
		line, b = nextLine(b)
		var dst *uint64
		switch {
		case hasPrefix(line, "MemTotal:"):
			dst = &m.memTotal
		case hasPrefix(line, "MemAvailable:"):
			dst = &m.memAvailable
		case hasPrefix(line, "SwapTotal:"):
			dst = &m.swapTotal
		case hasPrefix(line, "SwapFree:"):
			dst = &m.swapFree
		default:
			continue
		}
		_, rest := nextField(line)
		f, _ := nextField(rest)
		v, ok := parseUint(f)
		if !ok {
			return m, false
		}
		*dst = v
		found++
	}
	return m, found == 4 || (found == 2 && m.memTotal > 0 && m.memAvailable > 0)
}

func (m meminfo) mem() proto.Mem {
	used := 0.0
	if m.memTotal > 0 {
		// MemFree is never used: it would count page cache as used memory.
		used = float64(m.memTotal-min(m.memAvailable, m.memTotal)) / float64(m.memTotal) * 100
	}
	return proto.Mem{
		TotalMB:     int(m.memTotal / 1024),
		AvailableMB: int(m.memAvailable / 1024),
		UsedPct:     pct(used),
	}
}

// parseVmstatSwap returns the cumulative pswpin and pswpout page counters.
func parseVmstatSwap(b []byte) (in, out uint64, ok bool) {
	found := 0
	for len(b) > 0 && found < 2 {
		var line []byte
		line, b = nextLine(b)
		name, rest := nextField(line)
		var dst *uint64
		switch string(name) {
		case "pswpin":
			dst = &in
		case "pswpout":
			dst = &out
		default:
			continue
		}
		f, _ := nextField(rest)
		v, ok := parseUint(f)
		if !ok {
			return 0, 0, false
		}
		*dst = v
		found++
	}
	return in, out, found == 2
}

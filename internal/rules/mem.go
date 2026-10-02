package rules

import (
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

// Agent-side resource rules that need every sample (spec A4.3). Both fire
// once when the condition starts and re-arm when it clears. The thresholds
// live in xnux-shared: the server uses them to end the events.
const (
	thrashInPS     = proto.SwapThrashingInPS
	thrashSamples  = proto.SwapThrashingSamples
	pressureAvail  = proto.MemPressureAvailPct // % of memory available
	pressureGrowth = 0.10                      // swap used growth within a minute
	pressureWindow = 60                        // seconds
)

type swapPoint struct {
	ts   int64
	used int
}

type memRules struct {
	streak    int
	thrashing bool
	pressure  bool
	hist      []swapPoint // the last ~90 s of swap usage
}

func (m *memRules) sample(met proto.Metric) []occ {
	var out []occ
	sw := met.Swap
	used := 0
	if sw != nil {
		used = sw.UsedMB
	}
	data := func() map[string]any {
		d := map[string]any{"available_mb": met.Mem.AvailableMB, "swap_used_mb": used}
		if sw != nil {
			d["in_ps"] = sw.InPS
		}
		return d
	}

	if sw != nil && sw.InPS >= thrashInPS {
		m.streak++
	} else {
		m.streak, m.thrashing = 0, false
	}
	if m.streak >= thrashSamples && !m.thrashing {
		m.thrashing = true
		out = append(out, occ{typ: proto.EventSwapThrashing, sev: proto.SeverityP2, key: "swap", ts: unix(met.TS), data: data()})
	}

	m.hist = append(m.hist, swapPoint{met.TS, used})
	for len(m.hist) > 1 && met.TS-m.hist[1].ts >= pressureWindow {
		m.hist = m.hist[1:]
	}
	low := met.Mem.TotalMB > 0 && float64(met.Mem.AvailableMB)*100/float64(met.Mem.TotalMB) < pressureAvail
	if !low {
		m.pressure = false
		return out
	}
	then := m.hist[0]
	growing := sw != nil && met.TS-then.ts > 0 && used > then.used &&
		(then.used == 0 || float64(used-then.used)/float64(then.used) > pressureGrowth)
	if growing && !m.pressure {
		m.pressure = true
		out = append(out, occ{typ: proto.EventMemPressure, sev: proto.SeverityP2, key: "mem", ts: unix(met.TS), data: data()})
	}
	return out
}

func unix(s int64) time.Time { return time.Unix(s, 0) }

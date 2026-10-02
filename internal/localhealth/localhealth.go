// Package localhealth scores this machine with the same algorithm as the
// service (xnux-shared/health, spec v1.1 delta 8), from the local black
// box: the metrics ring for the last hour's percentiles, the latest sample
// for disks, and the event log for the last 24 hours. Local events have no
// "resolved" state, so anything seen in the last 24 hours counts as open.
package localhealth

import (
	"math"
	"sort"
	"time"

	"github.com/xyfu/xnux-shared/health"
	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/localstore"
)

// Result is a score, or why there is none yet.
type Result struct {
	State string         `json:"state"` // scored | collecting
	Score *health.Result `json:"result,omitempty"`
}

// Score computes the local health. minutes are the last hour or more of
// the ring, latest the newest raw sample, events the last 24 hours.
func Score(minutes []localstore.Minute, latest *proto.Metric, events []localstore.Event, cores int, now time.Time) Result {
	hour := now.Add(-time.Hour).Unix()
	var recent []localstore.Minute
	for _, m := range minutes {
		if m.TS >= hour {
			recent = append(recent, m)
		}
	}
	// Like the service: an hour of data before the first score.
	if len(recent) < 50 {
		return Result{State: "collecting"}
	}
	in := health.Input{}
	pick := func(f func(localstore.Minute) *float64) []float64 {
		var v []float64
		for _, m := range recent {
			if p := f(m); p != nil {
				v = append(v, *p)
			}
		}
		return v
	}
	val := func(v float64) *float64 { return &v }
	in.CPUP95 = pct(pick(func(m localstore.Minute) *float64 { return val(m.CPU) }), 0.95)
	in.MemAvailP5 = pct(pick(func(m localstore.Minute) *float64 { return val(m.MemAvail) }), 0.05)
	in.SwapInP95 = pct(pick(func(m localstore.Minute) *float64 { return m.SwapInPS }), 0.95)
	in.IOWaitP95 = pct(pick(func(m localstore.Minute) *float64 { return val(m.IOWait) }), 0.95)
	if cores > 0 {
		in.LoadPerCoreP95 = pct(pick(func(m localstore.Minute) *float64 { return val(m.Load1 / float64(cores)) }), 0.95)
	}
	in.TempMaxP95 = pct(pick(func(m localstore.Minute) *float64 { return m.TempMax }), 0.95)
	last := recent[len(recent)-1]
	in.MemAvailNow = val(last.MemAvail)
	if latest != nil {
		for _, d := range latest.Disks {
			if in.DiskUsedMax == nil || d.UsedPct > *in.DiskUsedMax {
				in.DiskUsedMax, in.DiskUsedMount = val(d.UsedPct), d.Mount
			}
			if d.InodeUsedPct != nil && (in.InodeUsedMax == nil || *d.InodeUsedPct > *in.InodeUsedMax) {
				in.InodeUsedMax, in.InodeMount = val(*d.InodeUsedPct), d.Mount
			}
			if d.DaysToFull != nil && (in.DiskDaysToFull == nil || *d.DaysToFull < *in.DiskDaysToFull) {
				in.DiskDaysToFull, in.DiskDaysMount = val(*d.DaysToFull), d.Mount
			}
		}
	}

	// Local events have no status: those of the last 24 hours count as
	// open, one per type and key (the service merges them likewise).
	day, hourAgo := now.Add(-24*time.Hour).Unix(), now.Add(-time.Hour).Unix()
	byKey := map[string]int{}
	for _, e := range events {
		ts := e.TS
		if e.LastTS > ts {
			ts = e.LastTS
		}
		if ts < day {
			continue
		}
		n := max(e.Count, 1)
		recentN := 0
		if ts >= hourAgo {
			recentN = n
		}
		switch e.Type {
		case "service_failed":
			in.ServiceCrashes24h += n
		case "oom_kill":
			in.OOM24h += n
			in.OOM1h += recentN
		case "proc_segfault":
			in.Segfaults24h += n
		case "hung_task":
			in.HungTask24h += n
		case "ssh_root_password_login":
			in.RootPasswordLogin = true
		}
		k := e.Type + "\x00" + e.Key
		i, ok := byKey[k]
		if !ok {
			i = len(in.Events)
			byKey[k] = i
			in.Events = append(in.Events, health.Event{ID: e.ID, Type: e.Type, Severity: severity(e.Severity),
				State: health.StateOpen, Subject: e.Key})
		}
		ev := &in.Events[i]
		ev.Count24h += n
		ev.Count1h += recentN
		if s := severity(e.Severity); s < ev.Severity {
			ev.Severity = s
		}
	}
	r := health.Score(in)
	return Result{State: "scored", Score: &r}
}

// severity is "P0"…"P3" as 0…3 (3 when unknown).
func severity(s string) int {
	if len(s) == 2 && (s[0] == 'P' || s[0] == 'p') && s[1] >= '0' && s[1] <= '3' {
		return int(s[1] - '0')
	}
	return 3
}

// pct is the q-quantile (nearest rank), nil without data.
func pct(v []float64, q float64) *float64 {
	if len(v) == 0 {
		return nil
	}
	sort.Float64s(v)
	i := int(math.Ceil(q*float64(len(v)))) - 1
	i = max(0, min(i, len(v)-1))
	x := v[i]
	return &x
}

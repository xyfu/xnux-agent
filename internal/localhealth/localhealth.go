// Package localhealth scores this machine with the same algorithm as the
// service (xnux-shared/health, spec v1.1 delta 8), from the local black
// box: the metrics ring for the last hour's percentiles, the latest sample
// for disks, and the event log for the last 24 hours. Local events have no
// "resolved" state, so anything seen in the last 24 hours counts as open.
package localhealth

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/xyfu/xnux-shared/health"
	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/localstore"
)

var (
	security  = []string{"ssh_bruteforce", "ssh_spray", "ssh_root_password_login", "sudo_sensitive", "sudo_auth_fail", "su_root", "user_created", "proc_fileless", "proc_deleted_exe", "proc_stale_binary", "proc_tmp_exec"}
	intrusion = []string{"ssh_breach", "proc_reverse_shell"}
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

	day, hourAgo := now.Add(-24*time.Hour).Unix(), now.Add(-time.Hour).Unix()
	for _, e := range events {
		ts := e.TS
		if e.LastTS > ts {
			ts = e.LastTS
		}
		if ts < day {
			continue
		}
		n := max(e.Count, 1)
		switch e.Type {
		case "service_failed":
			in.OpenServiceFailed++
			in.ServiceCrashes24h += n
		case "oom_kill":
			in.OOM24h += n
			if ts >= hourAgo {
				in.OOM1h += n
			}
		case "proc_segfault":
			in.Segfaults24h += n
		case "hung_task":
			in.HungTask24h += n
		case "disk_error", "fs_readonly":
			in.OpenDiskFailure++
		}
		if e.Type == "ssh_root_password_login" {
			in.RootPasswordLogin = true
		}
		switch {
		case has(intrusion, e.Type):
			in.OpenP0Intrusion++
		case e.Type == "ssh_bruteforce" || e.Type == "ssh_spray":
			// Once per server (health/v2): P1 while root may use a password.
			if strings.EqualFold(e.Severity, "P1") {
				in.OpenSSHAttack = 1
			} else if in.OpenSSHAttack == 0 {
				in.OpenSSHAttack = 2
			}
		case e.Type == "db_public_access":
			in.OpenDBPublic++
		case has(security, e.Type):
			switch strings.ToUpper(e.Severity) {
			case "P1":
				in.OpenP1Security++
			case "P2":
				in.OpenP2Security++
			}
		}
	}
	r := health.Score(in)
	return Result{State: "scored", Score: &r}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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

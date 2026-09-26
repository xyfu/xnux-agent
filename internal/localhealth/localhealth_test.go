package localhealth

import (
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/localstore"
)

func TestScore(t *testing.T) {
	now := time.Now()
	var mins []localstore.Minute
	for i := 0; i < 60; i++ {
		mins = append(mins, localstore.Minute{TS: now.Add(-time.Duration(60-i) * time.Minute).Unix(), CPU: 89, MemAvail: 50, Load1: 0.5})
	}
	days := 16.0
	latest := &proto.Metric{Disks: []proto.Disk{{Mount: "/data", UsedPct: 60, DaysToFull: &days}}}
	evs := []localstore.Event{{Event: proto.Event{ID: "1", TS: now.Add(-2 * time.Hour).Unix(), Type: "oom_kill", Severity: "P1", Count: 1}}}
	r := Score(mins, latest, evs, 2, now)
	if r.State != "scored" || r.Score.Score < 84 || r.Score.Score > 85 || r.Score.Top() != "disk_days_to_full" {
		t.Fatalf("%+v %+v", r, r.Score)
	}
	if got := Score(mins[:10], latest, nil, 2, now); got.State != "collecting" {
		t.Fatalf("collecting: %+v", got)
	}
	// A breach in the last day caps the score at 20.
	evs = append(evs, localstore.Event{Event: proto.Event{ID: "2", TS: now.Add(-time.Hour).Unix(), Type: "ssh_breach", Severity: "P0", Count: 1}})
	if r := Score(mins, latest, evs, 2, now); r.Score.Score != 20 {
		t.Fatalf("breach: %+v", r.Score)
	}
}

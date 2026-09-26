package localstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

func TestEventLog(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	for i, typ := range []string{"oom_kill", "service_failed", "oom_kill"} {
		ev := proto.Event{ID: string(rune('a' + i)), TS: now.Unix() - int64(100-i), Type: typ, Severity: "P1", Count: 1, Data: map[string]any{"i": i}}
		if err := l.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	// An update of event "a".
	_ = l.Append(proto.Event{ID: "a", TS: now.Unix() - 100, LastTS: now.Unix(), Type: "oom_kill", Severity: "P1", Count: 3})
	_ = l.Close()
	got, err := l.Query(Filter{Types: []string{"oom_kill"}})
	if err != nil || len(got) != 2 || got[0].ID != "a" || got[0].Count != 3 {
		t.Fatalf("query: %+v %v", got, err)
	}
	if e, ok, _ := l.Get("b"); !ok || e.Type != "service_failed" {
		t.Fatalf("get: %+v %v", e, ok)
	}
	fi, _ := os.Stat(filepath.Join(dir, "20260927.jsonl"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}

	// A line cut short by a power cut is skipped, and the next append starts
	// on a fresh line.
	fh, _ := os.OpenFile(filepath.Join(dir, "20260927.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	_, _ = fh.WriteString(`{"id":"torn","type":"oo`)
	_ = fh.Close()
	if err := l.Append(proto.Event{ID: "d", TS: now.Unix(), Type: "hung_task", Severity: "P2", Count: 1}); err != nil {
		t.Fatal(err)
	}
	got, _ = l.Query(Filter{})
	if len(got) != 4 {
		t.Fatalf("after torn line: %d events", len(got))
	}

	// Files beyond 30 days are pruned.
	old := filepath.Join(dir, "20260801.jsonl")
	_ = os.WriteFile(old, []byte("{}\n"), 0o600)
	l.prune()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old file kept")
	}
}

func TestFileOrder(t *testing.T) {
	for _, pair := range [][2]string{{"20260927.jsonl", "20260927.1.jsonl"}, {"20260927.2.jsonl", "20260927.10.jsonl"},
		{"20260927.10.jsonl", "20260928.jsonl"}} {
		if fileKey(pair[0]) >= fileKey(pair[1]) {
			t.Errorf("%s should sort before %s", pair[0], pair[1])
		}
	}
}

func TestRing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.ring")
	r, err := OpenRing(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Truncate(time.Minute).Add(-30 * time.Minute)
	days := 12.5
	for i := 0; i < 20*4+1; i++ { // 20 minutes of 15-second samples
		ts := start.Add(time.Duration(i) * 15 * time.Second).Unix()
		m := proto.Metric{TS: ts, CPU: proto.CPU{TotalPct: float64(i % 4 * 10)}, Mem: proto.Mem{TotalMB: 1000, AvailableMB: 250, UsedPct: 75},
			Disks: []proto.Disk{{Mount: "/", UsedPct: 50}, {Mount: "/data", UsedPct: 81, DaysToFull: &days}}}
		if err := r.Add(m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.Read(start)
	if err != nil || len(got) != 20 {
		t.Fatalf("read %d minutes: %v", len(got), err)
	}
	m := got[0]
	if m.CPU != 15 || m.MemAvail != 25 || *m.DiskUsedMax != 81 || *m.DiskDaysMin != 12.5 || m.SwapUsedMB != nil || m.TempMax != nil {
		t.Fatalf("minute: %+v", m)
	}
	fi, _ := os.Stat(path)
	if fi.Size() != Slots*RecordSize || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file %d %v", fi.Size(), fi.Mode())
	}
	// A torn record is skipped; the others survive.
	f, _ := os.OpenFile(path, os.O_WRONLY, 0)
	slot := (got[5].TS / 60) % Slots
	_, _ = f.WriteAt([]byte{1, 2, 3}, slot*RecordSize+10)
	_ = f.Close()
	got2, _ := r.Read(start)
	if len(got2) != 19 {
		t.Fatalf("after torn record: %d", len(got2))
	}
}

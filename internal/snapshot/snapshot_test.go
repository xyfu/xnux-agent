package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/procfs"
)

func TestSeries(t *testing.T) {
	r := NewRing(15)
	now := time.Unix(1_790_000_000, 0)
	if r.Series(now) != nil {
		t.Fatal("empty ring gave a series")
	}
	// 70 samples at 15 s, with one missing, ending at now; 1 hour of history.
	for i := 69; i >= 0; i-- {
		if i == 3 {
			continue
		}
		m := proto.Metric{TS: now.Unix() - int64(i*15), CPU: proto.CPU{TotalPct: float64(i)}, Mem: proto.Mem{UsedPct: 50}}
		if i%2 == 0 {
			m.Swap = &proto.Swap{UsedMB: 10}
		}
		r.Add(m)
	}
	s := r.Series(now)
	if s.Step != 15 || len(s.CPUTotal) != 40 || len(s.SwapUsedMB) != 40 {
		t.Fatalf("shape: step %d, %d points", s.Step, len(s.CPUTotal))
	}
	if *s.CPUTotal[39] != 0 || *s.CPUTotal[0] != 39 || s.CPUTotal[36] != nil {
		t.Fatalf("values: last %v first %v gap %v", *s.CPUTotal[39], *s.CPUTotal[0], s.CPUTotal[36])
	}
	if s.SwapUsedMB[38] != nil || s.SwapUsedMB[39] == nil {
		t.Fatal("swap gaps")
	}
}

func TestCaptureRealProc(t *testing.T) {
	r := NewRing(15)
	r.Add(proto.Metric{TS: time.Now().Unix(), CPU: proto.CPU{TotalPct: 5}})
	c := &Capturer{Ring: r, Proc: procfs.FS{Root: "/proc"}}
	var stop atomic.Bool
	go func() { // something to show up in top CPU
		for !stop.Load() {
		}
	}()
	defer stop.Store(true)
	start := time.Now()
	sn := c.Capture(context.Background())
	if took := time.Since(start); took > Timeout {
		t.Fatalf("capture took %v", took)
	}
	if sn == nil || sn.Series == nil || len(sn.TopRSS) == 0 || len(sn.TopCPU) == 0 || len(sn.TopRSS) > 5 {
		t.Fatalf("snapshot: %+v", sn)
	}
	self := false
	for _, p := range sn.TopCPU {
		if p.PID == os.Getpid() && p.CPUPct > 20 {
			self = true
		}
	}
	if !self {
		t.Errorf("busy test process not in top CPU: %+v", sn.TopCPU)
	}
	if sn.TopRSS[0].RSSMB <= 0 || sn.TopRSS[0].Comm == "" {
		t.Errorf("top RSS: %+v", sn.TopRSS[0])
	}

	// A cancelled context still returns what it has.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sn := c.Capture(ctx); sn == nil || sn.TopCPU != nil || sn.TopRSS == nil {
		t.Fatalf("cancelled: %+v", sn)
	}
}

func TestUnit(t *testing.T) {
	root := t.TempDir()
	for pid, cg := range map[string]string{
		"42": "0::/system.slice/nginx.service\n",
		"43": "12:pids:/user.slice\n1:name=systemd:/system.slice/docker.service/abc\n",
	} {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cgroup"), []byte(cg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := procfs.FS{Root: root}
	if u := fs.Unit(42); u != "nginx.service" {
		t.Errorf("v2: %q", u)
	}
	if u := fs.Unit(43); u != "docker.service" {
		t.Errorf("v1: %q", u)
	}
	if u := fs.Unit(44); u != "" {
		t.Errorf("missing: %q", u)
	}
}

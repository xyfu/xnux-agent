// Package snapshot captures on-site context for events (spec A4.5): the
// last 10 minutes of metrics from an in-memory ring, and the top five
// processes by RSS and by CPU.
package snapshot

import (
	"context"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/procfs"
	"github.com/xyfu/xnux-agent/internal/rules"
)

const (
	ringSize  = 240 // one hour at 15 s (spec A5.1)
	window    = 10 * time.Minute
	topN      = 5
	cpuSample = 500 * time.Millisecond
	// Timeout bounds a whole capture; an event without a snapshot still goes out.
	Timeout = 2 * time.Second
)

type point struct {
	ts             int64
	cpu, mem, load float64
	swap           float64
	hasSwap        bool
}

// Ring keeps recent samples. It is safe for concurrent use: the agent loop
// adds, snapshot goroutines read.
type Ring struct {
	mu   sync.Mutex
	pts  [ringSize]point
	next int
	n    int
	step int
}

func NewRing(stepSeconds int) *Ring { return &Ring{step: stepSeconds} }

// Add records a sample.
func (r *Ring) Add(m proto.Metric) {
	p := point{ts: m.TS, cpu: m.CPU.TotalPct, mem: m.Mem.UsedPct, load: m.Load.L1}
	if m.Swap != nil {
		p.swap, p.hasSwap = float64(m.Swap.UsedMB), true
	}
	r.mu.Lock()
	r.pts[r.next] = p
	r.next = (r.next + 1) % ringSize
	r.n = min(r.n+1, ringSize)
	r.mu.Unlock()
}

// Series returns the samples of the last 10 minutes before now, oldest
// first, with nil where a sample is missing (spec A4.5: 40 points at 15 s).
func (r *Ring) Series(now time.Time) *proto.SnapshotSeries {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == 0 {
		return nil
	}
	step := int64(r.step)
	slots := int(window.Seconds()) / r.step
	end := now.Unix()
	start := end - int64(slots)*step
	s := &proto.SnapshotSeries{Step: r.step,
		CPUTotal: make([]*float64, slots), MemUsedPct: make([]*float64, slots), Load1: make([]*float64, slots)}
	swap := make([]*float64, slots)
	any, anySwap := false, false
	for i := 0; i < r.n; i++ {
		p := r.pts[(r.next-1-i+ringSize)%ringSize]
		if p.ts <= start || p.ts > end {
			continue
		}
		k := int((p.ts - start - 1) / step)
		if k < 0 || k >= slots || s.CPUTotal[k] != nil {
			continue
		}
		s.CPUTotal[k], s.MemUsedPct[k], s.Load1[k] = ptr(p.cpu), ptr(p.mem), ptr(p.load)
		any = true
		if p.hasSwap {
			swap[k], anySwap = ptr(p.swap), true
		}
	}
	if !any {
		return nil
	}
	if anySwap {
		s.SwapUsedMB = swap
	}
	return s
}

func ptr(v float64) *float64 { return &v }

// Capturer builds snapshots.
type Capturer struct {
	Ring *Ring
	Proc procfs.FS
	Now  func() time.Time
	// PageSize and ClockTick default to the host's values.
	PageSize  int64
	ClockTick float64
}

// Capture returns the snapshot, giving up on the process lists (but not on
// the series) when ctx ends.
func (c *Capturer) Capture(ctx context.Context) *proto.Snapshot {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	sn := &proto.Snapshot{Series: c.Ring.Series(now)}
	pids, err := c.Proc.PIDs()
	if err == nil {
		sn.TopRSS = c.topRSS(pids)
		sn.TopCPU = c.topCPU(ctx, pids)
	}
	if sn.Series == nil && sn.TopRSS == nil && sn.TopCPU == nil {
		return nil
	}
	return sn
}

func (c *Capturer) pageSize() int64 {
	if c.PageSize > 0 {
		return c.PageSize
	}
	return int64(os.Getpagesize())
}

func (c *Capturer) process(pid int) proto.Process {
	st := c.Proc.Status(pid)
	p := proto.Process{PID: pid, Comm: rules.Clean(c.Proc.Comm(pid), rules.MaxField),
		Cmdline: rules.Cmdline(c.Proc.Read(pid, "cmdline")), Unit: c.Proc.Unit(pid)}
	if st.OK {
		uid := st.UID
		p.UID = &uid
	}
	if p.Comm == "" {
		p.Comm = "?"
	}
	return p
}

func (c *Capturer) topRSS(pids []int) []proto.Process {
	type r struct {
		pid   int
		pages int64
	}
	var all []r
	for _, pid := range pids {
		if n, ok := c.Proc.RSSPages(pid); ok && n > 0 {
			all = append(all, r{pid, n})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].pages > all[j].pages })
	var out []proto.Process
	for _, x := range all[:min(topN, len(all))] {
		p := c.process(x.pid)
		p.RSSMB = round1(float64(x.pages*c.pageSize()) / (1 << 20))
		out = append(out, p)
	}
	return out
}

// topCPU reads utime+stime twice, 500 ms apart, and ranks the difference.
func (c *Capturer) topCPU(ctx context.Context, pids []int) []proto.Process {
	before := make(map[int]uint64, len(pids))
	for _, pid := range pids {
		if t, ok := c.Proc.CPUTicks(pid); ok {
			before[pid] = t
		}
	}
	start := time.Now()
	t := time.NewTimer(cpuSample)
	select {
	case <-ctx.Done():
		t.Stop()
		return nil
	case <-t.C:
	}
	elapsed := time.Since(start).Seconds()
	tick := c.ClockTick
	if tick == 0 {
		tick = 100 // USER_HZ on every Linux architecture the agent ships for
	}
	type r struct {
		pid int
		pct float64
	}
	var all []r
	for pid, b := range before {
		if a, ok := c.Proc.CPUTicks(pid); ok && a > b {
			all = append(all, r{pid, float64(a-b) / tick / elapsed * 100})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].pct > all[j].pct })
	var out []proto.Process
	for _, x := range all[:min(topN, len(all))] {
		p := c.process(x.pid)
		p.CPUPct = round1(x.pct)
		out = append(out, p)
	}
	return out
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const mountRefresh = 10 * time.Minute

// Options locate the filesystems to read; tests point them at fixtures.
type Options struct {
	Root     string // "/" on a real host
	ProcRoot string // "/proc"
	SysRoot  string // "/sys"
	// Statfs defaults to syscall.Statfs.
	Statfs func(path string) (statfsResult, error)
	// DiskGrowth restores the per-mount growth rings saved in state.json.
	DiskGrowth map[string][][2]int64
}

// Sampler takes one metric sample per call. It is not safe for concurrent use.
type Sampler struct {
	opts Options

	stat, meminfo, vmstat, loadavg, mountinfo *procFile

	cores int
	virt  string

	prevCPU                 cpuTimes
	hasPrevCPU              bool
	prevSwapIn, prevSwapOut uint64
	prevSwapTS              time.Time

	mounts        []mount
	mountsRefresh time.Time
	growth        map[string]growthRing

	sensors []sensor
}

// New opens the /proc files once and discovers sensors.
func New(opts Options) (*Sampler, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = filepath.Join(opts.Root, "proc")
	}
	if opts.SysRoot == "" {
		opts.SysRoot = filepath.Join(opts.Root, "sys")
	}
	if opts.Statfs == nil {
		opts.Statfs = realStatfs
	}
	s := &Sampler{opts: opts, growth: map[string]growthRing{}}
	for m, r := range opts.DiskGrowth {
		s.growth[m] = r
	}

	var err error
	open := func(dst **procFile, name string, size int) {
		if err != nil {
			return
		}
		*dst, err = openProcFile(filepath.Join(opts.ProcRoot, name), size)
	}
	open(&s.stat, "stat", 4096)
	open(&s.meminfo, "meminfo", 4096)
	open(&s.loadavg, "loadavg", 128)
	open(&s.mountinfo, "self/mountinfo", 16384)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("collect: %w", err)
	}
	// vmstat is optional: without it swap rates are reported as 0.
	s.vmstat, _ = openProcFile(filepath.Join(opts.ProcRoot, "vmstat"), 16384)

	full, err := os.ReadFile(filepath.Join(opts.ProcRoot, "stat"))
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("collect: %w", err)
	}
	s.cores = max(1, countCPUs(full))
	s.virt = detectVirt(opts.Root, opts.ProcRoot, opts.SysRoot)
	s.sensors = discoverSensors(opts.SysRoot)
	return s, nil
}

// HasTemps reports whether any temperature sensor was found.
func (s *Sampler) HasTemps() bool { return len(s.sensors) > 0 }

// Cores is the number of CPUs in /proc/stat.
func (s *Sampler) Cores() int { return s.cores }

// Host returns the current host description (spec A2.7).
func (s *Sampler) Host() proto.Host { return s.hostInfo() }

// DiskGrowth exports the growth rings for state.json.
func (s *Sampler) DiskGrowth() map[string][][2]int64 {
	out := make(map[string][][2]int64, len(s.growth))
	for m, r := range s.growth {
		out[m] = append([][2]int64(nil), r...)
	}
	return out
}

// Sample reads every source once, all stamped with the same ts. The first
// call only records the CPU baseline and reports false.
func (s *Sampler) Sample(now time.Time) (proto.Metric, bool) {
	ts := now.Unix()
	b, err := s.stat.read()
	if err != nil {
		return proto.Metric{}, false
	}
	cur, ok := parseCPULine(b)
	if !ok {
		return proto.Metric{}, false
	}
	cpu, ok := cpuDelta(s.prevCPU, cur)
	first := !s.hasPrevCPU
	s.prevCPU, s.hasPrevCPU = cur, true
	if first || !ok {
		s.sampleSwapRates(now) // establish the swap baseline too
		return proto.Metric{}, false
	}

	m := proto.Metric{TS: ts, CPU: cpu}
	if b, err := s.loadavg.read(); err == nil {
		m.Load, _ = parseLoadavg(b)
	}
	b, err = s.meminfo.read()
	if err != nil {
		return proto.Metric{}, false
	}
	mi, ok := parseMeminfo(b)
	if !ok {
		return proto.Metric{}, false
	}
	m.Mem = mi.mem()
	in, out := s.sampleSwapRates(now)
	if mi.swapTotal > 0 {
		m.Swap = &proto.Swap{
			TotalMB: int(mi.swapTotal / 1024),
			UsedMB:  int((mi.swapTotal - min(mi.swapFree, mi.swapTotal)) / 1024),
			InPS:    in,
			OutPS:   out,
		}
	}
	m.Disks = s.sampleDisks(now)
	m.Temps = sampleTemps(s.sensors)
	return m, true
}

// sampleSwapRates returns pages/s swapped in and out since the last call.
func (s *Sampler) sampleSwapRates(now time.Time) (in, out float64) {
	if s.vmstat == nil {
		return 0, 0
	}
	b, err := s.vmstat.read()
	if err != nil {
		return 0, 0
	}
	ci, co, ok := parseVmstatSwap(b)
	if !ok {
		return 0, 0
	}
	if !s.prevSwapTS.IsZero() && ci >= s.prevSwapIn && co >= s.prevSwapOut {
		if dt := now.Sub(s.prevSwapTS).Seconds(); dt > 0 {
			in = round(float64(ci-s.prevSwapIn)/dt, 1)
			out = round(float64(co-s.prevSwapOut)/dt, 1)
		}
	}
	s.prevSwapIn, s.prevSwapOut, s.prevSwapTS = ci, co, now
	return in, out
}

func (s *Sampler) sampleDisks(now time.Time) []proto.Disk {
	if s.mountsRefresh.IsZero() || now.Sub(s.mountsRefresh) >= mountRefresh {
		if b, err := s.mountinfo.read(); err == nil {
			s.mounts = parseMountinfo(b)
			s.mountsRefresh = now
		}
	}
	if len(s.mounts) == 0 {
		return nil
	}
	disks := make([]proto.Disk, 0, len(s.mounts))
	for _, m := range s.mounts {
		st, err := s.opts.Statfs(m.path)
		if err != nil || st.blocks == 0 {
			continue
		}
		d := st.disk(m)
		r := s.growth[m.path].add(now.Unix(), st.usedBytes())
		s.growth[m.path] = r
		applyGrowth(&d, r)
		disks = append(disks, d)
	}
	// Forget rings of mounts that disappeared.
	for p := range s.growth {
		keep := false
		for _, m := range s.mounts {
			keep = keep || m.path == p
		}
		if !keep {
			delete(s.growth, p)
		}
	}
	if len(disks) == 0 {
		return nil
	}
	return disks
}

// Close releases the file handles.
func (s *Sampler) Close() {
	for _, f := range []*procFile{s.stat, s.meminfo, s.vmstat, s.loadavg, s.mountinfo} {
		f.Close()
	}
	for _, sn := range s.sensors {
		sn.f.Close()
	}
}

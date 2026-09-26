package localstore

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const (
	// Slots is one day of minutes.
	Slots = 1440
	// RecordSize is one minute on disk: the minute, 15 four-byte values,
	// 4 spare bytes and a CRC.
	RecordSize = 72
)

// Minute is one minute of metrics: averages, except disk and temperature
// which keep the worst value (spec v1.1 delta 2). Nil means no data.
type Minute struct {
	TS          int64    `json:"ts"` // start of the minute
	CPU         float64  `json:"cpu_pct"`
	IOWait      float64  `json:"iowait_pct"`
	Steal       float64  `json:"steal_pct"`
	Load1       float64  `json:"load1"`
	Load5       float64  `json:"load5"`
	Load15      float64  `json:"load15"`
	MemUsed     float64  `json:"mem_used_pct"`
	MemAvail    float64  `json:"mem_avail_pct"`
	MemTotalMB  float64  `json:"mem_total_mb"`
	SwapUsedMB  *float64 `json:"swap_used_mb,omitempty"`
	SwapInPS    *float64 `json:"swap_in_ps,omitempty"`
	DiskUsedMax *float64 `json:"disk_used_max_pct,omitempty"`
	DiskDaysMin *float64 `json:"disk_days_to_full_min,omitempty"`
	InodeMax    *float64 `json:"inode_used_max_pct,omitempty"`
	TempMax     *float64 `json:"temp_max_c,omitempty"`
}

// Ring is the metrics file: Slots fixed-size records indexed by minute.
// A record is written in place with one pwrite and carries a CRC, so a
// write torn by a power cut is detected and skipped (at most that one
// minute is lost).
type Ring struct {
	mu   sync.Mutex
	f    *os.File
	acc  acc
	sync bool
}

// OpenRing opens (creating, 0600, preallocated) the ring file.
func OpenRing(path string) (*Ring, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // fixed path under the state dir
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err == nil && fi.Size() != Slots*RecordSize {
		if err := f.Truncate(Slots * RecordSize); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return &Ring{f: f, sync: true}, nil
}

// Close flushes nothing (a partial minute is dropped) and closes the file.
func (r *Ring) Close() error { return r.f.Close() }

type acc struct {
	minute                                          int64
	n                                               int
	cpu, iow, steal, l1, l5, l15, mem, avail, total float64
	swapUsed, swapIn                                float64
	swapN                                           int
	disk, days, inode, temp                         float64
	hasDisk, hasDays, hasInode, hasTemp             bool
}

// Add folds one sample into its minute; when a new minute starts, the
// finished one is written.
func (r *Ring) Add(m proto.Metric) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	minute := m.TS / 60
	if r.acc.n > 0 && minute != r.acc.minute {
		if err := r.write(r.acc.minuteRecord()); err != nil {
			return err
		}
		r.acc = acc{}
	}
	a := &r.acc
	a.minute = minute
	a.n++
	a.cpu += m.CPU.TotalPct
	a.iow += m.CPU.IOWaitPct
	a.steal += m.CPU.StealPct
	a.l1 += m.Load.L1
	a.l5 += m.Load.L5
	a.l15 += m.Load.L15
	a.mem += m.Mem.UsedPct
	if m.Mem.TotalMB > 0 {
		a.avail += float64(m.Mem.AvailableMB) / float64(m.Mem.TotalMB) * 100
		a.total = float64(m.Mem.TotalMB)
	}
	if m.Swap != nil {
		a.swapUsed += float64(m.Swap.UsedMB)
		a.swapIn += m.Swap.InPS
		a.swapN++
	}
	for _, d := range m.Disks {
		if !a.hasDisk || d.UsedPct > a.disk {
			a.disk, a.hasDisk = d.UsedPct, true
		}
		if d.DaysToFull != nil && (!a.hasDays || *d.DaysToFull < a.days) {
			a.days, a.hasDays = *d.DaysToFull, true
		}
		if d.InodeUsedPct != nil && (!a.hasInode || *d.InodeUsedPct > a.inode) {
			a.inode, a.hasInode = *d.InodeUsedPct, true
		}
	}
	for _, t := range m.Temps {
		if !a.hasTemp || t.C > a.temp {
			a.temp, a.hasTemp = t.C, true
		}
	}
	return nil
}

func (a *acc) minuteRecord() Minute {
	n := float64(a.n)
	m := Minute{TS: a.minute * 60, CPU: a.cpu / n, IOWait: a.iow / n, Steal: a.steal / n, Load1: a.l1 / n, Load5: a.l5 / n,
		Load15: a.l15 / n, MemUsed: a.mem / n, MemAvail: a.avail / n, MemTotalMB: a.total}
	if a.swapN > 0 {
		m.SwapUsedMB, m.SwapInPS = f(a.swapUsed/float64(a.swapN)), f(a.swapIn/float64(a.swapN))
	}
	if a.hasDisk {
		m.DiskUsedMax = f(a.disk)
	}
	if a.hasDays {
		m.DiskDaysMin = f(a.days)
	}
	if a.hasInode {
		m.InodeMax = f(a.inode)
	}
	if a.hasTemp {
		m.TempMax = f(a.temp)
	}
	return m
}

func f(v float64) *float64 { return &v }

func opt(p *float64) float32 {
	if p == nil {
		return float32(math.NaN())
	}
	return float32(*p)
}

func back(v float32) *float64 {
	if math.IsNaN(float64(v)) {
		return nil
	}
	return f(float64(v))
}

func encode(m Minute) []byte {
	b := make([]byte, RecordSize)
	binary.LittleEndian.PutUint32(b[0:], uint32(m.TS/60)) //nolint:gosec // minutes since 1970 fit until 10136
	vals := []float32{float32(m.CPU), float32(m.IOWait), float32(m.Steal), float32(m.Load1), float32(m.Load5), float32(m.Load15),
		float32(m.MemUsed), float32(m.MemAvail), float32(m.MemTotalMB), opt(m.SwapUsedMB), opt(m.SwapInPS), opt(m.DiskUsedMax),
		opt(m.DiskDaysMin), opt(m.InodeMax), opt(m.TempMax)}
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4+4*i:], math.Float32bits(v))
	}
	binary.LittleEndian.PutUint32(b[RecordSize-4:], crc32.ChecksumIEEE(b[:RecordSize-4]))
	return b
}

func decode(b []byte) (Minute, bool) {
	if binary.LittleEndian.Uint32(b[RecordSize-4:]) != crc32.ChecksumIEEE(b[:RecordSize-4]) {
		return Minute{}, false
	}
	minute := binary.LittleEndian.Uint32(b[0:])
	if minute == 0 {
		return Minute{}, false
	}
	v := func(i int) float32 { return math.Float32frombits(binary.LittleEndian.Uint32(b[4+4*i:])) }
	return Minute{TS: int64(minute) * 60, CPU: float64(v(0)), IOWait: float64(v(1)), Steal: float64(v(2)), Load1: float64(v(3)),
		Load5: float64(v(4)), Load15: float64(v(5)), MemUsed: float64(v(6)), MemAvail: float64(v(7)), MemTotalMB: float64(v(8)),
		SwapUsedMB: back(v(9)), SwapInPS: back(v(10)), DiskUsedMax: back(v(11)), DiskDaysMin: back(v(12)), InodeMax: back(v(13)),
		TempMax: back(v(14))}, true
}

func (r *Ring) write(m Minute) error {
	slot := (m.TS / 60) % Slots
	if _, err := r.f.WriteAt(encode(m), slot*RecordSize); err != nil {
		return err
	}
	if r.sync {
		return r.f.Sync()
	}
	return nil
}

// Read returns the stored minutes at or after since, oldest first.
func (r *Ring) Read(since time.Time) ([]Minute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	buf := make([]byte, Slots*RecordSize)
	if _, err := r.f.ReadAt(buf, 0); err != nil {
		return nil, err
	}
	var out []Minute
	for i := 0; i < Slots; i++ {
		m, ok := decode(buf[i*RecordSize : (i+1)*RecordSize])
		if ok && m.TS >= since.Unix() && m.TS > time.Now().Add(-25*time.Hour).Unix() {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out, nil
}

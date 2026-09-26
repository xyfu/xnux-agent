package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

// copyTree copies the fixture so tests can rewrite files between samples.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeFS returns statfs results per mount; used bytes can be changed by tests.
type fakeFS map[string]statfsResult

func (f fakeFS) statfs(p string) (statfsResult, error) {
	if r, ok := f[p]; ok {
		return r, nil
	}
	return statfsResult{}, os.ErrNotExist
}

func newFixtureSampler(t *testing.T) (*Sampler, string, fakeFS) {
	t.Helper()
	root := copyTree(t, "testdata/host")
	fs := fakeFS{
		"/":             {blocks: 1000, bfree: 300, bavail: 250, files: 100, ffree: 80, bsize: 1 << 20},
		"/data":         {blocks: 2000, bfree: 1000, bavail: 1000, files: 0, ffree: 0, bsize: 1 << 20},
		"/home":         {blocks: 500, bfree: 400, bavail: 400, files: 0, ffree: 0, bsize: 1 << 20},
		"/srv/bind dir": {blocks: 2000, bfree: 1000, bavail: 1000, bsize: 1 << 20},
	}
	s, err := New(Options{Root: root, Statfs: fs.statfs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, root, fs
}

func TestSampleFixture(t *testing.T) {
	s, root, _ := newFixtureSampler(t)
	t0 := time.Unix(1790000000, 0)
	if _, ok := s.Sample(t0); ok {
		t.Fatal("first sample must only set the baseline")
	}
	// +1000 user, +2000 idle, +500 iowait, +500 steal => total 4000,
	// busy = total - idle - iowait (steal counts as busy)
	write(t, root, "proc/stat", "cpu  2000 0 500 10000 600 0 0 500 0 0\ncpu0 1 0 0 0\ncpu1 1 0 0 0\n")
	write(t, root, "proc/vmstat", "pswpin 1150\npswpout 2000\n")
	m, ok := s.Sample(t0.Add(15 * time.Second))
	if !ok {
		t.Fatal("second sample failed")
	}

	want := proto.CPU{TotalPct: 37.5, IOWaitPct: 12.5, StealPct: 12.5}
	if m.CPU != want {
		t.Errorf("cpu = %+v, want %+v", m.CPU, want)
	}
	if m.Load != (proto.Load{L1: 0.42, L5: 0.38, L15: 0.30}) {
		t.Errorf("load = %+v", m.Load)
	}
	if m.Mem != (proto.Mem{TotalMB: 3924, AvailableMB: 1810, UsedPct: 53.9}) {
		t.Errorf("mem = %+v", m.Mem)
	}
	if m.Swap == nil || *m.Swap != (proto.Swap{TotalMB: 2048, UsedMB: 120, InPS: 10, OutPS: 0}) {
		t.Errorf("swap = %+v", m.Swap)
	}

	var mounts []string
	for _, d := range m.Disks {
		mounts = append(mounts, d.Mount)
	}
	sort.Strings(mounts)
	// /srv/bind dir is a bind of /data (same dev), /var/lib/data a btrfs
	// subvolume of the same device as /home, overlay and squashfs are skipped.
	if strings.Join(mounts, ",") != "/,/data,/home" {
		t.Errorf("mounts = %v", mounts)
	}
	root0 := m.Disks[0]
	if root0.Mount != "/" || root0.TotalGB != 0.98 || root0.FreeGB != 0.24 || root0.UsedPct != 73.7 ||
		root0.InodeUsedPct == nil || *root0.InodeUsedPct != 20 {
		t.Errorf("root disk = %+v", root0)
	}
	for _, d := range m.Disks {
		if d.Mount == "/data" && d.InodeUsedPct != nil {
			t.Errorf("inode pct must be omitted when Files = 0")
		}
	}

	var temps []string
	for _, tp := range m.Temps {
		temps = append(temps, tp.Name)
	}
	if strings.Join(temps, "|") != "coretemp Package id 0|coretemp temp2|thermal x86_pkg_temp" {
		t.Errorf("temps = %v", temps)
	}
	if m.Temps[0].C != 52 || m.Temps[1].C != 48.5 {
		t.Errorf("temp values = %+v", m.Temps)
	}
}

func TestNoSwapNoSensors(t *testing.T) {
	root := copyTree(t, "testdata/host")
	write(t, root, "proc/meminfo", "MemTotal: 1024000 kB\nMemFree: 1 kB\nMemAvailable: 512000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	if err := os.RemoveAll(filepath.Join(root, "sys/class")); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Root: root, Statfs: fakeFS{}.statfs})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Sample(time.Unix(0, 0))
	write(t, root, "proc/stat", "cpu  2000 0 500 10000 600 0 0 500 0 0\n")
	m, ok := s.Sample(time.Unix(15, 0))
	if !ok {
		t.Fatal("sample failed")
	}
	if m.Swap != nil || m.Temps != nil || m.Disks != nil || s.HasTemps() {
		t.Fatalf("absent data must be omitted, got %+v", m)
	}
}

func TestCounterResetDropsSample(t *testing.T) {
	s, root, _ := newFixtureSampler(t)
	s.Sample(time.Unix(0, 0))
	write(t, root, "proc/stat", "cpu  10 0 5 80 1 0 0 0 0 0\n")
	if _, ok := s.Sample(time.Unix(15, 0)); ok {
		t.Fatal("counter going backwards must drop the sample")
	}
	write(t, root, "proc/stat", "cpu  20 0 5 90 1 0 0 0 0 0\n")
	if m, ok := s.Sample(time.Unix(30, 0)); !ok || m.CPU.TotalPct != 50 {
		t.Fatalf("after reset: %+v %v", m.CPU, ok)
	}
}

func TestDiskGrowthRegression(t *testing.T) {
	s, root, fs := newFixtureSampler(t)
	start := time.Unix(1790000000, 0)
	s.Sample(start)
	var last proto.Metric
	// 13 samples 5 min apart, root grows by 10 MiB each => 120 MiB/h.
	for i := 1; i <= 13; i++ {
		r := fs["/"]
		r.bfree -= 10
		r.bavail -= 10
		fs["/"] = r
		write(t, root, "proc/stat", "cpu  "+strconv.Itoa(2000*i)+" 0 500 10000 600 0 0 0 0 0\n")
		m, ok := s.Sample(start.Add(time.Duration(i) * 5 * time.Minute))
		if !ok {
			t.Fatalf("sample %d failed", i)
		}
		last = m
	}
	var root0 proto.Disk
	for _, d := range last.Disks {
		if d.Mount == "/" {
			root0 = d
		}
	}
	if root0.GrowthMBH == nil || *root0.GrowthMBH != 120 {
		t.Fatalf("growth = %v", root0.GrowthMBH)
	}
	// free = 250-130 = 120 MiB => 120 / (120*24) days
	if root0.DaysToFull == nil || *root0.DaysToFull != 0 {
		t.Fatalf("days_to_full = %v", root0.DaysToFull)
	}
	for _, d := range last.Disks {
		if d.Mount == "/data" && (d.GrowthMBH == nil || *d.GrowthMBH != 0 || d.DaysToFull != nil) {
			t.Fatalf("flat disk must report 0 growth and no days_to_full: %+v", d)
		}
	}
	// Rings survive a restart through DiskGrowth.
	saved := s.DiskGrowth()
	if len(saved["/"]) != 13 {
		t.Fatalf("saved ring len = %d", len(saved["/"]))
	}
}

func TestGrowthRingWindow(t *testing.T) {
	var r growthRing
	for i := range 100 {
		r = r.add(int64(i*growthStep), int64(i))
	}
	if len(r) != growthCapacity || r[len(r)-1][0]-r[0][0] > growthWindow {
		t.Fatalf("ring len %d span %d", len(r), r[len(r)-1][0]-r[0][0])
	}
	if r2 := r.add(r[len(r)-1][0]+10, 0); len(r2) != len(r) {
		t.Fatal("samples closer than growthStep must be ignored")
	}
}

func TestHost(t *testing.T) {
	s, _, _ := newFixtureSampler(t)
	h := s.Host()
	want := proto.Host{Hostname: "web-01", OS: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic",
		Arch: runtime.GOARCH, Cores: 2, Uptime: 864000, Virt: "kvm"}
	if h.Hostname != want.Hostname || h.OS != want.OS || h.Kernel != want.Kernel || h.Arch != want.Arch ||
		h.Cores != want.Cores || h.Uptime != want.Uptime || h.Virt != want.Virt {
		t.Fatalf("host = %+v\nwant %+v", h, want)
	}
}

func TestVirtContainer(t *testing.T) {
	root := copyTree(t, "testdata/host")
	write(t, root, ".dockerenv", "")
	if v := detectVirt(root, filepath.Join(root, "proc"), filepath.Join(root, "sys")); v != "container" {
		t.Fatalf("virt = %s", v)
	}
}

func TestParseFloat(t *testing.T) {
	for in, want := range map[string]float64{"0.42": 0.42, "12": 12, "3.5": 3.5, "864000.55": 864000.55} {
		got, ok := parseFloat([]byte(in))
		if !ok || round(got, 2) != want {
			t.Errorf("parseFloat(%q) = %v, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a", "1.x", "-1"} {
		if _, ok := parseFloat([]byte(bad)); ok {
			t.Errorf("parseFloat(%q) should fail", bad)
		}
	}
}

// TestRealHostBudget samples the real /proc (spec A2: one round < 1 ms,
// F1-9). It uses the median of 50 rounds to stay stable on shared CI.
func TestRealHostBudget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.Sample(now)
	var d []time.Duration
	for i := 1; i <= 50; i++ {
		start := time.Now()
		s.Sample(now.Add(time.Duration(i) * time.Second))
		d = append(d, time.Since(start))
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	if med := d[len(d)/2]; med > time.Millisecond {
		t.Fatalf("median sample time %v exceeds 1ms", med)
	} else {
		t.Logf("median sample time %v", med)
	}
}

func BenchmarkSample(b *testing.B) {
	s, err := New(Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.Sample(now)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		s.Sample(now.Add(time.Duration(i+1) * time.Second))
	}
}

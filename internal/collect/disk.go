package collect

import (
	"sort"
	"strings"
	"syscall"

	"github.com/xyfu/xnux-shared/proto"
)

const (
	maxMounts = 16

	growthStep     = 300      // seconds between growth samples
	growthWindow   = 6 * 3600 // seconds of history used for the regression
	growthCapacity = growthWindow / growthStep
	growthMinPts   = 12 // one hour
	growthMinMBH   = 0.1
)

// Only real, block-backed filesystems are reported.
var diskFSTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"zfs": true, "f2fs": true, "jfs": true, "bcachefs": true,
}

type mount struct {
	path   string
	fs     string
	dev    string // major:minor
	source string
}

// parseMountinfo returns the mounts worth reporting, deduplicated: one entry
// per device (bind mounts keep the shortest path) and, for btrfs, one per
// source device so subvolumes are not counted twice.
func parseMountinfo(b []byte) []mount {
	byKey := map[string]mount{}
	for len(b) > 0 {
		var line []byte
		line, b = nextLine(b)
		// id parent major:minor root mountpoint options [optional...] - fstype source superopts
		f := strings.Fields(string(line))
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 10 || sep < 0 || sep+2 >= len(f) {
			continue
		}
		m := mount{path: unescapeMount(f[4]), fs: f[sep+1], dev: f[2], source: f[sep+2]}
		if !diskFSTypes[m.fs] {
			continue
		}
		key := m.dev
		if m.fs == "btrfs" {
			key = "btrfs:" + m.source
		}
		if cur, ok := byKey[key]; !ok || len(m.path) < len(cur.path) {
			byKey[key] = m
		}
	}
	out := make([]mount, 0, len(byKey))
	for _, m := range byKey {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	if len(out) > maxMounts {
		out = out[:maxMounts]
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 etc.) used in mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// statfsResult holds the statfs fields we use, in bytes and inode counts.
type statfsResult struct {
	blocks, bfree, bavail, files, ffree, bsize uint64
}

func realStatfs(path string) (statfsResult, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return statfsResult{}, err
	}
	bs := uint64(s.Frsize)
	if bs == 0 {
		bs = uint64(s.Bsize)
	}
	return statfsResult{blocks: s.Blocks, bfree: s.Bfree, bavail: s.Bavail, files: s.Files, ffree: s.Ffree, bsize: bs}, nil
}

func (s statfsResult) usedBytes() int64 {
	return int64((s.blocks - min(s.bfree, s.blocks)) * s.bsize)
}

// disk builds the payload entry; growth fields are filled in by the caller.
func (s statfsResult) disk(m mount) proto.Disk {
	const gb = 1 << 30
	d := proto.Disk{
		Mount:   m.path,
		FS:      m.fs,
		TotalGB: round(float64(s.blocks*s.bsize)/gb, 2),
		FreeGB:  round(float64(s.bavail*s.bsize)/gb, 2),
	}
	used := s.blocks - min(s.bfree, s.blocks)
	if denom := used + s.bavail; denom > 0 { // same formula as df
		d.UsedPct = pct(float64(used) / float64(denom) * 100)
	}
	if s.files > 0 {
		v := pct(float64(s.files-min(s.ffree, s.files)) / float64(s.files) * 100)
		d.InodeUsedPct = &v
	}
	return d
}

// growthRing keeps (unix, used bytes) samples every growthStep seconds.
type growthRing [][2]int64

func (r growthRing) add(ts, used int64) growthRing {
	if n := len(r); n > 0 && ts-r[n-1][0] < growthStep {
		return r
	}
	r = append(r, [2]int64{ts, used})
	// Drop samples outside the window and keep at most growthCapacity.
	cut := 0
	for cut < len(r) && (ts-r[cut][0] > growthWindow || len(r)-cut > growthCapacity) {
		cut++
	}
	return append(r[:0:0], r[cut:]...)
}

// slopeMBPerHour is the least-squares slope of used bytes over time.
func (r growthRing) slopeMBPerHour() (float64, bool) {
	n := float64(len(r))
	if len(r) < growthMinPts {
		return 0, false
	}
	t0 := float64(r[0][0])
	var st, sy, stt, sty float64
	for _, p := range r {
		t, y := float64(p[0])-t0, float64(p[1])
		st += t
		sy += y
		stt += t * t
		sty += t * y
	}
	den := n*stt - st*st
	if den == 0 {
		return 0, false
	}
	bytesPerSec := (n*sty - st*sy) / den
	return bytesPerSec * 3600 / (1 << 20), true
}

// applyGrowth sets growth_mb_h and days_to_full from the ring.
func applyGrowth(d *proto.Disk, r growthRing) {
	g, ok := r.slopeMBPerHour()
	if !ok {
		return
	}
	g = round(g, 1)
	d.GrowthMBH = &g
	if g >= growthMinMBH {
		days := round(d.FreeGB*1024/(g*24), 1)
		d.DaysToFull = &days
	}
}

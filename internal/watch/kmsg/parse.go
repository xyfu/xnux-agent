// Package kmsg reads /dev/kmsg for OOM kills, segfaults, disk and file
// system errors and hung tasks (spec A3.2).
package kmsg

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/rules"
)

// Entry is one /dev/kmsg record.
type Entry struct {
	Seq  uint64
	USec int64 // since boot
	Msg  string
}

// ParseEntry splits "<prio>,<seq>,<ts_usec>,<flags>;<message>\n key=value…".
func ParseEntry(b []byte) (Entry, bool) {
	s := string(b)
	head, msg, ok := strings.Cut(s, ";")
	if !ok {
		return Entry{}, false
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 { // continuation dictionary
		msg = msg[:i]
	}
	f := strings.SplitN(head, ",", 4)
	if len(f) < 3 {
		return Entry{}, false
	}
	seq, err1 := strconv.ParseUint(f[1], 10, 64)
	usec, err2 := strconv.ParseInt(f[2], 10, 64)
	if err1 != nil || err2 != nil {
		return Entry{}, false
	}
	return Entry{Seq: seq, USec: usec, Msg: unescape(msg)}, true
}

// unescape decodes the \xNN escapes the kernel uses for non-printable bytes.
func unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var (
	reOOM     = regexp.MustCompile(`(Memory cgroup )?[Oo]ut of memory.*?: Killed process (\d+) \((.+?)\) total-vm:(\d+)kB, anon-rss:(\d+)kB, file-rss:(\d+)kB, shmem-rss:(\d+)kB(?:, UID:(\d+))?.*?oom_score_adj:(-?\d+)`)
	reOOMCons = regexp.MustCompile(`oom-kill:constraint=(\w+),.*?oom_memcg=([^,]*),task_memcg=([^,]*),task=([^,]+),pid=(\d+)`)
	reSegv    = regexp.MustCompile(`(\S+)\[(\d+)\]: segfault at ([0-9a-f]+) ip ([0-9a-f]+) sp ([0-9a-f]+) error (\d+)(?: in (\S+))?`)
	// "dev sdb," and ext4's "(device sda1)"; names like dm-0 and md127p1.
	reDevWord  = regexp.MustCompile(`\bdev(?:ice)? (\w[\w.-]*\w|\w)`)
	reDevParen = regexp.MustCompile(`\((\w[\w.-]*\w|\w)\)`)
	reHung     = regexp.MustCompile(`task (\S+):(\d+) blocked for more than (\d+) seconds`)
)

const (
	maxMessage  = 256
	maxDevice   = 64
	mergeWindow = 2 * time.Second
)

type constraint struct {
	constraint, memcg string
	at                time.Time
}

// Matcher turns kernel messages into records. It keeps the recent
// oom-kill:constraint lines so they can be merged into the kill that
// follows them (spec A3.2).
type Matcher struct {
	cons map[int]constraint
}

func NewMatcher() *Matcher { return &Matcher{cons: map[int]constraint{}} }

func kb2mb(s string) int {
	n, _ := strconv.ParseInt(s, 10, 64)
	return int((n + 512) / 1024)
}

// Match returns the record for msg logged at ts, if it is one the agent
// reports. Cheap substring checks run before any regular expression.
func (m *Matcher) Match(msg string, ts time.Time) (raw.Record, bool) {
	switch {
	case strings.Contains(msg, "oom-kill:"):
		if g := reOOMCons.FindStringSubmatch(msg); g != nil {
			pid, _ := strconv.Atoi(g[5])
			for p, c := range m.cons {
				if ts.Sub(c.at) > mergeWindow {
					delete(m.cons, p)
				}
			}
			m.cons[pid] = constraint{constraint: g[1], memcg: g[3], at: ts}
		}
		return raw.Record{}, false

	case strings.Contains(msg, "Killed process"):
		g := reOOM.FindStringSubmatch(msg)
		if g == nil {
			return raw.Record{}, false
		}
		pid, _ := strconv.Atoi(g[2])
		adj, _ := strconv.Atoi(g[9])
		scope := "global"
		if g[1] != "" {
			scope = "memcg"
		}
		d := map[string]any{
			"victim": g[3], "pid": pid, "total_vm_mb": kb2mb(g[4]), "anon_rss_mb": kb2mb(g[5]),
			"file_rss_mb": kb2mb(g[6]), "shmem_rss_mb": kb2mb(g[7]), "oom_score_adj": adj, "scope": scope,
		}
		if c, ok := m.cons[pid]; ok && ts.Sub(c.at) <= mergeWindow {
			delete(m.cons, pid)
			d["constraint"] = c.constraint
			if c.memcg != "" && c.memcg != "/" {
				d["memcg"] = c.memcg
			}
			if c.constraint == "CONSTRAINT_MEMCG" {
				d["scope"] = "memcg"
			}
		}
		return raw.Record{Kind: proto.EventOOMKill, TS: ts, Key: g[3], Data: d}, true

	case strings.Contains(msg, "segfault at"):
		g := reSegv.FindStringSubmatch(msg)
		if g == nil {
			return raw.Record{}, false
		}
		pid, _ := strconv.Atoi(g[2])
		d := map[string]any{"comm": g[1], "pid": pid}
		if mod, _, _ := strings.Cut(g[7], "["); mod != "" {
			d["module"] = mod
		}
		return raw.Record{Kind: proto.EventProcSegfault, TS: ts, Key: g[1], Data: d}, true

	case strings.Contains(msg, "Remounting filesystem read-only"):
		return device(proto.EventFSReadonly, msg, ts), true

	case strings.Contains(msg, "blocked for more than"):
		g := reHung.FindStringSubmatch(msg)
		if g == nil {
			return raw.Record{}, false
		}
		pid, _ := strconv.Atoi(g[2])
		secs, _ := strconv.Atoi(g[3])
		return raw.Record{Kind: proto.EventHungTask, TS: ts, Key: g[1],
			Data: map[string]any{"comm": g[1], "pid": pid, "blocked_seconds": secs}}, true

	case isDiskError(msg):
		return device(proto.EventDiskError, msg, ts), true
	}
	return raw.Record{}, false
}

func isDiskError(msg string) bool {
	return strings.Contains(msg, "I/O error") || strings.Contains(msg, "EXT4-fs error") ||
		(strings.Contains(msg, "XFS (") && strings.Contains(msg, "error")) ||
		strings.Contains(msg, "BTRFS error") || strings.Contains(msg, "critical medium error")
}

func device(typ, msg string, ts time.Time) raw.Record {
	dev := ""
	if g := reDevWord.FindStringSubmatch(msg); g != nil {
		dev = g[1]
	} else if g := reDevParen.FindStringSubmatch(msg); g != nil {
		dev = g[1]
	}
	d := map[string]any{"message": rules.Clean(msg, maxMessage)}
	key := "unknown"
	if dev != "" {
		dev = rules.Clean(dev, maxDevice)
		d["device"], key = dev, dev
	}
	return raw.Record{Kind: typ, TS: ts, Key: key, Data: d}
}

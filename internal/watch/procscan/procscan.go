// Package procscan scans /proc every 300 s (plus up to 30 s of jitter) for
// fileless, deleted, temp-dir and reverse-shell processes (spec A3.4).
package procscan

import (
	"context"
	"encoding/hex"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/procfs"
	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/rules"
	"github.com/xyfu/xnux-agent/internal/state"
)

const (
	Interval   = 300 * time.Second
	Jitter     = 30 * time.Second
	staleEvery = 24 * time.Hour
	deleted    = " (deleted)"
)

// Directories whose executables are suspicious (spec A3.4).
var (
	tmpDirs      = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	filelessDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}
	shells       = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
		"perl": true, "ruby": true, "php": true, "nc": true, "ncat": true, "socat": true}
)

// Scanner is not safe for concurrent use; Run owns it.
type Scanner struct {
	Proc procfs.FS
	// Root resolves executable paths ("/" on a real host).
	Root          string
	WhitelistExe  []string
	WhitelistComm []string
	Out           chan<- raw.Record
	Now           func() time.Time

	// Interval and Jitter default to 300 s and 30 s.
	Interval, Jitter time.Duration

	mu       sync.Mutex
	reported map[string]string // "pid:starttime" → exe, once per process, persisted
	stale    map[string]int64  // exe → last report (unix), persisted in state.json
}

func (s *Scanner) bootID() string {
	b, _ := os.ReadFile(filepath.Join(s.Root, "proc/sys/kernel/random/boot_id"))
	return strings.TrimSpace(string(b))
}

// SetReported restores the processes already reported, unless the host
// has rebooted since.
func (s *Scanner) SetReported(r *state.ProcReported) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reported = map[string]string{}
	if r == nil || r.BootID == "" || r.BootID != s.bootID() {
		return
	}
	for k, v := range r.Procs {
		s.reported[k] = v
	}
}

// Reported returns the processes already reported, to persist.
func (s *Scanner) Reported() *state.ProcReported {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.bootID()
	if id == "" || len(s.reported) == 0 {
		return nil
	}
	out := &state.ProcReported{BootID: id, Procs: make(map[string]string, len(s.reported))}
	for k, v := range s.reported {
		out.Procs[k] = v
	}
	return out
}

// SetStale restores proc_stale_binary report times from state.json.
func (s *Scanner) SetStale(m map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stale = make(map[string]int64, len(m))
	for k, v := range m {
		s.stale[k] = v
	}
}

// Stale returns the report times to persist; entries older than a day are
// dropped.
func (s *Scanner) Stale() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int64{}
	cutoff := s.now().Add(-staleEvery).Unix()
	for k, v := range s.stale {
		if v >= cutoff {
			out[k] = v
		}
	}
	return out
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run scans on a timer until ctx ends. The first scan happens after the
// jitter alone, so problems present at start are found early.
func (s *Scanner) Run(ctx context.Context) error {
	interval, jitter := s.Interval, s.Jitter
	if interval == 0 {
		interval = Interval
	}
	if jitter == 0 {
		jitter = Jitter
	}
	wait := rand.N(jitter) //nolint:gosec // scheduling jitter, not security
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		for _, r := range s.Scan() {
			select {
			case s.Out <- r:
			case <-ctx.Done():
				return nil
			}
		}
		wait = interval + rand.N(jitter) //nolint:gosec // scheduling jitter, not security
	}
}

func (s *Scanner) whitelisted(exe, comm string) bool {
	for _, w := range s.WhitelistExe {
		if w == exe {
			return true
		}
	}
	for _, w := range s.WhitelistComm {
		if w == comm {
			return true
		}
	}
	return false
}

func hasPrefixAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// Scan runs one pass and returns the new findings.
func (s *Scanner) Scan() []raw.Record {
	s.mu.Lock()
	if s.reported == nil {
		s.reported = map[string]string{}
	}
	s.mu.Unlock()
	pids, err := s.Proc.PIDs()
	if err != nil {
		return nil
	}
	now := s.now()
	alive := make(map[string]bool, len(pids))
	var out []raw.Record
	for _, pid := range pids {
		exe, err := s.Proc.Readlink(pid, "exe")
		if err != nil || exe == "" {
			continue // kernel thread, gone, or not ours to read
		}
		id := strconv.Itoa(pid)
		if st, ok := s.Proc.StartTime(pid); ok {
			id += ":" + strconv.FormatUint(st, 10)
		}
		alive[id] = true
		s.mu.Lock()
		prev, seen := s.reported[id]
		s.mu.Unlock()
		if seen && prev == exe {
			continue
		}
		comm := s.Proc.Comm(pid)
		if s.whitelisted(strings.TrimSuffix(exe, deleted), comm) {
			continue
		}
		typ, sev := s.classify(pid, exe, comm, now)
		if typ == "" {
			continue
		}
		s.mu.Lock()
		s.reported[id] = exe
		s.mu.Unlock()
		out = append(out, s.record(pid, exe, comm, typ, sev, now))
	}
	s.mu.Lock()
	for id := range s.reported {
		if !alive[id] {
			delete(s.reported, id)
		}
	}
	s.mu.Unlock()
	return out
}

func (s *Scanner) exists(path string) bool {
	_, err := os.Stat(filepath.Join(s.Root, path))
	return err == nil
}

func (s *Scanner) classify(pid int, exe, comm string, now time.Time) (typ, sev string) {
	if isShell(comm) && s.reverseShell(pid) != "" {
		return proto.EventProcReverseShell, proto.SeverityP0
	}
	if strings.HasPrefix(exe, "/memfd:") {
		return proto.EventProcFileless, proto.SeverityP1
	}
	if orig, ok := strings.CutSuffix(exe, deleted); ok {
		switch {
		case hasPrefixAny(orig, filelessDirs):
			return proto.EventProcFileless, proto.SeverityP1
		case s.exists(orig):
			// Upgraded package, process not restarted: once a day per binary.
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.stale == nil {
				s.stale = map[string]int64{}
			}
			if last, ok := s.stale[orig]; ok && now.Unix()-last < int64(staleEvery.Seconds()) {
				return "", ""
			}
			s.stale[orig] = now.Unix()
			return proto.EventProcStaleBinary, proto.SeverityP3
		default:
			return proto.EventProcDeletedExe, proto.SeverityP2
		}
	}
	if hasPrefixAny(exe, tmpDirs) && s.exists(exe) {
		return proto.EventProcTmpExec, proto.SeverityP2
	}
	return "", ""
}

func isShell(comm string) bool {
	return shells[comm] || strings.HasPrefix(comm, "python")
}

func (s *Scanner) record(pid int, exe, comm, typ, sev string, now time.Time) raw.Record {
	st := s.Proc.Status(pid)
	d := map[string]any{"pid": pid, "comm": comm, "exe": exe, "cmdline": rules.Cmdline(s.Proc.Read(pid, "cmdline"))}
	if st.OK {
		d["uid"] = st.UID
		if pc := s.Proc.Comm(st.PPid); pc != "" {
			d["ppid_comm"] = pc
		}
	}
	// The key is the binary's path for every type: the server merges by it
	// (decision L20; reverse shells used comm:pid and dropped exe).
	key := strings.TrimSuffix(exe, deleted)
	if typ == proto.EventProcReverseShell {
		d["remote"] = s.reverseShell(pid)
	}
	return raw.Record{Kind: typ, TS: now, Key: key, Severity: sev, Data: d}
}

// reverseShell returns the remote address when at least two of fds 0–2 are
// sockets and one of them is an ESTABLISHED TCP connection, looked up in the
// process's own network namespace.
func (s *Scanner) reverseShell(pid int) string {
	var inodes []string
	for _, fd := range []string{"fd/0", "fd/1", "fd/2"} {
		l, err := s.Proc.Readlink(pid, fd)
		if err == nil && strings.HasPrefix(l, "socket:[") {
			inodes = append(inodes, strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"))
		}
	}
	if len(inodes) < 2 {
		return ""
	}
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		for _, line := range strings.Split(string(s.Proc.Read(pid, table)), "\n")[1:] {
			f := strings.Fields(line)
			// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
			if len(f) < 10 || f[3] != "01" {
				continue
			}
			for _, ino := range inodes {
				if f[9] == ino {
					return decodeAddr(f[2])
				}
			}
		}
	}
	return ""
}

// decodeAddr turns /proc/net/tcp's "0100007F:1F90" (little-endian words)
// into "127.0.0.1:8080".
func decodeAddr(s string) string {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return ""
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return ""
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return ""
	}
	// Each 32-bit word is in host (little-endian) order.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return ""
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
}

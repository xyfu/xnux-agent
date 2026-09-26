// Package procfs reads per-process files under /proc for the process scan
// and event snapshots. Processes come and go while they are read, so every
// function treats a missing file as "process gone" rather than an error.
package procfs

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FS is a /proc mount; Root is "/proc" on a real host.
type FS struct{ Root string }

// PIDs lists the numeric entries of /proc.
func (fs FS) PIDs() ([]int, error) {
	d, err := os.Open(fs.Root)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(names))
	for _, n := range names {
		if n == "" || n[0] < '1' || n[0] > '9' {
			continue
		}
		if pid, err := strconv.Atoi(n); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (fs FS) path(pid int, name string) string {
	return filepath.Join(fs.Root, strconv.Itoa(pid), name)
}

// Read returns a per-process file, or nil when it cannot be read.
func (fs FS) Read(pid int, name string) []byte {
	b, err := os.ReadFile(fs.path(pid, name))
	if err != nil {
		return nil
	}
	return b
}

// Readlink reads a per-process link such as exe or fd/0.
func (fs FS) Readlink(pid int, name string) (string, error) {
	return os.Readlink(fs.path(pid, name))
}

// Comm is the process name.
func (fs FS) Comm(pid int) string {
	return string(bytes.TrimSpace(fs.Read(pid, "comm")))
}

// Status holds the fields of /proc/<pid>/status the agent uses.
type Status struct {
	PPid int
	UID  int // real uid
	OK   bool
}

func (fs FS) Status(pid int) Status {
	var st Status
	for _, line := range strings.Split(string(fs.Read(pid, "status")), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			st.PPid, _ = strconv.Atoi(strings.TrimSpace(v))
			st.OK = true
		} else if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				st.UID, _ = strconv.Atoi(f[0])
			}
		}
	}
	return st
}

// RSSPages is the second column of /proc/<pid>/statm.
func (fs FS) RSSPages(pid int) (int64, bool) {
	f := strings.Fields(string(fs.Read(pid, "statm")))
	if len(f) < 2 {
		return 0, false
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	return n, err == nil
}

// CPUTicks is utime + stime from /proc/<pid>/stat, in clock ticks.
func (fs FS) CPUTicks(pid int) (uint64, bool) {
	b := fs.Read(pid, "stat")
	// comm may contain spaces and parentheses: fields start after the last ')'.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	// After ')': state(3) ppid … utime is field 14, stime 15 → indexes 11, 12.
	if len(f) < 13 {
		return 0, false
	}
	u, err1 := strconv.ParseUint(f[11], 10, 64)
	s, err2 := strconv.ParseUint(f[12], 10, 64)
	return u + s, err1 == nil && err2 == nil
}

// Unit is the systemd service the process belongs to, from its cgroup path
// ("…/nginx.service" or "…/nginx.service/…"), or "".
func (fs FS) Unit(pid int) string {
	for _, line := range strings.Split(string(fs.Read(pid, "cgroup")), "\n") {
		// "0::/system.slice/nginx.service" (v2) or "1:name=systemd:/…" (v1)
		_, path, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, path, ok = strings.Cut(path, ":"); !ok {
			continue
		}
		parts := strings.Split(path, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], ".service") {
				return parts[i]
			}
		}
	}
	return ""
}

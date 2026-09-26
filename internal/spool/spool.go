// Package spool stores sanitized, compressed payloads on disk while the
// server is unreachable (spec A5.3).
//
// File names sort in send order: <seq, 20 digits>[.<part>][.e].json.gz. The
// ".e" marks payloads carrying events, which are evicted last.
package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/xyfu/xnux-agent/internal/fsutil"
)

const (
	DefaultMax       = 50 << 20 // metric-only files are evicted beyond this
	DefaultMaxEvents = 60 << 20 // files with events are evicted beyond this
)

// Entry is one spooled payload.
type Entry struct {
	Name      string
	Seq       uint64
	Part      int
	HasEvents bool
	size      int64
}

// Spool is safe for concurrent use.
type Spool struct {
	dir            string
	max, maxEvents int64

	mu      sync.Mutex
	entries []Entry // sorted by name
	total   int64
	evicted int
}

// Open creates dir (0700) if needed and indexes existing files.
func Open(dir string, max, maxEvents int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the x bit
		return nil, err
	}
	s := &Spool{dir: dir, max: max, maxEvents: maxEvents}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, de := range des {
		e, ok := parseName(de.Name())
		if !ok {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		e.size = fi.Size()
		s.entries = append(s.entries, e)
		s.total += e.size
	}
	sort.Slice(s.entries, func(i, j int) bool { return s.entries[i].Name < s.entries[j].Name })
	return s, nil
}

func fileName(seq uint64, part int, hasEvents bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%020d", seq)
	if part > 0 {
		fmt.Fprintf(&b, ".%d", part)
	}
	if hasEvents {
		b.WriteString(".e")
	}
	b.WriteString(".json.gz")
	return b.String()
}

func parseName(name string) (Entry, bool) {
	base, ok := strings.CutSuffix(name, ".json.gz")
	if !ok || len(base) < 20 {
		return Entry{}, false
	}
	seq, err := strconv.ParseUint(base[:20], 10, 64)
	if err != nil {
		return Entry{}, false
	}
	e := Entry{Name: name, Seq: seq}
	for _, f := range strings.Split(base[20:], ".")[1:] {
		if f == "e" {
			e.HasEvents = true
		} else if p, err := strconv.Atoi(f); err == nil && p > 0 {
			e.Part = p
		} else {
			return Entry{}, false
		}
	}
	return e, true
}

// Put stores a compressed payload and evicts old files beyond the limits.
func (s *Spool) Put(seq uint64, part int, hasEvents bool, gz []byte) error {
	e := Entry{Name: fileName(seq, part, hasEvents), Seq: seq, Part: part, HasEvents: hasEvents, size: int64(len(gz))}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, e.Name), gz, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.entries), func(i int) bool { return s.entries[i].Name >= e.Name })
	if i < len(s.entries) && s.entries[i].Name == e.Name {
		s.total -= s.entries[i].size
		s.entries[i] = e
	} else {
		s.entries = append(s.entries, Entry{})
		copy(s.entries[i+1:], s.entries[i:])
		s.entries[i] = e
	}
	s.total += e.size
	s.evictLocked()
	return nil
}

func (s *Spool) evictLocked() {
	for i := 0; s.total > s.max && i < len(s.entries); {
		if s.entries[i].HasEvents {
			i++
			continue
		}
		s.removeLocked(i)
	}
	for s.total > s.maxEvents && len(s.entries) > 0 {
		s.removeLocked(0)
	}
}

func (s *Spool) removeLocked(i int) {
	_ = os.Remove(filepath.Join(s.dir, s.entries[i].Name))
	s.total -= s.entries[i].size
	s.entries = append(s.entries[:i], s.entries[i+1:]...)
	s.evicted++
}

// Oldest returns the first entry in send order and its bytes.
func (s *Spool) Oldest() (Entry, []byte, bool, error) {
	s.mu.Lock()
	if len(s.entries) == 0 {
		s.mu.Unlock()
		return Entry{}, nil, false, nil
	}
	e := s.entries[0]
	s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, e.Name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.Remove(e.Name)
		}
		return e, nil, true, err
	}
	return e, b, true, nil
}

// Remove deletes an entry by name.
func (s *Spool) Remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.Name == name {
			s.removeLocked(i)
			s.evicted-- // not an eviction
			return
		}
	}
}

// RemoveSeq deletes the entry for (seq, part), if spooled.
func (s *Spool) RemoveSeq(seq uint64, part int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.Seq == seq && e.Part == part {
			s.removeLocked(i)
			s.evicted--
			return
		}
	}
}

// Len is the number of spooled payloads.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Size is the total spooled bytes.
func (s *Spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// Evicted counts payloads dropped to respect the size limits.
func (s *Spool) Evicted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evicted
}

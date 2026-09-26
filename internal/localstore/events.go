// Package localstore keeps the black box on the machine (spec v1.1 delta
// 2): every event as JSON lines under /var/lib/xnux/events/ for 30 days,
// and 24 hours of one-minute metrics in a fixed-size ring file. What is
// stored here is the raw data (it never leaves the machine), so files are
// 0600; only the redaction barrier's output is ever sent.
package localstore

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const (
	// RetentionDays of events kept on disk.
	RetentionDays = 30
	// MaxFileBytes before a day's file rotates to the next part.
	MaxFileBytes = 10 << 20
	// MaxTotalBytes for all event files; the oldest go first beyond it, so
	// the whole local store stays under 350 MB with the metrics ring.
	MaxTotalBytes = 340 << 20
)

// Event is one stored event: the event as the agent saw it, before
// redaction, and when it was stored. The same ID stored again is an update.
type Event struct {
	proto.Event
	StoredAt int64 `json:"stored_at"`
}

// EventLog appends events to daily JSON-lines files.
type EventLog struct {
	dir string
	now func() time.Time

	mu   sync.Mutex
	f    *os.File
	name string
	size int64
}

// OpenEvents opens (creating) the events directory.
func OpenEvents(dir string) (*EventLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &EventLog{dir: dir, now: time.Now}
	l.prune()
	return l, nil
}

// Close closes the current file.
func (l *EventLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// fileFor returns the file name for today's events, rotating past
// MaxFileBytes: 20260927.jsonl, 20260927.1.jsonl, …
func (l *EventLog) fileFor(t time.Time) (string, error) {
	day := t.UTC().Format("20060102")
	for part := 0; part < 1000; part++ {
		name := day + ".jsonl"
		if part > 0 {
			name = fmt.Sprintf("%s.%d.jsonl", day, part)
		}
		fi, err := os.Stat(filepath.Join(l.dir, name))
		if errors.Is(err, os.ErrNotExist) || (err == nil && fi.Size() < MaxFileBytes) {
			return name, nil
		}
	}
	return "", errors.New("too many event files today")
}

// Append stores an event. Each line is written and synced on its own, so
// a power cut can at most leave the last line cut short (readers skip it).
func (l *EventLog) Append(ev proto.Event) error {
	b, err := json.Marshal(Event{Event: ev, StoredAt: l.now().Unix()})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	name, err := l.fileFor(l.now())
	if err != nil {
		return err
	}
	if l.f == nil || name != l.name || l.size+int64(len(b)) > MaxFileBytes {
		if l.f != nil {
			_ = l.f.Close()
			l.f = nil
		}
		if l.size+int64(len(b)) > MaxFileBytes && name == l.name {
			if name, err = l.fileFor(l.now()); err != nil {
				return err
			}
		}
		f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		fi, _ := f.Stat()
		l.f, l.name, l.size = f, name, fi.Size()
		if l.size > 0 && !endsWithNewline(f, l.size) {
			// A line cut short by a crash: start ours on a fresh line.
			if _, err := f.Write([]byte{'\n'}); err == nil {
				l.size++
			}
		}
		go l.prune()
	}
	if _, err := l.f.Write(b); err != nil {
		return err
	}
	l.size += int64(len(b))
	return l.f.Sync()
}

func endsWithNewline(f *os.File, size int64) bool {
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, size-1); err != nil {
		return true
	}
	return b[0] == '\n'
}

// files lists event files, oldest first.
func (l *EventLog) files() []string {
	ents, _ := os.ReadDir(l.dir)
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool { return fileKey(names[i]) < fileKey(names[j]) })
	return names
}

// fileKey orders 20260927.jsonl before 20260927.1.jsonl before 20260927.10.jsonl.
func fileKey(name string) string {
	base := strings.TrimSuffix(name, ".jsonl")
	day, part, _ := strings.Cut(base, ".")
	return fmt.Sprintf("%s.%06s", day, part)
}

// prune removes files older than RetentionDays, then the oldest while the
// total exceeds MaxTotalBytes.
func (l *EventLog) prune() {
	cut := l.now().UTC().AddDate(0, 0, -RetentionDays).Format("20060102")
	names := l.files()
	var total int64
	sizes := map[string]int64{}
	for _, n := range names {
		if n[:8] < cut {
			_ = os.Remove(filepath.Join(l.dir, n))
			continue
		}
		if fi, err := os.Stat(filepath.Join(l.dir, n)); err == nil {
			sizes[n] = fi.Size()
			total += fi.Size()
		}
	}
	for _, n := range names {
		if total <= MaxTotalBytes {
			break
		}
		if s, ok := sizes[n]; ok && n != l.name {
			_ = os.Remove(filepath.Join(l.dir, n))
			total -= s
		}
	}
}

// Filter selects events.
type Filter struct {
	Since    time.Time
	Types    []string
	Severity []string
	Limit    int
}

// Query returns the latest version of each matching event, newest first.
func (l *EventLog) Query(f Filter) ([]Event, error) {
	names := l.files()
	since := ""
	if !f.Since.IsZero() {
		since = f.Since.UTC().Format("20060102")
	}
	seen := map[string]bool{}
	var out []Event
	for i := len(names) - 1; i >= 0; i-- {
		if since != "" && names[i][:8] < since {
			break
		}
		evs, err := readFile(filepath.Join(l.dir, names[i]))
		if err != nil {
			return nil, err
		}
		for j := len(evs) - 1; j >= 0; j-- {
			e := evs[j]
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			if !f.Since.IsZero() && time.Unix(lastTS(e), 0).Before(f.Since) {
				continue
			}
			if len(f.Types) > 0 && !contains(f.Types, e.Type) {
				continue
			}
			if len(f.Severity) > 0 && !contains(f.Severity, e.Severity) {
				continue
			}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return lastTS(out[i]) > lastTS(out[j]) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// Get returns the latest version of one event.
func (l *EventLog) Get(id string) (Event, bool, error) {
	names := l.files()
	for i := len(names) - 1; i >= 0; i-- {
		evs, err := readFile(filepath.Join(l.dir, names[i]))
		if err != nil {
			return Event{}, false, err
		}
		for j := len(evs) - 1; j >= 0; j-- {
			if evs[j].ID == id {
				return evs[j], true, nil
			}
		}
	}
	return Event{}, false, nil
}

// Size is the bytes used by event files.
func (l *EventLog) Size() int64 {
	var total int64
	for _, n := range l.files() {
		if fi, err := os.Stat(filepath.Join(l.dir, n)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

func lastTS(e Event) int64 {
	if e.LastTS > 0 {
		return e.LastTS
	}
	return e.TS
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// readFile parses a JSON-lines file, skipping a line cut short by a crash.
func readFile(path string) ([]Event, error) {
	f, err := os.Open(path) //nolint:gosec // our own directory
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Event
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 1 {
			var e Event
			if json.Unmarshal(line, &e) == nil && e.ID != "" {
				out = append(out, e)
			}
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

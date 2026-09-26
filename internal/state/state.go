// Package state persists /var/lib/xnux/state.json atomically: next seq, auth
// log offsets, disk growth rings (spec A5.4).
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/xyfu/xnux-agent/internal/fsutil"
)

const Version = 1

// AuthlogPos is the resume position of the auth log tailer.
type AuthlogPos struct {
	Path   string `json:"path"`
	Dev    uint64 `json:"dev"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Data is the on-disk document.
type Data struct {
	Version             int                   `json:"version"`
	NextSeq             uint64                `json:"next_seq"`
	Authlog             *AuthlogPos           `json:"authlog,omitempty"`
	DiskGrowth          map[string][][2]int64 `json:"disk_growth,omitempty"` // mount -> [unix, used bytes]
	StaleBinaryReported map[string]int64      `json:"stale_binary_reported,omitempty"`
}

// Store guards Data and writes it atomically. It is safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	d    Data
	last []byte // content of the last successful write
}

// Open loads path. A missing or corrupt file (the latter kept as
// state.json.corrupt) starts fresh with seq = current Unix time in
// milliseconds: the server deduplicates by the highest seq it has seen, so
// a reinstalled agent must start above anything it sent before.
func Open(path string) (*Store, error) {
	s := &Store{path: path, d: Data{Version: Version, NextSeq: uint64(time.Now().UnixMilli())}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil || d.Version != Version || d.NextSeq == 0 {
		if rerr := os.Rename(path, path+".corrupt"); rerr != nil {
			return nil, fmt.Errorf("state corrupt and cannot be moved aside: %w", rerr)
		}
		return s, nil
	}
	s.d = d
	return s, nil
}

// Memory returns a store that is never written to disk (dry-run without
// access to the state directory).
func Memory() *Store {
	return &Store{d: Data{Version: Version, NextSeq: uint64(time.Now().UnixMilli())}}
}

// Update runs fn with exclusive access to the data.
func (s *Store) Update(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
}

// View runs fn with the data; fn must not retain or modify it.
func (s *Store) View(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
}

// NextSeq allocates the next payload sequence number.
func (s *Store) NextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.d.NextSeq
	s.d.NextSeq++
	return seq
}

// Save writes the state atomically (temp file, fsync, rename, mode 0600).
// Unchanged state is not rewritten, which keeps the idle agent off the disk.
func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(&s.d)
	if err != nil {
		return err
	}
	if bytes.Equal(b, s.last) {
		return nil
	}
	if err := fsutil.WriteFileAtomic(s.path, b, 0o600); err != nil {
		return err
	}
	s.last = b
	return nil
}

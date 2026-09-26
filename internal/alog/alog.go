// Package alog is the agent's own logger. Every message and attribute passes
// through the redaction barrier before it is written, so the log file is no
// back door around it (spec A1, G-4).
package alog

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/xyfu/xnux-shared/sanitize"
)

// New returns a JSON logger writing to w with every string redacted.
func New(w io.Writer, b *sanitize.Barrier, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Value.Kind() {
			case slog.KindString:
				a.Value = slog.StringValue(b.String(a.Value.String()))
			case slog.KindAny:
				a.Value = slog.StringValue(b.String(fmt.Sprint(a.Value.Any())))
			}
			return a
		},
	}))
}

// RotatingFile appends to path and rotates it at maxSize, keeping keep old
// files (path.1 … path.keep).
type RotatingFile struct {
	path    string
	maxSize int64
	keep    int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotating opens path (0600) for appending; its directory is created.
func OpenRotating(path string, maxSize int64, keep int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxSize: maxSize, keep: keep}
	return r, r.open()
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.maxSize && r.size > 0 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	r.f.Close()
	for i := r.keep; i >= 1; i-- {
		src := r.path
		if i > 1 {
			src = r.path + "." + strconv.Itoa(i-1)
		}
		_ = os.Rename(src, r.path+"."+strconv.Itoa(i))
	}
	return r.open()
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

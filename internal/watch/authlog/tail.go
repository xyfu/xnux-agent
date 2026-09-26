package authlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/state"
)

const (
	maxLine   = 4 << 10
	readChunk = 32 << 10
	dirMask   = unix.IN_CREATE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE
	fileMask  = unix.IN_MODIFY
)

// Tailer follows one log file across logrotate (rename + create, and
// copytruncate) and agent restarts (spec A3.3).
type Tailer struct {
	Path string
	// Start is the saved position; nil (first install) starts at the end so
	// history is never replayed.
	Start *state.AuthlogPos
	Out   chan<- raw.Record
	Now   func() time.Time

	mu  sync.Mutex
	pos state.AuthlogPos
}

// Position is where to resume; the agent saves it every 10 s and on exit.
func (t *Tailer) Position() *state.AuthlogPos {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pos.Inode == 0 {
		return nil
	}
	p := t.pos
	return &p
}

// handle is an open log file and the unfinished line at its end.
type handle struct {
	f        *os.File
	wd       int
	dev, ino uint64
	off      int64 // bytes read
	done     int64 // end of the last complete line: the resume position
	partial  []byte
	skipping bool // inside an over-long line
}

type run struct {
	t      *Tailer
	ctx    context.Context
	ifd    int
	cur    *handle
	old    *handle // the rotated file, drained until the writer moves on
	buf    []byte
	sendOK bool
}

func (t *Tailer) Run(ctx context.Context) error {
	if t.Now == nil {
		t.Now = time.Now
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	// The runtime poller parks the reading goroutine; Close wakes it.
	inotify := os.NewFile(uintptr(fd), "inotify")
	stop := context.AfterFunc(ctx, func() { inotify.Close() })
	defer func() {
		if stop() {
			inotify.Close()
		}
	}()
	if _, err := unix.InotifyAddWatch(fd, filepath.Dir(t.Path), dirMask); err != nil {
		return err
	}

	r := &run{t: t, ctx: ctx, ifd: fd, buf: make([]byte, readChunk), sendOK: true}
	defer func() {
		r.close(r.cur)
		r.close(r.old)
	}()
	if err := r.resume(); err != nil {
		return err
	}

	ev := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	base := filepath.Base(t.Path)
	for {
		n, err := inotify.Read(ev)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			e := (*unix.InotifyEvent)(unsafe.Pointer(&ev[off])) //nolint:gosec // kernel-defined struct layout, bounds checked above
			name := ""
			if e.Len > 0 {
				nb := ev[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(e.Len)]
				name = string(bytes.TrimRight(nb, "\x00"))
			}
			off += unix.SizeofInotifyEvent + int(e.Len)
			if err := r.handle(e.Wd, e.Mask, name, base); err != nil {
				return err
			}
		}
		if !r.sendOK {
			return nil
		}
	}
}

func (r *run) handle(wd int32, mask uint32, name, base string) error {
	switch {
	case r.cur != nil && int(wd) == r.cur.wd && mask&unix.IN_MODIFY != 0:
		// First write to the new file: the writer has reopened, so the
		// rotated file is complete.
		r.finishOld()
		return r.drain(r.cur, true)
	case r.old != nil && int(wd) == r.old.wd && mask&unix.IN_MODIFY != 0:
		return r.drain(r.old, false)
	case name != base:
		return nil
	case mask&(unix.IN_MOVED_FROM|unix.IN_DELETE) != 0:
		// Rotated away (or deleted): keep reading the old inode until the
		// writer switches to the new file.
		if r.cur != nil {
			if err := r.drain(r.cur, false); err != nil {
				return err
			}
			r.finishOld()
			r.old, r.cur = r.cur, nil
		}
	case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
		if r.cur != nil { // replaced without a MOVED_FROM we saw
			if err := r.drain(r.cur, false); err != nil {
				return err
			}
			r.finishOld()
			r.old, r.cur = r.cur, nil
		}
		if err := r.open(0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if r.cur != nil {
			return r.drain(r.cur, true)
		}
	}
	return nil
}

// resume opens the file at the saved position. When the inode changed while
// the agent was down, the remainder of the rotated file (path.1) is read
// first if it is the one the position refers to.
func (r *run) resume() error {
	t := r.t
	st, err := stat(t.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil // wait for IN_CREATE
	case err != nil:
		return err
	}
	p := t.Start
	switch {
	case p == nil || p.Path != t.Path:
		return r.openAt(-1) // first run: from the end
	case p.Dev == st.Dev && p.Inode == st.Ino:
		return r.openAt(p.Offset)
	}
	if rs, err := stat(t.Path + ".1"); err == nil && rs.Dev == p.Dev && rs.Ino == p.Inode {
		if f, err := os.Open(t.Path + ".1"); err == nil {
			h := &handle{f: f, wd: -1, dev: rs.Dev, ino: rs.Ino}
			if p.Offset <= rs.Size {
				if _, err := f.Seek(p.Offset, io.SeekStart); err == nil {
					h.off, h.done = p.Offset, p.Offset
				}
			}
			err := r.drain(h, false)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
	return r.openAt(0)
}

type fileID struct {
	Dev, Ino uint64
	Size     int64
}

func stat(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, errors.New("no inode information")
	}
	return fileID{Dev: s.Dev, Ino: s.Ino, Size: fi.Size()}, nil
}

// openAt opens the current file at off; -1 means its end.
func (r *run) openAt(off int64) error {
	if err := r.open(off); err != nil {
		return err
	}
	return r.drain(r.cur, true)
}

func (r *run) open(off int64) error {
	f, err := os.Open(r.t.Path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s, _ := fi.Sys().(*syscall.Stat_t)
	h := &handle{f: f, wd: -1}
	if s != nil {
		h.dev, h.ino = s.Dev, s.Ino
	}
	switch {
	case off < 0 || off > fi.Size():
		off = fi.Size()
		if off < 0 {
			off = 0
		}
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	h.off, h.done = off, off
	wd, err := unix.InotifyAddWatch(r.ifd, r.t.Path, fileMask)
	if err != nil {
		f.Close()
		return err
	}
	h.wd = wd
	r.cur = h
	r.save(h)
	return nil
}

func (r *run) close(h *handle) {
	if h == nil {
		return
	}
	if h.wd >= 0 {
		_, _ = unix.InotifyRmWatch(r.ifd, uint32(h.wd))
	}
	h.f.Close()
}

func (r *run) finishOld() {
	if r.old != nil {
		_ = r.drain(r.old, false) // best effort: the file is gone either way
		r.close(r.old)
		r.old = nil
	}
}

func (r *run) save(h *handle) {
	r.t.mu.Lock()
	r.t.pos = state.AuthlogPos{Path: r.t.Path, Dev: h.dev, Inode: h.ino, Offset: h.done}
	r.t.mu.Unlock()
}

// drain reads h to EOF and parses every complete line. For the current
// file a size below the offset means copytruncate: start over from 0.
func (r *run) drain(h *handle, current bool) error {
	if current {
		if fi, err := h.f.Stat(); err == nil && fi.Size() < h.off {
			if _, err := h.f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			h.off, h.done, h.partial, h.skipping = 0, 0, nil, false
		}
	}
	for {
		n, err := h.f.Read(r.buf)
		if n > 0 {
			r.lines(h, r.buf[:n])
		}
		if errors.Is(err, io.EOF) || n == 0 {
			break
		}
		if err != nil {
			return err
		}
	}
	if current {
		r.save(h)
	}
	return nil
}

// lines splits data into lines, carrying an unfinished tail over. The
// resume position only moves past complete lines. Lines over 4 KB are
// dropped.
func (r *run) lines(h *handle, data []byte) {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if !h.skipping {
				h.partial = append(h.partial, data...)
				if len(h.partial) > maxLine {
					h.partial, h.skipping = nil, true
				}
			}
			h.off += int64(len(data))
			return
		}
		chunk := data[:i]
		data = data[i+1:]
		h.off += int64(i + 1)
		h.done = h.off
		if h.skipping {
			h.skipping = false
			continue
		}
		line := chunk
		if len(h.partial) > 0 {
			line = append(h.partial, chunk...)
			h.partial = nil
		}
		if len(line) > maxLine {
			continue
		}
		r.emit(string(line))
	}
}

func (r *run) emit(line string) {
	now := r.t.Now()
	for _, rec := range Parse(line, LineTime(line, now)) {
		if !r.sendOK {
			return
		}
		select {
		case r.t.Out <- rec:
		case <-r.ctx.Done():
			r.sendOK = false
		}
	}
}

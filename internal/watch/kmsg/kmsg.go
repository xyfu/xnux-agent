package kmsg

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xyfu/xnux-agent/internal/raw"
)

// Watcher tails /dev/kmsg from its end: history before the agent started is
// never replayed.
type Watcher struct {
	Path string // "/dev/kmsg"
	Out  chan<- raw.Record

	lost atomic.Int64
}

// Lost counts records the kernel overwrote before they were read (EPIPE).
func (w *Watcher) Lost() int64 { return w.lost.Load() }

// Available reports whether the device can be opened for reading.
func Available(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Run reads until ctx ends or the device fails.
func (w *Watcher) Run(ctx context.Context) error {
	// os.Open registers the fd with the runtime poller (kmsg supports poll),
	// so the read below parks the goroutine and Close wakes it.
	f, err := os.Open(w.Path)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer func() {
		if stop() {
			f.Close()
		}
	}()

	m := NewMatcher()
	buf := make([]byte, 8192) // one read returns one record
	for {
		n, err := f.Read(buf)
		switch {
		case errors.Is(err, syscall.EPIPE):
			w.lost.Add(1)
			continue
		case err != nil:
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		e, ok := ParseEntry(buf[:n])
		if !ok {
			continue
		}
		ts := wallTime(e.USec)
		if r, ok := m.Match(e.Msg, ts); ok {
			select {
			case w.Out <- r:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// wallTime converts a record's timestamp (microseconds of the kernel's
// monotonic clock) to wall time. The spec's btime + ts_usec drifts by hours
// on hosts that were suspended or live-migrated, because btime is fixed
// while the monotonic clock stops; measuring the age of the record against
// the monotonic clock now does not.
func wallTime(usec int64) time.Time {
	now := time.Now()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return now
	}
	age := time.Duration(ts.Nano() - usec*1000)
	if age < 0 {
		return now
	}
	return now.Add(-age)
}

package riskscan

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Scan timing (spec v1.1 delta 10.3).
const (
	sshDebounce = 10 * time.Second // after a change under /etc/ssh/
	portsEvery  = 5 * time.Minute  // with the process patrol
	fullEvery   = 24 * time.Hour
)

// Scheduler runs the scans and sends every new result to Out: all checks at
// start and daily, the SSH checks 10 s after files under /etc/ssh/ change,
// the database ports every 5 minutes.
type Scheduler struct {
	Scanner *Scanner
	Out     chan<- Result
	Log     *slog.Logger
	// Debounce and PortsEvery replace the defaults in tests.
	Debounce, PortsEvery time.Duration
}

func (s *Scheduler) Run(ctx context.Context) error {
	debounce, ports := s.Debounce, s.PortsEvery
	if debounce == 0 {
		debounce = sshDebounce
	}
	if ports == 0 {
		ports = portsEvery
	}
	res := s.Scanner.Full(ctx)
	if !s.send(ctx, res) {
		return nil
	}

	changes := make(chan struct{}, 1)
	w, err := watchDirs(s.Scanner.path("etc/ssh"), changes)
	if err != nil {
		s.Log.Warn("riskscan: cannot watch /etc/ssh; SSH checks run at start and daily only", "err", err)
	} else {
		defer w.close()
	}

	portT := time.NewTicker(ports)
	fullT := time.NewTicker(fullEvery)
	defer portT.Stop()
	defer fullT.Stop()
	settle := time.NewTimer(time.Hour)
	settle.Stop()
	defer settle.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changes:
			settle.Reset(debounce)
			continue
		case <-settle.C:
			res.SSH = s.Scanner.ScanSSH(ctx)
			res.At = s.Scanner.now()
			if w != nil {
				w.rewatch() // sshd_config.d may have appeared
			}
		case <-portT.C:
			s.Scanner.ScanPorts(&res)
		case <-fullT.C:
			res = s.Scanner.Full(ctx)
		}
		if !s.send(ctx, res) {
			return nil
		}
	}
}

func (s *Scheduler) send(ctx context.Context, r Result) bool {
	r.DB = append([]Exposure(nil), r.DB...)
	r.Docker = append([]Exposure(nil), r.Docker...)
	select {
	case s.Out <- r:
		return true
	case <-ctx.Done():
		return false
	}
}

// dirWatch is an inotify watch on /etc/ssh and /etc/ssh/sshd_config.d.
type dirWatch struct {
	fd   int
	f    *os.File
	dirs []string
}

const watchMask = syscall.IN_CLOSE_WRITE | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_TO |
	syscall.IN_MOVED_FROM | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF

func watchDirs(sshDir string, changes chan<- struct{}) (*dirWatch, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	w := &dirWatch{fd: fd, dirs: []string{sshDir, filepath.Join(sshDir, "sshd_config.d")}}
	if _, err := syscall.InotifyAddWatch(fd, sshDir, watchMask); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	w.rewatch()
	// A non-blocking descriptor goes through the runtime poller, so Close
	// unblocks the reader.
	w.f = os.NewFile(uintptr(fd), "inotify")
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := w.f.Read(buf); err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				time.Sleep(time.Second)
				continue
			}
			select {
			case changes <- struct{}{}:
			default:
			}
		}
	}()
	return w, nil
}

// rewatch adds the drop-in directory (watching it again is harmless).
func (w *dirWatch) rewatch() {
	for _, d := range w.dirs[1:] {
		_, _ = syscall.InotifyAddWatch(w.fd, d, watchMask)
	}
}

func (w *dirWatch) close() {
	if w.f != nil {
		_ = w.f.Close()
	}
}

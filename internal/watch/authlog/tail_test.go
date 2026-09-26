package authlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/state"
)

type logFile struct {
	t    *testing.T
	path string
	f    *os.File
	n    int
}

func (l *logFile) open() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.t.Fatal(err)
	}
	l.f = f
}

// write appends n numbered failure lines, each naming a unique user.
func (l *logFile) write(n int) {
	for range n {
		l.n++
		fmt.Fprintf(l.f, "2026-09-25T10:00:00+00:00 host sshd[1]: Failed password for u%04d from 203.0.113.1 port %d ssh2\n", l.n, l.n)
	}
}

type collector struct {
	ch   chan raw.Record
	seen []string
}

func (c *collector) wait(t *testing.T, total int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for len(c.seen) < total {
		select {
		case r := <-c.ch:
			c.seen = append(c.seen, r.Data["user"].(string))
		case <-deadline:
			t.Fatalf("got %d lines, want %d", len(c.seen), total)
		}
	}
	// Nothing extra (duplicates) may follow.
	select {
	case r := <-c.ch:
		t.Fatalf("unexpected extra record %v", r.Data)
	case <-time.After(200 * time.Millisecond):
	}
}

// check reports lines from..to seen exactly once, in any order.
func (c *collector) check(t *testing.T, from, to int) {
	t.Helper()
	got := append([]string(nil), c.seen...)
	sort.Strings(got)
	var want []string
	for i := from; i <= to; i++ {
		want = append(want, fmt.Sprintf("u%04d", i))
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("lines seen:\n%v\nwant:\n%v", got, want)
	}
}

func start(t *testing.T, path string, pos *state.AuthlogPos) (*Tailer, *collector, context.CancelFunc, chan error) {
	c := &collector{ch: make(chan raw.Record, 1000)}
	tl := &Tailer{Path: path, Start: pos, Out: c.ch}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Run(ctx) }()
	time.Sleep(50 * time.Millisecond) // let it open the file and add watches
	return tl, c, cancel, done
}

func stop(t *testing.T, cancel context.CancelFunc, done chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not stop")
	}
}

// F4-3 acceptance: across logrotate's rename + create (with the writer still
// appending to the old file until it reopens) and copytruncate, no line is
// lost and none is read twice.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	lf := &logFile{t: t, path: filepath.Join(dir, "auth.log")}
	lf.open()
	lf.write(5) // history: never replayed on first start

	_, c, cancel, done := start(t, lf.path, nil)
	defer stop(t, cancel, done)
	lf.write(10)
	c.wait(t, 10)

	// rename + create; the writer keeps its old descriptor for a while.
	if err := os.Rename(lf.path, lf.path+".1"); err != nil {
		t.Fatal(err)
	}
	lf.write(5) // still into auth.log.1
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(lf.path, nil, 0o600); err != nil { // logrotate's "create"
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	lf.write(3) // late lines into the old file
	lf.f.Close()
	lf.open() // the writer reopens (HUP)
	lf.write(7)
	c.wait(t, 25)

	// copytruncate: copy away, then truncate in place.
	lf.write(4)
	c.wait(t, 29)
	if err := lf.f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := lf.f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	lf.write(6)
	c.wait(t, 35)
	c.check(t, 6, 40)
}

// Restart: resume at the saved offset; when the file was rotated while the
// agent was down, finish the rotated file (path.1) first.
func TestResume(t *testing.T) {
	dir := t.TempDir()
	lf := &logFile{t: t, path: filepath.Join(dir, "auth.log")}
	lf.open()
	tl, c, cancel, done := start(t, lf.path, nil)
	lf.write(4)
	c.wait(t, 4)
	lf.write(1)
	fmt.Fprint(lf.f, "2026-09-25T10:00:00+00:00 host sshd[1]: Failed password for u9999 fr") // unfinished line
	c.wait(t, 5)
	stop(t, cancel, done)
	pos := tl.Position()
	if pos == nil || pos.Inode == 0 {
		t.Fatalf("position %+v", pos)
	}
	fmt.Fprint(lf.f, "om 203.0.113.1 port 1 ssh2\n") // finished while the agent is down

	// Down: more lines, then a rotation.
	lf.write(3)
	if err := os.Rename(lf.path, lf.path+".1"); err != nil {
		t.Fatal(err)
	}
	lf.f.Close()
	lf.open()
	lf.write(2)

	_, c2, cancel2, done2 := start(t, lf.path, pos)
	defer stop(t, cancel2, done2)
	c2.wait(t, 6)
	got := append([]string(nil), c2.seen...)
	sort.Strings(got)
	if fmt.Sprint(got) != "[u0006 u0007 u0008 u0009 u0010 u9999]" {
		t.Fatalf("after restart: %v", got)
	}
}

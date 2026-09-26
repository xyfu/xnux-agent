package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		done <- Serve(ctx, path, func(_ context.Context, cmd string, args json.RawMessage) (any, error) {
			if cmd == "fail" {
				return nil, errors.New("nope")
			}
			var a struct{ N int }
			_ = json.Unmarshal(args, &a)
			return map[string]any{"cmd": cmd, "n": a.N * 2}, nil
		})
	}()
	var c *Client
	var err error
	for i := 0; i < 50; i++ {
		if c, err = Dial(path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Cmd string
		N   int
	}
	if err := c.Call("status", map[string]int{"n": 21}, &out); err != nil || out.Cmd != "status" || out.N != 42 {
		t.Fatalf("%+v %v", out, err)
	}
	if err := c.Call("fail", nil, nil); err == nil || err.Error() != "nope" {
		t.Fatalf("error: %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	_ = c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(path); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("after stop: %v", err)
	}
}

func TestOversizedRequestIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Serve(ctx, path, func(context.Context, string, json.RawMessage) (any, error) { return "ok", nil })
	}()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("unix", path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(`{"cmd":"` + strings.Repeat("x", MaxRequest+10)))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// EOF, or a reset when unread bytes were still queued.
	if n, err := conn.Read(make([]byte, 16)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read %d, %v; want the connection closed", n, err)
	}
	// The server keeps serving others.
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var s string
	if err := c.Call("status", nil, &s); err != nil || s != "ok" {
		t.Fatalf("%q %v", s, err)
	}
}

// Package ipc connects the xnux CLI to the running agent over a Unix
// socket (spec v1.1 delta 2): line-delimited JSON, one request and one
// response per line. The agent still listens on no network port.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// DefaultPath is where the agent listens.
const DefaultPath = "/run/xnux/agent.sock"

// Group may use the CLI: the socket is 0660 root:xnux (or the agent's user).
const Group = "xnux"

// MaxRequest is the longest request line and MaxConns the most connections
// served at once.
const (
	MaxRequest = 64 << 10
	MaxConns   = 8
)

// Request is one CLI call.
type Request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response carries data or an error.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Handler answers one request.
type Handler func(ctx context.Context, cmd string, args json.RawMessage) (any, error)

// Serve listens on path until ctx ends. A stale socket file is replaced.
func Serve(ctx context.Context, path string, h Handler) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // the group must reach the socket
		return err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group xnux may use the CLI (spec v1.1 delta 2)
		_ = l.Close()
		return err
	}
	if g, err := user.LookupGroup(Group); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(path, -1, gid)
		}
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
		_ = os.Remove(path)
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, MaxConns)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		// A handful of CLIs at once is plenty; more is a runaway script.
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			serveConn(ctx, c, h)
		}()
	}
}

func serveConn(ctx context.Context, c net.Conn, h Handler) {
	defer c.Close()
	r := bufio.NewReaderSize(c, MaxRequest)
	for {
		_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
		// ReadSlice fails once a line outgrows the buffer: requests are
		// small, so a longer one ends the connection instead of growing memory.
		line, err := r.ReadSlice('\n')
		if err != nil {
			return
		}
		var req Request
		resp := Response{}
		if err := json.Unmarshal(line, &req); err != nil {
			resp.Error = "bad request"
		} else {
			data, err := h(ctx, req.Cmd, req.Args)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.OK = true
				resp.Data, _ = json.Marshal(data)
			}
		}
		b, _ := json.Marshal(resp)
		if _, err := c.Write(append(b, '\n')); err != nil {
			return
		}
	}
}

// Client talks to the agent.
type Client struct {
	c net.Conn
	r *bufio.Reader
}

// ErrNotRunning means nothing listens on the socket.
var ErrNotRunning = errors.New("the agent is not running (systemctl status xnux-agent)")

// ErrDenied means the socket exists but this user may not use it.
var ErrDenied = errors.New("permission denied: run with sudo, or add yourself to the \"xnux\" group (sudo usermod -aG xnux $USER, then log in again)")

// Dial connects to the agent.
func Dial(path string) (*Client, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, ErrDenied
		}
		return nil, ErrNotRunning
	}
	return &Client{c: c, r: bufio.NewReaderSize(c, 1<<20)}, nil
}

// Close ends the connection.
func (c *Client) Close() error { return c.c.Close() }

// Call sends one request and decodes the data into out (when not nil).
func (c *Client) Call(cmd string, args any, out any) error {
	req := Request{Cmd: cmd}
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		req.Args = b
	}
	b, _ := json.Marshal(req)
	_ = c.c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

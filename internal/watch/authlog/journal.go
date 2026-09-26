package authlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xyfu/xnux-agent/internal/raw"
)

// Source picks where security logs come from (spec A3.3): auth.log, then
// secure, then the journal. An empty mode means none is available.
func Source(root string) (mode, path string) {
	for _, p := range []string{"var/log/auth.log", "var/log/secure"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return "file", filepath.Join(root, p)
		}
	}
	if _, err := exec.LookPath("journalctl"); err == nil {
		return "journal", ""
	}
	return "", ""
}

// journalArgs follows only new entries of the programs the parser knows.
// OpenSSH 9.8+ logs from sshd-session (spec A3.3).
var journalArgs = []string{"-f", "-n", "0", "-o", "json", "--no-pager",
	"_COMM=sshd", "+", "_COMM=sshd-session", "+", "_COMM=sudo", "+", "_COMM=useradd", "+", "_COMM=su"}

// Journal streams security entries from a long-running journalctl (the
// second of the two external commands the agent runs).
type Journal struct {
	Out chan<- raw.Record
	// Command defaults to "journalctl"; tests substitute a script.
	Command string
}

type entry struct {
	Message    json.RawMessage `json:"MESSAGE"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	Comm       string          `json:"_COMM"`
	PID        string          `json:"_PID"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
}

// message decodes MESSAGE, which journald exports as a byte array when it
// is not valid UTF-8.
func (e entry) message() string {
	var s string
	if json.Unmarshal(e.Message, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(e.Message, &ints) == nil {
		for _, v := range ints {
			b = append(b, byte(v))
		}
	}
	return string(b)
}

// Line rebuilds "<program>[pid]: <message>" so journal and file lines share
// one parser, and returns the entry time.
func (e entry) line() (string, time.Time) {
	prog := e.Identifier
	if prog == "" {
		prog = e.Comm
	}
	if e.PID != "" {
		prog += "[" + e.PID + "]"
	}
	ts := time.Now()
	if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
		ts = time.UnixMicro(us)
	}
	return prog + ": " + e.message(), ts
}

func (j *Journal) Run(ctx context.Context) error {
	name := j.Command
	if name == "" {
		name = "journalctl"
	}
	cmd := exec.CommandContext(ctx, name, journalArgs...) //nolint:gosec // fixed arguments; name is journalctl outside tests
	cmd.Env = []string{"LANG=C", "SYSTEMD_COLORS=0", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		line, ts := e.line()
		if len(line) > maxLine {
			continue
		}
		for _, rec := range Parse(line, ts) {
			select {
			case j.Out <- rec:
			case <-ctx.Done():
			}
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = errors.New("journalctl exited")
	}
	return err
}

package authlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xyfu/xnux-agent/internal/raw"
)

func TestParseLines(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		line, kind string
		want       map[string]any
	}{
		{"Jan  2 03:00:01 host sshd[811]: Failed publickey for git from 2001:db8::7 port 22 ssh2: RSA SHA256:x", raw.SSHFail, map[string]any{"user": "git", "ip": "2001:db8::7"}},
		{"Jan  2 03:00:01 host sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 4 ssh2", raw.SSHFail, map[string]any{"user": "admin"}},
		{"Jan  2 03:00:01 host sshd-session[9]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 5 ssh2 [preauth]", raw.SSHMaxAuth, map[string]any{"user": "root"}},
		{"Jan  2 03:00:01 host sshd[9]: Invalid user  from 203.0.113.9 port 5", raw.SSHInvalidUser, map[string]any{"user": ""}},
		{"Jan  2 03:00:01 host sshd[9]: Accepted keyboard-interactive/pam for bob from 10.1.1.1 port 5 ssh2", raw.SSHAccept, map[string]any{"method": "keyboard-interactive/pam", "user": "bob"}},
		{"Jan  2 03:00:01 host useradd[77]: new user: name=svc, UID=998, GID=998, home=/home/svc, shell=/bin/sh, from=none", raw.UserCreated, map[string]any{"name": "svc", "uid": 998}},
		{"Jan  2 03:00:01 host su: pam_unix(su-l:session): session opened for user root by carol(uid=1002)", raw.SuRoot, map[string]any{"by_user": "carol"}},
	}
	for _, c := range cases {
		rs := Parse(c.line, LineTime(c.line, now))
		if len(rs) != 1 || rs[0].Kind != c.kind {
			t.Errorf("%q → %+v, want %s", c.line, rs, c.kind)
			continue
		}
		for k, v := range c.want {
			if rs[0].Data[k] != v {
				t.Errorf("%q: %s = %v, want %v", c.line, k, rs[0].Data[k], v)
			}
		}
		if got := rs[0].TS; !got.Equal(time.Date(2026, 1, 2, 3, 0, 1, 0, time.UTC)) {
			t.Errorf("%q: time %v", c.line, got)
		}
	}
	for _, noise := range []string{
		"Jan  2 03:00:01 host CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)",
		"Jan  2 03:00:01 host sshd[1]: Received disconnect from 10.0.0.1 port 22:11: bye",
		"Jan  2 03:00:01 host kernel: sudo: something",
	} {
		if rs := Parse(noise, now); len(rs) != 0 {
			t.Errorf("noise %q → %+v", noise, rs)
		}
	}
	// A December line read on January 2nd belongs to last year.
	if ts := LineTime("Dec 31 23:59:59 host x", now); ts.Year() != 2025 {
		t.Errorf("year rollover: %v", ts)
	}
}

func TestJournal(t *testing.T) {
	script := filepath.Join(t.TempDir(), "journalctl")
	body := `#!/bin/sh
echo '{"MESSAGE":"Failed password for root from 203.0.113.4 port 22 ssh2","SYSLOG_IDENTIFIER":"sshd-session","_PID":"42","__REALTIME_TIMESTAMP":"1790000000123456"}'
echo '{"MESSAGE":"    dave : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/visudo","SYSLOG_IDENTIFIER":"sudo","_PID":"43","__REALTIME_TIMESTAMP":"1790000001000000"}'
echo '{"MESSAGE":[70,97,105,108,101,100,32,112,97,115,115,119,111,114,100,32,102,111,114,32,120,32,102,114,111,109,32,49,46,50,46,51,46,52,32,112,111,114,116,32,49,32,115,115,104,50],"_COMM":"sshd","__REALTIME_TIMESTAMP":"1790000002000000"}'
exec sleep 30
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	out := make(chan raw.Record, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Journal{Out: out, Command: script}).Run(ctx) }()
	var got []raw.Record
	for len(got) < 3 {
		select {
		case r := <-out:
			got = append(got, r)
		case <-time.After(5 * time.Second):
			t.Fatalf("got %d records", len(got))
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got[0].Kind != raw.SSHFail || !got[0].TS.Equal(time.UnixMicro(1790000000123456)) ||
		got[1].Kind != raw.SudoCmd || got[1].Data["command"] != "/usr/sbin/visudo" ||
		got[2].Kind != raw.SSHFail || got[2].Data["ip"] != "1.2.3.4" {
		t.Fatalf("%+v", got)
	}
}

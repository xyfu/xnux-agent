// Package authlog tails auth.log / secure through inotify, or reads
// journalctl on systems without them, and turns sshd, sudo, useradd and su
// lines into security records (spec A3.3). Nothing it reads is reported as
// is: the rules engine decides what becomes an event.
package authlog

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xyfu/xnux-agent/internal/raw"
)

// Programs whose lines are parsed; everything else is skipped cheaply.
var reProgram = regexp.MustCompile(`(?:^|\s)(sshd-session|sshd|sudo|useradd|su)(?:\[\d+\])?:\s`)

var (
	reSSHFail    = regexp.MustCompile(`Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port \d+`)
	reSSHInvalid = regexp.MustCompile(`Invalid user (\S*) from (\S+)`)
	reSSHMaxAuth = regexp.MustCompile(`maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)`)
	reSSHAccept  = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port \d+`)
	reSudoCmd    = regexp.MustCompile(`^\s*(\S+) : .*?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$`)
	reSudoFail   = regexp.MustCompile(`^\s*(\S+) : (?:(\d+) incorrect password attempts?|.*authentication failure)`)
	reUseradd    = regexp.MustCompile(`new user: name=([^,]+), UID=(\d+)`)
	reSuRoot     = regexp.MustCompile(`session opened for user root(?:\(uid=0\))? by (\S+?)(?:\(uid=\d+\))?$`)
)

// Parse turns one line into records (usually none or one). Lines from files carry the syslog
// prefix ("<time> <host> sshd[123]: …"); journal lines are rebuilt as
// "<program>[pid]: <message>" so both go through the same path.
func Parse(line string, ts time.Time) []raw.Record {
	loc := reProgram.FindStringSubmatchIndex(line)
	if loc == nil {
		return nil
	}
	prog := line[loc[2]:loc[3]]
	msg := strings.TrimRight(line[loc[1]:], "\r\n")
	rec := func(kind, key string, d map[string]any) []raw.Record {
		return []raw.Record{{Kind: kind, TS: ts, Key: key, Data: d}}
	}
	switch prog {
	case "sshd", "sshd-session":
		if g := reSSHFail.FindStringSubmatch(msg); g != nil {
			return rec(raw.SSHFail, g[2], map[string]any{"user": g[1], "ip": g[2]})
		}
		if g := reSSHMaxAuth.FindStringSubmatch(msg); g != nil {
			return rec(raw.SSHMaxAuth, g[2], map[string]any{"user": g[1], "ip": g[2]})
		}
		if g := reSSHInvalid.FindStringSubmatch(msg); g != nil {
			return rec(raw.SSHInvalidUser, g[2], map[string]any{"user": g[1], "ip": g[2]})
		}
		if g := reSSHAccept.FindStringSubmatch(msg); g != nil {
			return rec(raw.SSHAccept, g[3], map[string]any{"method": g[1], "user": g[2], "ip": g[3]})
		}
	case "sudo":
		// sudo logs one line per invocation. Failed passwords are counted in
		// it ("3 incorrect password attempts ; … COMMAND=…"); the command
		// part matters too, since a later attempt may have succeeded. The
		// per-attempt pam_unix lines are not counted on top.
		var out []raw.Record
		if g := reSudoFail.FindStringSubmatch(msg); g != nil {
			n, err := strconv.Atoi(g[2])
			if err != nil || n < 1 {
				n = 1
			}
			out = append(out, rec(raw.SudoFail, g[1], map[string]any{"user": g[1], "attempts": n})...)
		}
		if g := reSudoCmd.FindStringSubmatch(msg); g != nil {
			out = append(out, rec(raw.SudoCmd, g[1], map[string]any{"by_user": g[1], "pwd": g[2], "as_user": g[3], "command": g[4]})...)
		}
		return out
	case "useradd":
		if g := reUseradd.FindStringSubmatch(msg); g != nil {
			uid, _ := strconv.Atoi(g[2])
			return rec(raw.UserCreated, g[1], map[string]any{"name": g[1], "uid": uid})
		}
	case "su":
		if g := reSuRoot.FindStringSubmatch(msg); g != nil {
			return rec(raw.SuRoot, g[1], map[string]any{"by_user": g[1]})
		}
	}
	return nil
}

// LineTime reads the syslog timestamp at the start of a file line: RFC 3339
// (rsyslog's default on current distributions) or "Jan _2 15:04:05". The
// fallback is now, which is right for a live tail.
func LineTime(line string, now time.Time) time.Time {
	if sp := strings.IndexByte(line, ' '); sp > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:sp]); err == nil {
			return t
		}
	}
	if len(line) >= 15 {
		if t, err := time.ParseInLocation(time.Stamp, line[:15], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // December lines read in January
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return now
}

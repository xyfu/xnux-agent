package authlog

import (
	"testing"
	"time"
)

// Log lines are attacker-controlled (user names, source strings): the
// parser must never panic, whatever it is fed.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"Jan  2 03:00:01 host sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 4 ssh2",
		"2026-09-25T10:00:00+00:00 host sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
		"host useradd[1]: new user: name=x, UID=0",
		"su: session opened for user root by (uid=0)",
		"sshd[1]: Accepted  for  from  port 1",
	} {
		f.Add(s)
	}
	now := time.Unix(1_790_000_000, 0)
	f.Fuzz(func(t *testing.T, line string) {
		for _, r := range Parse(line, LineTime(line, now)) {
			if r.Kind == "" || r.Data == nil {
				t.Fatalf("incomplete record %+v", r)
			}
		}
	})
}

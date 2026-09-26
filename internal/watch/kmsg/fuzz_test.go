package kmsg

import (
	"testing"
	"time"
)

func FuzzMatch(f *testing.F) {
	for _, s := range []string{
		"6,1,2,-;Out of memory: Killed process 1 (a) total-vm:1kB, anon-rss:1kB, file-rss:1kB, shmem-rss:1kB, UID:0 pgtables:1kB oom_score_adj:0",
		"4,2,3,-;oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),oom_memcg=,task_memcg=/,task=a,pid=1,uid=0",
		"6,3,4,-;x[1]: segfault at 0 ip 0 sp 0 error 4 in y[1+2]",
		"3,4,5,-;I/O error, dev sda, sector 1\n SUBSYSTEM=block",
		"3,5,6,-;INFO: task a:1 blocked for more than 1 seconds.",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m := NewMatcher()
		if e, ok := ParseEntry(b); ok {
			if r, ok := m.Match(e.Msg, time.Unix(0, 0)); ok && (r.Kind == "" || r.Data == nil) {
				t.Fatalf("incomplete record %+v", r)
			}
		}
	})
}

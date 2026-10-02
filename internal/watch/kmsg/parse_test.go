package kmsg

import (
	"testing"
	"time"
)

func TestParseEntry(t *testing.T) {
	e, ok := ParseEntry([]byte("3,1234,5678901,-;EXT4-fs error (device sda1): bad\\x20block\n SUBSYSTEM=block\n DEVICE=b8:1\n"))
	if !ok || e.Seq != 1234 || e.USec != 5678901 || e.Msg != "EXT4-fs error (device sda1): bad block" {
		t.Fatalf("%+v %v", e, ok)
	}
	if _, ok := ParseEntry([]byte("garbage")); ok {
		t.Fatal("garbage parsed")
	}
}

// Real kernel lines (6.x) for every record type.
func TestMatch(t *testing.T) {
	ts := time.Unix(1_790_000_000, 0)
	m := NewMatcher()

	// The constraint line precedes the kill and is merged by pid.
	if _, ok := m.Match("oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/system.slice/app.service,task_memcg=/system.slice/app.service,task=java,pid=21877,uid=1001", ts); ok {
		t.Fatal("constraint line reported on its own")
	}
	r, ok := m.Match("Memory cgroup out of memory: Killed process 21877 (java) total-vm:6266880kB, anon-rss:3380224kB, file-rss:12288kB, shmem-rss:0kB, UID:1001 pgtables:7200kB oom_score_adj:0", ts.Add(time.Millisecond))
	d := r.Data
	if !ok || r.Kind != "oom_kill" || r.Key != "java" || d["pid"] != 21877 || d["total_vm_mb"] != 6120 ||
		d["anon_rss_mb"] != 3301 || d["file_rss_mb"] != 12 || d["scope"] != "memcg" ||
		d["constraint"] != "CONSTRAINT_MEMCG" || d["memcg"] != "/system.slice/app.service" {
		t.Fatalf("oom: %+v", r)
	}
	r, ok = m.Match("Out of memory: Killed process 999 (stress-ng-vm) total-vm:1048576kB, anon-rss:1000000kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:2000kB oom_score_adj:-100", ts)
	if !ok || r.Data["scope"] != "global" || r.Data["oom_score_adj"] != -100 || r.Data["constraint"] != nil {
		t.Fatalf("global oom: %+v", r)
	}

	r, ok = m.Match("myapp[4321]: segfault at 0 ip 000055d5c2a4b129 sp 00007ffc5a3e1b40 error 6 in myapp[55d5c2a4b000+1000] likely on CPU 1 (core 1, socket 0)", ts)
	if !ok || r.Kind != "proc_segfault" || r.Data["comm"] != "myapp" || r.Data["pid"] != 4321 || r.Data["module"] != "myapp" {
		t.Fatalf("segfault: %+v", r)
	}
	r, ok = m.Match("I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2", ts)
	if !ok || r.Kind != "disk_error" || r.Data["device"] != "sdb" || r.Key != "sdb" {
		t.Fatalf("io error: %+v", r)
	}
	r, ok = m.Match("EXT4-fs error (device nvme0n1p2): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0", ts)
	if !ok || r.Kind != "disk_error" || r.Data["device"] != "nvme0n1p2" {
		t.Fatalf("ext4: %+v", r)
	}
	r, ok = m.Match("EXT4-fs (sda1): Remounting filesystem read-only", ts)
	if !ok || r.Kind != "fs_readonly" || r.Data["device"] != "sda1" {
		t.Fatalf("readonly: %+v", r)
	}
	// Device-mapper and md names keep their dash (they used to become "dm").
	for msg, want := range map[string]string{
		"Buffer I/O error on dev dm-0, logical block 0, async page read":    "dm-0",
		"XFS (dm-1): metadata I/O error in \"xfs_imap_to_bp\" at daddr 0x4": "dm-1",
		"EXT4-fs (md127p1): Remounting filesystem read-only":                "md127p1",
	} {
		if r, ok := m.Match(msg, ts); !ok || r.Data["device"] != want || r.Key != want {
			t.Errorf("%q: %+v, want device %s", msg, r, want)
		}
	}
	if r, ok := m.Match("blk_update_request: critical medium error, sector 2048", ts); !ok || r.Key != "unknown" || r.Data["device"] != nil {
		t.Errorf("no device: %+v", r)
	}
	r, ok = m.Match("INFO: task jbd2/sda1-8:312 blocked for more than 122 seconds.", ts)
	if !ok || r.Kind != "hung_task" || r.Data["comm"] != "jbd2/sda1-8" || r.Data["pid"] != 312 || r.Data["blocked_seconds"] != 122 {
		t.Fatalf("hung: %+v", r)
	}
	for _, noise := range []string{"usb 1-1: new high-speed USB device", "audit: type=1400 apparmor=\"DENIED\"", "EXT4-fs (sda1): mounted filesystem"} {
		if r, ok := m.Match(noise, ts); ok {
			t.Fatalf("noise matched: %q → %+v", noise, r)
		}
	}
}

func BenchmarkMatchNoise(b *testing.B) {
	m := NewMatcher()
	ts := time.Now()
	for b.Loop() {
		m.Match("audit: type=1400 audit(1790000000.123:456): apparmor=\"STATUS\" operation=\"profile_load\"", ts)
	}
}

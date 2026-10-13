package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

// Status reads the real and effective uid from the Uid: line, and whether
// CapEff holds any capability (thread 0029).
func TestStatusUIDs(t *testing.T) {
	root := t.TempDir()
	write := func(pid, status string) {
		t.Helper()
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "Name:\tapi.test\nPPid:\t9\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nCapEff:\t0000000000000000\n")
	write("11", "Name:\tsu\nPPid:\t9\nUid:\t1001\t0\t0\t0\nCapEff:\t000001ffffffffff\n")
	write("12", "Name:\told\nPPid:\t9\nUid:\t1001\n")
	write("13", "Name:\tping\nPPid:\t9\nUid:\t1001\t1001\t1001\t1001\nCapEff:\t0000000000002000\n")
	fs := FS{Root: root}
	for pid, want := range map[int]Status{
		10: {PPid: 9, UID: 1001, EUID: 1001, HasEUID: true, OK: true},
		11: {PPid: 9, UID: 1001, EUID: 0, HasEUID: true, Caps: true, OK: true},
		12: {PPid: 9, UID: 1001, OK: true},
		13: {PPid: 9, UID: 1001, EUID: 1001, HasEUID: true, Caps: true, OK: true},
	} {
		if got := fs.Status(pid); got != want {
			t.Errorf("pid %d: %+v, want %+v", pid, got, want)
		}
	}
}

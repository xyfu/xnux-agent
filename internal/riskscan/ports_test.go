package riskscan

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpLine(local, remote, st string) string {
	return "   0: " + local + " " + remote + " " + st + " 00000000:00000000 00:00000000 00000000   999        0 12345 1 0000000000000000 100 0 0 10 0\n"
}

func TestDBExposure(t *testing.T) {
	tcp := tcpHeader +
		tcpLine("00000000:18EB", "00000000:0000", StateListen) + // redis on 0.0.0.0
		tcpLine("0100007F:1538", "00000000:0000", StateListen) + // postgres on 127.0.0.1
		tcpLine("0100000A:0CEA", "00000000:0000", StateListen) + // mysql on 10.0.0.1
		tcpLine("08080808:23F0", "00000000:0000", StateListen) + // elasticsearch on a public address
		tcpLine("00000000:0016", "00000000:0000", StateListen) // ssh: not a database
	tcp6 := tcpHeader +
		tcpLine("00000000000000000000000000000000:6989", "00000000000000000000000000000000:0000", StateListen) // mongodb on ::
	s := &Scanner{Root: fixture(t, map[string]string{"proc/net/tcp": tcp, "proc/net/tcp6": tcp6})}
	var r Result
	s.ScanPorts(&r)
	var got []string
	for _, e := range r.DB {
		got = append(got, e.Service+"@"+e.Addr)
	}
	want := "redis@0.0.0.0 elasticsearch@8.8.8.8 mongodb@::"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

func TestDockerExposure(t *testing.T) {
	cmd := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []int
	}{
		{"no docker", map[string]string{}, nil},
		{"unix socket only", map[string]string{"proc/42/comm": "dockerd\n", "proc/42/cmdline": cmd("/usr/bin/dockerd", "-H", "fd://")}, nil},
		{"tcp on all interfaces", map[string]string{"proc/42/comm": "dockerd\n",
			"proc/42/cmdline": cmd("/usr/bin/dockerd", "-H", "fd://", "-H", "tcp://0.0.0.0:2375")}, []int{2375}},
		{"tcp with tls", map[string]string{"proc/42/comm": "dockerd\n",
			"proc/42/cmdline": cmd("/usr/bin/dockerd", "--tlsverify", "--host=tcp://0.0.0.0:2376")}, nil},
		{"tcp on loopback", map[string]string{"proc/42/comm": "dockerd\n", "proc/42/cmdline": cmd("/usr/bin/dockerd", "-Htcp://127.0.0.1:2375")}, nil},
		{"daemon.json hosts", map[string]string{"etc/docker/daemon.json": `{"hosts": ["unix:///var/run/docker.sock", "tcp://:4243"]}`}, []int{4243}},
		{"daemon.json with tls", map[string]string{"etc/docker/daemon.json": `{"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true}`}, nil},
		{"listening on 2375", map[string]string{"proc/net/tcp": tcpHeader + tcpLine("00000000:0947", "00000000:0000", StateListen)}, []int{2375}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &Scanner{Root: fixture(t, c.files)}
			got := s.ScanDocker()
			var ports []int
			for _, e := range got {
				ports = append(ports, e.Port)
			}
			if len(ports) != len(c.want) || (len(ports) > 0 && ports[0] != c.want[0]) {
				t.Fatalf("got %+v, want ports %v", got, c.want)
			}
		})
	}
}

func TestMonitor(t *testing.T) {
	root := fixture(t, map[string]string{"proc/net/tcp": tcpHeader +
		tcpLine("0100000A:18EB", "04030201:C350", StateEstablished) + // 1.2.3.4 -> redis
		tcpLine("0100000A:18EB", "05030201:C351", StateEstablished) + // 1.2.3.5 -> redis
		tcpLine("0100000A:18EB", "0900000A:C352", StateEstablished) + // 10.0.0.9 -> redis: private
		tcpLine("0100000A:0947", "0900000A:C353", StateEstablished), // 10.0.0.9 -> docker
	})
	r := &Result{DB: []Exposure{{Port: 6379, Service: "redis"}}, Docker: []Exposure{{Port: 2375, Service: "docker"}}}
	m := &Monitor{Root: root}
	now := time.Unix(1_800_000_000, 0)
	got := m.Check(r, now)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	db, dk := got[0], got[1]
	if db.Type != proto.EventDBPublicAccess || db.Connections != 2 || strings.Join(db.Sources, ",") != "1.2.3.x" || db.Service != "redis" {
		t.Errorf("db: %+v", db)
	}
	if dk.Type != proto.EventDockerAPIAccess || dk.Connections != 1 || dk.Sources[0] != "10.0.0.x" {
		t.Errorf("docker: %+v", dk)
	}
	if again := m.Check(r, now.Add(30*time.Minute)); len(again) != 0 {
		t.Errorf("within the hour: %+v", again)
	}
	if later := m.Check(r, now.Add(61*time.Minute)); len(later) != 2 {
		t.Errorf("next hour: %+v", later)
	}
	if none := (&Monitor{Root: root}).Check(&Result{}, now); none != nil {
		t.Errorf("nothing exposed: %+v", none)
	}
}

func TestFullScanAndScheduler(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ssh/sshd_config": "PasswordAuthentication yes\n",
		"proc/net/tcp":        tcpHeader + tcpLine("00000000:18EB", "00000000:0000", StateListen),
	})
	out := make(chan Result, 4)
	s := &Scheduler{Scanner: &Scanner{Root: root, SSHD: noSSHD}, Out: out, Log: discardLog(), Debounce: 50 * time.Millisecond, PortsEvery: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	first := <-out
	if !first.SSH.Password || len(first.DB) != 1 || first.FullAt.IsZero() {
		t.Fatalf("first scan: %+v", first)
	}
	// Turning passwords off is seen shortly after the file changes.
	if err := os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config"), []byte("PasswordAuthentication no\nKbdInteractiveAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-out:
		if r.SSH.Password {
			t.Fatalf("after the change: %+v", r.SSH)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no rescan after /etc/ssh changed")
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The user manual must name what the code reads (spec v1.1 delta 10.6).
func TestDocsListWhatIsRead(t *testing.T) {
	for _, doc := range []string{"../../docs/risk-scan.md", "../../docs/risk-scan.zh-CN.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, src := range Sources {
			if !strings.Contains(text, src) {
				t.Errorf("%s does not mention %q", doc, src)
			}
		}
		for port, svc := range DBPorts {
			if !strings.Contains(strings.ToLower(text), svc) || !strings.Contains(text, strconv.Itoa(port)) {
				t.Errorf("%s does not list %s (%d)", doc, svc, port)
			}
		}
		if !regexp.MustCompile(`(?m)^\s*riskscan: false`).MatchString(text) {
			t.Errorf("%s does not show how to turn the scan off", doc)
		}
	}
}

package systemd

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/xyfu/xnux-agent/internal/raw"
)

// startBus runs a private dbus-daemon; systemd is played by the test.
func startBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(addr)
}

type manager struct{ units []listedUnit }

func (m *manager) Subscribe() *dbus.Error                 { return nil }
func (m *manager) ListUnits() ([]listedUnit, *dbus.Error) { return m.units, nil }

type fakeSystemd struct {
	t    *testing.T
	conn *dbus.Conn
}

func newFake(t *testing.T, addr string, units ...listedUnit) *fakeSystemd {
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.Export(&manager{units: units}, managerPath, managerIf); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(dest, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", reply, err)
	}
	return &fakeSystemd{t: t, conn: conn}
}

func running(name string) listedUnit {
	return listedUnit{Name: name, LoadState: "loaded", ActiveState: "active", SubState: "running",
		Path: unitPath(name), JobPath: "/"}
}

func unitPath(name string) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/systemd1/unit/" + strings.NewReplacer(".", "_2e", "-", "_2d").Replace(name))
}

// unit exports the Unit and Service properties of name.
func (f *fakeSystemd) unit(name string, service map[string]any) {
	sp := map[string]*prop.Prop{}
	for k, v := range service {
		sp[k] = &prop.Prop{Value: v, Emit: prop.EmitFalse}
	}
	_, err := prop.Export(f.conn, unitPath(name), prop.Map{
		unitIf:    {"Id": {Value: name, Emit: prop.EmitFalse}},
		serviceIf: sp,
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSystemd) state(name, active, sub string) {
	err := f.conn.Emit(unitPath(name), propsIf+".PropertiesChanged", unitIf,
		map[string]dbus.Variant{"ActiveState": dbus.MakeVariant(active), "SubState": dbus.MakeVariant(sub)}, []string{})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSystemd) job(id uint32, unit, result string) {
	err := f.conn.Emit(managerPath, managerIf+".JobRemoved", id, dbus.ObjectPath("/org/freedesktop/systemd1/job/1"), unit, result)
	if err != nil {
		f.t.Fatal(err)
	}
}

func next(t *testing.T, ch chan raw.Record) raw.Record {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no record")
	}
	return raw.Record{}
}

func TestWatcher(t *testing.T) {
	addr := startBus(t)
	f := newFake(t, addr,
		running("app.service"),
		running("worker.service"),
		running("apt-daily.service"),
		running("dbus.socket"),
	)
	f.unit("app.service", map[string]any{"Result": "core-dump", "ExecMainCode": int32(3), "ExecMainStatus": int32(11),
		"NRestarts": uint32(0), "MemoryPeak": uint64(50 << 20)})
	f.unit("worker.service", map[string]any{"Result": "signal", "ExecMainCode": int32(2), "ExecMainStatus": int32(9),
		"NRestarts": uint32(3), "MemoryPeak": ^uint64(0)})
	f.unit("apt-daily.service", map[string]any{"Result": "exit-code"})
	f.unit("late.service", map[string]any{"Result": "exit-code", "ExecMainCode": int32(1), "ExecMainStatus": int32(2)})

	out := make(chan raw.Record, 16)
	w := &Watcher{Address: addr, Ignore: []string{"apt-daily.service"}, Out: out, RecoverAfter: 300 * time.Millisecond,
		LogTail: func(_ context.Context, unit string) []string { return []string{unit + ": boom"} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(200 * time.Millisecond) // subscribed and listed

	// F4-1 acceptance: a SIGSEGV crash is reported within a second with the signal name.
	start := time.Now()
	f.state("app.service", "failed", "failed")
	r := next(t, out)
	took := time.Since(start)
	d := r.Data
	if r.Kind != "service_failed" || r.Key != "app.service" || d["signal"] != "SIGSEGV" || d["result"] != "core-dump" ||
		d["restarting"] != false || d["memory_peak_mb"] != int64(50) || d["exit_code"] != nil ||
		len(d["log_tail"].([]string)) != 1 || took > time.Second {
		t.Fatalf("crash (%v): %+v", took, r)
	}

	// Restart=always: running → auto-restart is a crash too; SIGKILL; no memory accounting.
	f.state("worker.service", "activating", "auto-restart")
	r = next(t, out)
	if r.Kind != "service_failed" || r.Data["restarting"] != true || r.Data["signal"] != "SIGKILL" ||
		r.Data["n_restarts"] != uint64(3) || r.Data["memory_peak_mb"] != nil {
		t.Fatalf("auto-restart: %+v", r)
	}

	// Back to active and staying there: recovered.
	f.state("worker.service", "active", "running")
	r = next(t, out)
	if r.Kind != "service_recovered" || r.Data["unit"] != "worker.service" {
		t.Fatalf("recovery: %+v", r)
	}
	// Active only briefly: no recovery.
	f.state("app.service", "active", "running")
	f.state("app.service", "deactivating", "stop-sigterm")
	select {
	case r := <-out:
		t.Fatalf("recovered while flapping: %+v", r)
	case <-time.After(600 * time.Millisecond):
	}

	// A unit loaded after start is looked up by path; exit codes stay codes.
	f.state("late.service", "failed", "failed")
	r = next(t, out)
	if r.Kind != "service_failed" || r.Key != "late.service" || r.Data["exit_code"] != int64(2) {
		t.Fatalf("late unit: %+v", r)
	}

	// Failed start job.
	f.job(7, "db.service", "timeout")
	r = next(t, out)
	if r.Kind != "service_start_failed" || r.Data["job_result"] != "timeout" {
		t.Fatalf("job: %+v", r)
	}

	// Ignored units and non-services are silent.
	f.state("apt-daily.service", "failed", "failed")
	f.state("dbus.socket", "failed", "failed")
	f.job(8, "apt-daily.service", "failed")
	select {
	case r := <-out:
		t.Fatalf("ignored unit reported: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

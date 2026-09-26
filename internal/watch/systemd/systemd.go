// Package systemd watches unit state changes over D-Bus and reports service
// crashes, failed starts and recoveries (spec A3.1).
package systemd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/raw"
)

const (
	dest        = "org.freedesktop.systemd1"
	managerPath = dbus.ObjectPath("/org/freedesktop/systemd1")
	managerIf   = "org.freedesktop.systemd1.Manager"
	unitIf      = "org.freedesktop.systemd1.Unit"
	serviceIf   = "org.freedesktop.systemd1.Service"
	propsIf     = "org.freedesktop.DBus.Properties"

	// RecoverAfter is how long a unit must stay active after a failure
	// before service_recovered is reported.
	RecoverAfter = 60 * time.Second

	tailLines   = "50"
	tailTimeout = 3 * time.Second
	maxTailLine = 512
)

// Available reports whether systemd is the init system.
func Available() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// Watcher follows .service units.
type Watcher struct {
	// Address of the bus; empty means the system bus.
	Address string
	Ignore  []string
	Out     chan<- raw.Record
	Now     func() time.Time
	// LogTail returns the unit's recent log lines; nil runs journalctl.
	LogTail      func(ctx context.Context, unit string) []string
	RecoverAfter time.Duration
}

type unitState struct {
	name, active, sub string
	down              bool      // a failure was reported and not yet recovered
	downAt            time.Time // when it went down
	activeAt          time.Time // when it last became active
}

type listedUnit struct {
	Name, Description, LoadState, ActiveState, SubState, Following string
	Path                                                           dbus.ObjectPath
	JobID                                                          uint32
	JobType                                                        string
	JobPath                                                        dbus.ObjectPath
}

type watch struct {
	w       *Watcher
	ctx     context.Context
	conn    *dbus.Conn
	units   map[dbus.ObjectPath]*unitState
	byName  map[string]*unitState
	recover chan dbus.ObjectPath
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) connect() (*dbus.Conn, error) {
	if w.Address == "" {
		return dbus.ConnectSystemBus()
	}
	return dbus.Connect(w.Address)
}

// Run subscribes and handles signals until ctx ends or the bus goes away.
func (w *Watcher) Run(ctx context.Context) error {
	conn, err := w.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	sigs := make(chan *dbus.Signal, 256)
	conn.Signal(sigs)
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(propsIf), dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchPathNamespace("/org/freedesktop/systemd1/unit")); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(managerIf), dbus.WithMatchMember("JobRemoved")); err != nil {
		return err
	}
	mgr := conn.Object(dest, managerPath)
	if err := mgr.CallWithContext(ctx, managerIf+".Subscribe", 0).Err; err != nil {
		return err
	}
	x := &watch{w: w, ctx: ctx, conn: conn, units: map[dbus.ObjectPath]*unitState{},
		byName: map[string]*unitState{}, recover: make(chan dbus.ObjectPath, 16)}
	// Rebuild the state table on every (re)connect (spec A3.1).
	var listed []listedUnit
	if err := mgr.CallWithContext(ctx, managerIf+".ListUnits", 0).Store(&listed); err != nil {
		return err
	}
	for _, u := range listed {
		if x.wanted(u.Name) {
			x.add(u.Path, u.Name, u.ActiveState, u.SubState)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case s, ok := <-sigs:
			if !ok {
				return errors.New("D-Bus connection closed")
			}
			x.signal(s)
		case p := <-x.recover:
			x.checkRecovered(p)
		}
	}
}

func (x *watch) wanted(name string) bool {
	if !strings.HasSuffix(name, ".service") {
		return false
	}
	for _, ig := range x.w.Ignore {
		if ig == name {
			return false
		}
	}
	return true
}

func (x *watch) add(p dbus.ObjectPath, name, active, sub string) *unitState {
	u := &unitState{name: name, active: active, sub: sub}
	if active == "active" {
		u.activeAt = x.w.now()
	}
	x.units[p] = u
	x.byName[name] = u
	return u
}

func (x *watch) signal(s *dbus.Signal) {
	switch s.Name {
	case propsIf + ".PropertiesChanged":
		x.propertiesChanged(s)
	case managerIf + ".JobRemoved":
		x.jobRemoved(s)
	}
}

// lookup finds or loads the unit behind an object path; units that did
// not exist at ListUnits time are fetched on first sight.
func (x *watch) lookup(p dbus.ObjectPath) *unitState {
	if u, ok := x.units[p]; ok {
		return u
	}
	v, err := x.conn.Object(dest, p).GetProperty(unitIf + ".Id")
	if err != nil {
		return nil
	}
	name, _ := v.Value().(string)
	if !x.wanted(name) {
		x.units[p] = nil // remember uninteresting paths
		return nil
	}
	return x.add(p, name, "", "")
}

func (x *watch) propertiesChanged(s *dbus.Signal) {
	if len(s.Body) < 2 {
		return
	}
	if iface, _ := s.Body[0].(string); iface != unitIf {
		return
	}
	changed, _ := s.Body[1].(map[string]dbus.Variant)
	u := x.lookup(s.Path)
	if u == nil {
		return
	}
	active, sub := u.active, u.sub
	if v, ok := changed["ActiveState"]; ok {
		active, _ = v.Value().(string)
	}
	if v, ok := changed["SubState"]; ok {
		sub, _ = v.Value().(string)
	}
	prevActive, prevSub := u.active, u.sub
	u.active, u.sub = active, sub
	now := x.w.now()

	switch {
	case active == "failed" && prevActive != "failed":
		x.failed(s.Path, u, false, now)
	case sub == "auto-restart" && prevSub != "auto-restart" &&
		(prevSub == "running" || prevActive == "active" || prevActive == "deactivating"):
		// Restart= units rarely reach "failed": the crash shows up as the
		// auto-restart sub-state instead (spec A3.1).
		x.failed(s.Path, u, true, now)
	}
	if active == "active" && prevActive != "active" {
		u.activeAt = now
		if u.down {
			x.scheduleRecovery(s.Path)
		}
	} else if active != "active" {
		u.activeAt = time.Time{}
	}
}

func (x *watch) jobRemoved(s *dbus.Signal) {
	if len(s.Body) < 4 {
		return
	}
	name, _ := s.Body[2].(string)
	result, _ := s.Body[3].(string)
	if result != "failed" && result != "timeout" && result != "dependency" {
		return
	}
	if !x.wanted(name) {
		return
	}
	now := x.w.now()
	if u := x.byName[name]; u != nil && !u.down {
		u.down, u.downAt = true, now
	}
	x.send(raw.Record{Kind: proto.EventServiceStartFailed, TS: now, Key: name,
		Data: map[string]any{"unit": name, "job_result": result, "log_tail": x.tail(name)}})
}

func (x *watch) failed(p dbus.ObjectPath, u *unitState, restarting bool, now time.Time) {
	if !u.down {
		u.down, u.downAt = true, now
	}
	d := map[string]any{"unit": u.name, "restarting": restarting, "n_restarts": 0}
	props := map[string]dbus.Variant{}
	_ = x.conn.Object(dest, p).CallWithContext(x.ctx, propsIf+".GetAll", 0, serviceIf).Store(&props)
	if v, ok := props["Result"]; ok {
		d["result"], _ = v.Value().(string)
	}
	if d["result"] == nil || d["result"] == "" {
		d["result"] = "unknown"
	}
	if n, ok := uintProp(props, "NRestarts"); ok {
		d["n_restarts"] = n
	}
	code, cok := intProp(props, "ExecMainCode")
	status, sok := intProp(props, "ExecMainStatus")
	if cok && sok {
		switch code {
		case 1: // CLD_EXITED
			d["exit_code"] = status
		case 2, 3: // CLD_KILLED, CLD_DUMPED
			d["signal"] = signalName(status)
		}
	}
	if peak, ok := uintProp(props, "MemoryPeak"); ok && peak != ^uint64(0) {
		d["memory_peak_mb"] = int64(peak >> 20)
	}
	d["log_tail"] = x.tail(u.name)
	x.send(raw.Record{Kind: proto.EventServiceFailed, TS: now, Key: u.name, Data: d})
}

func signalName(n int64) string {
	if name := unix.SignalName(syscall.Signal(n)); name != "" {
		return name
	}
	return "SIG" + strconv.FormatInt(n, 10)
}

func intProp(m map[string]dbus.Variant, k string) (int64, bool) {
	v, ok := m[k]
	if !ok {
		return 0, false
	}
	switch t := v.Value().(type) {
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint32:
		return int64(t), true
	}
	return 0, false
}

func uintProp(m map[string]dbus.Variant, k string) (uint64, bool) {
	v, ok := m[k]
	if !ok {
		return 0, false
	}
	switch t := v.Value().(type) {
	case uint32:
		return uint64(t), true
	case uint64:
		return t, true
	}
	return 0, false
}

func (x *watch) scheduleRecovery(p dbus.ObjectPath) {
	after := x.w.RecoverAfter
	if after == 0 {
		after = RecoverAfter
	}
	time.AfterFunc(after, func() {
		select {
		case x.recover <- p:
		case <-x.ctx.Done():
		}
	})
}

func (x *watch) checkRecovered(p dbus.ObjectPath) {
	u := x.units[p]
	after := x.w.RecoverAfter
	if after == 0 {
		after = RecoverAfter
	}
	now := x.w.now()
	if u == nil || !u.down || u.active != "active" || u.activeAt.IsZero() || now.Sub(u.activeAt) < after-time.Second {
		return
	}
	u.down = false
	x.send(raw.Record{Kind: proto.EventServiceRecovered, TS: now, Key: u.name,
		Data: map[string]any{"unit": u.name, "down_seconds": int64(u.activeAt.Sub(u.downAt).Seconds())}})
}

func (x *watch) send(r raw.Record) {
	select {
	case x.w.Out <- r:
	case <-x.ctx.Done():
	}
}

func (x *watch) tail(unit string) []string {
	ctx, cancel := context.WithTimeout(x.ctx, tailTimeout)
	defer cancel()
	if x.w.LogTail != nil {
		return x.w.LogTail(ctx, unit)
	}
	return JournalTail(ctx, unit)
}

// JournalTail runs journalctl once for the unit's last 50 lines of the last
// 10 minutes (one of the two external commands the agent runs, and only
// when an event happens).
func JournalTail(ctx context.Context, unit string) []string {
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", tailLines, "-o", "cat", "--no-pager", "--since=-10min") //nolint:gosec // unit name comes from systemd
	cmd.Env = []string{"LANG=C", "SYSTEMD_COLORS=0", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return []string{}
	}
	lines := []string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.TrimSpace(l) == "" {
			continue
		}
		if len(l) > maxTailLine {
			l = l[:maxTailLine]
		}
		lines = append(lines, l)
	}
	return lines
}

// Package app wires the agent together: config, collectors, redaction,
// batching and either the sender or the dry-run printer.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/alog"
	"github.com/xyfu/xnux-agent/internal/batch"
	"github.com/xyfu/xnux-agent/internal/collect"
	"github.com/xyfu/xnux-agent/internal/config"
	"github.com/xyfu/xnux-agent/internal/dryrun"
	"github.com/xyfu/xnux-agent/internal/ipc"
	"github.com/xyfu/xnux-agent/internal/localstore"
	"github.com/xyfu/xnux-agent/internal/mirror"
	"github.com/xyfu/xnux-agent/internal/procfs"
	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/rules"
	"github.com/xyfu/xnux-agent/internal/sender"
	"github.com/xyfu/xnux-agent/internal/snapshot"
	"github.com/xyfu/xnux-agent/internal/spool"
	"github.com/xyfu/xnux-agent/internal/state"
	"github.com/xyfu/xnux-agent/internal/watch"
	"github.com/xyfu/xnux-agent/internal/watch/authlog"
	"github.com/xyfu/xnux-agent/internal/watch/kmsg"
	"github.com/xyfu/xnux-agent/internal/watch/procscan"
	"github.com/xyfu/xnux-agent/internal/watch/systemd"
)

const (
	heartbeatAfter = 60 * time.Second
	saveEvery      = 10 * time.Second
	hostEvery      = 6 * time.Hour
	shutdownDrain  = 5 * time.Second
	onceDrain      = 30 * time.Second
	// eventGather collects events arriving together into one payload (spec A5.2).
	eventGather = time.Second
)

// Options select the run mode and the filesystem layout.
type Options struct {
	ConfigPath  string
	DryRun      bool
	Once        bool
	PrintConfig bool
	Check       bool
	Version     string

	Stdout, Stderr io.Writer
	StdoutTTY      bool

	// Defaults: /var/lib/xnux, /var/log/xnux and "/" (spec A1).
	StateDir string
	LogDir   string
	Root     string
	// Socket is where the xnux CLI reaches the daemon (spec v1.1 delta 2);
	// default /run/xnux/agent.sock.
	Socket string
}

func (o *Options) defaults() {
	if o.StateDir == "" {
		o.StateDir = "/var/lib/xnux"
	}
	if o.LogDir == "" {
		o.LogDir = "/var/log/xnux"
	}
	if o.Root == "" {
		o.Root = "/"
	}
	if o.Socket == "" {
		o.Socket = ipc.DefaultPath
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// Run executes the selected mode until ctx is cancelled (or one round, with
// Once).
func Run(ctx context.Context, o Options) error {
	o.defaults()
	cfg, warns, err := config.Load(o.ConfigPath)
	if err != nil {
		return err
	}
	if o.PrintConfig {
		_, err := fmt.Fprint(o.Stdout, cfg.Printable())
		return err
	}

	var st *state.Store
	if !o.Check {
		st, err = state.Open(filepath.Join(o.StateDir, "state.json"))
		if err != nil {
			if !o.DryRun {
				return err
			}
			st = state.Memory() // dry-run may run without access to the state dir
		}
	}
	var growth map[string][][2]int64
	if st != nil {
		st.View(func(d *state.Data) { growth = d.DiskGrowth })
	}
	sampler, err := collect.New(collect.Options{Root: o.Root, DiskGrowth: growth,
		Net: collect.NetFilter{Include: cfg.Network.Include, Exclude: cfg.Network.Exclude}})
	if err != nil {
		return err
	}
	defer sampler.Close()
	host := sampler.Host()

	bopts := sanitize.Options{MaskEmail: cfg.Sanitize.MaskEmail, ExtraPatterns: cfg.Sanitize.ExtraPatterns}
	if cfg.HideHostname {
		bopts.HideHostname = host.Hostname
	}
	barrier, err := sanitize.New(bopts)
	if err != nil {
		return err
	}

	// Interactive modes log to stderr; the daemon logs to agent.log
	// (5 MB x 3). Either way every line passes the barrier.
	logw := o.Stderr
	if !o.DryRun && !o.Once && !o.Check {
		rf, err := alog.OpenRotating(filepath.Join(o.LogDir, "agent.log"), 5<<20, 2)
		if err != nil {
			return err
		}
		defer rf.Close()
		logw = rf
	}
	log := alog.New(logw, barrier, slog.LevelInfo)
	for _, w := range warns {
		log.Warn(w)
	}

	if o.Check {
		return check(ctx, o, cfg, sampler)
	}

	a := &agent{o: o, cfg: cfg, log: log, sampler: sampler, barrier: barrier, host: host, st: st}
	return a.run(ctx)
}

type agent struct {
	o       Options
	cfg     *config.Config
	log     *slog.Logger
	sampler *collect.Sampler
	barrier *sanitize.Barrier
	host    proto.Host

	st         *state.Store
	batcher    *batch.Batcher
	sender     *sender.Sender
	stopSender context.CancelFunc
	senderDone chan struct{}
	spool      *spool.Spool
	mirror     *mirror.Mirror
	emit       func(sanitize.SanitizedPayload)
	lastEmit   time.Time
	sentHost   proto.Host

	// The local black box (spec v1.1 delta 2), daemon mode only.
	local   *localstore.EventLog
	mring   *localstore.Ring
	reload  chan chan error
	started time.Time
	view    atomic.Pointer[view]
	localMu sync.Mutex
	shared  localState
	netMu   sync.Mutex
	netr    *collect.NetReader // "xnux top" reads the counters itself, every 2 s

	sampleErrors int

	engine   *rules.Engine
	ring     *snapshot.Ring
	capturer *snapshot.Capturer
	records  chan raw.Record
	snapped  chan proto.Event
	watchErr watch.Errors
	kmsgW    *kmsg.Watcher
	tailer   *authlog.Tailer
	scanner  *procscan.Scanner
	eventT   *time.Timer
	dueT     *time.Timer
}

// Collector availability (spec A1 start-up): a collector that is enabled
// but cannot work here is switched off and left out of capabilities.
func (a *agent) capabilities() []string {
	c := a.cfg.Collectors
	caps := []string{}
	if c.Metrics {
		caps = append(caps, "metrics")
		if a.sampler.HasTemps() {
			caps = append(caps, "temps")
		}
	}
	if c.Systemd && a.exists("run/systemd/system") {
		caps = append(caps, "systemd")
	}
	if c.Kmsg && kmsg.Available(filepath.Join(a.o.Root, "dev/kmsg")) {
		caps = append(caps, "kmsg")
	}
	if mode, _ := authlog.Source(a.o.Root); c.Authlog && mode != "" {
		caps = append(caps, "authlog")
	}
	if c.Procscan && a.exists("proc/self") {
		caps = append(caps, "procscan")
	}
	return caps
}

func (a *agent) exists(p string) bool {
	_, err := os.Stat(filepath.Join(a.o.Root, p))
	return err == nil
}

func (a *agent) run(ctx context.Context) error {
	a.host.Capabilities = a.capabilities()

	var err error
	a.engine, err = rules.New(rules.Options{Security: a.cfg.Security})
	if err != nil {
		return err
	}
	a.ring = snapshot.NewRing(a.cfg.IntervalSeconds)
	a.capturer = &snapshot.Capturer{Ring: a.ring, Proc: procfs.FS{Root: filepath.Join(a.o.Root, "proc")}}
	a.records = make(chan raw.Record, 256)
	a.snapped = make(chan proto.Event, 64)

	a.newBatcher()

	if a.o.DryRun {
		summary := a.o.Stderr
		if a.o.StdoutTTY {
			summary = a.o.Stdout
		}
		pr, err := dryrun.New(a.o.Stdout, summary, a.o.StdoutTTY)
		if err != nil {
			return err
		}
		a.emit = func(p sanitize.SanitizedPayload) {
			if err := pr.Print(p); err != nil {
				a.log.Error("dry-run print failed", "err", err)
			}
		}
	} else if err := a.connect(); err != nil {
		return err
	}
	defer a.disconnect(0)

	if a.o.Once {
		return a.once(ctx)
	}
	return a.loop(ctx)
}

// newBatcher builds payloads for the current token (its hash is part of
// the machine fingerprint).
func (a *agent) newBatcher() {
	a.batcher = batch.New(batch.Options{
		Barrier:      a.barrier,
		NextSeq:      a.st.NextSeq,
		AgentVersion: a.o.Version,
		MachineFP:    machineFP(a.o.Root, a.cfg.Token, a.host.Hostname),
		Diag:         a.diag,
	})
}

// connect starts the sender, unless the agent is standalone: then payloads
// are still built (so "xnux payload --next" can show them) but nothing is
// sent and no connection is ever opened (spec v1.1 delta 2).
func (a *agent) connect() error {
	if a.cfg.Standalone() {
		a.emit = a.keepNext
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	if err := a.startSender(ctx, done); err != nil {
		cancel()
		return err
	}
	a.stopSender, a.senderDone = cancel, done
	return nil
}

// disconnect stops the sender, giving queued payloads up to drain.
func (a *agent) disconnect(drain time.Duration) {
	if a.sender == nil {
		return
	}
	a.stopSender()
	<-a.senderDone
	if drain > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), drain)
		a.sender.Drain(ctx)
		cancel()
	}
	a.sender, a.stopSender, a.senderDone = nil, nil, nil
}

func (a *agent) startSender(ctx context.Context, done chan struct{}) error {
	var err error
	if a.spool == nil {
		if a.spool, err = spool.Open(filepath.Join(a.o.StateDir, "spool"), spool.DefaultMax, spool.DefaultMaxEvents); err != nil {
			return err
		}
	}
	if a.mirror, err = mirror.New(a.o.LogDir, a.cfg.MirrorHistory); err != nil {
		return err
	}
	mir := a.mirror
	a.sender, err = sender.New(sender.Options{
		Endpoint: a.cfg.Endpoint, Token: a.cfg.Token, CAFile: a.cfg.TLS.CAFile, Proxy: a.cfg.Proxy,
		Version: a.o.Version, Barrier: a.barrier, Spool: a.spool, Log: a.log,
		OnAccepted: func(p sanitize.SanitizedPayload) {
			if err := mir.Write(p); err != nil {
				a.log.Warn("mirror write failed", "err", err)
			}
		},
	})
	if err != nil {
		return err
	}
	snd := a.sender
	a.emit = func(p sanitize.SanitizedPayload) {
		a.keepNext(p)
		snd.Enqueue(p)
	}
	go func() {
		snd.Run(ctx)
		close(done)
	}()
	return nil
}

// loop is the daemon: one sampling ticker, periodic flush, heartbeat and
// state saves; everything else is idle (spec A1: no busy loops).
func (a *agent) loop(ctx context.Context) error {
	a.log.Info("agent started", "version", a.o.Version, "dry_run", a.o.DryRun, "standalone", a.cfg.Standalone(),
		"capabilities", a.host.Capabilities)
	a.started = time.Now()
	if !a.o.DryRun {
		closeLocal, err := a.openLocal(ctx)
		if err != nil {
			return err
		}
		defer closeLocal()
	}
	interval := time.Duration(a.cfg.IntervalSeconds) * time.Second
	sampleT := time.NewTicker(interval)
	flushT := time.NewTicker(time.Duration(a.cfg.FlushSeconds) * time.Second)
	hbT := time.NewTicker(heartbeatAfter)
	saveT := time.NewTicker(saveEvery)
	hostT := time.NewTicker(hostEvery)
	defer func() {
		for _, t := range []*time.Ticker{sampleT, flushT, hbT, saveT, hostT} {
			t.Stop()
		}
	}()

	a.sampler.Sample(time.Now()) // CPU baseline
	a.refreshHost(true)
	a.flush(false) // registration payload with host info (spec A1)

	wctx, stopWatchers := context.WithCancel(ctx)
	defer stopWatchers()
	a.startWatchers(wctx)
	a.eventT = stoppedTimer()
	a.dueT = stoppedTimer()
	defer a.eventT.Stop()
	defer a.dueT.Stop()

	for {
		select {
		case <-ctx.Done():
			stopWatchers()
			return a.shutdown()
		case reply := <-a.reload:
			reply <- a.applyReload()
		case r := <-a.records:
			a.events(a.engine.Record(r))
		case ev := <-a.snapped:
			a.addEvent(ev)
		case <-a.eventT.C:
			a.flush(false)
		case <-a.dueT.C:
			a.events(a.engine.Due())
			a.armDue()
		case t := <-sampleT.C:
			a.sample(t)
		case <-flushT.C:
			a.refreshHost(false)
			a.flush(false)
		case <-hbT.C:
			if time.Since(a.lastEmit) >= heartbeatAfter {
				a.flush(true)
			}
		case <-saveT.C:
			a.save()
		case <-hostT.C:
			a.refreshHost(true)
		}
	}
}

func (a *agent) once(ctx context.Context) error {
	a.sampler.Sample(time.Now())
	t := time.NewTimer(time.Second) // CPU needs two readings
	select {
	case <-ctx.Done():
		t.Stop()
		return ctx.Err()
	case now := <-t.C:
		a.sample(now)
	}
	a.refreshHost(true)
	a.flush(false)
	if a.sender == nil {
		return nil
	}
	snd := a.sender
	a.disconnect(onceDrain)
	a.save()
	if n := snd.Queued(); n > 0 {
		return fmt.Errorf("%d payload(s) not delivered, kept in the spool", n)
	}
	return nil
}

func (a *agent) shutdown() error {
	a.log.Info("shutting down")
	a.flush(false)
	a.disconnect(shutdownDrain)
	a.save()
	return nil
}

func (a *agent) sample(t time.Time) {
	if !a.cfg.Collectors.Metrics {
		return
	}
	m, ok := a.sampler.Sample(t) // the exact time: rates divide by it
	if !ok {
		a.sampleErrors++
		return
	}
	if a.ring != nil {
		a.ring.Add(m)
	}
	a.recordMetric(m)
	if a.engine != nil {
		a.events(a.engine.Metric(m))
	}
	if a.batcher.AddMetric(m) {
		a.flush(false)
	}
}

func stoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}

// startWatchers launches the enabled event collectors under the supervisor
// (spec A3); each failure restarts only that collector.
func (a *agent) startWatchers(ctx context.Context) {
	caps := map[string]bool{}
	for _, c := range a.host.Capabilities {
		caps[c] = true
	}
	start := func(name string, fn func(context.Context) error) {
		go watch.Supervise(ctx, name, a.log, &a.watchErr, fn)
	}
	if caps["systemd"] {
		w := &systemd.Watcher{Ignore: a.cfg.Systemd.IgnoreUnits, Out: a.records}
		start("systemd", w.Run)
	}
	if caps["kmsg"] {
		a.kmsgW = &kmsg.Watcher{Path: filepath.Join(a.o.Root, "dev/kmsg"), Out: a.records}
		start("kmsg", a.kmsgW.Run)
	}
	if caps["authlog"] {
		switch mode, path := authlog.Source(a.o.Root); mode {
		case "file":
			var pos *state.AuthlogPos
			a.st.View(func(d *state.Data) {
				if d.Authlog != nil {
					p := *d.Authlog
					pos = &p
				}
			})
			a.tailer = &authlog.Tailer{Path: path, Start: pos, Out: a.records}
			start("authlog", a.tailer.Run)
		case "journal":
			j := &authlog.Journal{Out: a.records}
			start("authlog", j.Run)
		}
	}
	if caps["procscan"] {
		a.scanner = &procscan.Scanner{Proc: procfs.FS{Root: filepath.Join(a.o.Root, "proc")}, Root: a.o.Root,
			WhitelistExe: a.cfg.Procscan.WhitelistExe, WhitelistComm: a.cfg.Procscan.WhitelistComm, Out: a.records}
		a.st.View(func(d *state.Data) { a.scanner.SetStale(d.StaleBinaryReported) })
		start("procscan", a.scanner.Run)
	}
}

// events hands new events on: those that carry a snapshot wait for it in
// their own goroutine (at most 2 s), the rest go to the batcher now.
func (a *agent) events(evs []proto.Event) {
	for _, ev := range evs {
		if !rules.NeedsSnapshot(ev) {
			a.addEvent(ev)
			continue
		}
		go func(ev proto.Event) {
			ctx, cancel := context.WithTimeout(context.Background(), snapshot.Timeout)
			defer cancel()
			ev.Snapshot = a.capturer.Capture(ctx)
			a.snapped <- ev
		}(ev)
	}
	a.armDue()
}

// addEvent queues an event and flushes a second later, so events that
// arrive together share a payload (spec A5.2). P0 goes out at once.
func (a *agent) addEvent(ev proto.Event) {
	a.recordEvent(ev)
	a.batcher.AddEvent(ev)
	if a.eventT == nil { // --once: the final flush carries it
		return
	}
	if ev.Severity == proto.SeverityP0 {
		a.eventT.Stop()
		a.flush(false)
		return
	}
	if !a.eventT.Stop() {
		select { // drain a fired but unread timer
		case <-a.eventT.C:
		default:
		}
	}
	a.eventT.Reset(eventGather)
}

// armDue wakes the loop when a debounce window or burst silence ends.
func (a *agent) armDue() {
	if a.dueT == nil {
		return
	}
	next, ok := a.engine.NextDue()
	if !a.dueT.Stop() {
		select {
		case <-a.dueT.C:
		default:
		}
	}
	if ok {
		a.dueT.Reset(max(time.Until(next), 10*time.Millisecond))
	}
}

func (a *agent) flush(heartbeat bool) {
	ps, err := a.batcher.Flush(heartbeat)
	if err != nil {
		a.log.Error("building payload failed", "err", err)
		return
	}
	for _, p := range ps {
		a.emit(p)
	}
	if len(ps) > 0 {
		a.lastEmit = time.Now()
	}
}

// refreshHost attaches host info when forced (start, every 6 h) or when it
// changed (ignoring uptime).
func (a *agent) refreshHost(force bool) {
	h := a.sampler.Host()
	h.Capabilities = a.host.Capabilities
	if a.cfg.HideHostname {
		h.Hostname = "host"
	}
	p := a.sentHost
	changed := h.Hostname != p.Hostname || h.OS != p.OS || h.Kernel != p.Kernel || h.Arch != p.Arch ||
		h.Cores != p.Cores || h.Virt != p.Virt || !slices.Equal(h.Capabilities, p.Capabilities)
	if force || changed {
		a.batcher.SetHost(h)
		a.sentHost = h
	}
}

func (a *agent) save() {
	if a.o.DryRun {
		return // dry-run must not move seq or offsets (spec A8.1)
	}
	growth := a.sampler.DiskGrowth()
	a.st.Update(func(d *state.Data) {
		d.DiskGrowth = growth
		if a.tailer != nil {
			if p := a.tailer.Position(); p != nil {
				d.Authlog = p
			}
		}
		if a.scanner != nil {
			d.StaleBinaryReported = a.scanner.Stale()
		}
	})
	if err := a.st.Save(); err != nil {
		a.log.Error("saving state failed", "err", err)
	}
}

func (a *agent) diag() *proto.Diag {
	d := &proto.Diag{RSSMB: selfRSSMB()}
	if a.spool != nil {
		d.SpoolMB = float64(a.spool.Size()*10/(1<<20)) / 10
		// Payloads evicted from a full spool; nearly all are metric-only.
		d.DroppedMetrics = int64(a.spool.Evicted())
	}
	if a.kmsgW != nil {
		d.KmsgLost = a.kmsgW.Lost()
	}
	errs := a.watchErr.Snapshot()
	if a.sampleErrors > 0 {
		errs["metrics"] = a.sampleErrors
	}
	if len(errs) > 0 {
		d.CollectorErrors = errs
	}
	return d
}

// selfRSSMB reads VmRSS of this process.
func selfRSSMB() float64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			var kb float64
			if _, err := fmt.Sscan(strings.TrimSuffix(strings.TrimSpace(v), " kB"), &kb); err == nil {
				return float64(int(kb/1024*10)) / 10
			}
		}
	}
	return 0
}

// machineFP is sha256(machine-id + token), first 16 hex chars: stable per
// host and agent install, and not linkable to the raw machine-id across
// accounts (spec A2.7 salts with the server id; the token is the agent's
// equivalent of it). Without a machine-id the hostname stands in.
func machineFP(root, token, hostname string) string {
	id := ""
	for _, p := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(filepath.Join(root, p)); err == nil {
			if id = strings.TrimSpace(string(b)); id != "" {
				break
			}
		}
	}
	if id == "" {
		id = "hostname:" + hostname
	}
	h := sha256.Sum256([]byte(id + "\x00" + token))
	return hex.EncodeToString(h[:])[:16]
}

// check reports collector availability and endpoint reachability.
func check(ctx context.Context, o Options, cfg *config.Config, s *collect.Sampler) error {
	w := o.Stdout
	ok := true
	line := func(name, status string, good bool) {
		mark := "ok  "
		if !good {
			mark = "FAIL"
		}
		fmt.Fprintf(w, "%s %-10s %s\n", mark, name, status)
	}
	info := func(name, status string) { fmt.Fprintf(w, "--   %-10s %s\n", name, status) }

	fmt.Fprintf(w, "config     %s\n", o.ConfigPath)
	s.Sample(time.Now())
	t := time.NewTimer(200 * time.Millisecond)
	<-t.C
	if m, good := s.Sample(time.Now()); good {
		line("metrics", fmt.Sprintf("cpu %.1f%%, mem %.1f%%, %d disk(s)", m.CPU.TotalPct, m.Mem.UsedPct, len(m.Disks)), true)
		if m.Net != nil {
			info("network", fmt.Sprintf("down %s, up %s", collect.FormatBps(m.Net.RxBps), collect.FormatBps(m.Net.TxBps)))
		} else {
			info("network", "no interfaces counted (see network.include / network.exclude)")
		}
	} else {
		line("metrics", "cannot read /proc", false)
		ok = false
	}
	if s.HasTemps() {
		info("temps", "sensors found")
	} else {
		info("temps", "no sensors (module hidden)")
	}
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(o.Root, p)); return err == nil }
	col := cfg.Collectors
	info("systemd", enabled(col.Systemd, present(exists("run/systemd/system"))))
	kmsgState := "not readable (needs CAP_SYSLOG)"
	if kmsg.Available(filepath.Join(o.Root, "dev/kmsg")) {
		kmsgState = "readable"
	}
	info("kmsg", enabled(col.Kmsg, kmsgState))
	auth := "none (no auth.log, secure or journalctl)"
	switch mode, path := authlog.Source(o.Root); mode {
	case "file":
		auth = path
	case "journal":
		auth = "journalctl"
	}
	info("authlog", enabled(col.Authlog, auth))
	info("procscan", enabled(col.Procscan, present(exists("proc/self"))))

	if cfg.Standalone() {
		info("endpoint", "standalone: no token, nothing is sent (xnux connect to link)")
		if !ok {
			return errors.New("check failed")
		}
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	code, err := sender.Probe(pctx, sender.Options{Endpoint: cfg.Endpoint, CAFile: cfg.TLS.CAFile, Proxy: cfg.Proxy, Version: o.Version})
	if err != nil {
		line("endpoint", err.Error(), false)
		ok = false
	} else {
		line("endpoint", fmt.Sprintf("%s reachable (HTTP %d)", cfg.Endpoint, code), true)
	}
	if !ok {
		return errors.New("check failed")
	}
	return nil
}

func enabled(on bool, status string) string {
	if !on {
		return "disabled in config"
	}
	return status
}

func present(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

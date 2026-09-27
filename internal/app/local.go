package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/collect"
	"github.com/xyfu/xnux-agent/internal/config"
	"github.com/xyfu/xnux-agent/internal/ipc"
	"github.com/xyfu/xnux-agent/internal/localhealth"
	"github.com/xyfu/xnux-agent/internal/localstore"
	"github.com/xyfu/xnux-agent/internal/mirror"
)

// view is what the CLI may read while the loop runs.
type view struct {
	Standalone bool
	Endpoint   string
	Caps       []string
}

// localState is shared with the IPC goroutines, under agent.a.localMu.
type localState struct {
	latest  *proto.Metric
	next    []byte
	nextSeq uint64
}

// openLocal starts the black box and the CLI socket (spec v1.1 delta 2).
func (a *agent) openLocal(ctx context.Context) (func(), error) {
	var err error
	if a.local, err = localstore.OpenEvents(filepath.Join(a.o.StateDir, "events")); err != nil {
		return nil, err
	}
	if a.mring, err = localstore.OpenRing(filepath.Join(a.o.StateDir, "metrics.ring")); err != nil {
		_ = a.local.Close()
		return nil, err
	}
	// Without /proc/net/dev "xnux top" shows the sampled throughput.
	a.netr, _ = collect.OpenNet(filepath.Join(a.o.Root, "proc"),
		collect.NetFilter{Include: a.cfg.Network.Include, Exclude: a.cfg.Network.Exclude})
	a.reload = make(chan chan error)
	a.publishView()
	ictx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := ipc.Serve(ictx, a.o.Socket, a.handle); err != nil {
			a.log.Warn("CLI socket unavailable", "path", a.o.Socket, "err", err)
		}
	}()
	return func() {
		stop()
		<-done
		_ = a.mring.Close()
		_ = a.local.Close()
		a.netr.Close()
	}, nil
}

func (a *agent) publishView() {
	a.view.Store(&view{Standalone: a.cfg.Standalone(), Endpoint: a.cfg.Endpoint, Caps: a.host.Capabilities})
}

// recordMetric keeps the latest sample and the per-minute ring.
func (a *agent) recordMetric(m proto.Metric) {
	a.localMu.Lock()
	mc := m
	a.shared.latest = &mc
	a.localMu.Unlock()
	if a.mring != nil {
		if err := a.mring.Add(m); err != nil {
			a.log.Warn("metrics ring write failed", "err", err)
		}
	}
}

// recordEvent stores the event as seen here, before redaction: it never
// leaves the machine (files are 0600).
func (a *agent) recordEvent(ev proto.Event) {
	if a.local == nil {
		return
	}
	if err := a.local.Append(ev); err != nil {
		a.log.Warn("event log write failed", "err", err)
	}
}

// keepNext remembers the newest payload built, sent or not.
func (a *agent) keepNext(p sanitize.SanitizedPayload) {
	a.localMu.Lock()
	a.shared.next = p.Bytes()
	a.shared.nextSeq = p.Seq()
	a.localMu.Unlock()
}

// applyReload re-reads the config and connects or disconnects without a
// restart ("xnux connect" / "xnux disconnect"). Only the token and the
// connection settings change live; other settings apply on restart.
func (a *agent) applyReload() error {
	cfg, warns, err := config.Load(a.o.ConfigPath)
	if err != nil {
		return err
	}
	for _, w := range warns {
		a.log.Warn(w)
	}
	same := cfg.Token == a.cfg.Token && cfg.Endpoint == a.cfg.Endpoint && cfg.Proxy == a.cfg.Proxy && cfg.TLS == a.cfg.TLS
	if same {
		return nil
	}
	a.flush(false)
	a.disconnect(5 * time.Second)
	a.cfg.Token, a.cfg.Endpoint, a.cfg.Proxy, a.cfg.TLS, a.cfg.MirrorHistory = cfg.Token, cfg.Endpoint, cfg.Proxy, cfg.TLS, cfg.MirrorHistory
	a.newBatcher()
	if err := a.connect(); err != nil {
		a.log.Error("connecting failed; staying standalone", "err", err)
		a.cfg.Token = ""
		a.emit = a.keepNext
		a.publishView()
		return err
	}
	a.publishView()
	a.log.Info("configuration reloaded", "standalone", a.cfg.Standalone())
	// The registration payload goes out now, so the console sees the
	// server within seconds.
	a.refreshHost(true)
	a.flush(false)
	return nil
}

// handle answers the CLI.
func (a *agent) handle(ctx context.Context, cmd string, args json.RawMessage) (any, error) {
	switch cmd {
	case "status":
		return a.status(), nil
	case "top":
		return a.top(ctx), nil
	case "events":
		var in struct {
			SinceSeconds int64    `json:"since_s"`
			Types        []string `json:"types"`
			Severity     []string `json:"severity"`
			Limit        int      `json:"limit"`
		}
		_ = json.Unmarshal(args, &in)
		if in.SinceSeconds <= 0 {
			in.SinceSeconds = 86400
		}
		if in.Limit <= 0 || in.Limit > 1000 {
			in.Limit = 200
		}
		evs, err := a.local.Query(localstore.Filter{Since: time.Now().Add(-time.Duration(in.SinceSeconds) * time.Second),
			Types: in.Types, Severity: in.Severity, Limit: in.Limit})
		for i := range evs {
			evs[i].Snapshot = nil // the list stays small; "xnux event ID" has it
		}
		return evs, err
	case "event":
		var in struct{ ID string }
		_ = json.Unmarshal(args, &in)
		ev, ok, err := a.local.Get(in.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("no event %q in the last %d days", in.ID, localstore.RetentionDays)
		}
		before, _ := a.mring.Read(time.Unix(ev.TS, 0).Add(-10 * time.Minute))
		var curve []localstore.Minute
		for _, m := range before {
			if m.TS <= ev.TS {
				curve = append(curve, m)
			}
		}
		return map[string]any{"event": ev, "before": curve}, nil
	case "history":
		var in struct{ Hours int }
		_ = json.Unmarshal(args, &in)
		if in.Hours <= 0 || in.Hours > 24 {
			in.Hours = 24
		}
		return a.mring.Read(time.Now().Add(-time.Duration(in.Hours) * time.Hour))
	case "payload":
		var in struct{ Which string }
		_ = json.Unmarshal(args, &in)
		if in.Which == "last" {
			b, err := os.ReadFile(filepath.Join(a.o.LogDir, mirror.FileName))
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("nothing sent yet")
			}
			return json.RawMessage(b), err
		}
		a.localMu.Lock()
		next := a.shared.next
		a.localMu.Unlock()
		if next == nil {
			return nil, errors.New("no payload built yet; try again in a minute")
		}
		return json.RawMessage(next), nil
	case "reload":
		reply := make(chan error, 1)
		select {
		case a.reload <- reply:
		case <-time.After(10 * time.Second):
			return nil, errors.New("the agent is busy; try again")
		}
		select {
		case err := <-reply:
			if err != nil {
				return nil, err
			}
			return a.status(), nil
		case <-time.After(20 * time.Second):
			return nil, errors.New("reload timed out")
		}
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}

func (a *agent) health() localhealth.Result {
	now := time.Now()
	mins, _ := a.mring.Read(now.Add(-65 * time.Minute))
	evs, _ := a.local.Query(localstore.Filter{Since: now.Add(-24 * time.Hour)})
	a.localMu.Lock()
	latest := a.shared.latest
	a.localMu.Unlock()
	return localhealth.Score(mins, latest, evs, a.host.Cores, now)
}

func (a *agent) status() map[string]any {
	v := a.view.Load()
	mode := "connected"
	if v.Standalone {
		mode = "standalone"
	}
	out := map[string]any{
		"version": a.o.Version, "mode": mode, "started_at": a.started.Unix(), "uptime_s": int64(time.Since(a.started).Seconds()),
		"capabilities": v.Caps, "collector_errors": a.watchErr.Snapshot(),
		"host":    map[string]any{"hostname": a.host.Hostname, "os": a.host.OS, "kernel": a.host.Kernel, "arch": a.host.Arch, "cores": a.host.Cores},
		"storage": map[string]any{"events_bytes": a.local.Size(), "metrics_bytes": localstore.Slots * localstore.RecordSize, "dir": a.o.StateDir},
		"health":  a.health(),
		"rss_mb":  selfRSSMB(),
	}
	if !v.Standalone {
		out["endpoint"] = v.Endpoint
	}
	return out
}

func (a *agent) top(ctx context.Context) map[string]any {
	a.localMu.Lock()
	latest := a.shared.latest
	a.localMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	sn := a.capturer.Capture(cctx)
	cancel()
	evs, _ := a.local.Query(localstore.Filter{Limit: 5})
	for i := range evs {
		evs[i].Snapshot = nil
	}
	out := map[string]any{"metric": latest, "events": evs, "health": a.health(), "cores": a.host.Cores,
		"hostname": a.host.Hostname, "mode": map[bool]string{true: "standalone", false: "connected"}[a.view.Load().Standalone]}
	if sn != nil {
		out["top_cpu"], out["top_rss"] = sn.TopCPU, sn.TopRSS
	}
	if a.netr != nil {
		a.netMu.Lock()
		c, err := a.netr.Read(time.Now())
		a.netMu.Unlock()
		if err == nil {
			out["net"] = c
		}
	}
	return out
}

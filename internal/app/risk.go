package app

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/riskscan"
	"github.com/xyfu/xnux-agent/internal/rules"
)

// startRiskScan runs the local risk scan (spec v1.1 delta 10) when enabled;
// its results come back to the loop on a.riskCh. Disabled, the rules only
// report breaches, root password logins and the hourly summary.
func (a *agent) startRiskScan(ctx context.Context) {
	if !a.cfg.Collectors.Riskscan {
		a.engine.SetRisk(rules.Risk{})
		return
	}
	a.riskCh = make(chan riskscan.Result, 1)
	s := &riskscan.Scheduler{Scanner: a.riskScanner(), Out: a.riskCh, Log: a.log}
	go func() {
		if err := s.Run(ctx); err != nil {
			a.log.Warn("risk scan stopped", "err", err)
		}
	}()
}

func (a *agent) riskScanner() *riskscan.Scanner {
	return &riskscan.Scanner{Root: a.o.Root}
}

// scanOnce runs every check synchronously (--once and --dry-run --once).
func (a *agent) scanOnce(ctx context.Context) {
	if !a.cfg.Collectors.Riskscan {
		a.engine.SetRisk(rules.Risk{})
		return
	}
	a.applyRisk(a.riskScanner().Full(ctx))
}

func (a *agent) applyRisk(r riskscan.Result) {
	a.risk.Store(&r)
	a.engine.SetRisk(rules.Risk{Scan: true, SSHPassword: r.SSH.Password, RootPassword: r.SSH.RootPassword})
}

// checkAccess looks for outside connections to exposed ports at each metric
// tick (spec v1.1 delta 10.4).
func (a *agent) checkAccess(now time.Time) {
	r := a.risk.Load()
	if r == nil {
		return
	}
	if a.monitor == nil {
		a.monitor = &riskscan.Monitor{Root: filepath.Clean(a.o.Root)}
	}
	for _, ac := range a.monitor.Check(r, now) {
		a.events(a.engine.Access(ac.Type, ac.Port, ac.Service, ac.BindScope, ac.Connections, ac.Sources))
	}
}

// attachSummary adds the hourly SSH attack summary to the next payload once
// an hour has ended (only where the auth log is read).
func (a *agent) attachSummary() {
	if !slices.Contains(a.host.Capabilities, "authlog") {
		return
	}
	if s := a.engine.SecuritySummary(); s != nil {
		a.batcher.SetSecuritySummary(s)
	}
}

// riskStatus is the scan section of "xnux status": when it ran, what each
// check found and which reports are on because of it.
func (a *agent) riskStatus() map[string]any {
	if !a.cfg.Collectors.Riskscan {
		return map[string]any{"enabled": false, "reporting": alwaysReported}
	}
	r := a.risk.Load()
	if r == nil {
		return map[string]any{"enabled": true}
	}
	check := func(name string, found bool, detail any) map[string]any {
		return map[string]any{"name": name, "found": found, "detail": detail}
	}
	ssh := map[string]any{"present": r.SSH.Present, "source": r.SSH.Source}
	if r.SSH.Err != "" {
		ssh["error"] = r.SSH.Err
	}
	checks := []map[string]any{
		check(riskscan.CheckSSHPassword, r.SSH.Password, ssh),
		check(riskscan.CheckRootPassword, r.SSH.RootPassword, ssh),
		check(riskscan.CheckDBPublic, len(r.DB) > 0, r.DB),
		check(riskscan.CheckDockerAPI, len(r.Docker) > 0, r.Docker),
	}
	return map[string]any{"enabled": true, "at": r.At.Unix(), "full_at": r.FullAt.Unix(), "checks": checks,
		"reporting": reporting(r)}
}

// alwaysReported goes out whatever the scan finds.
var alwaysReported = []string{proto.EventSSHBreach, proto.EventSSHRootPasswordLogin, "security_summary"}

func reporting(r *riskscan.Result) []string {
	out := append([]string(nil), alwaysReported...)
	if r.SSH.Password {
		out = append(out, proto.EventSSHBruteforce, proto.EventSSHSpray)
	}
	if len(r.DB) > 0 {
		out = append(out, proto.EventDBPublicAccess)
	}
	if len(r.Docker) > 0 {
		out = append(out, proto.EventDockerAPIAccess)
	}
	return out
}

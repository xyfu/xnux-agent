package rules_test

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/config"
	"github.com/xyfu/xnux-agent/internal/raw"
	"github.com/xyfu/xnux-agent/internal/rules"
	"github.com/xyfu/xnux-agent/internal/watch/authlog"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newEngine(t *testing.T, c *clock) *rules.Engine {
	t.Helper()
	n := 0
	e, err := rules.New(rules.Options{Security: config.Default().Security, Now: c.now,
		NewID: func() string { n++; return fmt.Sprintf("01J%023d", n) }})
	if err != nil {
		t.Fatal(err)
	}
	// The risk scan found password login on: attacks are reported.
	e.SetRisk(rules.Risk{Scan: true, SSHPassword: true})
	return e
}

// F4-4 acceptance: a replayed auth.log is graded exactly as the spec says.
func TestReplayAuthLog(t *testing.T) {
	f, err := os.Open("testdata/auth.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := &clock{}
	e := newEngine(t, c)
	var got []proto.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ts := authlog.LineTime(sc.Text(), time.Now())
		c.t = ts
		for _, r := range authlog.Parse(sc.Text(), ts) {
			got = append(got, e.Record(r)...)
		}
	}
	want := []struct {
		typ, sev, key string
		check         func(d map[string]any) bool
	}{
		{proto.EventSSHBruteforce, "P2", "ssh_bruteforce", func(d map[string]any) bool {
			return d["fail_count"] == 20 && d["window_seconds"] == 300 && fmt.Sprint(d["top_users"]) == "[root]" &&
				d["source"] == "203.0.113.7" && d["source_count"] == 1
		}},
		{proto.EventSSHSpray, "P2", "ssh_spray", func(d map[string]any) bool { return d["user_count"] == 5 && d["source"] == "198.51.100.9" }},
		{proto.EventSSHBreach, "P0", "192.0.2.50", func(d map[string]any) bool {
			return d["prior_failures"] == 12 && d["user"] == "deploy" && d["method"] == "password"
		}},
		{proto.EventSSHRootPasswordLogin, "P1", "10.0.0.5", func(d map[string]any) bool { return d["source"] == "10.0.0.5" }},
		{proto.EventSudoSensitive, "P1", "alice:/bin/bash", func(d map[string]any) bool { return d["as_user"] == "root" && d["pwd"] == "/home/alice" }},
		{proto.EventSudoSensitive, "P1", "", func(d map[string]any) bool { return strings.Contains(d["command"].(string), "| bash") }},
		{proto.EventSudoAuthFail, "P2", "bob", func(d map[string]any) bool { return d["attempts"] == 3 }},
		{proto.EventUserCreated, "P1", "backdoor", func(d map[string]any) bool { return d["uid"] == 0 }},
		{proto.EventSuRoot, "P3", "alice", func(d map[string]any) bool { return d["by_user"] == "alice" }},
	}
	if len(got) != len(want) {
		for _, g := range got {
			t.Logf("%s %s %s %v", g.Type, g.Severity, g.Key, g.Data)
		}
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Type != w.typ || g.Severity != w.sev || (w.key != "" && g.Key != w.key) || !w.check(g.Data) {
			t.Errorf("event %d: got %s %s %q %v, want %s %s %q", i, g.Type, g.Severity, g.Key, g.Data, w.typ, w.sev, w.key)
		}
	}
	p := proto.Payload{V: 1, Seq: 1, SentAt: c.t.Unix(), AgentVersion: "test", MachineFP: "0123456789abcdef",
		Events: got, Redactions: map[string]int{}}
	if err := p.Validate(); err != nil {
		t.Errorf("events do not validate: %v", err)
	}

	// The brute force went on during its 10-minute silence (5 more
	// failures): one update with the same id and a higher count.
	c.t = time.Unix(got[0].TS, 0).Add(10*time.Minute + time.Second)
	due := e.Due()
	var upd *proto.Event
	for i := range due {
		if due[i].ID == got[0].ID {
			upd = &due[i]
		}
	}
	if upd == nil || upd.Count != 2 || upd.LastTS == 0 {
		t.Fatalf("no brute-force update after the silence: %+v", due)
	}
	// Quiet since: the next silence end closes it without another update.
	c.t = c.t.Add(10*time.Minute + time.Second)
	for _, ev := range e.Due() {
		if ev.ID == got[0].ID {
			t.Fatalf("quiet burst updated again: %+v", ev)
		}
	}
}

func TestDebounce(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	rec := func() raw.Record {
		return raw.Record{Kind: proto.EventServiceFailed, TS: c.t, Key: "app.service",
			Data: map[string]any{"unit": "app.service", "result": "signal", "restarting": true, "n_restarts": 1}}
	}
	first := e.Record(rec())
	if len(first) != 1 || first[0].Count != 1 || !rules.NeedsSnapshot(first[0]) {
		t.Fatalf("first: %+v", first)
	}
	// 11 more crashes within the minute: merged, nothing sent now.
	for i := 0; i < 11; i++ {
		c.t = c.t.Add(5 * time.Second)
		if evs := e.Record(rec()); len(evs) != 0 {
			t.Fatalf("repeat %d not debounced: %+v", i, evs)
		}
	}
	next, ok := e.NextDue()
	if !ok {
		t.Fatal("nothing due")
	}
	c.t = next
	upd := e.Due()
	if len(upd) != 1 || upd[0].ID != first[0].ID || upd[0].Count != 12 || rules.NeedsSnapshot(upd[0]) {
		t.Fatalf("update: %+v", upd)
	}
	// Quiet window: closed without an update; the next crash is a new event.
	c.t = c.t.Add(61 * time.Second)
	if evs := e.Due(); len(evs) != 0 {
		t.Fatalf("quiet window sent %+v", evs)
	}
	if again := e.Record(rec()); len(again) != 1 || again[0].ID == first[0].ID {
		t.Fatalf("after quiet window: %+v", again)
	}

	// P0 is never debounced.
	p0 := raw.Record{Kind: proto.EventProcReverseShell, Severity: "P0", TS: c.t, Key: "bash:1",
		Data: map[string]any{"pid": 1, "comm": "bash", "remote": "203.0.113.1:4444"}}
	a, b := e.Record(p0), e.Record(p0)
	if len(a) != 1 || len(b) != 1 || a[0].ID == b[0].ID {
		t.Fatal("P0 was debounced")
	}
}

func TestCleaning(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	long := strings.Repeat("é", 400) // 800 bytes
	evs := e.Record(raw.Record{Kind: proto.EventProcSegfault, TS: c.t.Add(-48 * time.Hour), Key: "x\x1b[31mred\x1b[0m",
		Data: map[string]any{"comm": "bad\xff\x07name", "pid": 3, "module": long, "nan": math.NaN()}})
	if len(evs) != 1 {
		t.Fatal(evs)
	}
	ev := evs[0]
	if ev.Key != "xred" || ev.Data["comm"] != "bad�name" || !ev.TSAdjusted || ev.TS != c.t.Unix() {
		t.Fatalf("cleaning: %+v", ev)
	}
	if m := ev.Data["module"].(string); len(m) > rules.MaxField+3 || !strings.HasSuffix(m, "…") {
		t.Fatalf("not truncated: %d bytes", len(m))
	}
	if _, ok := ev.Data["nan"]; ok {
		t.Fatal("NaN kept")
	}
	if got := rules.Cmdline([]byte("java\x00-jar\x00app.jar\x00")); got != "java -jar app.jar" {
		t.Fatalf("cmdline %q", got)
	}
	if got := rules.Cmdline([]byte("python3\x00-c\x00import os\nos.system('x')\x00")); got != "python3 -c import os os.system('x')" {
		t.Fatalf("cmdline %q", got)
	}
}

func TestMemRules(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	m := func(ts int64, avail, swapUsed int, in float64) proto.Metric {
		return proto.Metric{TS: ts, Mem: proto.Mem{TotalMB: 4000, AvailableMB: avail},
			Swap: &proto.Swap{TotalMB: 2000, UsedMB: swapUsed, InPS: in}}
	}
	var got []proto.Event
	ts := c.t.Unix()
	for i := 0; i < 6; i++ { // thrashing: 4 samples ≥ 100 pages/s → once
		got = append(got, e.Metric(m(ts+int64(i*15), 2000, 100, 150))...)
	}
	if len(got) != 1 || got[0].Type != proto.EventSwapThrashing {
		t.Fatalf("thrashing: %+v", got)
	}
	// Available below 5% while swap use grows by more than 10% in a minute.
	got = nil
	ts += 200
	for i, used := range []int{100, 105, 110, 115, 130} {
		got = append(got, e.Metric(m(ts+int64(i*15), 150, used, 0))...)
	}
	if len(got) != 1 || got[0].Type != proto.EventMemPressure || got[0].Data["available_mb"] != 150 {
		t.Fatalf("pressure: %+v", got)
	}
}

// The state machine sees full addresses; what leaves the agent is only the
// masked network (spec A4.2 + A6).
func TestSourceMaskedOnTheWire(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	var evs []proto.Event
	for range 20 {
		evs = append(evs, e.Record(raw.Record{Kind: raw.SSHFail, TS: c.t, Data: map[string]any{"ip": "8.8.4.4", "user": "root"}})...)
	}
	if len(evs) != 1 || evs[0].Data["source"] != "8.8.4.4" {
		t.Fatalf("engine: %+v", evs)
	}
	b, err := sanitize.New(sanitize.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := b.Seal(&proto.Payload{V: 1, Seq: 1, SentAt: 1, AgentVersion: "t", MachineFP: "0123456789abcdef",
		Events: evs, Redactions: map[string]int{}})
	if err != nil {
		t.Fatal(err)
	}
	body := string(sp.Bytes())
	if strings.Contains(body, "8.8.4.4") || !strings.Contains(body, `"source":"8.8.4.x"`) || !strings.Contains(body, `"key":"ssh_bruteforce"`) {
		t.Fatalf("sealed: %s", body)
	}
}

func fails(e *rules.Engine, c *clock, ip, user string, n int) []proto.Event {
	var out []proto.Event
	for range n {
		out = append(out, e.Record(raw.Record{Kind: raw.SSHFail, TS: c.t, Data: map[string]any{"ip": ip, "user": user}})...)
	}
	return out
}

// Spec v1.1 delta 10.4: brute force is reported only while the scan finds
// password login on; breaches always are.
func TestAttacksFollowTheRiskScan(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	e.SetRisk(rules.Risk{Scan: true, SSHPassword: false})
	if evs := fails(e, c, "8.8.4.4", "root", 25); len(evs) != 0 {
		t.Fatalf("password login off, still reported: %+v", evs)
	}
	// Failures are still tracked: a login after them is a breach.
	evs := e.Record(raw.Record{Kind: raw.SSHAccept, TS: c.t, Data: map[string]any{"ip": "8.8.4.4", "user": "deploy", "method": "publickey"}})
	if len(evs) != 1 || evs[0].Type != proto.EventSSHBreach {
		t.Fatalf("breach: %+v", evs)
	}

	// The scan turned off: only breaches and root password logins.
	e.SetRisk(rules.Risk{})
	if evs := fails(e, c, "8.8.8.8", "admin", 25); len(evs) != 0 {
		t.Fatalf("scan off, still reported: %+v", evs)
	}

	// Password login turns on: an attack still going on is reported afresh.
	e.SetRisk(rules.Risk{Scan: true, SSHPassword: true})
	c.t = c.t.Add(time.Second)
	evs = fails(e, c, "8.8.8.8", "admin", 1)
	if len(evs) != 1 || evs[0].Type != proto.EventSSHBruteforce || evs[0].Severity != "P2" {
		t.Fatalf("after turning on: %+v", evs)
	}
	if _, ok := evs[0].Data["root_attempts"]; ok || evs[0].Data["root_password"] != false {
		t.Fatal("root attempts counted while root cannot use a password")
	}
}

// One brute-force event per server: more sources join it rather than
// starting their own (spec v1.1 delta 10.4).
func TestBruteForceMergedPerServer(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	e.SetRisk(rules.Risk{Scan: true, SSHPassword: true, RootPassword: true})
	first := fails(e, c, "8.8.4.4", "root", 20)
	if len(first) != 1 || first[0].Severity != "P1" || first[0].Data["root_attempts"] != 20 || first[0].Data["root_password"] != true {
		t.Fatalf("first: %+v", first)
	}
	c.t = c.t.Add(time.Minute)
	if more := append(fails(e, c, "9.9.9.9", "root", 20), fails(e, c, "1.1.1.1", "admin", 20)...); len(more) != 0 {
		t.Fatalf("other sources started their own events: %+v", more)
	}
	c.t = c.t.Add(10 * time.Minute)
	var upd *proto.Event
	for _, ev := range e.Due() {
		if ev.ID == first[0].ID {
			upd = &ev
		}
	}
	// The update counts everything since the first report.
	if upd == nil || upd.Count != 2 || upd.Data["source_count"] != 3 || upd.Data["fail_count"] != 60 ||
		upd.Data["root_attempts"] != 40 || upd.Key != "ssh_bruteforce" || upd.Data["window_seconds"] != 660 {
		t.Fatalf("update: %+v", upd)
	}
}

func TestSecuritySummary(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 28, 10, 20, 0, 0, time.UTC)}
	e := newEngine(t, c)
	e.SetRisk(rules.Risk{Scan: true}) // password login off: no events, still counted
	if s := e.SecuritySummary(); s != nil {
		t.Fatalf("summary before the hour ended: %+v", s)
	}
	fails(e, c, "8.8.4.4", "root", 30)
	fails(e, c, "9.9.9.9", "admin", 5)
	fails(e, c, "9.9.9.9", "root", 2)
	c.t = c.t.Add(30 * time.Minute)
	if s := e.SecuritySummary(); s != nil {
		t.Fatalf("summary mid-hour: %+v", s)
	}
	c.t = time.Date(2026, 9, 28, 11, 0, 5, 0, time.UTC)
	s := e.SecuritySummary()
	if s == nil || s.Attempts != 37 || s.RootAttempts != 32 || s.Sources != 2 || s.Sources24h != 2 || len(s.TopUsers) != 2 || s.TopUsers[0] != (proto.UserCount{User: "root", Count: 32}) ||
		s.Start != time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC).Unix() || s.End != time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("summary: %+v", s)
	}
	// A quiet hour still yields a summary, with zero attempts.
	c.t = c.t.Add(time.Hour)
	if s := e.SecuritySummary(); s == nil || s.Attempts != 0 || s.Sources != 0 || s.Sources24h != 2 {
		t.Fatalf("quiet hour: %+v", s)
	}
	// The 24-hour count keeps a source for a day, then drops it.
	c.t = time.Date(2026, 9, 29, 10, 30, 0, 0, time.UTC)
	fails(e, c, "1.1.1.1", "ubuntu", 1)
	e.SecuritySummary() // the hour started 12:00 on the 28th: sources of the 28th still count
	c.t = time.Date(2026, 9, 29, 11, 0, 5, 0, time.UTC)
	if s := e.SecuritySummary(); s == nil || s.Sources24h != 1 || s.RootAttempts != 0 {
		t.Fatalf("next day: %+v", s)
	}
}

func TestAccessEvents(t *testing.T) {
	c := &clock{t: time.Unix(1_790_000_000, 0)}
	e := newEngine(t, c)
	db := e.Access(proto.EventDBPublicAccess, 6379, "redis", proto.BindAllInterfaces, 3, []string{"203.0.113.x"})
	dk := e.Access(proto.EventDockerAPIAccess, 2375, "docker", proto.BindPublicAddress, 1, nil)
	if len(db) != 1 || db[0].Severity != "P1" || db[0].Key != "db_public_access:6379" || db[0].Data["service"] != "redis" {
		t.Fatalf("db: %+v", db)
	}
	if db[0].Data["bind_scope"] != proto.BindAllInterfaces {
		t.Fatalf("db bind_scope: %+v", db[0].Data)
	}
	if len(dk) != 1 || dk[0].Severity != "P0" || dk[0].Data["port"] != 2375 || dk[0].Data["tls"] != false || dk[0].Data["bind_scope"] != proto.BindPublicAddress {
		t.Fatalf("docker: %+v", dk)
	}
	p := proto.Payload{V: 1, Seq: 1, SentAt: c.t.Unix(), AgentVersion: "test", MachineFP: "0123456789abcdef",
		Events: append(db, dk...), Redactions: map[string]int{}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

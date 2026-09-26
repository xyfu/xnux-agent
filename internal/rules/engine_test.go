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
		{proto.EventSSHBruteforce, "P2", "203.0.113.7", func(d map[string]any) bool {
			return d["fail_count"] == 20 && d["window_seconds"] == 300 && fmt.Sprint(d["top_users"]) == "[root]"
		}},
		{proto.EventSSHSpray, "P2", "198.51.100.9", func(d map[string]any) bool { return d["user_count"] == 5 }},
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
	if strings.Contains(body, "8.8.4.4") || !strings.Contains(body, `"source":"8.8.4.x"`) || !strings.Contains(body, `"key":"8.8.4.x"`) {
		t.Fatalf("sealed: %s", body)
	}
}

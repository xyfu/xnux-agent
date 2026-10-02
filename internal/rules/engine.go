// Package rules turns watcher records and metric samples into normalized
// events (spec A4): it cleans every field, runs the security state machine
// on full source addresses, applies the two agent-side resource rules and
// debounces repeats. It runs before the redaction barrier.
package rules

import (
	"strconv"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/config"
	"github.com/xyfu/xnux-agent/internal/raw"
)

const (
	// debounceWindow merges repeats of one fingerprint (spec A4.4).
	debounceWindow = 60 * time.Second
	maxDebounce    = 1000
)

// Default severities of event types that watchers report directly
// (security and process events are graded where they are detected).
var defaultSeverity = map[string]string{
	proto.EventServiceFailed:      proto.SeverityP1,
	proto.EventServiceStartFailed: proto.SeverityP1,
	proto.EventServiceRecovered:   proto.SeverityP3,
	proto.EventOOMKill:            proto.SeverityP1,
	proto.EventProcSegfault:       proto.SeverityP2,
	proto.EventDiskError:          proto.SeverityP1,
	proto.EventFSReadonly:         proto.SeverityP1,
	proto.EventHungTask:           proto.SeverityP2,
	proto.EventProcFileless:       proto.SeverityP1,
	proto.EventProcDeletedExe:     proto.SeverityP2,
	proto.EventProcStaleBinary:    proto.SeverityP3,
	proto.EventProcTmpExec:        proto.SeverityP2,
	proto.EventProcReverseShell:   proto.SeverityP0,
	proto.EventSwapThrashing:      proto.SeverityP2,
	proto.EventMemPressure:        proto.SeverityP2,
}

// Options configure an Engine.
type Options struct {
	Security config.Security
	Now      func() time.Time
	NewID    func() string
}

// Engine is not safe for concurrent use; the agent loop owns it.
type Engine struct {
	o   Options
	sec *security
	mem memRules
	deb map[string]*pending
}

type pending struct {
	ev    proto.Event
	until time.Time
	dirty bool
}

// occ is one occurrence before debouncing. A non-nil ev is an already
// built event (a security burst or its update) that bypasses debouncing.
type occ struct {
	typ, sev, key string
	ts            time.Time
	data          map[string]any
	ev            *proto.Event
}

func New(o Options) (*Engine, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NewID == nil {
		o.NewID = func() string { return ulid.Make().String() }
	}
	sec, err := newSecurity(o.Security, o.NewID)
	if err != nil {
		return nil, err
	}
	return &Engine{o: o, sec: sec, deb: map[string]*pending{}}, nil
}

// Record handles one watcher record and returns the events to send now.
func (e *Engine) Record(r raw.Record) []proto.Event {
	now := e.o.Now()
	if e.sec.handles(r.Kind) {
		return e.emit(e.sec.record(r, now), now)
	}
	sev := r.Severity
	if sev == "" {
		sev = defaultSeverity[r.Kind]
	}
	if sev == "" {
		return nil // unknown kind: a watcher bug, never reported half-formed
	}
	return e.emit([]occ{{typ: r.Kind, sev: sev, key: r.Key, ts: r.TS, data: r.Data}}, now)
}

// SetRisk applies the local risk scan's result (spec v1.1 delta 10.4).
func (e *Engine) SetRisk(r Risk) { e.sec.setRisk(r) }

// SecuritySummary returns the hourly SSH attack summary once an hour has
// ended, whatever the scan found.
func (e *Engine) SecuritySummary() *proto.SecuritySummary { return e.sec.summary(e.o.Now()) }

// Access reports connections from outside to a port the scan found
// exposed: db_public_access (P1) or docker_api_access (P0). bind is where
// the port listens (proto.BindAllInterfaces or proto.BindPublicAddress).
// The caller limits them to one per port per hour.
func (e *Engine) Access(typ string, port int, service, bind string, connections int, sources []string) []proto.Event {
	sev := proto.SeverityP1
	data := map[string]any{"port": port, "connections": connections, "bind_scope": bind}
	if typ == proto.EventDockerAPIAccess {
		sev = proto.SeverityP0
		data["tls"] = false // the scan only flags the plain-text API
	} else {
		data["service"] = service
	}
	if len(sources) > 0 {
		data["sources"] = sources
	}
	now := e.o.Now()
	return e.emit([]occ{{typ: typ, sev: sev, key: typ + ":" + strconv.Itoa(port), ts: now, data: data}}, now)
}

// Metric runs the agent-side resource rules on a sample (spec A4.3).
func (e *Engine) Metric(m proto.Metric) []proto.Event {
	return e.emit(e.mem.sample(m), e.o.Now())
}

// Due returns updates whose debounce window or burst silence has ended.
func (e *Engine) Due() []proto.Event {
	now := e.o.Now()
	var out []proto.Event
	for fp, p := range e.deb {
		if now.Before(p.until) {
			continue
		}
		if !p.dirty {
			delete(e.deb, fp)
			continue
		}
		// Still repeating: send the update and keep merging under the same id.
		out = append(out, copyEvent(p.ev))
		p.dirty = false
		p.until = now.Add(debounceWindow)
	}
	for _, o := range e.sec.due(now) {
		out = append(out, *o.ev)
	}
	return out
}

// NextDue is when Due has something to do; ok is false when nothing waits.
func (e *Engine) NextDue() (t time.Time, ok bool) {
	for _, p := range e.deb {
		if !ok || p.until.Before(t) {
			t, ok = p.until, true
		}
	}
	if st, sok := e.sec.nextDue(); sok && (!ok || st.Before(t)) {
		t, ok = st, true
	}
	return t, ok
}

// NeedsSnapshot reports whether ev is a first occurrence that carries the
// on-site snapshot: P0/P1, OOM kills, service crashes and memory pressure
// (spec A4.5).
func NeedsSnapshot(ev proto.Event) bool {
	if ev.Count != 1 || ev.LastTS != 0 {
		return false
	}
	switch ev.Type {
	case proto.EventOOMKill, proto.EventServiceFailed, proto.EventMemPressure:
		return true
	}
	return ev.Severity == proto.SeverityP0 || ev.Severity == proto.SeverityP1
}

func (e *Engine) emit(os []occ, now time.Time) []proto.Event {
	var out []proto.Event
	for _, o := range os {
		if o.ev != nil {
			cleanData(o.ev.Data)
			o.ev.Key = Clean(o.ev.Key, MaxField)
			out = append(out, copyEvent(*o.ev))
			continue
		}
		if ev, ok := e.occur(o, now); ok {
			out = append(out, ev)
		}
	}
	return out
}

func (e *Engine) occur(o occ, now time.Time) (proto.Event, bool) {
	if o.data == nil {
		o.data = map[string]any{}
	}
	cleanData(o.data)
	key := Clean(o.key, MaxField)
	if key == "" {
		key = o.typ
	}
	ts, adjusted := eventTime(o.ts, now)
	fp := o.typ + ":" + key

	// P0 is never debounced (spec A4.4).
	if o.sev != proto.SeverityP0 {
		if p, ok := e.deb[fp]; ok && now.Before(p.until) {
			p.ev.Count++
			p.ev.LastTS = ts.Unix()
			p.ev.Data = o.data // the latest occurrence's details
			if o.sev < p.ev.Severity {
				p.ev.Severity = o.sev // never lower within one id (C-AG-EVENT-UPDATES)
			}
			p.dirty = true
			return proto.Event{}, false
		}
	}
	ev := proto.Event{
		ID: e.o.NewID(), TS: ts.Unix(), Type: o.typ, Severity: o.sev, Count: 1,
		Key: key, Data: o.data, TSAdjusted: adjusted,
	}
	if o.sev != proto.SeverityP0 && e.room(now) {
		e.deb[fp] = &pending{ev: ev, until: now.Add(debounceWindow)}
	}
	return copyEvent(ev), true
}

// room makes space in the debounce table; a full table stops debouncing
// rather than dropping events.
func (e *Engine) room(now time.Time) bool {
	if len(e.deb) < maxDebounce {
		return true
	}
	for fp, p := range e.deb {
		if !p.dirty && !now.Before(p.until) {
			delete(e.deb, fp)
		}
	}
	return len(e.deb) < maxDebounce
}

// copyEvent detaches the data map so later updates do not change an event
// already handed to the batcher.
func copyEvent(ev proto.Event) proto.Event {
	d := make(map[string]any, len(ev.Data))
	for k, v := range ev.Data {
		d[k] = v
	}
	ev.Data = d
	return ev
}

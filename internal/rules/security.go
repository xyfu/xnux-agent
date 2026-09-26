package rules

import (
	"container/list"
	"regexp"
	"sort"
	"time"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/config"
	"github.com/xyfu/xnux-agent/internal/raw"
)

// Security state limits and windows (spec A4.2). The table is keyed by the
// full source address, lives only in memory and is never written to disk.
const (
	maxSources    = 10_000
	maxFails      = 64
	maxUsers      = 32
	idleExpiry    = 30 * time.Minute
	bruteWindow   = 5 * time.Minute
	sprayWindow   = 30 * time.Minute
	breachWindow  = 30 * time.Minute
	burstSilence  = 10 * time.Minute
	sudoWindow    = 10 * time.Minute
	sudoFailLimit = 3
	maxAuthFails  = 6 // "maximum authentication attempts exceeded" counts as six failures
)

// Built-in sensitive sudo commands, matched against COMMAND= (spec A4.2).
var sudoSensitive = []string{
	`(^|/)(ba|z|da|k)?sh(\s|$)`,
	`(^|/)su(\s|$)`,
	`(^|/)(visudo|useradd|usermod|userdel|passwd|chpasswd)(\s|$)`,
	`chmod\s+([0-7]*777|u\+s|\+s)`,
	`(curl|wget)\s.*\|\s*(ba)?sh`,
	`(^|/)(iptables|nft|ufw)\s+.*(-F|flush|disable)`,
	`/etc/(sudoers|shadow|passwd)`,
}

type userSeen struct {
	last time.Time
	n    int
}

type source struct {
	addr  string
	fails []time.Time // oldest first, at most maxFails
	users map[string]*userSeen
	last  time.Time
	brute *burst
	spray *burst
}

// burst is an ongoing brute-force or spray event: after it fires, further
// attempts only count until the silence ends (spec A4.2).
type burst struct {
	ev    proto.Event
	until time.Time
	more  int
}

type security struct {
	cfg     config.Security
	sudo    []*regexp.Regexp
	newID   func() string
	lru     *list.List // front = most recently active; values are *source
	byAddr  map[string]*list.Element
	bursts  map[string]*source // sources with an active burst
	sudoBad map[string][]time.Time
}

func newSecurity(cfg config.Security, newID func() string) (*security, error) {
	s := &security{cfg: cfg, newID: newID, lru: list.New(), byAddr: map[string]*list.Element{},
		bursts: map[string]*source{}, sudoBad: map[string][]time.Time{}}
	for _, p := range append(append([]string(nil), sudoSensitive...), cfg.SudoSensitiveExtra...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		s.sudo = append(s.sudo, re)
	}
	return s, nil
}

func (s *security) handles(kind string) bool {
	switch kind {
	case raw.SSHFail, raw.SSHInvalidUser, raw.SSHMaxAuth, raw.SSHAccept, raw.SudoCmd, raw.SudoFail, raw.UserCreated, raw.SuRoot:
		return true
	}
	return false
}

func str(d map[string]any, k string) string {
	v, _ := d[k].(string)
	return v
}

func (s *security) record(r raw.Record, now time.Time) []occ {
	t, _ := eventTime(r.TS, now)
	d := r.Data
	switch r.Kind {
	case raw.SSHFail:
		return s.fail(str(d, "ip"), str(d, "user"), 1, t)
	case raw.SSHMaxAuth:
		return s.fail(str(d, "ip"), str(d, "user"), maxAuthFails, t)
	case raw.SSHInvalidUser:
		// sshd follows this line with "Failed … for invalid user" when a
		// password was tried; counting both would double the failures, so
		// the name only feeds the spray rule.
		return s.fail(str(d, "ip"), str(d, "user"), 0, t)
	case raw.SSHAccept:
		return s.accept(str(d, "ip"), str(d, "user"), str(d, "method"), t)
	case raw.SudoCmd:
		cmd := str(d, "command")
		for _, re := range s.sudo {
			if re.MatchString(cmd) {
				by := str(d, "by_user")
				return []occ{{typ: proto.EventSudoSensitive, sev: proto.SeverityP1, key: by + ":" + cmd, ts: t,
					data: map[string]any{"by_user": by, "as_user": str(d, "as_user"), "command": cmd, "pwd": str(d, "pwd")}}}
			}
		}
		return nil
	case raw.SudoFail:
		n, _ := d["attempts"].(int)
		return s.sudoFail(str(d, "user"), max(n, 1), t)
	case raw.UserCreated:
		return []occ{{typ: proto.EventUserCreated, sev: proto.SeverityP1, key: str(d, "name"), ts: t,
			data: map[string]any{"name": str(d, "name"), "uid": d["uid"]}}}
	case raw.SuRoot:
		return []occ{{typ: proto.EventSuRoot, sev: proto.SeverityP3, key: str(d, "by_user"), ts: t,
			data: map[string]any{"by_user": str(d, "by_user")}}}
	}
	return nil
}

// get returns the state for addr, creating it and evicting the least
// recently active source when the table is full.
func (s *security) get(addr string, now time.Time) *source {
	s.expire(now)
	if el, ok := s.byAddr[addr]; ok {
		s.lru.MoveToFront(el)
		return el.Value.(*source)
	}
	if s.lru.Len() >= maxSources {
		s.drop(s.lru.Back())
	}
	src := &source{addr: addr, users: map[string]*userSeen{}}
	s.byAddr[addr] = s.lru.PushFront(src)
	return src
}

// expire lazily removes sources idle for 30 minutes.
func (s *security) expire(now time.Time) {
	for el := s.lru.Back(); el != nil; el = s.lru.Back() {
		src := el.Value.(*source)
		if now.Sub(src.last) < idleExpiry || src.brute != nil || src.spray != nil {
			return
		}
		s.drop(el)
	}
}

func (s *security) drop(el *list.Element) {
	src := el.Value.(*source)
	s.lru.Remove(el)
	delete(s.byAddr, src.addr)
	delete(s.bursts, src.addr)
}

func countSince(ts []time.Time, since time.Time) int {
	i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(since) })
	return len(ts) - i
}

func (src *source) usersSince(since time.Time) int {
	n := 0
	for _, u := range src.users {
		if !u.last.Before(since) {
			n++
		}
	}
	return n
}

func (src *source) topUsers(since time.Time) []string {
	type kv struct {
		name string
		n    int
	}
	var all []kv
	for name, u := range src.users {
		if !u.last.Before(since) {
			all = append(all, kv{name, u.n})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	out := []string{}
	for i := 0; i < len(all) && i < 5; i++ {
		out = append(out, all[i].name)
	}
	return out
}

func (s *security) fail(addr, user string, n int, t time.Time) []occ {
	if addr == "" {
		return nil
	}
	src := s.get(addr, t)
	src.last = t
	for range n {
		src.fails = append(src.fails, t)
	}
	if extra := len(src.fails) - maxFails; extra > 0 {
		src.fails = append(src.fails[:0], src.fails[extra:]...)
	}
	if user != "" {
		if u, ok := src.users[user]; ok {
			u.last, u.n = t, u.n+max(n, 1)
		} else if len(src.users) < maxUsers {
			src.users[user] = &userSeen{last: t, n: max(n, 1)}
		}
	}

	var out []occ
	if src.brute != nil {
		src.brute.more += n
	} else if countSince(src.fails, t.Add(-bruteWindow)) >= s.cfg.BruteforceFailThreshold {
		src.brute = s.burst(src, proto.EventSSHBruteforce, bruteWindow, t)
		out = append(out, occ{ev: &src.brute.ev})
	}
	if src.spray != nil {
		src.spray.more += max(n, 1)
	} else if src.usersSince(t.Add(-sprayWindow)) >= s.cfg.SprayUserThreshold {
		src.spray = s.burst(src, proto.EventSSHSpray, sprayWindow, t)
		out = append(out, occ{ev: &src.spray.ev})
	}
	return out
}

func (s *security) burst(src *source, typ string, window time.Duration, t time.Time) *burst {
	s.bursts[src.addr] = src
	return &burst{
		ev: proto.Event{ID: s.newID(), TS: t.Unix(), Type: typ, Severity: proto.SeverityP2, Count: 1,
			Key: src.addr, Data: burstData(src, window, t)},
		until: t.Add(burstSilence),
	}
}

func burstData(src *source, window time.Duration, t time.Time) map[string]any {
	since := t.Add(-window)
	return map[string]any{
		"source":         src.addr,
		"fail_count":     countSince(src.fails, since),
		"user_count":     src.usersSince(since),
		"top_users":      src.topUsers(since),
		"window_seconds": int(window.Seconds()),
	}
}

func (s *security) accept(addr, user, method string, t time.Time) []occ {
	if addr == "" {
		return nil
	}
	var out []occ
	src := s.get(addr, t)
	src.last = t
	// Breach is P0: never silenced or debounced (spec A4.2).
	if prior := countSince(src.fails, t.Add(-breachWindow)); prior >= s.cfg.BreachFailThreshold {
		out = append(out, occ{typ: proto.EventSSHBreach, sev: proto.SeverityP0, key: addr, ts: t,
			data: map[string]any{"source": addr, "user": user, "method": method, "prior_failures": prior}})
	}
	if user == "root" && method == "password" {
		out = append(out, occ{typ: proto.EventSSHRootPasswordLogin, sev: proto.SeverityP1, key: addr, ts: t,
			data: map[string]any{"source": addr}})
	}
	return out
}

func (s *security) sudoFail(user string, n int, t time.Time) []occ {
	if user == "" {
		return nil
	}
	ts := s.sudoBad[user]
	for range min(n, 64) {
		ts = append(ts, t)
	}
	i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(t.Add(-sudoWindow)) })
	ts = ts[i:]
	if len(ts) >= sudoFailLimit {
		delete(s.sudoBad, user)
		return []occ{{typ: proto.EventSudoAuthFail, sev: proto.SeverityP2, key: user, ts: t,
			data: map[string]any{"user": user, "attempts": len(ts)}}}
	}
	if len(s.sudoBad) < maxSources {
		s.sudoBad[user] = ts
	}
	return nil
}

// due ends silences: a burst that saw more attempts sends an update with
// the same id and a higher count, then stays silenced; a quiet one ends.
func (s *security) due(now time.Time) []occ {
	var out []occ
	for addr, src := range s.bursts {
		for _, pb := range []**burst{&src.brute, &src.spray} {
			b := *pb
			if b == nil || now.Before(b.until) {
				continue
			}
			if b.more == 0 {
				*pb = nil
				continue
			}
			window := bruteWindow
			if b.ev.Type == proto.EventSSHSpray {
				window = sprayWindow
			}
			b.ev.Count++
			b.ev.LastTS = now.Unix()
			b.ev.Data = burstData(src, window, now)
			b.more = 0
			b.until = now.Add(burstSilence)
			ev := b.ev
			out = append(out, occ{ev: &ev})
		}
		if src.brute == nil && src.spray == nil {
			delete(s.bursts, addr)
		}
	}
	return out
}

func (s *security) nextDue() (t time.Time, ok bool) {
	for _, src := range s.bursts {
		for _, b := range []*burst{src.brute, src.spray} {
			if b != nil && (!ok || b.until.Before(t)) {
				t, ok = b.until, true
			}
		}
	}
	return t, ok
}

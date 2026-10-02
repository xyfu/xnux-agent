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
	// Whether this source crossed the brute-force or spray threshold; it
	// then feeds the server's burst of that type.
	brute, spray bool
}

// burst is an ongoing brute-force or spray event for the whole server
// (fingerprint = server + type, spec v1.1 delta 10.4): after it fires,
// further attempts only count until the silence ends (spec A4.2).
type burst struct {
	ev    proto.Event
	until time.Time
	more  int
}

// Risk is what the local risk scan found (spec v1.1 delta 10.4). Brute
// force and spray are reported only while sshd accepts passwords.
type Risk struct {
	Scan         bool // the scan runs (collectors.riskscan)
	SSHPassword  bool
	RootPassword bool
}

func (r Risk) reportAttacks() bool { return r.Scan && r.SSHPassword }

type security struct {
	cfg     config.Security
	sudo    []*regexp.Regexp
	newID   func() string
	lru     *list.List // front = most recently active; values are *source
	byAddr  map[string]*list.Element
	sudoBad map[string][]time.Time
	risk    Risk
	brute   *burst
	spray   *burst
	hour    hourly
	// seen24h is when each source address last failed, for the summary's
	// 24-hour distinct count; the addresses never leave the agent.
	seen24h map[string]time.Time
}

// hourly is the security summary being counted (spec v1.1 delta 10.4).
type hourly struct {
	start    time.Time
	attempts int
	root     int
	sources  map[string]struct{}
	users    map[string]int
}

// Bounds of the hourly summary's tables.
const (
	maxHourSources = 10_000
	maxHourUsers   = 1000
	max24hSources  = 50_000
)

func newSecurity(cfg config.Security, newID func() string) (*security, error) {
	s := &security{cfg: cfg, newID: newID, lru: list.New(), byAddr: map[string]*list.Element{},
		sudoBad: map[string][]time.Time{}, seen24h: map[string]time.Time{}}
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
		if now.Sub(src.last) < idleExpiry {
			return
		}
		s.drop(el)
	}
}

func (s *security) drop(el *list.Element) {
	src := el.Value.(*source)
	s.lru.Remove(el)
	delete(s.byAddr, src.addr)
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

// topN returns the n most tried names, most tried first.
func topN(counts map[string]int, n int) []string {
	type kv struct {
		name string
		n    int
	}
	all := make([]kv, 0, len(counts))
	for name, c := range counts {
		all = append(all, kv{name, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	out := []string{}
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, all[i].name)
	}
	return out
}

func (s *security) fail(addr, user string, n int, t time.Time) []occ {
	if addr == "" {
		return nil
	}
	s.count(addr, user, n, t)
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

	// Failures are always tracked (ssh_breach needs them); brute force and
	// spray are reported only while the scan finds password login on.
	var out []occ
	if src.brute && s.brute != nil {
		s.brute.more += n
	} else if countSince(src.fails, t.Add(-bruteWindow)) >= s.cfg.BruteforceFailThreshold {
		src.brute = true
		out = append(out, s.trigger(&s.brute, proto.EventSSHBruteforce, t)...)
	}
	if src.spray && s.spray != nil {
		s.spray.more += max(n, 1)
	} else if src.usersSince(t.Add(-sprayWindow)) >= s.cfg.SprayUserThreshold {
		src.spray = true
		out = append(out, s.trigger(&s.spray, proto.EventSSHSpray, t)...)
	}
	return out
}

// trigger adds a source to the server's burst of typ, starting the burst
// (and its event) when there is none.
func (s *security) trigger(pb **burst, typ string, t time.Time) []occ {
	if !s.risk.reportAttacks() {
		return nil
	}
	if *pb != nil {
		(*pb).more++
		return nil
	}
	*pb = &burst{
		ev: proto.Event{ID: s.newID(), TS: t.Unix(), Type: typ, Severity: s.attackSeverity(), Count: 1,
			Key: typ, Data: s.burstData(typ, t, t.Add(-window(typ)))},
		until: t.Add(burstSilence),
	}
	return []occ{{ev: &(*pb).ev}}
}

// attackSeverity is P2, or P1 while root may log in with a password.
func (s *security) attackSeverity() string {
	if s.risk.RootPassword {
		return proto.SeverityP1
	}
	return proto.SeverityP2
}

func window(typ string) time.Duration {
	if typ == proto.EventSSHSpray {
		return sprayWindow
	}
	return bruteWindow
}

// burstData sums the sources that crossed typ's threshold and were active
// since the given time (the rule's window for the first report, the
// previous report for an update): the latest of them is "source".
func (s *security) burstData(typ string, t, since time.Time) map[string]any {
	var latest *source
	fails, sources, root := 0, 0, 0
	users := map[string]int{}
	for el := s.lru.Front(); el != nil; el = el.Next() {
		src := el.Value.(*source)
		if (typ == proto.EventSSHSpray && !src.spray) || (typ == proto.EventSSHBruteforce && !src.brute) || src.last.Before(since) {
			continue
		}
		if latest == nil {
			latest = src // the list is most recently active first
		}
		sources++
		fails += countSince(src.fails, since)
		for name, u := range src.users {
			if !u.last.Before(since) && (len(users) < maxHourUsers || users[name] > 0) {
				users[name] += u.n
			}
		}
		if u, ok := src.users["root"]; ok && !u.last.Before(since) {
			root += u.n
		}
	}
	d := map[string]any{
		"source":         "",
		"fail_count":     fails,
		"user_count":     len(users),
		"top_users":      topN(users, 5),
		"window_seconds": max(int(t.Sub(since).Seconds()), 1),
		"source_count":   sources,
	}
	if latest != nil {
		d["source"] = latest.addr
	}
	d["root_password"] = s.risk.RootPassword
	if s.risk.RootPassword {
		d["root_attempts"] = root
	}
	return d
}

// setRisk applies a new scan result. When attacks stop being reportable the
// bursts end silently (no "fixed" notice, spec v1.1 delta 10.4); sources
// start over, so an attack still going on is reported afresh when they
// become reportable again.
func (s *security) setRisk(r Risk) {
	if r == s.risk {
		return
	}
	was := s.risk.reportAttacks()
	s.risk = r
	if was != r.reportAttacks() {
		s.brute, s.spray = nil, nil
		for el := s.lru.Front(); el != nil; el = el.Next() {
			src := el.Value.(*source)
			src.brute, src.spray = false, false
		}
	}
}

// count feeds the hourly summary, whatever the scan found.
func (s *security) count(addr, user string, n int, t time.Time) {
	h := &s.hour
	if h.sources == nil {
		h.start = t.Truncate(time.Hour)
		h.sources, h.users = map[string]struct{}{}, map[string]int{}
	}
	h.attempts += n
	if user == "root" {
		h.root += n
	}
	if _, ok := s.seen24h[addr]; ok || len(s.seen24h) < max24hSources {
		s.seen24h[addr] = t
	}
	if len(h.sources) < maxHourSources {
		h.sources[addr] = struct{}{}
	}
	if user != "" {
		if _, ok := h.users[user]; ok || len(h.users) < maxHourUsers {
			h.users[user] += max(n, 1)
		}
	}
}

// summary returns the finished hour's summary once the hour is over, and
// starts the next one; nothing before the first hour ends.
func (s *security) summary(now time.Time) *proto.SecuritySummary {
	h := &s.hour
	if h.sources == nil {
		h.start = now.Truncate(time.Hour)
		h.sources, h.users = map[string]struct{}{}, map[string]int{}
		return nil
	}
	end := h.start.Add(time.Hour)
	if now.Before(end) {
		return nil
	}
	sum := &proto.SecuritySummary{Start: h.start.Unix(), End: end.Unix(), Attempts: h.attempts,
		RootAttempts: min(h.root, h.attempts), Sources: len(h.sources), Sources24h: s.sources24h(end)}
	for _, name := range topN(h.users, proto.MaxTopUsers) {
		sum.TopUsers = append(sum.TopUsers, proto.UserCount{User: name, Count: h.users[name]})
	}
	*h = hourly{start: now.Truncate(time.Hour), sources: map[string]struct{}{}, users: map[string]int{}}
	return sum
}

// sources24h drops addresses last seen more than 24 hours before end and
// counts the rest.
func (s *security) sources24h(end time.Time) int {
	from := end.Add(-24 * time.Hour)
	n := 0
	for addr, t := range s.seen24h {
		switch {
		case t.Before(from):
			delete(s.seen24h, addr)
		case t.Before(end):
			n++
		}
	}
	return n
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
	for _, pb := range []**burst{&s.brute, &s.spray} {
		b := *pb
		if b == nil || now.Before(b.until) {
			continue
		}
		if b.more == 0 {
			// Quiet for the whole silence: the burst ends, and its sources
			// start over, so an attack resumed later is reported again.
			*pb = nil
			s.resetSources(b.ev.Type)
			continue
		}
		b.ev.Count++
		b.ev.LastTS = now.Unix()
		if sev := s.attackSeverity(); sev < b.ev.Severity {
			b.ev.Severity = sev // never lower within one id (C-AG-EVENT-UPDATES)
		}
		b.ev.Data = s.burstData(b.ev.Type, now, b.until.Add(-burstSilence))
		b.more = 0
		b.until = now.Add(burstSilence)
		ev := b.ev
		out = append(out, occ{ev: &ev})
	}
	return out
}

// resetSources clears the brute-force or spray mark of every source.
func (s *security) resetSources(typ string) {
	for el := s.lru.Front(); el != nil; el = el.Next() {
		src := el.Value.(*source)
		if typ == proto.EventSSHSpray {
			src.spray = false
		} else {
			src.brute = false
		}
	}
}

func (s *security) nextDue() (t time.Time, ok bool) {
	for _, b := range []*burst{s.brute, s.spray} {
		if b != nil && (!ok || b.until.Before(t)) {
			t, ok = b.until, true
		}
	}
	return t, ok
}

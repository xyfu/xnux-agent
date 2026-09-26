package sender

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/spool"
)

type got struct {
	seq  uint64
	part int
}

// fakeServer records accepted payloads; respond decides the status per request.
type fakeServer struct {
	mu       sync.Mutex
	accepted []got
	requests int
	respond  func(n int, p proto.Payload) (int, http.Header)
	t        *testing.T
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer xat_test" || r.Header.Get("Content-Encoding") != "gzip" ||
		r.Header.Get(proto.HeaderSchema) != "1" || r.URL.Path != "/v1/ingest" {
		f.t.Errorf("bad request: %v %v", r.URL.Path, r.Header)
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		f.t.Error(err)
		return
	}
	body, _ := io.ReadAll(zr)
	var p proto.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		f.t.Error(err)
	}
	if r.Header.Get(proto.HeaderSeq) != strconv.FormatUint(p.Seq, 10) {
		f.t.Errorf("seq header %s != body %d", r.Header.Get(proto.HeaderSeq), p.Seq)
	}
	f.mu.Lock()
	f.requests++
	n := f.requests
	respond := f.respond
	f.mu.Unlock()
	code := http.StatusAccepted
	var hdr http.Header
	if respond != nil {
		code, hdr = respond(n, p)
	}
	for k, v := range hdr {
		w.Header()[k] = v
	}
	if code == http.StatusAccepted {
		f.mu.Lock()
		// Server-side dedupe as in spec B3.1.
		if len(f.accepted) == 0 || (got{p.Seq, p.Part}).after(f.accepted[len(f.accepted)-1]) {
			f.accepted = append(f.accepted, got{p.Seq, p.Part})
		}
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(proto.IngestResponse{AckSeq: p.Seq, ServerTime: time.Now().Unix()})
		return
	}
	w.WriteHeader(code)
}

func (g got) after(o got) bool { return g.seq > o.seq || (g.seq == o.seq && g.part > o.part) }

func (f *fakeServer) snapshot() []got {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]got(nil), f.accepted...)
}

type harness struct {
	srv   *httptest.Server
	fake  *fakeServer
	sp    *spool.Spool
	br    *sanitize.Barrier
	s     *Sender
	dir   string
	acked chan uint64
}

func newHarness(t *testing.T, dir string) *harness {
	t.Helper()
	h := &harness{fake: &fakeServer{t: t}, acked: make(chan uint64, 1000), dir: dir}
	h.srv = httptest.NewServer(h.fake)
	t.Cleanup(h.srv.Close)
	h.br, _ = sanitize.New(sanitize.Options{})
	h.newSender(t)
	return h
}

func (h *harness) newSender(t *testing.T) {
	var err error
	h.sp, err = spool.Open(h.dir, spool.DefaultMax, spool.DefaultMaxEvents)
	if err != nil {
		t.Fatal(err)
	}
	h.s, err = New(Options{
		Endpoint: h.srv.URL, Token: "xat_test", Version: "test", Barrier: h.br, Spool: h.sp,
		OnAccepted: func(p sanitize.SanitizedPayload) { h.acked <- p.Seq() },
		MinBackoff: 2 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		PauseRetry: 20 * time.Millisecond, SpillAfter: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (h *harness) payload(t *testing.T, seq uint64, withEvent bool) sanitize.SanitizedPayload {
	p := &proto.Payload{V: 1, Seq: seq, SentAt: 1, AgentVersion: "1", MachineFP: "0123456789abcdef",
		Metrics: []proto.Metric{{TS: int64(seq)}, {TS: int64(seq) + 1}}}
	if withEvent {
		p.Events = []proto.Event{{ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", Type: "oom_kill", Severity: "P1", Count: 1, Key: "k", Data: map[string]any{}}}
	}
	sp, err := h.br.Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func (h *harness) run(t *testing.T) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertInOrder(t *testing.T, g []got, n int) {
	t.Helper()
	if len(g) != n {
		t.Fatalf("accepted %d payloads, want %d: %v", len(g), n, g)
	}
	for i := 1; i < len(g); i++ {
		if !g[i].after(g[i-1]) {
			t.Fatalf("out of order at %d: %v", i, g)
		}
	}
}

func TestSendsInOrder(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.run(t)
	for seq := uint64(1); seq <= 5; seq++ {
		h.s.Enqueue(h.payload(t, seq, false))
	}
	waitFor(t, "5 accepted", func() bool { return len(h.fake.snapshot()) == 5 })
	assertInOrder(t, h.fake.snapshot(), 5)
	waitFor(t, "OnAccepted x5", func() bool { return len(h.acked) == 5 })
}

// F1-7: after an outage the backlog (memory + spool) arrives complete, in
// order and without duplicates.
func TestOutageRecovery(t *testing.T) {
	h := newHarness(t, t.TempDir())
	var mu sync.Mutex
	down := true
	h.fake.respond = func(int, proto.Payload) (int, http.Header) {
		mu.Lock()
		defer mu.Unlock()
		if down {
			return http.StatusServiceUnavailable, nil
		}
		return http.StatusAccepted, nil
	}
	h.run(t)
	for seq := uint64(1); seq <= 50; seq++ {
		h.s.Enqueue(h.payload(t, seq, seq%7 == 0))
		time.Sleep(200 * time.Microsecond)
	}
	waitFor(t, "spooling", func() bool { return h.sp.Len() > 0 })
	mu.Lock()
	down = false
	mu.Unlock()
	waitFor(t, "backlog", func() bool { return len(h.fake.snapshot()) == 50 })
	assertInOrder(t, h.fake.snapshot(), 50)
	waitFor(t, "empty queue", func() bool { return h.s.Queued() == 0 })
}

func TestRestartResumesFromSpool(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.fake.respond = func(int, proto.Payload) (int, http.Header) { return http.StatusBadGateway, nil }
	for seq := uint64(1); seq <= 5; seq++ {
		h.s.Enqueue(h.payload(t, seq, false))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	h.s.Drain(ctx)
	cancel()
	if h.sp.Len() != 5 {
		t.Fatalf("spooled %d, want 5", h.sp.Len())
	}

	h.fake.respond = nil
	h.newSender(t) // "restart": same spool dir
	h.run(t)
	h.s.Enqueue(h.payload(t, 6, false))
	waitFor(t, "6 accepted", func() bool { return len(h.fake.snapshot()) == 6 })
	assertInOrder(t, h.fake.snapshot(), 6)
}

func TestBadRequestIsDropped(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.fake.respond = func(_ int, p proto.Payload) (int, http.Header) {
		if p.Seq == 2 {
			return http.StatusBadRequest, nil
		}
		return http.StatusAccepted, nil
	}
	h.run(t)
	for seq := uint64(1); seq <= 3; seq++ {
		h.s.Enqueue(h.payload(t, seq, false))
	}
	waitFor(t, "2 accepted", func() bool { return len(h.fake.snapshot()) == 2 })
	if g := h.fake.snapshot(); g[0].seq != 1 || g[1].seq != 3 {
		t.Fatalf("accepted %v", g)
	}
}

func TestUnauthorizedPausesThenResumes(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.fake.respond = func(n int, _ proto.Payload) (int, http.Header) {
		if n <= 2 {
			return http.StatusUnauthorized, nil
		}
		return http.StatusAccepted, nil
	}
	h.run(t)
	h.s.Enqueue(h.payload(t, 1, false))
	waitFor(t, "accepted after pause", func() bool { return len(h.fake.snapshot()) == 1 })
}

func TestTooLargeIsSplit(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.fake.respond = func(_ int, p proto.Payload) (int, http.Header) {
		if p.Part == 0 && p.Seq == 1 {
			return http.StatusRequestEntityTooLarge, nil
		}
		return http.StatusAccepted, nil
	}
	h.run(t)
	h.s.Enqueue(h.payload(t, 1, true))
	h.s.Enqueue(h.payload(t, 2, false))
	waitFor(t, "3 accepted", func() bool { return len(h.fake.snapshot()) == 3 })
	want := []got{{1, 1}, {1, 2}, {2, 0}}
	for i, g := range h.fake.snapshot() {
		if g != want[i] {
			t.Fatalf("accepted %v, want %v", h.fake.snapshot(), want)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	h := newHarness(t, t.TempDir())
	h.fake.respond = func(n int, _ proto.Payload) (int, http.Header) {
		if n == 1 {
			return http.StatusTooManyRequests, http.Header{"Retry-After": {"0"}}
		}
		return http.StatusAccepted, nil
	}
	h.run(t)
	h.s.Enqueue(h.payload(t, 1, false))
	waitFor(t, "accepted after 429", func() bool { return len(h.fake.snapshot()) == 1 })
}

func TestProbe(t *testing.T) {
	h := newHarness(t, t.TempDir())
	code, err := Probe(context.Background(), Options{Endpoint: h.srv.URL})
	if err != nil || code == 0 {
		t.Fatalf("probe: %d %v", code, err)
	}
}

// Package sender posts sanitized payloads to /v1/ingest strictly in seq
// order, with backoff, and falls back to the on-disk spool while the server
// is unreachable (spec A5.3, A7).
//
// It is the only agent package allowed to import net/http, and it accepts
// nothing but sanitize.SanitizedPayload, so no unredacted byte can leave.
package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/codec"
	"github.com/xyfu/xnux-agent/internal/spool"
)

// Options configure a Sender.
type Options struct {
	Endpoint string
	Token    string
	CAFile   string
	Proxy    string
	Version  string

	Barrier *sanitize.Barrier
	Spool   *spool.Spool
	// OnAccepted runs after each 202, e.g. to write the mirror file.
	OnAccepted func(sanitize.SanitizedPayload)
	Log        *slog.Logger

	MemQueue   int           // default 20
	MinBackoff time.Duration // default 1s
	MaxBackoff time.Duration // default 5m
	PauseRetry time.Duration // default 10m, after 401/403/409
	SpillAfter time.Duration // default 60s of failures before spooling
}

// Sender is safe for concurrent Enqueue; Run and Drain must not overlap.
type Sender struct {
	o      Options
	url    string
	client *http.Client

	mu        sync.Mutex
	mem       []sanitize.SanitizedPayload
	spoolMode bool // everything new goes to the spool until it drains

	wake         chan struct{}
	backoff      time.Duration
	failingSince time.Time
	lastNotice   string
}

// New validates the options and builds the HTTP client (TLS >= 1.2, the
// system roots plus an optional CA file, no insecure option).
func New(o Options) (*Sender, error) {
	if o.MemQueue == 0 {
		o.MemQueue = 20
	}
	if o.MinBackoff == 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 5 * time.Minute
	}
	if o.PauseRetry == 0 {
		o.PauseRetry = 10 * time.Minute
	}
	if o.SpillAfter == 0 {
		o.SpillAfter = time.Minute
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Barrier == nil || o.Spool == nil {
		return nil, errors.New("sender: Barrier and Spool are required")
	}
	u, err := url.Parse(strings.TrimRight(o.Endpoint, "/") + proto.IngestPath)
	if err != nil {
		return nil, fmt.Errorf("sender: endpoint: %w", err)
	}
	client, err := newClient(o)
	if err != nil {
		return nil, err
	}
	return &Sender{o: o, url: u.String(), client: client, wake: make(chan struct{}, 1),
		spoolMode: o.Spool.Len() > 0, backoff: o.MinBackoff}, nil
}

func newClient(o Options) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("sender: tls.ca_file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("sender: tls.ca_file %s: no certificates found", o.CAFile)
		}
	}
	proxy := http.ProxyFromEnvironment
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, fmt.Errorf("sender: proxy: %w", err)
		}
		proxy = http.ProxyURL(pu)
	}
	tr := &http.Transport{
		Proxy:               proxy,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     5 * time.Minute,
		DisableCompression:  true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// Enqueue queues a payload. It never blocks on the network.
func (s *Sender) Enqueue(p sanitize.SanitizedPayload) {
	s.mu.Lock()
	if s.spoolMode || len(s.mem) >= s.o.MemQueue {
		s.spillLocked()
		s.spoolPut(p)
	} else {
		s.mem = append(s.mem, p)
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// spillLocked moves the memory queue to the spool and keeps spooling until
// the spool drains, so send order is preserved.
func (s *Sender) spillLocked() {
	for _, p := range s.mem {
		s.spoolPut(p)
	}
	s.mem = nil
	s.spoolMode = true
}

func (s *Sender) spoolPut(p sanitize.SanitizedPayload) {
	gz, err := codec.Gzip(p.Bytes())
	if err == nil {
		err = s.o.Spool.Put(p.Seq(), p.Part(), p.Events() > 0, gz)
	}
	if err != nil {
		s.o.Log.Error("spool write failed, payload dropped", "seq", p.Seq(), "err", err)
	}
}

// Queued is the number of payloads waiting in memory and on disk.
func (s *Sender) Queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mem) + s.o.Spool.Len()
}

type item struct {
	p         sanitize.SanitizedPayload
	spoolName string
}

// head returns the next payload in send order: the spool first, then memory.
func (s *Sender) head() (item, bool) {
	for {
		s.mu.Lock()
		if !s.spoolMode {
			defer s.mu.Unlock()
			if len(s.mem) == 0 {
				return item{}, false
			}
			return item{p: s.mem[0]}, true
		}
		s.mu.Unlock()

		e, gz, ok, err := s.o.Spool.Oldest()
		if !ok {
			s.mu.Lock()
			if s.o.Spool.Len() == 0 {
				s.spoolMode = false
			}
			s.mu.Unlock()
			continue
		}
		if err == nil {
			var body []byte
			if body, err = codec.Gunzip(gz, proto.MaxDecompressedBytes); err == nil {
				var p sanitize.SanitizedPayload
				if p, err = s.o.Barrier.Restore(body); err == nil {
					return item{p: p, spoolName: e.Name}, true
				}
			}
		}
		s.o.Log.Error("unreadable spool file dropped", "file", e.Name, "err", err)
		s.o.Spool.Remove(e.Name)
	}
}

// done removes a sent (or dropped) payload from wherever it now lives.
func (s *Sender) done(it item) {
	if it.spoolName != "" {
		s.o.Spool.Remove(it.spoolName)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mem) > 0 && s.mem[0].Seq() == it.p.Seq() && s.mem[0].Part() == it.p.Part() {
		s.mem = s.mem[1:]
		return
	}
	// It was spilled to the spool while in flight.
	s.o.Spool.RemoveSeq(it.p.Seq(), it.p.Part())
}

// replace puts the two halves of a split payload where the original was.
func (s *Sender) replace(it item, a, b sanitize.SanitizedPayload) {
	if it.spoolName != "" {
		s.spoolPut(a)
		s.spoolPut(b)
		s.o.Spool.Remove(it.spoolName)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mem) > 0 && s.mem[0].Seq() == it.p.Seq() && s.mem[0].Part() == 0 {
		s.mem = append([]sanitize.SanitizedPayload{a, b}, s.mem[1:]...)
		return
	}
	s.o.Spool.RemoveSeq(it.p.Seq(), 0)
	s.spoolPut(a)
	s.spoolPut(b)
}

type outcome int

const (
	accepted outcome = iota
	drop
	split
	pause
	retryAfter
	backoff
)

type result struct {
	kind    outcome
	wait    time.Duration
	notice  string
	dropped []proto.DroppedEvent
	err     error
}

// Run sends until ctx is done.
func (s *Sender) Run(ctx context.Context) {
	for ctx.Err() == nil {
		it, ok := s.head()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
				continue
			}
		}
		if wait := s.attempt(ctx, it); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
	}
}

// Drain tries to send what is queued until ctx is done or a send fails,
// then spools the rest (spec A1: at most 5 s at shutdown).
func (s *Sender) Drain(ctx context.Context) {
	for ctx.Err() == nil {
		it, ok := s.head()
		if !ok || s.attempt(ctx, it) > 0 {
			break
		}
	}
	s.mu.Lock()
	if len(s.mem) > 0 {
		s.spillLocked()
	}
	s.mu.Unlock()
}

// attempt sends one payload and returns how long to wait before the next try.
func (s *Sender) attempt(ctx context.Context, it item) time.Duration {
	r := s.send(ctx, it.p)
	if r.notice != "" && r.notice != s.lastNotice {
		s.o.Log.Warn("server notice", "notice", r.notice)
	}
	s.lastNotice = r.notice
	switch r.kind {
	case accepted:
		for _, d := range r.dropped {
			s.o.Log.Warn("event dropped by the server", "seq", it.p.Seq(), "id", d.ID, "code", d.Code)
		}
		s.done(it)
		s.backoff, s.failingSince = s.o.MinBackoff, time.Time{}
		if s.o.OnAccepted != nil {
			s.o.OnAccepted(it.p)
		}
		return 0
	case drop:
		s.o.Log.Error("payload rejected by server and dropped", "seq", it.p.Seq(), "part", it.p.Part(), "err", r.err)
		s.done(it)
		return 0
	case split:
		a, b, err := s.o.Barrier.Split(it.p)
		if err != nil {
			s.o.Log.Error("payload too large and cannot be split, dropped", "seq", it.p.Seq(), "err", err)
			s.done(it)
			return 0
		}
		s.replace(it, a, b)
		return 0
	case pause:
		s.o.Log.Warn("Xnux refused the agent key; sending paused, collection continues", "err", r.err, "retry_in", s.o.PauseRetry)
		s.failing()
		return s.o.PauseRetry
	case retryAfter:
		s.failing()
		return r.wait
	default:
		s.o.Log.Warn("send failed, will retry", "seq", it.p.Seq(), "err", r.err, "retry_in", s.backoff)
		s.failing()
		wait := jitter(s.backoff)
		s.backoff = min(2*s.backoff, s.o.MaxBackoff)
		return wait
	}
}

// failing records a failure and spools the memory queue once failures have
// lasted SpillAfter.
func (s *Sender) failing() {
	now := time.Now()
	if s.failingSince.IsZero() {
		s.failingSince = now
		return
	}
	if now.Sub(s.failingSince) >= s.o.SpillAfter {
		s.mu.Lock()
		if len(s.mem) > 0 {
			s.spillLocked()
		}
		s.mu.Unlock()
	}
}

// jitter spreads d by ±20%.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // jitter, not crypto
}

func (s *Sender) send(ctx context.Context, p sanitize.SanitizedPayload) result {
	gz, err := codec.Gzip(p.Bytes())
	if err != nil {
		return result{kind: drop, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(gz))
	if err != nil {
		return result{kind: backoff, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+s.o.Token)
	req.Header.Set("User-Agent", fmt.Sprintf("xnux-agent/%s (linux; %s)", s.o.Version, runtime.GOARCH))
	req.Header.Set(proto.HeaderSeq, strconv.FormatUint(p.Seq(), 10))
	req.Header.Set(proto.HeaderSchema, strconv.Itoa(proto.SchemaVersion))

	resp, err := s.client.Do(req)
	if err != nil {
		return result{kind: backoff, err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch code := resp.StatusCode; code {
	case http.StatusAccepted:
		var ack proto.IngestResponse
		_ = json.Unmarshal(body, &ack)
		return result{kind: accepted, notice: ack.Notice, dropped: ack.DroppedEvents}
	case http.StatusBadRequest:
		return result{kind: drop, err: fmt.Errorf("400: %s", truncate(body))}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict:
		return result{kind: pause, err: fmt.Errorf("%d: %s", code, truncate(body))}
	case http.StatusRequestEntityTooLarge:
		return result{kind: split}
	case http.StatusTooManyRequests:
		wait := s.backoff
		if sec, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && sec > 0 {
			wait = time.Duration(sec) * time.Second
		}
		return result{kind: retryAfter, wait: min(wait, s.o.MaxBackoff)}
	default:
		return result{kind: backoff, err: fmt.Errorf("%d: %s", code, truncate(body))}
	}
}

func truncate(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return strings.TrimSpace(string(b))
}

// Probe checks that the endpoint answers over HTTP(S) at all; any response
// status counts as reachable. It sends no payload and needs no spool.
func Probe(ctx context.Context, o Options) (int, error) {
	client, err := newClient(o)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(o.Endpoint, "/")+proto.IngestPath, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("xnux-agent/%s (linux; %s)", o.Version, runtime.GOARCH))
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

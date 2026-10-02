// Package batch packs metrics and events into payloads, assigns their seq
// and seals them (spec A5.2).
package batch

import (
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/codec"
)

// MaxMetrics triggers a flush when reached.
const MaxMetrics = 500

// Options configure a Batcher.
type Options struct {
	Barrier      *sanitize.Barrier
	NextSeq      func() uint64
	AgentVersion string
	MachineFP    string
	// Diag, if set, is attached to every payload.
	Diag func() *proto.Diag
	Now  func() time.Time
	// Limits default to the protocol limits (spec A7.1).
	MaxCompressed, MaxRaw int
}

// Batcher is not safe for concurrent use.
type Batcher struct {
	o       Options
	metrics []proto.Metric
	events  []proto.Event
	host    *proto.Host
	summary *proto.SecuritySummary
	failed  []string // non-nil when the failed-unit list goes with the next payload
}

func New(o Options) *Batcher {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxCompressed == 0 {
		o.MaxCompressed = proto.MaxCompressedBytes
	}
	if o.MaxRaw == 0 {
		o.MaxRaw = proto.MaxDecompressedBytes
	}
	return &Batcher{o: o}
}

// AddMetric queues a sample and reports whether the batch is full.
func (b *Batcher) AddMetric(m proto.Metric) (full bool) {
	b.metrics = append(b.metrics, m)
	return len(b.metrics) >= MaxMetrics
}

// AddEvent queues an event; the caller flushes shortly after.
func (b *Batcher) AddEvent(e proto.Event) { b.events = append(b.events, e) }

// SetHost attaches host info to the next payload.
func (b *Batcher) SetHost(h proto.Host) { b.host = &h }

// SetSecuritySummary attaches the hourly security summary to the next payload.
func (b *Batcher) SetSecuritySummary(s *proto.SecuritySummary) { b.summary = s }

// SetServicesFailed attaches the list of failed units to the next payload;
// an empty list is sent as such.
func (b *Batcher) SetServicesFailed(units []string) {
	b.failed = append(make([]string, 0, len(units)), units...)
}

// Pending reports whether anything is waiting to be flushed.
func (b *Batcher) Pending() bool {
	return len(b.metrics) > 0 || len(b.events) > 0 || b.host != nil || b.summary != nil || b.failed != nil
}

// Flush builds, seals and returns the pending payload, split into parts if
// it exceeds the size limits. With heartbeat, an empty batch still yields a
// header-only payload. Nothing pending and no heartbeat returns nil.
func (b *Batcher) Flush(heartbeat bool) ([]sanitize.SanitizedPayload, error) {
	if !b.Pending() && !heartbeat {
		return nil, nil
	}
	p := &proto.Payload{
		V:            proto.SchemaVersion,
		Seq:          b.o.NextSeq(),
		SentAt:       b.o.Now().Unix(),
		AgentVersion: b.o.AgentVersion,
		MachineFP:    b.o.MachineFP,
		Host:         b.host,
		Metrics:      b.metrics,
		Events:       b.events,
		Redactions:   map[string]int{},

		SecuritySummary: b.summary,
		ServicesFailed:  b.failed,
	}
	if b.o.Diag != nil {
		p.Diag = b.o.Diag()
	}
	b.metrics, b.events, b.host, b.summary, b.failed = nil, nil, nil, nil, nil

	sp, err := b.o.Barrier.Seal(p)
	if err != nil {
		return nil, err
	}
	if b.fits(sp) {
		return []sanitize.SanitizedPayload{sp}, nil
	}
	// Split parts carry the same seq with part = 1, 2, … (spec A5.2).
	var out []sanitize.SanitizedPayload
	for i, r := range b.splitAll(p) {
		r.Part = i + 1
		sp, err := b.o.Barrier.Seal(r)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, nil
}

func (b *Batcher) fits(sp sanitize.SanitizedPayload) bool {
	if len(sp.Bytes()) > b.o.MaxRaw {
		return false
	}
	gz, err := codec.Gzip(sp.Bytes())
	return err == nil && len(gz) <= b.o.MaxCompressed
}

// splitAll halves p until every piece fits; events come first.
func (b *Batcher) splitAll(p *proto.Payload) []*proto.Payload {
	x, y, ok := proto.Split(p)
	if !ok {
		return []*proto.Payload{p} // cannot shrink further; the server decides
	}
	y.Redactions = map[string]int{}
	var out []*proto.Payload
	for _, q := range []*proto.Payload{x, y} {
		if sp, err := b.o.Barrier.Seal(q); err == nil && b.fits(sp) {
			out = append(out, q)
		} else {
			out = append(out, b.splitAll(q)...)
		}
	}
	return out
}

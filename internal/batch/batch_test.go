package batch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"
)

func newBatcher(t *testing.T, o Options) *Batcher {
	t.Helper()
	br, err := sanitize.New(sanitize.Options{})
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(100)
	o.Barrier = br
	o.NextSeq = func() uint64 { seq++; return seq }
	o.AgentVersion, o.MachineFP = "1.0.0", "0123456789abcdef"
	o.Now = func() time.Time { return time.Unix(1790000000, 0) }
	return New(o)
}

func decode(t *testing.T, sp sanitize.SanitizedPayload) proto.Payload {
	var p proto.Payload
	if err := json.Unmarshal(sp.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFlushPacksAndClears(t *testing.T) {
	b := newBatcher(t, Options{})
	if out, _ := b.Flush(false); out != nil {
		t.Fatal("empty flush must return nothing")
	}
	b.SetHost(proto.Host{Hostname: "h", OS: "o", Kernel: "k", Arch: "amd64"})
	b.AddMetric(proto.Metric{TS: 1})
	b.AddMetric(proto.Metric{TS: 2})
	out, err := b.Flush(false)
	if err != nil || len(out) != 1 {
		t.Fatalf("flush: %v %v", out, err)
	}
	p := decode(t, out[0])
	if p.Seq != 101 || p.SentAt != 1790000000 || len(p.Metrics) != 2 || p.Host == nil || p.Part != 0 {
		t.Fatalf("payload = %+v", p)
	}
	if b.Pending() {
		t.Fatal("batch not cleared")
	}
	hb, _ := b.Flush(true)
	if len(hb) != 1 || decode(t, hb[0]).Seq != 102 || hb[0].Metrics() != 0 {
		t.Fatal("heartbeat must be a header-only payload with a new seq")
	}
}

func TestFullAt500(t *testing.T) {
	b := newBatcher(t, Options{})
	for i := 1; i < MaxMetrics; i++ {
		if b.AddMetric(proto.Metric{TS: int64(i)}) {
			t.Fatalf("full at %d", i)
		}
	}
	if !b.AddMetric(proto.Metric{TS: 500}) {
		t.Fatal("want full at 500")
	}
}

func TestSplitWhenTooLarge(t *testing.T) {
	b := newBatcher(t, Options{MaxRaw: 2000})
	b.AddEvent(proto.Event{ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", Type: "oom_kill", Severity: "P1", Count: 1, Key: "k",
		Data: map[string]any{"x": strings.Repeat("a", 500)}})
	for i := range 40 {
		b.AddMetric(proto.Metric{TS: int64(i), Mem: proto.Mem{TotalMB: 1024}})
	}
	out, err := b.Flush(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 3 {
		t.Fatalf("want several parts, got %d", len(out))
	}
	metrics := 0
	for i, sp := range out {
		p := decode(t, sp)
		if p.Seq != 101 || p.Part != i+1 || len(sp.Bytes()) > 2000 {
			t.Fatalf("part %d: seq %d part %d size %d", i, p.Seq, p.Part, len(sp.Bytes()))
		}
		if i == 0 && len(p.Events) != 1 {
			t.Fatal("events must be in the first part")
		}
		metrics += len(p.Metrics)
	}
	if metrics != 40 {
		t.Fatalf("lost metrics: %d", metrics)
	}
}

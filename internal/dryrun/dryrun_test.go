package dryrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"
)

func payload(t *testing.T) sanitize.SanitizedPayload {
	b, _ := sanitize.New(sanitize.Options{})
	p, err := b.Seal(&proto.Payload{V: 1, Seq: 42, SentAt: 1, AgentVersion: "1", MachineFP: "0123456789abcdef",
		Host: &proto.Host{Hostname: "h", OS: "x", Kernel: "k", Arch: "amd64"},
		Events: []proto.Event{{ID: "01JABCD7XK4R2N5Q8V3W6Y9Z0E", Type: "oom_kill", Severity: "P1", Count: 1, Key: "k",
			Data: map[string]any{"cmd": "mysql password=abc from 8.8.8.8"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlainIsValidJSON(t *testing.T) {
	var out, sum bytes.Buffer
	pr, err := New(&out, &sum, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := pr.Print(payload(t)); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("not JSON:\n%s", out.String())
	}
	if !strings.HasPrefix(sum.String(), "seq=42 size=") || !strings.Contains(sum.String(), "redactions={ipv4:1,kv_secret:1}") {
		t.Fatalf("summary = %q", sum.String())
	}
}

func TestColor(t *testing.T) {
	var out, sum bytes.Buffer
	pr, _ := New(&out, &sum, true)
	_ = pr.Print(payload(t))
	s := out.String()
	for _, want := range []string{cyan + `"seq"` + reset, yellow + "42" + reset, markerOn + "[REDACTED:secret]" + reset, markerOn + "8.8.8.x" + reset} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

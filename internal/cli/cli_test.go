package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xyfu/xnux-agent/internal/localstore"
)

func TestEditConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	orig := "# comment\ninterval_seconds: 15\ncollectors:\n  token: nested\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := editConfig(path, map[string]string{"token": "xat_abc", "endpoint": "https://w.example"}, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	for _, want := range []string{`token: "xat_abc"`, `endpoint: "https://w.example"`, "# comment", "interval_seconds: 15", "  token: nested"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if err := editConfig(path, map[string]string{"token": "xat_new"}, nil); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Count(string(b), "xat_") != 1 || !strings.Contains(string(b), `token: "xat_new"`) {
		t.Fatalf("replace:\n%s", b)
	}
	if err := editConfig(path, nil, []string{"token", "endpoint"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "xat_") || strings.Contains(string(b), "endpoint") || !strings.Contains(string(b), "  token: nested") {
		t.Fatalf("remove:\n%s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestSeriesShowsGaps(t *testing.T) {
	var mins []localstore.Minute
	for i := int64(0); i < 10; i++ {
		if i == 4 || i == 5 {
			continue // agent stopped
		}
		mins = append(mins, localstore.Minute{TS: 6000 + i*60, CPU: float64(i * 10)})
	}
	var b bytes.Buffer
	series(&b, "cpu %", mins, func(m localstore.Minute) *float64 { v := m.CPU; return &v }, nil, 6000, 60)
	line := b.String()
	if !strings.Contains(line, "▁▁▂▃  ▅▆▇█") {
		t.Fatalf("got %q", line)
	}
	if !strings.HasSuffix(line, "0.0 / 45.0 / 90.0\n") {
		t.Fatalf("stats: %q", line)
	}
}

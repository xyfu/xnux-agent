package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `
token: "xat_abcdefghijklmnop"
endpoint: "https://ingest.xnux.net"
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.IntervalSeconds != 15 || c.FlushSeconds != 60 || !c.Sanitize.MaskEmail || !c.Collectors.Metrics {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestParseOverridesAndFalseBools(t *testing.T) {
	c, err := Parse([]byte(minimal + `
interval_seconds: 30
sanitize:
  mask_email: false
collectors:
  kmsg: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.IntervalSeconds != 30 || c.Sanitize.MaskEmail || c.Collectors.Kmsg || !c.Collectors.Metrics {
		t.Fatalf("overrides wrong: %+v", c)
	}
}

func TestExampleFileParses(t *testing.T) {
	b, err := os.ReadFile("../../deploy/agent.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if _, err := Parse([]byte(s)); err != nil {
		t.Fatalf("deploy/agent.yaml.example: %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"bad token":      "token: abc\nendpoint: https://x",
		"bad endpoint":   "token: xat_1\nendpoint: ftp://x",
		"interval range": minimal + "interval_seconds: 5",
		"flush range":    minimal + "flush_seconds: 500",
		"bad regex":      minimal + "sanitize:\n  extra_patterns: ['(']",
		"unknown field":  minimal + "bogus: 1",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// Without a token the agent runs standalone (spec v1.1 delta 2).
func TestStandalone(t *testing.T) {
	for _, y := range []string{"", `endpoint: "https://x"`} {
		c, err := Parse([]byte(y))
		if err != nil || !c.Standalone() || c.Endpoint == "" {
			t.Errorf("%q: %+v %v", y, c, err)
		}
	}
	c, warns, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil || !c.Standalone() || len(warns) != 1 {
		t.Errorf("missing file: %v %v", warns, err)
	}
	if c, _ := Parse([]byte(minimal)); c.Standalone() {
		t.Error("token given, still standalone")
	}
}

func TestLoadWarnsOnLoosePermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}
	_, warns, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("want 1 warning, got %v", warns)
	}
}

func TestPrintableMasksToken(t *testing.T) {
	c, _ := Parse([]byte(minimal))
	out := c.Printable()
	if strings.Contains(out, "abcdefghijkl") || !strings.Contains(out, "****mnop") {
		t.Fatalf("token not masked:\n%s", out)
	}
}

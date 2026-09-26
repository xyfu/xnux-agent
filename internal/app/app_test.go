package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/mirror"
)

type ingest struct {
	mu     sync.Mutex
	down   bool
	bodies [][]byte
	seqs   []uint64
}

func (s *ingest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	zr, _ := gzip.NewReader(r.Body)
	body, _ := io.ReadAll(zr)
	var p proto.Payload
	_ = json.Unmarshal(body, &p)
	s.bodies = append(s.bodies, body)
	s.seqs = append(s.seqs, p.Seq)
	w.WriteHeader(http.StatusAccepted)
}

func setup(t *testing.T, endpoint string) Options {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	y := "token: xat_apptest\nendpoint: " + endpoint + "\nsanitize:\n  extra_patterns: ['xnux-secret-\\d+']\n"
	if err := os.WriteFile(cfg, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are short (108 bytes): not under t.TempDir().
	sock, err := os.MkdirTemp("", "xa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sock) })
	return Options{ConfigPath: cfg, Version: "1.0.0-test", StateDir: filepath.Join(dir, "lib"),
		LogDir: filepath.Join(dir, "log"), Stdout: io.Discard, Stderr: io.Discard, Socket: filepath.Join(sock, "a.sock")}
}

func TestOnceDeliversAndMirrors(t *testing.T) {
	srv := &ingest{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	o := setup(t, ts.URL)
	o.Once = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(srv.bodies) != 1 {
		t.Fatalf("server got %d payloads", len(srv.bodies))
	}
	var p proto.Payload
	if err := json.Unmarshal(srv.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Host == nil || len(p.Metrics) != 1 || p.AgentVersion != "1.0.0-test" || len(p.MachineFP) != 16 {
		t.Fatalf("payload = %s", srv.bodies[0])
	}
	// The mirror hash equals the hash of what the server received.
	sum, err := os.ReadFile(filepath.Join(o.LogDir, mirror.HashName))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(srv.bodies[0])
	if strings.TrimSpace(string(sum)) != hex.EncodeToString(h[:]) {
		t.Fatal("mirror sha256 differs from the received body")
	}
	// Seq is persisted: the next run continues.
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if srv.seqs[1] <= srv.seqs[0] {
		t.Fatalf("seq did not advance: %v", srv.seqs)
	}
}

func TestOutageSpoolsThenRecovers(t *testing.T) {
	srv := &ingest{down: true}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	o := setup(t, ts.URL)

	// Daemon mode against a dead server: the registration payload ends up in
	// the spool at shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, o) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(o.StateDir, "spool", "*.json.gz"))
	if len(files) == 0 {
		t.Fatal("nothing spooled")
	}
	logb, _ := os.ReadFile(filepath.Join(o.LogDir, "agent.log"))
	if !bytes.Contains(logb, []byte("agent started")) {
		t.Fatalf("agent.log:\n%s", logb)
	}

	srv.mu.Lock()
	srv.down = false
	srv.mu.Unlock()
	o.Once = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(srv.seqs) != len(files)+1 {
		t.Fatalf("got seqs %v, want %d payloads", srv.seqs, len(files)+1)
	}
	for i := 1; i < len(srv.seqs); i++ {
		if srv.seqs[i] <= srv.seqs[i-1] {
			t.Fatalf("out of order: %v", srv.seqs)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(o.StateDir, "spool", "*.json.gz")); len(left) != 0 {
		t.Fatalf("spool not drained: %v", left)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	o := setup(t, "http://127.0.0.1:1") // nothing listens; must not be contacted
	o.DryRun, o.Once = true, true
	var out bytes.Buffer
	o.Stdout = &out
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// The real payload must satisfy the protocol schema (F0-2).
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(proto.SchemaV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("ingest.v1.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("ingest.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("dry-run output is not JSON: %v\n%s", err, out.String())
	}
	if err := schema.Validate(inst); err != nil {
		t.Fatalf("payload violates the schema: %v\n%s", err, out.String())
	}
	for _, d := range []string{o.StateDir, o.LogDir} {
		if _, err := os.Stat(d); err == nil {
			t.Fatalf("dry-run created %s", d)
		}
	}
}

func TestPrintConfigMasksToken(t *testing.T) {
	o := setup(t, "https://x.example")
	o.PrintConfig = true
	var out bytes.Buffer
	o.Stdout = &out
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "xat_apptest") || !strings.Contains(out.String(), "****test") {
		t.Fatalf("print-config:\n%s", out.String())
	}
}

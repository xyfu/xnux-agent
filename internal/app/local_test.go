package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/xyfu/xnux-agent/internal/ipc"
)

// F11-1, F11-5: standalone opens no connection; connect switches to
// uploading without a restart, and the first upload follows at once;
// disconnect goes back.
func TestStandaloneConnectDisconnect(t *testing.T) {
	srv := &ingest{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	o := setup(t, ts.URL)
	if err := os.WriteFile(o.ConfigPath, []byte("endpoint: "+ts.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, o) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	var c *ipc.Client
	var err error
	for i := 0; i < 100; i++ {
		if c, err = ipc.Dial(o.Socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var st struct {
		Mode     string
		Endpoint string
		Health   struct{ State string }
	}
	if err := c.Call("status", nil, &st); err != nil || st.Mode != "standalone" || st.Endpoint != "" || st.Health.State != "collecting" {
		t.Fatalf("status: %+v %v", st, err)
	}
	var next json.RawMessage
	if err := c.Call("payload", map[string]string{"which": "next"}, &next); err != nil || !json.Valid(next) {
		t.Fatalf("payload --next: %s %v", next, err)
	}
	var evs []any
	if err := c.Call("events", nil, &evs); err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := c.Call("top", nil, &top); err != nil || top["mode"] != "standalone" {
		t.Fatalf("top: %v %v", top, err)
	}
	time.Sleep(200 * time.Millisecond)
	srv.mu.Lock()
	n := len(srv.bodies)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("standalone agent uploaded %d payloads", n)
	}

	// connect
	if err := os.WriteFile(o.ConfigPath, []byte("token: xat_apptest\nendpoint: "+ts.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("reload", nil, &st); err != nil || st.Mode != "connected" || st.Endpoint != ts.URL {
		t.Fatalf("after connect: %+v %v", st, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		srv.mu.Lock()
		n = len(srv.bodies)
		srv.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no upload after connect")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// disconnect
	if err := os.WriteFile(o.ConfigPath, []byte("endpoint: "+ts.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("reload", nil, &st); err != nil || st.Mode != "standalone" {
		t.Fatalf("after disconnect: %+v %v", st, err)
	}
	var last json.RawMessage
	if err := c.Call("payload", map[string]string{"which": "last"}, &last); err != nil || !json.Valid(last) {
		t.Fatalf("payload --last: %v", err)
	}
}

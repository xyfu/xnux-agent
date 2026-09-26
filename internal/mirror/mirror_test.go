package mirror

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"
)

func seal(t *testing.T, seq uint64) sanitize.SanitizedPayload {
	b, _ := sanitize.New(sanitize.Options{})
	p, err := b.Seal(&proto.Payload{V: 1, Seq: seq, SentAt: 1, AgentVersion: "1", MachineFP: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteAndHistory(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := m.Write(seal(t, seq)); err != nil {
			t.Fatal(err)
		}
	}
	last := seal(t, 3)
	got, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !strings.Contains(string(got), `"seq": 3`) {
		t.Fatalf("mirror content:\n%s", got)
	}
	sum, _ := os.ReadFile(filepath.Join(dir, HashName))
	h := sha256.Sum256(last.Bytes())
	if strings.TrimSpace(string(sum)) != hex.EncodeToString(h[:]) {
		t.Fatal("sha256 must be of the raw body bytes")
	}
	fi, _ := os.Stat(filepath.Join(dir, FileName))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	hist, _ := os.ReadDir(filepath.Join(dir, HistoryDir))
	if len(hist) != 2 || hist[0].Name() != "00000000000000000002.json" {
		t.Fatalf("history = %v", hist)
	}
}

// Package mirror writes the last outgoing payload and its sha256 to
// /var/log/xnux so users can audit what was sent (spec A8.2).
package mirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/xyfu/xnux-shared/sanitize"

	"github.com/xyfu/xnux-agent/internal/fsutil"
)

const (
	FileName    = "last_outgoing_payload.json"
	HashName    = "last_outgoing_payload.sha256"
	HistoryDir  = "outgoing"
	filePerm    = 0o600
	historyPerm = 0o700
)

// Mirror is used from the sender goroutine only.
type Mirror struct {
	dir     string
	history int
}

// New writes into dir, keeping the newest history payloads under
// dir/outgoing when history > 0.
func New(dir string, history int) (*Mirror, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if history > 0 {
		if err := os.MkdirAll(filepath.Join(dir, HistoryDir), historyPerm); err != nil {
			return nil, err
		}
	}
	return &Mirror{dir: dir, history: history}, nil
}

// Sum is the sha256 of the uncompressed body, the same value the server's
// audit console shows.
func Sum(p sanitize.SanitizedPayload) string {
	h := sha256.Sum256(p.Bytes())
	return hex.EncodeToString(h[:])
}

// Write records p after the server accepted it.
func (m *Mirror) Write(p sanitize.SanitizedPayload) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, p.Bytes(), "", "  "); err != nil {
		return err
	}
	pretty.WriteByte('\n')
	if err := fsutil.WriteFileAtomic(filepath.Join(m.dir, FileName), pretty.Bytes(), filePerm); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(m.dir, HashName), []byte(Sum(p)+"\n"), filePerm); err != nil {
		return err
	}
	if m.history <= 0 {
		return nil
	}
	name := fmt.Sprintf("%020d", p.Seq())
	if p.Part() > 0 {
		name += fmt.Sprintf(".%d", p.Part())
	}
	hdir := filepath.Join(m.dir, HistoryDir)
	if err := fsutil.WriteFileAtomic(filepath.Join(hdir, name+".json"), pretty.Bytes(), filePerm); err != nil {
		return err
	}
	return m.prune(hdir)
}

func (m *Mirror) prune(hdir string) error {
	des, err := os.ReadDir(hdir)
	if err != nil {
		return err
	}
	var names []string
	for _, de := range des {
		if filepath.Ext(de.Name()) == ".json" {
			names = append(names, de.Name())
		}
	}
	sort.Strings(names)
	for len(names) > m.history {
		_ = os.Remove(filepath.Join(hdir, names[0]))
		names = names[1:]
	}
	return nil
}

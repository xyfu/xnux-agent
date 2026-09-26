package alog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xyfu/xnux-shared/sanitize"
)

func TestRedactsMessageAndAttrs(t *testing.T) {
	b, _ := sanitize.New(sanitize.Options{})
	var buf bytes.Buffer
	l := New(&buf, b, 0)
	l.Info("login from 8.8.8.8 password=hunter2", "err", errors.New("dial 1.2.3.4: token=abc"), "url", "https://u:p@x.io")
	out := buf.String()
	for _, leak := range []string{"8.8.8.8", "hunter2", "1.2.3.4", "abc", "u:p@"} {
		if strings.Contains(out, leak) {
			t.Errorf("leak %q in %s", leak, out)
		}
	}
}

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.log")
	r, err := OpenRotating(p, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	read := func(name string) string { b, _ := os.ReadFile(name); return string(b) }
	if read(p) != "dddddddd\n" || read(p+".1") != "cccccccc\n" || read(p+".2") != "bbbbbbbb\n" {
		t.Fatalf("rotation: %q %q %q", read(p), read(p+".1"), read(p+".2"))
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("kept too many files")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

package spool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOrderAndReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, DefaultMax, DefaultMaxEvents)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Put(12, 0, false, []byte("b"))
	_ = s.Put(9, 0, true, []byte("a"))
	_ = s.Put(12000000000, 2, false, []byte("d"))
	_ = s.Put(12000000000, 1, true, []byte("c"))

	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode())
	}
	s2, err := Open(dir, DefaultMax, DefaultMaxEvents)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		e, b, ok, err := s2.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, b...)
		s2.Remove(e.Name)
	}
	if string(got) != "abcd" {
		t.Fatalf("order = %q", got)
	}
	if s2.Len() != 0 || s2.Size() != 0 {
		t.Fatal("not empty")
	}
}

func TestEvictionKeepsEvents(t *testing.T) {
	s, _ := Open(t.TempDir(), 10, 20)
	blob := bytes.Repeat([]byte("x"), 4)
	_ = s.Put(1, 0, true, blob)  // events
	_ = s.Put(2, 0, false, blob) // metrics
	_ = s.Put(3, 0, false, blob) // total 12 > 10: evict seq 2
	if s.Len() != 2 || s.Evicted() != 1 {
		t.Fatalf("len %d evicted %d", s.Len(), s.Evicted())
	}
	e, _, _, _ := s.Oldest()
	if e.Seq != 1 || !e.HasEvents {
		t.Fatalf("oldest = %+v", e)
	}
	// Metric-only files go first; events are kept until the events limit.
	_ = s.Put(4, 0, true, blob)
	_ = s.Put(5, 0, true, blob)
	_ = s.Put(6, 0, true, blob)
	_ = s.Put(7, 0, true, blob) // 24 bytes: seq 3 (metrics) is evicted
	if e, _, _, _ := s.Oldest(); e.Seq != 1 {
		t.Fatalf("event file evicted before metric file: oldest %+v", e)
	}
	_ = s.Put(8, 0, true, blob) // 24 bytes, only events left: seq 1 goes
	if s.Size() > 20 {
		t.Fatalf("size %d over events limit", s.Size())
	}
	e, _, _, _ = s.Oldest()
	if e.Seq == 1 {
		t.Fatal("oldest event file should have been evicted")
	}
}

func TestIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "123.json.gz"), []byte("x"), 0o600)
	s, err := Open(dir, DefaultMax, DefaultMaxEvents)
	if err != nil || s.Len() != 0 {
		t.Fatalf("len %d err %v", s.Len(), err)
	}
}

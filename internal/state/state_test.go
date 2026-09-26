package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFreshSaveReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	a, b := s.NextSeq(), s.NextSeq()
	if a < uint64(time.Now().Add(-time.Minute).UnixMilli()) || b != a+1 {
		t.Fatalf("fresh seq = %d, %d; want unix ms, consecutive", a, b)
	}
	s.Update(func(d *Data) { d.DiskGrowth = map[string][][2]int64{"/": {{1, 100}}} })
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.NextSeq(); got != b+1 {
		t.Fatalf("reloaded seq = %d, want %d", got, b+1)
	}
	s2.View(func(d *Data) {
		if d.DiskGrowth["/"][0][1] != 100 {
			t.Fatalf("disk growth lost: %+v", d.DiskGrowth)
		}
	})
}

func TestCorruptIsMovedAsideAndSeqStaysAhead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".corrupt"); err != nil {
		t.Fatal("corrupt file not preserved")
	}
	if seq := s.NextSeq(); seq < uint64(time.Now().Add(-time.Minute).UnixMilli()) {
		t.Fatalf("seq %d not reset to unix ms", seq)
	}
}

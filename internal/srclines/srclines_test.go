package srclines

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCacheLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := Cache{}
	lines, ok := c.Lines(path)
	if !ok {
		t.Fatalf("Lines(%q) ok = false, want true", path)
	}
	want := []string{"one", "two", "three"}
	if len(lines) != len(want) {
		t.Fatalf("Lines(%q) = %q, want %q", path, lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}

	// The read is memoized: a rewrite of the file must not be observed through
	// the same Cache (pass-scoped staleness is the documented contract).
	if err := os.WriteFile(path, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines2, ok := c.Lines(path)
	if !ok || len(lines2) != 3 || lines2[0] != "one" {
		t.Errorf("second Lines(%q) = %q, %v; want memoized first read", path, lines2, ok)
	}
}

func TestCacheLinesUnreadable(t *testing.T) {
	c := Cache{}
	missing := filepath.Join(t.TempDir(), "nope.txt")
	for i := 0; i < 2; i++ { // second lookup exercises the cached-miss path
		lines, ok := c.Lines(missing)
		if ok || lines != nil {
			t.Fatalf("Lines(missing) attempt %d = %q, %v; want nil, false", i+1, lines, ok)
		}
	}
	if entry, present := c[missing]; !present || entry != nil {
		t.Errorf("missing file not recorded as nil cache entry (present=%v, entry=%v)", present, entry)
	}
}

// TestCacheLinesEmptyFile pins that an empty-but-readable file is a hit (one
// empty line), distinct from an unreadable file — consumers branch on ok, and
// an empty file must not degrade like a read error.
func TestCacheLinesEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c := Cache{}
	lines, ok := c.Lines(path)
	if !ok {
		t.Fatalf("Lines(empty) ok = false, want true")
	}
	if len(lines) != 1 || lines[0] != "" {
		t.Errorf("Lines(empty) = %q, want one empty line", lines)
	}
}

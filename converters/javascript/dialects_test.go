package js_converter

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDialectsAllConvert asserts that every JavaScript dialect in
// testdata/dialects lowers without being dropped.
//
// This exists because the frontend used to pick its parse strategy from the file
// EXTENSION, and a wrong guess cost the whole file: ES modules in a .js failed at
// the import, Flow annotations failed at the first `:`, and both were discovered
// only by scanning a real project and noticing the findings were missing. The
// per-file skip is silent by design (one bad file must not sink a scan), so
// nothing else in the suite fails when a dialect stops parsing — coverage still
// reported ok while 165 of parse-server's 192 files were being dropped.
//
// Each file below is a dialect that reached production and is legal input. Adding
// one here is how a newly-encountered dialect gets locked in; a failure means the
// loader ladder needs another rung, not that the fixture is wrong.
func TestDialectsAllConvert(t *testing.T) {
	dir := filepath.Join("testdata", "dialects")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dialects dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no dialect fixtures found")
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			path := filepath.Join(dir, e.Name())
			mod, _, err := NewConverter().convertJSFile(path, "dialect")
			if err != nil {
				t.Fatalf("%s failed to convert: %v", e.Name(), err)
			}
			if mod == nil {
				t.Fatalf("%s converted to a nil module", e.Name())
			}
		})
	}
}

// TestKnownGapDialectsFailCleanly pins the dialects that genuinely cannot be
// lowered today, so they stay VISIBLE instead of blending into the background of
// per-file skips.
//
// Top-level await is the current member: it is only expressible in ES-module
// output, and the lowering consumes CommonJS, so esbuild rejects it in every
// format goja can read. That is a structural limit, not a missing rung on the
// loader ladder — no amount of loader-guessing fixes it.
//
// The assertion is that the failure is CLEAN (an error, not a panic or a silently
// empty module). If one of these starts converting, this test fails, which is the
// signal to move the fixture into testdata/dialects where it will be held to the
// stronger guarantee.
func TestKnownGapDialectsFailCleanly(t *testing.T) {
	dir := filepath.Join("testdata", "dialects_known_gaps")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read known-gaps dir: %v", err)
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			mod, _, err := NewConverter().convertJSFile(filepath.Join(dir, e.Name()), "gap")
			if err == nil {
				t.Fatalf("%s now converts (mod=%v) — move it into testdata/dialects", e.Name(), mod != nil)
			}
		})
	}
}

// TestDialectsScanReportsFullCoverage is the end-to-end half: converting the
// directory must skip nothing. It guards the count the scan layer reports as
// coverage, which is what makes a partially-dropped project visible.
func TestDialectsScanReportsFullCoverage(t *testing.T) {
	c := NewConverter()
	if _, err := c.ConvertFile(filepath.Join("testdata", "dialects")); err != nil {
		t.Fatalf("ConvertFile(dialects): %v", err)
	}
	if c.Skipped() != 0 {
		t.Errorf("Skipped() = %d, want 0 — a dialect stopped parsing; see the loader ladder", c.Skipped())
	}
}

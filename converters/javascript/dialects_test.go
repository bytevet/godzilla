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
// one here is how a newly-encountered dialect gets locked in; a failure means
// parseLadder needs another rung, not that the fixture is wrong.
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

// TestDialectsScanReportsFullCoverage is the end-to-end half: converting the
// directory must skip nothing. It guards the count the scan layer reports as
// coverage, which is what makes a partially-dropped project visible.
func TestDialectsScanReportsFullCoverage(t *testing.T) {
	c := NewConverter()
	if _, err := c.ConvertFile(filepath.Join("testdata", "dialects")); err != nil {
		t.Fatalf("ConvertFile(dialects): %v", err)
	}
	if c.Skipped() != 0 {
		t.Errorf("Skipped() = %d, want 0 — a dialect stopped parsing; see parseLadder", c.Skipped())
	}
}

// TestConvertCorpusTreeSkipsOnlyBroken pins the skip count over the whole JS
// corpus at exactly one — resilience/broken.js, which is deliberately
// unparseable.
//
// This is the only place a ladder regression surfaces at all. A batch errors
// only when ZERO files convert, so a rung that stops matching leaves Converted
// true and Failed() empty; the corpus assertions then pass for every sample
// still being read, and the dropped one simply has no findings to miss.
func TestConvertCorpusTreeSkipsOnlyBroken(t *testing.T) {
	c := NewConverter()
	if _, err := c.ConvertFile(filepath.Join("..", "..", "test", "js")); err != nil {
		t.Fatalf("ConvertFile(test/js): %v", err)
	}
	if c.Skipped() != 1 {
		t.Errorf("Skipped() = %d, want 1 (only resilience/broken.js)", c.Skipped())
	}
}

// TestLadderOrderKeepsRelationalArgs pins the rung ORDER, which is load-bearing
// in a way no parse error reveals.
//
// `f(a < b, c > (d))` is legal under BOTH the JS and TS rungs, and they disagree
// about what it means: JS reads two relational arguments, TS reads one argument
// with a type-argument list. Try TS first and an argument — and whatever taint
// flowed through it — silently leaves the IR, with nothing failing to parse.
// A .js file is JavaScript until proven otherwise, so the plain rung goes first.
func TestLadderOrderKeepsRelationalArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relational.js")
	if err := os.WriteFile(path, []byte("sink(a < b, c > (d));\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mod, _, err := NewConverter().convertJSFile(path, "relational")
	if err != nil {
		t.Fatalf("convertJSFile: %v", err)
	}
	args := -1
	for _, fn := range mod.Functions {
		for _, b := range fn.Blocks {
			for _, in := range b.Instrs {
				if in.GetCall().GetCallee() == "js:sink" {
					args = len(in.GetCall().GetArgs())
				}
			}
		}
	}
	if args != 2 {
		t.Errorf("js:sink lowered with %d args, want 2 — the TS rung ran first and ate one", args)
	}
}

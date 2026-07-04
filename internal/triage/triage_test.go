package triage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

func findingAt(rule, file string, line int32) analysis.Finding {
	return analysis.Finding{
		RuleID:     rule,
		Function:   "f",
		SinkCallee: "sink",
		SinkPos:    &ir.Position{Filename: file, Line: line, Column: 1},
	}
}

func TestApplyInlineIgnores_BareAndScoped(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.go")
	// line 1: plain sink (no directive)
	// line 2: sink with a bare ignore on the same line
	// line 3: directive line (scoped), line 4: the sink it protects
	// line 5: scoped ignore for a DIFFERENT rule, line 6: sink (must NOT suppress)
	content := "" +
		"exec(a)\n" +
		"exec(b) // godzilla:ignore\n" +
		"// godzilla:ignore[go-cmdi]\n" +
		"exec(c)\n" +
		"// godzilla:ignore[other-rule]\n" +
		"exec(d)\n"
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := []analysis.Finding{
		findingAt("go-cmdi", src, 1), // no directive -> active
		findingAt("go-cmdi", src, 2), // bare, same line -> suppressed
		findingAt("go-cmdi", src, 4), // scoped match on line above -> suppressed
		findingAt("go-cmdi", src, 6), // scoped for another rule -> active
	}
	out := ApplyInlineIgnores(findings)

	want := []bool{false, true, true, false}
	for i, w := range want {
		if out[i].Suppressed != w {
			t.Errorf("finding %d (line %d): Suppressed=%v want %v", i, out[i].SinkPos.GetLine(), out[i].Suppressed, w)
		}
		if out[i].Suppressed && out[i].SuppressedBy != "inline" {
			t.Errorf("finding %d: SuppressedBy=%q want inline", i, out[i].SuppressedBy)
		}
	}
}

func TestBaseline_RoundTripSuppressesKnownFindings(t *testing.T) {
	findings := []analysis.Finding{
		findingAt("r1", "a.go", 10),
		findingAt("r2", "b.go", 20),
	}

	var buf bytes.Buffer
	if err := WriteBaseline(&buf, findings); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}

	dir := t.TempDir()
	bpath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(bpath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	fps, err := LoadBaseline(bpath)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	// A rerun with the SAME findings plus a NEW one: the two baselined findings
	// are suppressed; the new one stays active.
	rerun := []analysis.Finding{
		findingAt("r1", "a.go", 10),
		findingAt("r2", "b.go", 20),
		findingAt("r3", "c.go", 30), // new
	}
	out := ApplyBaseline(rerun, fps)

	active := map[string]bool{}
	for _, f := range out {
		if !f.Suppressed {
			active[f.RuleID] = true
		} else if f.SuppressedBy != "baseline" {
			t.Errorf("%s suppressed by %q, want baseline", f.RuleID, f.SuppressedBy)
		}
	}
	if len(active) != 1 || !active["r3"] {
		t.Errorf("expected only the NEW finding r3 to gate, active=%v", active)
	}
}

func TestBaseline_FingerprintStableAcrossLineShift(t *testing.T) {
	// The same finding at a different LINE must keep its fingerprint (baseline
	// survives edits elsewhere in the file).
	a := findingAt("r1", "a.go", 10)
	b := findingAt("r1", "a.go", 42) // moved down
	if analysis.Fingerprint(a) != analysis.Fingerprint(b) {
		t.Errorf("fingerprint must be line-independent: %s != %s", analysis.Fingerprint(a), analysis.Fingerprint(b))
	}
	// A different rule at the same spot must differ.
	c := findingAt("r2", "a.go", 10)
	if analysis.Fingerprint(a) == analysis.Fingerprint(c) {
		t.Errorf("fingerprint must depend on the rule")
	}
}

func TestBaseline_DuplicateIsMultiset(t *testing.T) {
	// Two identical findings, but the baseline knows only one: exactly one is
	// suppressed, so a genuinely-new duplicate still surfaces.
	base := []analysis.Finding{findingAt("r1", "a.go", 10)}
	var buf bytes.Buffer
	_ = WriteBaseline(&buf, base)
	dir := t.TempDir()
	bpath := filepath.Join(dir, "b.json")
	_ = os.WriteFile(bpath, buf.Bytes(), 0o644)
	fps, _ := LoadBaseline(bpath)

	rerun := []analysis.Finding{
		findingAt("r1", "a.go", 10),
		findingAt("r1", "a.go", 99), // same fingerprint (line-independent), NEW occurrence
	}
	out := ApplyBaseline(rerun, fps)
	suppressed := 0
	for _, f := range out {
		if f.Suppressed {
			suppressed++
		}
	}
	if suppressed != 1 {
		t.Errorf("multiset baseline must suppress exactly one of two identical findings, got %d", suppressed)
	}
}

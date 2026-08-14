package analysis

import (
	"slices"
	"testing"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// TestCompareFindings pins the pipeline-wide display order the CLI and all
// three report writers share: worst severity first, then sink location with
// filename/line/column compared NUMERICALLY (line 9 before line 10 — not the
// lexical order where "10" < "9"), and nil (unknown) sink positions last
// within their severity.
func TestCompareFindings(t *testing.T) {
	pos := func(file string, line, col int32) *ir.Position {
		return &ir.Position{Filename: file, Line: line, Column: col}
	}
	f := func(sev rules.Severity, p *ir.Position) Finding {
		return Finding{Severity: sev, SinkPos: p}
	}

	want := []Finding{
		f(rules.SeverityHigh, nil),                   // worst severity first, even without a position
		f(rules.SeverityMedium, pos("a.go", 2, 1)),   // line 2 before line 10 (numeric, not lexical)
		f(rules.SeverityMedium, pos("a.go", 9, 7)),   // line 9 before line 10
		f(rules.SeverityMedium, pos("a.go", 10, 1)),  // column ties broken numerically too
		f(rules.SeverityMedium, pos("a.go", 10, 12)), // column 12 after column 1
		f(rules.SeverityMedium, pos("b.go", 1, 1)),   // filename before line
		f(rules.SeverityMedium, nil),                 // nil position last within its severity
		f(rules.SeverityLow, pos("a.go", 1, 1)),      // lower severity after nil-pos Medium
	}

	got := slices.Clone(want)
	slices.Reverse(got)
	slices.SortStableFunc(got, CompareFindings)

	for i := range want {
		if got[i].Severity != want[i].Severity || PosString(got[i].SinkPos) != PosString(want[i].SinkPos) {
			t.Errorf("position %d: got %s @ %s, want %s @ %s",
				i, got[i].Severity, PosString(got[i].SinkPos), want[i].Severity, PosString(want[i].SinkPos))
		}
	}
}

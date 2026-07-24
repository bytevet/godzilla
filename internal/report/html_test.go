package report

import (
	"bytes"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

func TestWriteHTML(t *testing.T) {
	findings := []analysis.Finding{
		{
			RuleID:     "GO-SQL-INJECTION",
			Severity:   rules.SeverityCritical,
			Confidence: analysis.ConfidenceHigh,
			CWE:        "CWE-89",
			Message:    "tainted value flows into SQL query",
			Language:   "go",
			Function:   "main.handler",
			SourcePos: &ir.Position{
				Filename: "handler.go",
				Line:     10,
				Column:   5,
			},
			SinkPos: &ir.Position{
				Filename: "handler.go",
				Line:     42,
				Column:   9,
			},
			SinkCallee: "go:database/sql.(*DB).Query",
		},
		{
			RuleID:     "GO-PATH-TRAVERSAL",
			Severity:   rules.SeverityMedium,
			Confidence: analysis.ConfidenceMedium,
			CWE:        "CWE-22",
			// Deliberately includes an HTML metacharacter payload to prove
			// html/template escapes finding content instead of trusting it.
			Message:    "path built from request data: <script>alert(1)</script>",
			Language:   "go",
			Function:   "main.readFile",
			SourcePos:  nil,
			SinkPos:    nil,
			SinkCallee: "go:os.Open",
		},
		{
			RuleID:     "GO-WEAK-RANDOM",
			Severity:   rules.SeverityLow,
			Confidence: analysis.ConfidenceLow,
			CWE:        "CWE-330",
			Message:    "use of math/rand for security-sensitive value",
			Language:   "go",
			Function:   "main.token",
			SinkCallee: "go:math/rand.Int",
		},
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, findings); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	out := buf.String()

	if out == "" {
		t.Fatal("WriteHTML produced empty output")
	}
	if !strings.HasPrefix(out, "<!DOCTYPE html>") && !strings.Contains(out, "<html") {
		t.Fatalf("output does not look like an HTML document; got prefix: %q", out[:min(80, len(out))])
	}

	if !strings.Contains(out, "Godzilla SAST Report") {
		t.Error("output missing report title")
	}

	for _, id := range []string{"GO-SQL-INJECTION", "GO-PATH-TRAVERSAL", "GO-WEAK-RANDOM"} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing rule ID %q", id)
		}
	}

	for _, sev := range []string{"CRITICAL", "MEDIUM", "LOW"} {
		if !strings.Contains(out, sev) {
			t.Errorf("output missing severity label %q", sev)
		}
	}

	// html/template must escape the malicious message content: the raw
	// payload must never appear, but its escaped form must.
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("output contains unescaped <script> payload; report is XSS-able")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("output missing escaped form of the script payload")
	}
}

func TestWriteHTML_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, nil); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings.") {
		t.Error("expected empty-state message for zero findings")
	}
	if !strings.Contains(out, "Total findings: <strong>0</strong>") {
		t.Error("expected total count of 0 in summary")
	}
}

func TestWriteHTML_TaintFlow(t *testing.T) {
	withSteps := analysis.Finding{
		RuleID:     "GO-SQL-INJECTION",
		Severity:   rules.SeverityHigh,
		Confidence: analysis.ConfidenceHigh,
		CWE:        "CWE-89",
		Message:    "tainted value flows into SQL query",
		Language:   "go",
		Function:   "main.handler",
		SourcePos:  &ir.Position{Filename: "h.go", Line: 10, Column: 5},
		SinkPos:    &ir.Position{Filename: "h.go", Line: 42, Column: 9},
		SinkCallee: "go:database/sql.(*DB).Query",
		Steps: []*ir.Position{
			{Filename: "h.go", Line: 10, Column: 5},
			{Filename: "h.go", Line: 25, Column: 3},
			{Filename: "h.go", Line: 42, Column: 9},
		},
	}
	endpointsOnly := analysis.Finding{
		RuleID:     "GO-CMD-INJECTION",
		Severity:   rules.SeverityHigh,
		Confidence: analysis.ConfidenceMedium,
		CWE:        "CWE-78",
		Message:    "cross-function flow",
		Language:   "go",
		Function:   "main.run",
		SourcePos:  &ir.Position{Filename: "a.go", Line: 3, Column: 1},
		SinkPos:    &ir.Position{Filename: "b.go", Line: 7, Column: 1},
		SinkCallee: "go:os/exec.Command",
		// no Steps
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, []analysis.Finding{withSteps, endpointsOnly}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Taint spread flow") {
		t.Error("expected a taint spread flow section")
	}
	// The reconstructed intra-procedural path renders each step location.
	for _, loc := range []string{"h.go:10:5", "h.go:25:3", "h.go:42:9"} {
		if !strings.Contains(out, loc) {
			t.Errorf("taint flow missing step location %q", loc)
		}
	}
	// The endpoints-only finding must carry the fallback note.
	if !strings.Contains(out, "Endpoints only") {
		t.Error("expected an endpoints-only note for a finding without reconstructed steps")
	}
}

// TestWriteHTML_NoUnsafeInterpolation guards the invariant that finding-derived
// text never lands inside the inline <script>: it is only ever rendered into
// the DOM through html/template's auto-escaping. A JS-breaking payload in a
// finding message must appear nowhere inside the script block.
func TestWriteHTML_NoUnsafeInterpolation(t *testing.T) {
	payload := `"};alert(document.cookie);//`
	var buf bytes.Buffer
	if err := WriteHTML(&buf, []analysis.Finding{{
		RuleID:     "GO-XSS",
		Severity:   rules.SeverityHigh,
		Confidence: analysis.ConfidenceHigh,
		CWE:        "CWE-79",
		Message:    payload,
		Language:   "go",
		Function:   "main.h",
		SinkCallee: "go:fmt.Fprintf",
	}}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	start := strings.LastIndex(out, "<script>")
	end := strings.LastIndex(out, "</script>")
	if start == -1 || end == -1 || end < start {
		t.Fatal("could not locate inline <script> block")
	}
	script := out[start:end]
	if strings.Contains(script, "alert(document.cookie)") {
		t.Error("finding-derived payload leaked into the inline <script> block")
	}
	// The payload must not appear raw anywhere (it is escaped in the DOM).
	if strings.Contains(out, payload) {
		t.Error("raw finding payload appears unescaped in the report")
	}
}

func TestCaretFor(t *testing.T) {
	cases := []struct {
		line string
		col  int32
		want string
	}{
		{"abcd", 3, "  ^"},      // 1-based col 3 → two spaces then caret
		{"\tx = f()", 2, "\t^"}, // tab preserved so the caret aligns under a tab-indented line
		{"abc", 0, ""},          // unknown column → no caret
		{"abc", 1, "^"},         // first column
		{"ab", 9, "  ^"},        // column past end clamps to line length
	}
	for _, c := range cases {
		if got := caretFor(c.line, c.col); got != c.want {
			t.Errorf("caretFor(%q, %d) = %q, want %q", c.line, c.col, got, c.want)
		}
	}
}

func TestFormatPosition(t *testing.T) {
	if got := analysis.PosString(nil); got != "<unknown>" {
		t.Errorf("PosString(nil) = %q, want %q", got, "<unknown>")
	}

	pos := &ir.Position{Filename: "foo.go", Line: 3, Column: 7}
	if got, want := analysis.PosString(pos), "foo.go:3:7"; got != want {
		t.Errorf("PosString(%+v) = %q, want %q", pos, got, want)
	}
}

func TestSeverityOrdering(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "LOW-1", Severity: rules.SeverityLow, Confidence: analysis.ConfidenceLow, SinkCallee: "x"},
		{RuleID: "CRIT-1", Severity: rules.SeverityCritical, Confidence: analysis.ConfidenceHigh, SinkCallee: "y"},
		{RuleID: "HIGH-1", Severity: rules.SeverityHigh, Confidence: analysis.ConfidenceHigh, SinkCallee: "z"},
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, findings); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}
	out := buf.String()

	critIdx := strings.Index(out, "CRIT-1")
	highIdx := strings.Index(out, "HIGH-1")
	lowIdx := strings.Index(out, "LOW-1")
	if critIdx == -1 || highIdx == -1 || lowIdx == -1 {
		t.Fatalf("expected all rule IDs present, got critIdx=%d highIdx=%d lowIdx=%d", critIdx, highIdx, lowIdx)
	}
	if critIdx >= highIdx || highIdx >= lowIdx {
		t.Errorf("expected findings ordered critical < high < low in output, got positions %d, %d, %d", critIdx, highIdx, lowIdx)
	}
}

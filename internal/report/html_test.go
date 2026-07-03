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

func TestFormatPosition(t *testing.T) {
	if got := formatPosition(nil); got != "<unknown>" {
		t.Errorf("formatPosition(nil) = %q, want %q", got, "<unknown>")
	}

	pos := &ir.Position{Filename: "foo.go", Line: 3, Column: 7}
	if got, want := formatPosition(pos), "foo.go:3:7"; got != want {
		t.Errorf("formatPosition(%+v) = %q, want %q", pos, got, want)
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

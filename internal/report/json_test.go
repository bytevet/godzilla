package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

func sampleFindings() []analysis.Finding {
	return []analysis.Finding{
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
			Message:    "path built from request data",
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
			SinkPos: &ir.Position{
				Filename: "token.go",
				Line:     7,
				Column:   2,
			},
			SinkCallee: "go:math/rand.Int",
		},
	}
}

func TestWriteJSON(t *testing.T) {
	findings := sampleFindings()

	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var doc struct {
		Tool     string `json:"tool"`
		Findings []struct {
			RuleID     string `json:"ruleId"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			CWE        string `json:"cwe"`
			Message    string `json:"message"`
			Language   string `json:"language"`
			Function   string `json:"function"`
			SinkCallee string `json:"sinkCallee"`
			Source     *struct {
				File   string `json:"file"`
				Line   int32  `json:"line"`
				Column int32  `json:"column"`
			} `json:"source"`
			Sink *struct {
				File   string `json:"file"`
				Line   int32  `json:"line"`
				Column int32  `json:"column"`
			} `json:"sink"`
		} `json:"findings"`
	}

	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output did not round-trip through json.Unmarshal: %v\noutput: %s", err, buf.String())
	}

	if doc.Tool != "godzilla" {
		t.Errorf("doc.Tool = %q, want %q", doc.Tool, "godzilla")
	}

	if len(doc.Findings) != 3 {
		t.Fatalf("len(doc.Findings) = %d, want 3", len(doc.Findings))
	}

	// Sorted worst-severity-first: critical, medium, low.
	wantOrder := []string{"GO-SQL-INJECTION", "GO-PATH-TRAVERSAL", "GO-WEAK-RANDOM"}
	for i, want := range wantOrder {
		if doc.Findings[i].RuleID != want {
			t.Errorf("doc.Findings[%d].RuleID = %q, want %q", i, doc.Findings[i].RuleID, want)
		}
	}

	// The critical finding has a fully-populated sink location.
	sqlFinding := doc.Findings[0]
	if sqlFinding.Sink == nil {
		t.Fatal("expected sink location for GO-SQL-INJECTION, got nil")
	}
	if sqlFinding.Sink.File != "handler.go" || sqlFinding.Sink.Line != 42 || sqlFinding.Sink.Column != 9 {
		t.Errorf("sink location = %+v, want {handler.go 42 9}", sqlFinding.Sink)
	}
	if sqlFinding.Source == nil {
		t.Fatal("expected source location for GO-SQL-INJECTION, got nil")
	}
	if sqlFinding.Source.File != "handler.go" || sqlFinding.Source.Line != 10 {
		t.Errorf("source location = %+v, want file handler.go line 10", sqlFinding.Source)
	}

	// The path traversal finding has nil positions; they must marshal to
	// JSON null, not zero-value objects.
	pathFinding := doc.Findings[1]
	if pathFinding.Source != nil {
		t.Errorf("expected nil source for GO-PATH-TRAVERSAL, got %+v", pathFinding.Source)
	}
	if pathFinding.Sink != nil {
		t.Errorf("expected nil sink for GO-PATH-TRAVERSAL, got %+v", pathFinding.Sink)
	}
}

func TestWriteJSON_NilSourceDoesNotCrash(t *testing.T) {
	findings := []analysis.Finding{
		{
			RuleID:     "GO-WEAK-RANDOM",
			Severity:   rules.SeverityLow,
			Confidence: analysis.ConfidenceLow,
			SinkCallee: "go:math/rand.Int",
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	raw := make(map[string]interface{})
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, nil); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var doc struct {
		Tool     string        `json:"tool"`
		Findings []interface{} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output did not round-trip through json.Unmarshal: %v", err)
	}
	if doc.Tool != "godzilla" {
		t.Errorf("doc.Tool = %q, want %q", doc.Tool, "godzilla")
	}
	if len(doc.Findings) != 0 {
		t.Errorf("len(doc.Findings) = %d, want 0", len(doc.Findings))
	}
}

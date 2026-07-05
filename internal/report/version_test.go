package report

import (
	"encoding/json"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// TestReportsStampVersion verifies the tool version and schema version reach both
// machine-readable reports (CI-8), so CI consumers can identify the producing
// binary and pin the format.
func TestReportsStampVersion(t *testing.T) {
	old := Version
	Version = "v1.2.3-test"
	defer func() { Version = old }()

	findings := []analysis.Finding{{
		RuleID:   "r",
		Severity: "high",
		SinkPos:  &ir.Position{Filename: "a.go", Line: 1, Column: 1},
	}}

	var jbuf strings.Builder
	if err := WriteJSON(&jbuf, findings); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc struct {
		ToolVersion   string `json:"toolVersion"`
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal([]byte(jbuf.String()), &doc); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if doc.ToolVersion != "v1.2.3-test" {
		t.Errorf("JSON toolVersion = %q, want v1.2.3-test", doc.ToolVersion)
	}
	if doc.SchemaVersion != "1" {
		t.Errorf("JSON schemaVersion = %q, want 1", doc.SchemaVersion)
	}

	var sbuf strings.Builder
	if err := WriteSARIF(&sbuf, findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(sbuf.String(), `"version": "v1.2.3-test"`) {
		t.Errorf("SARIF driver version not stamped:\n%s", sbuf.String())
	}
}

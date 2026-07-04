package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// suppressedFinding is a finding the LLM reviewer judged a false positive: it is
// retained but flagged, and must be surfaced (not hidden) in every report.
func suppressedFinding() analysis.Finding {
	return analysis.Finding{
		RuleID:            "GO-SSRF",
		Severity:          rules.SeverityHigh,
		Confidence:        analysis.ConfidenceMedium,
		CWE:               "CWE-918",
		Message:           "possible SSRF",
		Language:          "go",
		Function:          "main.fetch",
		SinkPos:           &ir.Position{Filename: "fetch.go", Line: 12, Column: 3},
		Suppressed:        true,
		SuppressedBy:      "llm-review",
		SuppressionReason: "host is a compile-time constant",
	}
}

func TestJSON_RetainsSuppressionMetadata(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []analysis.Finding{suppressedFinding()}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc struct {
		Findings []struct {
			RuleID            string `json:"ruleId"`
			Suppressed        bool   `json:"suppressed"`
			SuppressedBy      string `json:"suppressedBy"`
			SuppressionReason string `json:"suppressionReason"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected the suppressed finding to be retained, got %d", len(doc.Findings))
	}
	f := doc.Findings[0]
	if !f.Suppressed || f.SuppressedBy != "llm-review" || f.SuppressionReason == "" {
		t.Errorf("suppression metadata not preserved in JSON: %+v", f)
	}
}

func TestSARIF_EmitsSuppressionsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, []analysis.Finding{suppressedFinding()}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("expected one result, got runs=%d", len(doc.Runs))
	}
	sup := doc.Runs[0].Results[0].Suppressions
	if len(sup) != 1 || sup[0].Kind != "external" || sup[0].Justification == "" {
		t.Errorf("SARIF result missing a suppressions entry: %+v", sup)
	}
}

func TestSARIF_UnsuppressedHasNoSuppressions(t *testing.T) {
	var buf bytes.Buffer
	f := suppressedFinding()
	f.Suppressed = false
	f.SuppressedBy = ""
	f.SuppressionReason = ""
	if err := WriteSARIF(&buf, []analysis.Finding{f}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if strings.Contains(buf.String(), "\"suppressions\"") {
		t.Errorf("an active finding must not carry a suppressions array")
	}
}

func TestHTML_MarksSuppressedRow(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, []analysis.Finding{suppressedFinding()}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SUPPRESSED") || !strings.Contains(out, "class=\"suppressed\"") {
		t.Errorf("suppressed finding not visually marked in HTML report")
	}
}

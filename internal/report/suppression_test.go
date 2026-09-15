package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
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
	// A suppressed finding must be visually marked: the SUPPRESSED chip and a
	// "suppressed" class token on the finding card (combined with its severity
	// class, so we match the class token rather than a standalone attribute).
	if !strings.Contains(out, "SUPPRESSED") || !strings.Contains(out, " suppressed\"") {
		t.Errorf("suppressed finding not visually marked in HTML report")
	}
}

// TestHTML_SuppressedHiddenByDefault: a suppressed finding is kept, not
// dropped, but must not swell the headline severity counts the reader sees
// unfolded, and the list must render it already hidden — not only dimmed —
// so the default view shows live findings only.
func TestHTML_SuppressedHiddenByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, []analysis.Finding{suppressedFinding()}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `data-suppressed="1"`) {
		t.Error("suppressed row missing its data-suppressed marker")
	}
	if !strings.Contains(out, ` hidden`) {
		t.Error("a suppressed row must render hidden by default, not merely dimmed")
	}
	if !strings.Contains(out, "suppressed (1)") {
		t.Error("the reveal control must state how many findings it hides")
	}
	// The masthead verdict is a suppressed finding's whole severity: reporting
	// "1 high" here would repeat the exact false alarm suppression exists to
	// stop, right next to a list the reader is told is empty.
	if !strings.Contains(out, `<span class="verdict pass">`) {
		t.Error("a report with only a suppressed finding must read as a clean scan")
	}
}

// TestHTML_NoSuppressedControlWhenNoneSuppressed: the reveal toggle is only
// meaningful when something is hidden behind it.
func TestHTML_NoSuppressedControlWhenNoneSuppressed(t *testing.T) {
	var buf bytes.Buffer
	f := suppressedFinding()
	f.Suppressed, f.SuppressedBy, f.SuppressionReason = false, "", ""
	if err := WriteHTML(&buf, []analysis.Finding{f}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `id="f-sup"`) {
		t.Error("the suppressed-findings toggle rendered with nothing suppressed")
	}
	if strings.Contains(out, `<span class="verdict pass">`) {
		t.Error("a live high-severity finding must not read as a clean scan")
	}
}

func TestSARIF_EmitsCodeFlowFromSteps(t *testing.T) {
	f := analysis.Finding{
		RuleID:   "GO-SQLI",
		Severity: rules.SeverityHigh,
		Message:  "sqli",
		SinkPos:  &ir.Position{Filename: "h.go", Line: 42, Column: 3},
		Steps: []analysis.FlowStep{
			{Pos: &ir.Position{Filename: "h.go", Line: 10, Column: 5}, Func: "go:main.h", Kind: analysis.StepSource, InScope: true},
			{Pos: &ir.Position{Filename: "h.go", Line: 20, Column: 7}, Func: "go:main.h", Kind: analysis.StepStep, InScope: true},
			{Pos: &ir.Position{Filename: "h.go", Line: 42, Column: 3}, Func: "go:main.h", Kind: analysis.StepSink, InScope: true},
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, []analysis.Finding{f}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []struct {
							Location struct {
								PhysicalLocation struct{ Region struct{ StartLine int } }
							}
						} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cf := doc.Runs[0].Results[0].CodeFlows
	if len(cf) != 1 || len(cf[0].ThreadFlows) != 1 || len(cf[0].ThreadFlows[0].Locations) != 3 {
		t.Fatalf("expected a codeFlow with a 3-step threadFlow, got %+v", cf)
	}
}

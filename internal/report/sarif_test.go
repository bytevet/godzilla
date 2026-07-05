package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

func TestWriteSARIF(t *testing.T) {
	findings := sampleFindings()

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	if doc["version"] != "2.1.0" {
		t.Errorf(`doc["version"] = %v, want "2.1.0"`, doc["version"])
	}
	if doc["$schema"] == nil {
		t.Error(`doc["$schema"] missing`)
	}

	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]interface{})

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if driver["name"] != "Godzilla" {
		t.Errorf(`driver["name"] = %v, want "Godzilla"`, driver["name"])
	}

	rulesArr, ok := driver["rules"].([]interface{})
	if !ok {
		t.Fatalf("driver.rules is not an array: %v", driver["rules"])
	}

	wantRuleIDs := []string{"GO-SQL-INJECTION", "GO-PATH-TRAVERSAL", "GO-WEAK-RANDOM"}
	if len(rulesArr) != len(wantRuleIDs) {
		t.Fatalf("len(rules) = %d, want %d (distinct rule IDs)", len(rulesArr), len(wantRuleIDs))
	}
	ruleIndexByID := make(map[string]int)
	for i, r := range rulesArr {
		rm := r.(map[string]interface{})
		id, _ := rm["id"].(string)
		ruleIndexByID[id] = i
		if rm["name"] != id {
			t.Errorf("rule %d name = %v, want id %v", i, rm["name"], id)
		}
	}
	for _, id := range wantRuleIDs {
		if _, ok := ruleIndexByID[id]; !ok {
			t.Errorf("missing rule entry for %q", id)
		}
	}

	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 3 {
		t.Fatalf("expected 3 results, got %v", run["results"])
	}

	wantLevels := map[string]string{
		"GO-SQL-INJECTION":  "error",   // critical
		"GO-PATH-TRAVERSAL": "warning", // medium
		"GO-WEAK-RANDOM":    "note",    // low
	}

	sawRuleID := make(map[string]bool)
	for _, r := range results {
		rm := r.(map[string]interface{})
		ruleID, _ := rm["ruleId"].(string)
		sawRuleID[ruleID] = true

		wantLevel, ok := wantLevels[ruleID]
		if !ok {
			t.Fatalf("unexpected ruleId in results: %q", ruleID)
		}
		if rm["level"] != wantLevel {
			t.Errorf("result %q level = %v, want %v", ruleID, rm["level"], wantLevel)
		}

		// ruleIndex must point back at the matching rule.
		riFloat, ok := rm["ruleIndex"].(float64)
		if !ok {
			t.Fatalf("result %q ruleIndex missing or not a number: %v", ruleID, rm["ruleIndex"])
		}
		wantIndex := ruleIndexByID[ruleID]
		if int(riFloat) != wantIndex {
			t.Errorf("result %q ruleIndex = %v, want %d", ruleID, riFloat, wantIndex)
		}

		switch ruleID {
		case "GO-SQL-INJECTION":
			locs, ok := rm["locations"].([]interface{})
			if !ok || len(locs) != 1 {
				t.Fatalf("expected 1 location for %q, got %v", ruleID, rm["locations"])
			}
			loc := locs[0].(map[string]interface{})
			phys := loc["physicalLocation"].(map[string]interface{})
			artifact := phys["artifactLocation"].(map[string]interface{})
			if artifact["uri"] != "handler.go" {
				t.Errorf("sink uri = %v, want handler.go", artifact["uri"])
			}
			region := phys["region"].(map[string]interface{})
			if region["startLine"] != float64(42) {
				t.Errorf("sink startLine = %v, want 42", region["startLine"])
			}

			related, ok := rm["relatedLocations"].([]interface{})
			if !ok || len(related) != 1 {
				t.Fatalf("expected 1 related location for %q, got %v", ruleID, rm["relatedLocations"])
			}
			rl := related[0].(map[string]interface{})
			if rl["message"].(map[string]interface{})["text"] != "tainted source" {
				t.Errorf("related location message = %v, want %q", rl["message"], "tainted source")
			}

		case "GO-PATH-TRAVERSAL":
			// This finding has nil SourcePos and nil SinkPos: no crash, and
			// no location/relatedLocations should be emitted.
			if _, present := rm["locations"]; present {
				t.Errorf("expected no locations for %q with nil SinkPos, got %v", ruleID, rm["locations"])
			}
			if _, present := rm["relatedLocations"]; present {
				t.Errorf("expected no relatedLocations for %q with nil SourcePos, got %v", ruleID, rm["relatedLocations"])
			}
		}
	}
	for _, id := range wantRuleIDs {
		if !sawRuleID[id] {
			t.Errorf("missing result for rule %q", id)
		}
	}
}

func TestSARIFLevel(t *testing.T) {
	cases := []struct {
		sev  rules.Severity
		want string
	}{
		{rules.SeverityCritical, "error"},
		{rules.SeverityHigh, "error"},
		{rules.SeverityMedium, "warning"},
		{rules.SeverityLow, "note"},
		{rules.SeverityInfo, "note"},
		{rules.Severity("bogus"), "none"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.sev); got != c.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

// TestSARIFURI guards the GitHub-code-scanning contract: an absolute source
// path (as the Go SSA frontend emits) must be rewritten relative to the repo
// root, while relative paths pass through and separators are normalized to "/".
func TestSARIFURI(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	// Absolute path under the working directory -> repo-root-relative.
	abs := filepath.Join(cwd, "internal", "report", "sarif.go")
	if got, want := sarifURI(abs), "internal/report/sarif.go"; got != want {
		t.Errorf("sarifURI(absolute under cwd) = %q, want %q", got, want)
	}

	// Already-relative paths pass through unchanged (normalized to "/").
	if got, want := sarifURI("test/go/x/main.go"), "test/go/x/main.go"; got != want {
		t.Errorf("sarifURI(relative) = %q, want %q", got, want)
	}

	// Empty stays empty.
	if got := sarifURI(""); got != "" {
		t.Errorf("sarifURI(empty) = %q, want empty", got)
	}

	// An absolute path outside the working directory would relativize to a
	// "../" escape chain, which GitHub also rejects; keep it absolute instead.
	outside := filepath.Join(filepath.Dir(cwd), "somewhere-else", "main.go")
	if got := sarifURI(outside); got == "" || got[0] == '.' {
		t.Errorf("sarifURI(absolute outside cwd) = %q, should not be a ../ escape", got)
	}
}

func TestWriteSARIF_NilPositionsDoNotCrash(t *testing.T) {
	findings := []analysis.Finding{
		{
			RuleID:     "GO-WEAK-RANDOM",
			Severity:   rules.SeverityLow,
			Confidence: analysis.ConfidenceLow,
			SinkCallee: "go:math/rand.Int",
			SourcePos:  nil,
			SinkPos:    nil,
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestWriteSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs := doc["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]interface{})
	results, _ := run["results"].([]interface{})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// TestSARIFRuleMetadata checks the GitHub-integration metadata on rules[]
// (CI-4): security-severity, defaultConfiguration.level, shortDescription, and
// security tags.
func TestSARIFRuleMetadata(t *testing.T) {
	findings := []analysis.Finding{{
		RuleID: "go-sql-injection", Severity: rules.SeverityCritical, CWE: "CWE-89",
		Message: "SQL injection", SinkPos: &ir.Position{Filename: "a.go", Line: 1, Column: 1},
	}}
	var buf strings.Builder
	if err := WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ShortDescription     *struct{ Text string }  `json:"shortDescription"`
						DefaultConfiguration *struct{ Level string } `json:"defaultConfiguration"`
						Properties           struct {
							SecuritySeverity string   `json:"security-severity"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d run(s)", len(doc.Runs))
	}
	r := doc.Runs[0].Tool.Driver.Rules[0]
	if r.Properties.SecuritySeverity != "9.0" {
		t.Errorf("critical rule security-severity = %q, want 9.0", r.Properties.SecuritySeverity)
	}
	if r.DefaultConfiguration == nil || r.DefaultConfiguration.Level != "error" {
		t.Errorf("critical rule defaultConfiguration.level should be error, got %+v", r.DefaultConfiguration)
	}
	if r.ShortDescription == nil || r.ShortDescription.Text != "SQL injection" {
		t.Errorf("rule shortDescription not set from message, got %+v", r.ShortDescription)
	}
	hasSecurity := false
	for _, tag := range r.Properties.Tags {
		if tag == "security" {
			hasSecurity = true
		}
	}
	if !hasSecurity {
		t.Errorf("rule tags should include \"security\", got %v", r.Properties.Tags)
	}
}

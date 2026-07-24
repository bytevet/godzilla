package analysis

import (
	"strings"
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

func cmdiRuleSet(id string) *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:        id,
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os/exec",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     rules.SinksOf("go:*os/exec.Command*"),
	}}}
}

func analyzeGo(t *testing.T, path string, rs *rules.RuleSet) []Finding {
	t.Helper()
	prog, err := go_converter.NewConverter().ConvertFile(path)
	if err != nil {
		t.Fatalf("convert %s: %v", path, err)
	}
	return NewEngine(rs).Analyze(prog)
}

// TestFieldSensitivity_CleanFieldNotFlagged is the ENG-3 guard: tainting struct
// field A must not taint a read of the clean field B.
func TestFieldSensitivity_CleanFieldNotFlagged(t *testing.T) {
	findings := analyzeGo(t, "../../test/go/field_sensitive/main.go", cmdiRuleSet("GO-CMDI-FS"))
	for _, f := range findings {
		if f.RuleID == "GO-CMDI-FS" {
			t.Fatalf("field-insensitive FP: a clean field read was flagged (source %v -> sink %v)", f.SourcePos, f.SinkPos)
		}
	}
}

// TestFieldSensitivity_TaintedFieldStillFlagged guards the other direction:
// reading the TAINTED field must still fire (precision must not cost recall).
// The sql_injection sample's handler3 flows a tainted request param into a
// struct field (user.ID) and reads it in a method (u.ID) that hits a SQL sink;
// with the builtin rules that cross-function field flow must still be found.
func TestFieldSensitivity_TaintedFieldStillFlagged(t *testing.T) {
	// The sql_injection sample's handler3 exercises &User{ID: tainted} ->
	// user.GetByID() -> u.ID -> QueryRow, a cross-function struct-field flow.
	prog, err := go_converter.NewConverter().ConvertFile("../../test/go/sql_injection/main.go")
	if err != nil {
		t.Fatalf("convert sql_injection: %v", err)
	}
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-SQLI-FS",
		Languages: []string{"go"},
		Severity:  rules.SeverityHigh,
		CWE:       "CWE-89",
		Message:   "untrusted input reaches a SQL query",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     rules.SinksOf("go:*database/sql*.QueryRow", "go:*database/sql*.Query"),
	}}}
	findings := NewEngine(rs).Analyze(prog)
	// handler3: &User{ID: tainted} -> user.GetByID() -> u.ID -> QueryRow.
	var crossFn bool
	for _, f := range findings {
		if f.RuleID == "GO-SQLI-FS" && strings.Contains(f.SinkCallee, "QueryRow") {
			crossFn = true
		}
	}
	if !crossFn {
		t.Errorf("cross-function struct-field flow (user.ID -> u.ID -> QueryRow) was lost; field-sensitivity must not cost recall. got %d finding(s)", len(findings))
	}
}

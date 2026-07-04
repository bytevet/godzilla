// Package analysis implements Godzilla's taint analysis engine, which walks
// gIR programs and reports Findings for source-to-sink dataflows described by
// a rules.RuleSet. It performs inter-procedural taint tracking (taint flows
// across function-call boundaries via a call graph + function summaries) and
// assigns each finding a Confidence.
package analysis

import (
	"fmt"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Confidence expresses how certain the engine is that a finding is a true
// positive. Intra-procedural source->sink flows are High; flows that cross a
// function boundary (taint entering through a parameter) are Medium, since the
// context-insensitive summary merges all call sites and may over-approximate.
// Lower-confidence findings are the ones the (future) LLM reviewer triages.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Finding is a single reported vulnerability: a tainted value from some
// Source reaching a Sink without passing through a Sanitizer.
type Finding struct {
	RuleID     string
	Severity   rules.Severity
	Confidence Confidence
	CWE        string
	Message    string
	Language   string
	Function   string // enclosing function's CanonicalName
	SourcePos  *ir.Position
	SinkPos    *ir.Position
	SinkCallee string

	// Steps is the ordered taint path from source to sink (inclusive), when it
	// can be reconstructed intra-procedurally by walking the def-use chain. It
	// powers SARIF codeFlows (which GitHub code scanning renders as a data-flow)
	// and richer triage. Empty when only the endpoints are known (e.g. a flow
	// whose middle crossed a function boundary).
	Steps []*ir.Position

	// Suppressed marks a finding that a downstream triage stage (the LLM
	// reviewer) judged a false positive. A suppressed finding is RETAINED, not
	// discarded: it does not count toward the gate, but it stays visible in
	// reports with SuppressedBy/SuppressionReason so a nondeterministic model can
	// never silently erase a finding. Auditability over silent deletion.
	Suppressed        bool
	SuppressedBy      string // what suppressed it, e.g. "llm-review"
	SuppressionReason string // the reviewer's stated justification
}

// String renders a one-line human-readable summary of the finding.
func (f Finding) String() string {
	return fmt.Sprintf("[%s/%s/%s] %s: %s -> %s (%s) in %s at %s (source: %s)",
		f.RuleID, f.Severity, f.Confidence, f.CWE, f.Message, f.SinkCallee, f.Language,
		f.Function, formatPos(f.SinkPos), formatPos(f.SourcePos))
}

func formatPos(p *ir.Position) string {
	if p == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", p.GetFilename(), p.GetLine(), p.GetColumn())
}

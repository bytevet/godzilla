package analysis

import (
	"fmt"
	"strings"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Confidence expresses how certain the engine is that a finding is a true
// positive. Intra-procedural source->sink flows are High; flows that cross a
// function boundary (taint entering through a parameter) are Medium, since the
// context-insensitive summary merges all call sites and may over-approximate.
// Lower-confidence findings are the ones the LLM reviewer triages.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rank returns a comparable ordering for a confidence (higher is more
// certain): low=1, medium=2, high=3. Anything else — including a
// differently-cased spelling — ranks 0, which consumers treat as
// un-triageable: the LLM reviewer only reviews findings whose rank is
// positive and at/below its threshold. That is why ParseConfidence returns
// only the canonical lowercase constants.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceLow:
		return 1
	case ConfidenceMedium:
		return 2
	case ConfidenceHigh:
		return 3
	}
	return 0
}

// ParseConfidence maps a rule's declared `confidence:` spelling onto a
// Confidence, falling back to def for the empty (unset) string and for anything
// unrecognized — the loader already rejects a typo (rules.ValidConfidence), so a
// bad value here means a programmatically-built rule, and defaulting is safer
// than reporting a finding at a confidence nothing downstream understands. It
// deliberately returns only the canonical lowercase constants: Rank ranks any
// other string 0 and the LLM reviewer then never reviews the finding, which
// would look fine in the HTML report while being permanently un-triageable.
func ParseConfidence(s string, def Confidence) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ConfidenceLow):
		return ConfidenceLow
	case string(ConfidenceMedium):
		return ConfidenceMedium
	case string(ConfidenceHigh):
		return ConfidenceHigh
	}
	return def
}

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
	Package    string // enclosing function's package (for user-code scoping; see internal/scan)
	SourcePos  *ir.Position
	SinkPos    *ir.Position
	SinkCallee string

	// RuleSanitizers and RuleSources are the matched rule's sanitizer/source
	// globs, carried onto the finding so the LLM reviewer can adjudicate using the
	// rulepack's OWN vocabulary (which documented sanitizer neutralizes this sink,
	// what the sources are) instead of second-guessing from generic knowledge
	// (LLM-8). Not serialized in reports.
	RuleSanitizers []string
	RuleSources    []string

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

	// ReviewConfirmed marks a finding the LLM reviewer adjudicated as a TRUE
	// positive (kept, not suppressed); ReviewNote carries the reviewer's
	// exploitability/reasoning. This surfaces the value of a review on the
	// findings it KEEPS — a confirmed interprocedural finding is higher-priority
	// triage — instead of only recording the ones it drops (LLM-7).
	ReviewConfirmed bool
	ReviewNote      string
}

// String renders a one-line human-readable summary of the finding.
func (f Finding) String() string {
	return fmt.Sprintf("[%s/%s/%s] %s: %s -> %s (%s) in %s at %s (source: %s)",
		f.RuleID, f.Severity, f.Confidence, f.CWE, f.Message, f.SinkCallee, f.Language,
		f.Function, PosString(f.SinkPos), PosString(f.SourcePos))
}

// PosString renders an *ir.Position as "file:line:col", or "<unknown>" when p is
// nil. Shared by the CLI, the LLM reviewer, and the report writer so they all
// format positions identically.
func PosString(p *ir.Position) string {
	if p == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", p.GetFilename(), p.GetLine(), p.GetColumn())
}

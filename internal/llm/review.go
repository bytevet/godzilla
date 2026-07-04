// Package llm provides an optional, pluggable LLM-backed reviewer that
// adjudicates lower-confidence taint findings and discards likely false
// positives. It is the release valve for the project's "perfect signal/noise"
// goal: the deterministic analysis stays recall-oriented, and this stage trims
// residual false positives on the findings the engine was least sure about.
//
// This file is deliberately dependency-free (no Anthropic SDK import) so the
// filtering/prompt/parse logic is unit-testable on its own. The concrete
// Anthropic-backed Reviewer lives in anthropic.go.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// Verdict is a reviewer's judgment about a single finding.
type Verdict struct {
	FalsePositive bool
	Reason        string
}

// Reviewer adjudicates a finding, given some surrounding source context, and
// returns whether it judges the finding to be a false positive.
type Reviewer interface {
	Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error)
}

// ReviewStats summarizes one review pass for auditability. It lets the caller
// report exactly what the reviewer did — how many findings it adjudicated, how
// many it suppressed, how many it could not review — so a nondeterministic
// model's effect on the gate is never invisible.
type ReviewStats struct {
	Reviewed   int   // findings actually sent to the reviewer
	Suppressed int   // findings the reviewer judged false positives (retained, flagged)
	Errors     int   // reviewer errors (finding kept unreviewed, fail-open)
	LowContext int   // findings kept unreviewed because no code context was available
	FirstErr   error // first reviewer error, for a single actionable message
}

// Filter reviews every finding whose Confidence is at or below reviewUpTo. A
// finding the reviewer judges a false positive is RETAINED but marked
// Suppressed (with the reviewer's reason), not deleted — auditability over
// silent deletion. Findings above the threshold are passed through unreviewed.
//
// Two safety properties hold. Fail-open: on a reviewer error the finding is
// kept unreviewed — an LLM/network failure must never drop a real finding.
// Never-blind: a finding with no readable code context is kept unreviewed
// rather than judged on nothing, so an empty snippet can't cause a suppression.
//
// It returns all findings (surviving ones plus the suppressed-and-flagged ones)
// and a ReviewStats describing the pass.
func Filter(ctx context.Context, r Reviewer, findings []analysis.Finding, reviewUpTo analysis.Confidence) ([]analysis.Finding, ReviewStats) {
	var stats ReviewStats
	if r == nil {
		return findings, stats
	}
	out := make([]analysis.Finding, 0, len(findings))
	for _, f := range findings {
		if !shouldReview(f.Confidence, reviewUpTo) {
			out = append(out, f)
			continue
		}
		cc := codeContextFor(f)
		if strings.TrimSpace(cc) == "" {
			// No code to judge on: never adjudicate (and never drop) blind.
			stats.LowContext++
			out = append(out, f)
			continue
		}
		stats.Reviewed++
		v, err := r.Review(ctx, f, cc)
		if err != nil {
			stats.Errors++
			if stats.FirstErr == nil {
				stats.FirstErr = err
			}
			out = append(out, f) // fail open
			continue
		}
		if !v.FalsePositive {
			out = append(out, f)
			continue
		}
		f.Suppressed = true
		f.SuppressedBy = "llm-review"
		f.SuppressionReason = v.Reason
		stats.Suppressed++
		out = append(out, f)
	}
	return out, stats
}

// shouldReview reports whether a finding of confidence c should be sent to the
// reviewer, given that everything at or below reviewUpTo is reviewed.
func shouldReview(c, reviewUpTo analysis.Confidence) bool {
	cr := confidenceRank(c)
	return cr > 0 && cr <= confidenceRank(reviewUpTo)
}

func confidenceRank(c analysis.Confidence) int {
	switch c {
	case analysis.ConfidenceLow:
		return 1
	case analysis.ConfidenceMedium:
		return 2
	case analysis.ConfidenceHigh:
		return 3
	default:
		return 0
	}
}

// buildPrompt renders the adjudication prompt for a finding. It asks for a
// strict JSON verdict so parseVerdict can read it back reliably.
func buildPrompt(f analysis.Finding, codeContext string) string {
	var b strings.Builder
	b.WriteString("You are a security triage assistant reviewing a static-analysis (SAST) taint finding.\n")
	b.WriteString("Decide whether it is a TRUE positive (a real, exploitable vulnerability) or a FALSE positive.\n\n")
	fmt.Fprintf(&b, "Rule: %s\n", f.RuleID)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(&b, "CWE: %s\n", f.CWE)
	fmt.Fprintf(&b, "Message: %s\n", f.Message)
	fmt.Fprintf(&b, "Language: %s\n", f.Language)
	fmt.Fprintf(&b, "Function: %s\n", f.Function)
	fmt.Fprintf(&b, "Sink callee: %s\n", f.SinkCallee)
	fmt.Fprintf(&b, "Source location: %s\n", posString(f.SourcePos))
	fmt.Fprintf(&b, "Sink location: %s\n", posString(f.SinkPos))
	if len(f.Steps) >= 2 {
		b.WriteString("Taint path (source -> sink):\n")
		for _, p := range f.Steps {
			fmt.Fprintf(&b, "  - %s\n", posString(p))
		}
	}
	if strings.TrimSpace(codeContext) != "" {
		b.WriteString("\nCode context:\n")
		b.WriteString(codeContext)
		b.WriteString("\n")
	}
	b.WriteString("\nConsider whether the tainted data is actually attacker-controlled, whether an ")
	b.WriteString("effective sanitizer or validation sits on the path, and whether the sink is genuinely dangerous.\n")
	b.WriteString("Respond with ONLY a JSON object of the form ")
	b.WriteString(`{"verdict": "true_positive" | "false_positive", "reason": "<one sentence>"}.`)
	return b.String()
}

// buildAgenticPrompt renders the prompt for the tool-using reviewer. It states
// the finding (like buildPrompt) but instructs the model to gather evidence with
// the read-only tools before deciding — reading the callee, the sanitizer body,
// the route registration, or grepping for a validator — then emit the same
// strict JSON verdict. The safety default (unknown ⇒ true_positive) is stated
// so the reviewer never suppresses on thin evidence.
func buildAgenticPrompt(f analysis.Finding, codeContext string) string {
	var b strings.Builder
	b.WriteString("You are a security triage assistant reviewing a static-analysis (SAST) taint finding.\n")
	b.WriteString("You have read-only tools to investigate the code: read_file_range, find_function, and grep.\n")
	b.WriteString("Use them to trace the flow — read the tainted call's callee, any sanitizer or validation on the path, ")
	b.WriteString("the route/handler registration — before deciding. Do not guess when a tool can settle it.\n\n")
	fmt.Fprintf(&b, "Rule: %s\n", f.RuleID)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(&b, "CWE: %s\n", f.CWE)
	fmt.Fprintf(&b, "Message: %s\n", f.Message)
	fmt.Fprintf(&b, "Language: %s\n", f.Language)
	fmt.Fprintf(&b, "Function: %s\n", f.Function)
	fmt.Fprintf(&b, "Sink callee: %s\n", f.SinkCallee)
	fmt.Fprintf(&b, "Source location: %s\n", posString(f.SourcePos))
	fmt.Fprintf(&b, "Sink location: %s\n", posString(f.SinkPos))
	if len(f.Steps) >= 2 {
		b.WriteString("Taint path (source -> sink):\n")
		for _, p := range f.Steps {
			fmt.Fprintf(&b, "  - %s\n", posString(p))
		}
	}
	if strings.TrimSpace(codeContext) != "" {
		b.WriteString("\nInitial code context:\n")
		b.WriteString(codeContext)
		b.WriteString("\n")
	}
	b.WriteString("\nDecide whether this is a TRUE positive (a real, exploitable vulnerability) or a FALSE positive. ")
	b.WriteString("If the evidence is inconclusive, treat it as a true_positive (do not suppress on thin evidence).\n")
	b.WriteString("When done investigating, respond with ONLY a JSON object of the form ")
	b.WriteString(`{"verdict": "true_positive" | "false_positive", "reason": "<one sentence>"}.`)
	return b.String()
}

// parseVerdict extracts the JSON verdict from a model response. It tolerates
// surrounding prose by scanning for the outermost JSON object. When the verdict
// can't be determined it defaults to NOT a false positive (keep the finding).
func parseVerdict(text string) (Verdict, error) {
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return Verdict{}, fmt.Errorf("no JSON object in reviewer response")
	}
	var raw struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &raw); err != nil {
		return Verdict{}, fmt.Errorf("parsing reviewer response: %w", err)
	}
	v := Verdict{Reason: raw.Reason}
	switch strings.ToLower(strings.TrimSpace(raw.Verdict)) {
	case "false_positive", "false-positive", "false", "fp":
		v.FalsePositive = true
	default:
		v.FalsePositive = false // conservative: unrecognized => keep
	}
	return v, nil
}

// codeContextFor gathers the source lines the reviewer needs to judge a finding.
// When the finding carries a reconstructed taint path (Steps), it snippets code
// at EVERY hop along the path — so the reviewer can see any sanitizer/validation
// that sits between source and sink, not just the two endpoints (the "context
// poverty" that made interprocedural adjudication guesswork). Otherwise it falls
// back to snippets at the sink and source. Best-effort: any file-read error is
// skipped rather than failing the review; a fully empty context makes Filter
// keep the finding unreviewed.
func codeContextFor(f analysis.Finding) string {
	var b strings.Builder
	if len(f.Steps) >= 2 {
		seen := map[string]bool{}
		for i, p := range f.Steps {
			key := fmt.Sprintf("%s:%d", p.GetFilename(), p.GetLine())
			if seen[key] {
				continue
			}
			seen[key] = true
			if snip := snippet(p, 2); snip != "" {
				label := "step"
				switch i {
				case 0:
					label = "source"
				case len(f.Steps) - 1:
					label = "sink"
				}
				fmt.Fprintf(&b, "-- %s (%s) --\n", label, posString(p))
				b.WriteString(snip)
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	if snip := snippet(f.SinkPos, 3); snip != "" {
		b.WriteString("-- sink --\n")
		b.WriteString(snip)
	}
	if f.SourcePos != nil && (f.SinkPos == nil || f.SourcePos.GetFilename() != f.SinkPos.GetFilename() || f.SourcePos.GetLine() != f.SinkPos.GetLine()) {
		if snip := snippet(f.SourcePos, 3); snip != "" {
			b.WriteString("-- source --\n")
			b.WriteString(snip)
		}
	}
	return b.String()
}

func posString(p *ir.Position) string {
	if p == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("%s:%d:%d", p.GetFilename(), p.GetLine(), p.GetColumn())
}

// snippet returns up to ctx lines on either side of p's line, each prefixed with
// its 1-based line number and the pointed-at line marked with ">". Returns "" on
// any read error or invalid position.
func snippet(p *ir.Position, ctx int) string {
	if p == nil || p.GetFilename() == "" || p.GetLine() <= 0 {
		return ""
	}
	data, err := os.ReadFile(p.GetFilename())
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	target := int(p.GetLine())
	lo := target - ctx
	if lo < 1 {
		lo = 1
	}
	hi := target + ctx
	if hi > len(lines) {
		hi = len(lines)
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		marker := "  "
		if i == target {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d: %s\n", marker, i, lines[i-1])
	}
	return b.String()
}

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

// Filter reviews every finding whose Confidence is at or below reviewUpTo and
// drops the ones the reviewer judges to be false positives. Findings above the
// threshold (e.g. High confidence when reviewUpTo is Medium) are kept without
// review. On a reviewer error the finding is KEPT — the reviewer must never
// silently drop a real finding because of an LLM or network failure (fail open).
//
// It returns the surviving findings and the number of findings dropped.
func Filter(ctx context.Context, r Reviewer, findings []analysis.Finding, reviewUpTo analysis.Confidence) ([]analysis.Finding, int) {
	if r == nil {
		return findings, 0
	}
	kept := make([]analysis.Finding, 0, len(findings))
	dropped := 0
	for _, f := range findings {
		if !shouldReview(f.Confidence, reviewUpTo) {
			kept = append(kept, f)
			continue
		}
		v, err := r.Review(ctx, f, codeContextFor(f))
		if err != nil || !v.FalsePositive {
			kept = append(kept, f)
			continue
		}
		dropped++
	}
	return kept, dropped
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

// codeContextFor reads a few source lines around the sink (and source, if in a
// different file) to give the reviewer something concrete to judge. Best-effort:
// any file-read error yields an empty context rather than failing the review.
func codeContextFor(f analysis.Finding) string {
	var b strings.Builder
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

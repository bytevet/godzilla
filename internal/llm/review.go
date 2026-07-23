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
	"slices"
	"strings"
	"sync"
	"time"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// Verdict is a reviewer's judgment about a single finding. Beyond the binary
// false-positive decision, it can carry the model's self-confidence and a
// one-sentence exploitability assessment (LLM-7) — surfaced on a KEPT finding so
// a developer sees the reviewer's reasoning, not just a pass/drop.
type Verdict struct {
	FalsePositive  bool
	Reason         string
	Confidence     float64 // model self-confidence 0..1 (0 if not provided)
	Exploitability string  // one-sentence exploitability note (optional)
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
	Skipped    int   // findings past the per-scan review cap (kept unreviewed, fail-open)
	FirstErr   error // first reviewer error, for a single actionable message
}

// ReviewConfig bounds a review pass so a large scan cannot stall or cost
// unboundedly (LLM-5): reviews run through a bounded worker pool, each under a
// per-call timeout, capped at a maximum number per scan (excess findings are
// kept unreviewed — fail open).
type ReviewConfig struct {
	Concurrency int           // max concurrent reviews (default 8)
	Timeout     time.Duration // per-review timeout (0 = none; default 30s)
	MaxReviews  int           // cap on reviews per pass (0 = unlimited; default 200)
}

// DefaultReviewConfig returns the tuned defaults, so a pathological scan degrades
// to "some findings kept unreviewed" rather than an unbounded bill or stalled pipeline.
func DefaultReviewConfig() ReviewConfig {
	return ReviewConfig{Concurrency: 8, Timeout: 30 * time.Second, MaxReviews: 200}
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
	return FilterWithConfig(ctx, r, findings, reviewUpTo, DefaultReviewConfig())
}

// FilterWithConfig is Filter with an explicit ReviewConfig. Reviews run through
// a bounded worker pool (order-preserving output), each under a per-call
// timeout, capped at cfg.MaxReviews per pass; findings past the cap are kept
// unreviewed (fail open, counted in Skipped). The two safety properties of
// Filter still hold: fail-open on error/timeout, and never-blind on empty
// context.
func FilterWithConfig(ctx context.Context, r Reviewer, findings []analysis.Finding, reviewUpTo analysis.Confidence, cfg ReviewConfig) ([]analysis.Finding, ReviewStats) {
	var stats ReviewStats
	if r == nil {
		return findings, stats
	}
	out := slices.Clone(findings)

	// Decide, in order, which findings to review and with what context.
	type job struct {
		idx int
		cc  string
	}
	var jobs []job
	for i := range out {
		if !shouldReview(out[i].Confidence, reviewUpTo) {
			continue
		}
		cc := codeContextFor(out[i])
		if strings.TrimSpace(cc) == "" {
			stats.LowContext++ // never adjudicate (or drop) blind
			continue
		}
		jobs = append(jobs, job{idx: i, cc: cc})
	}

	// Cap the number of reviews per pass; the rest are kept unreviewed.
	if cfg.MaxReviews > 0 && len(jobs) > cfg.MaxReviews {
		stats.Skipped = len(jobs) - cfg.MaxReviews
		jobs = jobs[:cfg.MaxReviews]
	}

	// Review concurrently, bounded, each under its own timeout. Only reads of
	// out[idx] happen here; the suppression writes are applied afterward in
	// original order, so there is no data race on out.
	conc := max(cfg.Concurrency, 1)
	verdicts := make([]Verdict, len(jobs))
	errs := make([]error, len(jobs))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for k := range jobs {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rctx := ctx
			if cfg.Timeout > 0 {
				var cancel context.CancelFunc
				rctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
				defer cancel()
			}
			verdicts[k], errs[k] = r.Review(rctx, out[jobs[k].idx], jobs[k].cc)
		}(k)
	}
	wg.Wait()

	// Apply results in original order for deterministic stats and output.
	for k := range jobs {
		stats.Reviewed++
		if errs[k] != nil {
			stats.Errors++
			if stats.FirstErr == nil {
				stats.FirstErr = errs[k]
			}
			continue // fail open
		}
		idx := jobs[k].idx
		if verdicts[k].FalsePositive {
			out[idx].Suppressed = true
			out[idx].SuppressedBy = "llm-review"
			out[idx].SuppressionReason = verdicts[k].Reason
			stats.Suppressed++
			continue
		}
		// Kept after review: annotate as LLM-confirmed with the reviewer's
		// exploitability note (falling back to its reason), so a developer sees
		// why it survived triage (LLM-7).
		out[idx].ReviewConfirmed = true
		if note := verdicts[k].Exploitability; note != "" {
			out[idx].ReviewNote = note
		} else {
			out[idx].ReviewNote = verdicts[k].Reason
		}
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
	writeFindingFacts(&b, f)
	// Guard for direct callers (e.g. unit tests): the Filter path never reaches
	// here with empty context, as it skips blank-context findings before Review.
	if strings.TrimSpace(codeContext) != "" {
		b.WriteString("\nCode context:\n")
		b.WriteString(codeContext)
		b.WriteString("\n")
	}
	b.WriteString("\nConsider whether the tainted data is actually attacker-controlled, whether an ")
	b.WriteString("effective sanitizer (one of the rule's sanitizers above, or an equivalent) sits on the ")
	b.WriteString("path, and whether the sink is genuinely dangerous. ")
	b.WriteString(calibration)
	b.WriteString("\nRespond with ONLY a JSON object of the form ")
	b.WriteString(verdictJSONFormat)
	return b.String()
}

// verdictJSONFormat is the strict JSON verdict schema requested from the
// reviewer. Shared verbatim by the one-shot and agentic prompts so parseVerdict
// reads back the same shape regardless of which prompt produced it.
const verdictJSONFormat = `{"verdict": "true_positive" | "false_positive", "confidence": 0.0-1.0, "exploitability": "<one sentence: how it could be exploited, or why not>", "reason": "<one sentence>"}.`

// calibration steers the model toward the recall-preserving default: when the
// evidence is not decisive, keep the finding.
const calibration = "If the evidence does not clearly show the finding is a false positive, answer true_positive."

// writeFindingFacts writes the finding's identifying fields and reconstructed
// taint path — the block shared verbatim by the one-shot and agentic prompts.
func writeFindingFacts(b *strings.Builder, f analysis.Finding) {
	fmt.Fprintf(b, "Rule: %s\n", f.RuleID)
	fmt.Fprintf(b, "Severity: %s\n", f.Severity)
	fmt.Fprintf(b, "CWE: %s\n", f.CWE)
	fmt.Fprintf(b, "Message: %s\n", f.Message)
	fmt.Fprintf(b, "Language: %s\n", f.Language)
	fmt.Fprintf(b, "Function: %s\n", f.Function)
	fmt.Fprintf(b, "Sink callee: %s\n", f.SinkCallee)
	fmt.Fprintf(b, "Source location: %s\n", analysis.PosString(f.SourcePos))
	fmt.Fprintf(b, "Sink location: %s\n", analysis.PosString(f.SinkPos))
	if len(f.Steps) >= 2 {
		b.WriteString("Taint path (source -> sink):\n")
		for _, p := range f.Steps {
			fmt.Fprintf(b, "  - %s\n", analysis.PosString(p))
		}
	}
	writeRuleDefinition(b, f)
}

// writeRuleDefinition adds the matched rule's own source/sanitizer vocabulary to
// the prompt so the reviewer adjudicates by the rulepack's definition rather than
// generic knowledge — e.g. it will not "clear" a finding for a sanitizer the
// rule does not recognize, nor keep one an obvious rule sanitizer would clear
// (LLM-8).
func writeRuleDefinition(b *strings.Builder, f analysis.Finding) {
	if len(f.RuleSources) == 0 && len(f.RuleSanitizers) == 0 {
		return
	}
	b.WriteString("\nRule definition (canonical-name globs):\n")
	if len(f.RuleSources) > 0 {
		fmt.Fprintf(b, "  sources: %s\n", strings.Join(f.RuleSources, ", "))
	}
	if len(f.RuleSanitizers) > 0 {
		fmt.Fprintf(b, "  sanitizers: %s\n", strings.Join(f.RuleSanitizers, ", "))
	} else {
		b.WriteString("  sanitizers: (none — this rule declares no neutralizing function)\n")
	}
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
	writeFindingFacts(&b, f)
	// Guard for direct callers (e.g. unit tests): the Filter path never reaches
	// here with empty context, as it skips blank-context findings before Review.
	if strings.TrimSpace(codeContext) != "" {
		b.WriteString("\nInitial code context:\n")
		b.WriteString(codeContext)
		b.WriteString("\n")
	}
	b.WriteString("\nDecide whether this is a TRUE positive (a real, exploitable vulnerability) or a FALSE positive. ")
	b.WriteString(calibration + " (do not suppress on thin evidence).\n")
	b.WriteString("When done investigating, respond with ONLY a JSON object of the form ")
	b.WriteString(verdictJSONFormat)
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
		Verdict        string  `json:"verdict"`
		Reason         string  `json:"reason"`
		Confidence     float64 `json:"confidence"`
		Exploitability string  `json:"exploitability"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &raw); err != nil {
		return Verdict{}, fmt.Errorf("parsing reviewer response: %w", err)
	}
	v := Verdict{Reason: raw.Reason, Confidence: raw.Confidence, Exploitability: raw.Exploitability}
	// Leniency is allowed only in the KEEP direction. Dropping a finding is the
	// one verdict that must be unambiguous, so require the exact canonical token
	// and reject loose aliases like bare "false"/"fp" — anything unrecognized
	// keeps the finding (LLM-8).
	switch strings.ToLower(strings.TrimSpace(raw.Verdict)) {
	case "false_positive", "false-positive":
		v.FalsePositive = true
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
				fmt.Fprintf(&b, "-- %s (%s) --\n", label, analysis.PosString(p))
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
	lo := max(target-ctx, 1)
	hi := min(target+ctx, len(lines))
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

package llm

import (
	"context"
	"errors"
	"testing"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// mockReviewer marks findings whose RuleID is in fp as false positives, and
// optionally returns an error for every call. It records how many times it was
// called so tests can assert the empty-context guard skips the reviewer.
type mockReviewer struct {
	fp     map[string]bool
	reason string
	err    error
	calls  int
}

func (m *mockReviewer) Review(_ context.Context, f analysis.Finding, _ string) (Verdict, error) {
	m.calls++
	if m.err != nil {
		return Verdict{}, m.err
	}
	return Verdict{FalsePositive: m.fp[f.RuleID], Reason: m.reason}, nil
}

// withContext returns a finding whose sink points at the package testdata file,
// so codeContextFor yields a non-empty snippet and the reviewer is actually
// consulted. Use this for any finding that should be reviewed.
func withContext(ruleID string, c analysis.Confidence) analysis.Finding {
	return analysis.Finding{
		RuleID:     ruleID,
		Confidence: c,
		SinkPos:    &ir.Position{Filename: "testdata/sample.go", Line: 4, Column: 2},
	}
}

// activeCount counts findings that were not suppressed.
func activeCount(fs []analysis.Finding) int {
	n := 0
	for _, f := range fs {
		if !f.Suppressed {
			n++
		}
	}
	return n
}

func TestFilter_KeepsHighConfidenceWithoutReview(t *testing.T) {
	findings := []analysis.Finding{
		withContext("a", analysis.ConfidenceHigh),
		withContext("b", analysis.ConfidenceHigh),
	}
	m := &mockReviewer{fp: map[string]bool{"a": true, "b": true}}
	out, stats := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if m.calls != 0 {
		t.Errorf("high-confidence findings should not be reviewed, got %d calls", m.calls)
	}
	if activeCount(out) != 2 || stats.Suppressed != 0 {
		t.Errorf("expected all kept, got active=%d suppressed=%d", activeCount(out), stats.Suppressed)
	}
}

func TestFilter_SuppressesFalsePositivesButRetainsThem(t *testing.T) {
	findings := []analysis.Finding{
		withContext("real", analysis.ConfidenceMedium),
		withContext("fp", analysis.ConfidenceMedium),
		withContext("lowfp", analysis.ConfidenceLow),
	}
	m := &mockReviewer{fp: map[string]bool{"fp": true, "lowfp": true}, reason: "constant, not attacker-controlled"}
	out, stats := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if m.calls != 3 {
		t.Errorf("expected 3 reviews, got %d", m.calls)
	}
	if stats.Reviewed != 3 || stats.Suppressed != 2 {
		t.Errorf("expected reviewed=3 suppressed=2, got reviewed=%d suppressed=%d", stats.Reviewed, stats.Suppressed)
	}
	// Nothing is deleted: all three findings are returned, two flagged with a reason.
	if len(out) != 3 {
		t.Fatalf("suppressed findings must be RETAINED, not deleted: got %d of 3", len(out))
	}
	if activeCount(out) != 1 {
		t.Errorf("expected 1 active finding, got %d", activeCount(out))
	}
	for _, f := range out {
		if f.RuleID == "fp" || f.RuleID == "lowfp" {
			if !f.Suppressed {
				t.Errorf("%q should be marked Suppressed", f.RuleID)
			}
			if f.SuppressedBy != "llm-review" || f.SuppressionReason == "" {
				t.Errorf("%q missing suppression provenance: by=%q reason=%q", f.RuleID, f.SuppressedBy, f.SuppressionReason)
			}
		}
		if f.RuleID == "real" && f.Suppressed {
			t.Errorf("%q should remain active", f.RuleID)
		}
	}
}

func TestFilter_NeverDropsWithoutCodeContext(t *testing.T) {
	// A finding whose position points nowhere yields empty code context. Even a
	// reviewer that WOULD suppress it must not be consulted, and the finding must
	// be kept (never adjudicate blind).
	findings := []analysis.Finding{{
		RuleID:     "ctxless",
		Confidence: analysis.ConfidenceMedium,
		SinkPos:    &ir.Position{Filename: "testdata/does-not-exist.go", Line: 1},
	}}
	m := &mockReviewer{fp: map[string]bool{"ctxless": true}}
	out, stats := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if m.calls != 0 {
		t.Errorf("reviewer must not be called without code context, got %d calls", m.calls)
	}
	if activeCount(out) != 1 || stats.Suppressed != 0 {
		t.Errorf("empty-context finding must be kept, got active=%d suppressed=%d", activeCount(out), stats.Suppressed)
	}
	if stats.LowContext != 1 {
		t.Errorf("expected LowContext=1, got %d", stats.LowContext)
	}
}

func TestFilter_FailOpenOnErrorIsVisible(t *testing.T) {
	findings := []analysis.Finding{withContext("x", analysis.ConfidenceLow)}
	m := &mockReviewer{err: errors.New("network down")}
	out, stats := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if activeCount(out) != 1 || stats.Suppressed != 0 {
		t.Errorf("reviewer error must keep the finding, got active=%d suppressed=%d", activeCount(out), stats.Suppressed)
	}
	if stats.Errors != 1 || stats.FirstErr == nil {
		t.Errorf("reviewer error must be recorded for auditability, got errors=%d firstErr=%v", stats.Errors, stats.FirstErr)
	}
}

func TestFilter_ReviewerNoopIsDetectable(t *testing.T) {
	// A reviewer that errors on every finding (e.g. missing API key) must leave a
	// detectable trace: every reviewed finding errored, so Errors == Reviewed.
	findings := []analysis.Finding{
		withContext("a", analysis.ConfidenceMedium),
		withContext("b", analysis.ConfidenceMedium),
	}
	m := &mockReviewer{err: errors.New("401 unauthorized")}
	out, stats := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if activeCount(out) != 2 {
		t.Errorf("no-op reviewer must keep everything, got active=%d", activeCount(out))
	}
	if stats.Reviewed == 0 || stats.Errors != stats.Reviewed {
		t.Errorf("a total no-op should show Errors==Reviewed>0, got reviewed=%d errors=%d", stats.Reviewed, stats.Errors)
	}
}

func TestFilter_NilReviewerIsNoop(t *testing.T) {
	findings := []analysis.Finding{withContext("x", analysis.ConfidenceLow)}
	out, stats := Filter(context.Background(), nil, findings, analysis.ConfidenceMedium)
	if len(out) != 1 || stats.Suppressed != 0 || stats.Reviewed != 0 {
		t.Errorf("nil reviewer must pass findings through unchanged")
	}
}

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantFP  bool
		wantErr bool
	}{
		{"false positive", `{"verdict": "false_positive", "reason": "sanitized"}`, true, false},
		{"true positive", `{"verdict": "true_positive", "reason": "reachable"}`, false, false},
		{"surrounded by prose", "Sure!\n{\"verdict\":\"false_positive\",\"reason\":\"x\"}\nDone.", true, false},
		{"unrecognized keeps", `{"verdict": "maybe", "reason": "unsure"}`, false, false},
		{"no json", "I cannot answer.", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseVerdict(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && v.FalsePositive != tc.wantFP {
				t.Errorf("FalsePositive=%v want %v", v.FalsePositive, tc.wantFP)
			}
		})
	}
}

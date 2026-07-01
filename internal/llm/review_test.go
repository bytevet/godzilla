package llm

import (
	"context"
	"errors"
	"testing"

	"godzilla/internal/analysis"
)

// mockReviewer marks findings whose RuleID is in fp as false positives, and
// optionally returns an error for every call.
type mockReviewer struct {
	fp    map[string]bool
	err   error
	calls int
}

func (m *mockReviewer) Review(_ context.Context, f analysis.Finding, _ string) (Verdict, error) {
	m.calls++
	if m.err != nil {
		return Verdict{}, m.err
	}
	return Verdict{FalsePositive: m.fp[f.RuleID]}, nil
}

func TestFilter_KeepsHighConfidenceWithoutReview(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "a", Confidence: analysis.ConfidenceHigh},
		{RuleID: "b", Confidence: analysis.ConfidenceHigh},
	}
	m := &mockReviewer{fp: map[string]bool{"a": true, "b": true}}
	kept, dropped := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if m.calls != 0 {
		t.Errorf("high-confidence findings should not be reviewed, got %d calls", m.calls)
	}
	if len(kept) != 2 || dropped != 0 {
		t.Errorf("expected all kept, got kept=%d dropped=%d", len(kept), dropped)
	}
}

func TestFilter_DropsFalsePositives(t *testing.T) {
	findings := []analysis.Finding{
		{RuleID: "real", Confidence: analysis.ConfidenceMedium},
		{RuleID: "fp", Confidence: analysis.ConfidenceMedium},
		{RuleID: "lowfp", Confidence: analysis.ConfidenceLow},
	}
	m := &mockReviewer{fp: map[string]bool{"fp": true, "lowfp": true}}
	kept, dropped := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if m.calls != 3 {
		t.Errorf("expected 3 reviews, got %d", m.calls)
	}
	if dropped != 2 {
		t.Errorf("expected 2 dropped, got %d", dropped)
	}
	if len(kept) != 1 || kept[0].RuleID != "real" {
		t.Errorf("expected only 'real' kept, got %+v", kept)
	}
}

func TestFilter_FailOpenOnError(t *testing.T) {
	findings := []analysis.Finding{{RuleID: "x", Confidence: analysis.ConfidenceLow}}
	m := &mockReviewer{err: errors.New("network down")}
	kept, dropped := Filter(context.Background(), m, findings, analysis.ConfidenceMedium)
	if len(kept) != 1 || dropped != 0 {
		t.Errorf("reviewer error must keep the finding, got kept=%d dropped=%d", len(kept), dropped)
	}
}

func TestFilter_NilReviewerIsNoop(t *testing.T) {
	findings := []analysis.Finding{{RuleID: "x", Confidence: analysis.ConfidenceLow}}
	kept, dropped := Filter(context.Background(), nil, findings, analysis.ConfidenceMedium)
	if len(kept) != 1 || dropped != 0 {
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

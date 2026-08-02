package analysis

import "testing"

// TestConfidenceRank pins the Confidence ordering the LLM reviewer's
// review-up-to threshold depends on: low < medium < high, all positive, and
// anything non-canonical (including a differently-cased spelling) ranks 0 so
// it is never reviewed.
func TestConfidenceRank(t *testing.T) {
	tests := []struct {
		c    Confidence
		want int
	}{
		{ConfidenceLow, 1},
		{ConfidenceMedium, 2},
		{ConfidenceHigh, 3},
		{Confidence(""), 0},
		{Confidence("HIGH"), 0}, // non-canonical case ranks 0 by design
		{Confidence("bogus"), 0},
	}
	for _, tt := range tests {
		if got := tt.c.Rank(); got != tt.want {
			t.Errorf("Confidence(%q).Rank() = %d, want %d", tt.c, got, tt.want)
		}
	}
	if !(ConfidenceLow.Rank() < ConfidenceMedium.Rank() && ConfidenceMedium.Rank() < ConfidenceHigh.Rank()) {
		t.Error("confidence ranks are not strictly increasing low < medium < high")
	}
}

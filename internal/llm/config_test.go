package llm

import (
	"context"
	"sync"
	"testing"
	"time"

	"godzilla/internal/analysis"
)

// concurrencyProbe records the maximum number of concurrent Review calls, to
// verify the worker pool runs reviews in parallel but within the bound.
type concurrencyProbe struct {
	mu       sync.Mutex
	cur, max int
}

func (c *concurrencyProbe) Review(_ context.Context, _ analysis.Finding, _ string) (Verdict, error) {
	c.mu.Lock()
	c.cur++
	if c.cur > c.max {
		c.max = c.cur
	}
	c.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
	return Verdict{}, nil
}

func manyReviewable(n int) []analysis.Finding {
	fs := make([]analysis.Finding, n)
	for i := range fs {
		fs[i] = withContext("r", analysis.ConfidenceMedium)
	}
	return fs
}

// TestFilter_ConcurrencyBounded verifies reviews run concurrently (max > 1) but
// never exceed cfg.Concurrency (LLM-5 worker pool).
func TestFilter_ConcurrencyBounded(t *testing.T) {
	probe := &concurrencyProbe{}
	cfg := ReviewConfig{Concurrency: 4}
	_, stats := FilterWithConfig(context.Background(), probe, manyReviewable(12), analysis.ConfidenceMedium, cfg)
	if stats.Reviewed != 12 {
		t.Fatalf("expected 12 reviews, got %d", stats.Reviewed)
	}
	if probe.max <= 1 {
		t.Errorf("expected concurrent reviews (max>1), got %d", probe.max)
	}
	if probe.max > 4 {
		t.Errorf("concurrency exceeded the bound of 4, saw %d in flight", probe.max)
	}
}

// TestFilter_MaxReviewsCap verifies the per-scan cap keeps findings past it
// unreviewed (fail open) and reports them as Skipped.
func TestFilter_MaxReviewsCap(t *testing.T) {
	m := &mockReviewer{fp: map[string]bool{"r": true}}
	cfg := ReviewConfig{Concurrency: 2, MaxReviews: 2}
	out, stats := FilterWithConfig(context.Background(), m, manyReviewable(5), analysis.ConfidenceMedium, cfg)
	if stats.Reviewed != 2 {
		t.Errorf("expected 2 reviewed (capped), got %d", stats.Reviewed)
	}
	if stats.Skipped != 3 {
		t.Errorf("expected 3 skipped past the cap, got %d", stats.Skipped)
	}
	if m.callCount() != 2 {
		t.Errorf("reviewer must be called only up to the cap, got %d", m.callCount())
	}
	// The 3 uncapped findings are kept unreviewed (active); only the 2 reviewed
	// FPs are suppressed.
	if activeCount(out) != 3 {
		t.Errorf("expected 3 active (2 suppressed of 5), got %d", activeCount(out))
	}
}

// ctxReviewer respects the context deadline, so a per-call timeout surfaces as
// an error.
type ctxReviewer struct{}

func (ctxReviewer) Review(ctx context.Context, _ analysis.Finding, _ string) (Verdict, error) {
	select {
	case <-time.After(2 * time.Second):
		return Verdict{FalsePositive: true}, nil // would suppress if not timed out
	case <-ctx.Done():
		return Verdict{}, ctx.Err()
	}
}

// TestFilter_PerCallTimeoutFailsOpen verifies a slow review hits the per-call
// timeout, is recorded as an error, and the finding is kept (fail open) rather
// than suppressed.
func TestFilter_PerCallTimeoutFailsOpen(t *testing.T) {
	cfg := ReviewConfig{Concurrency: 2, Timeout: 10 * time.Millisecond}
	out, stats := FilterWithConfig(context.Background(), ctxReviewer{}, manyReviewable(2), analysis.ConfidenceMedium, cfg)
	if stats.Errors != 2 {
		t.Errorf("expected both reviews to time out (errors=2), got %d", stats.Errors)
	}
	if stats.Suppressed != 0 {
		t.Errorf("a timed-out review must not suppress, got suppressed=%d", stats.Suppressed)
	}
	if activeCount(out) != 2 {
		t.Errorf("timed-out findings must be kept, got active=%d", activeCount(out))
	}
}

// TestFilter_OrderPreserved verifies the output keeps input order and applies
// suppression to exactly the right findings, despite concurrent review.
func TestFilter_OrderPreserved(t *testing.T) {
	findings := []analysis.Finding{
		withContext("a", analysis.ConfidenceMedium),
		withContext("b", analysis.ConfidenceMedium),
		withContext("c", analysis.ConfidenceMedium),
		withContext("d", analysis.ConfidenceMedium),
		withContext("e", analysis.ConfidenceMedium),
	}
	m := &mockReviewer{fp: map[string]bool{"b": true, "d": true}}
	out, _ := FilterWithConfig(context.Background(), m, findings, analysis.ConfidenceMedium, DefaultReviewConfig())
	wantOrder := []string{"a", "b", "c", "d", "e"}
	for i, f := range out {
		if f.RuleID != wantOrder[i] {
			t.Fatalf("output order changed at %d: got %q want %q", i, f.RuleID, wantOrder[i])
		}
	}
	if !out[1].Suppressed || !out[3].Suppressed {
		t.Errorf("expected b and d suppressed")
	}
	if out[0].Suppressed || out[2].Suppressed || out[4].Suppressed {
		t.Errorf("expected a, c, e active")
	}
}

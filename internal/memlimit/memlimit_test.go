package memlimit

import (
	"os"
	"runtime/debug"
	"testing"
)

// TestConfigureRespectsEnv verifies Configure does not override an operator's
// explicit GOMEMLIMIT (Go reads that automatically; clobbering it would ignore a
// deliberate choice).
func TestConfigureRespectsEnv(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "5GiB")
	if got := Configure(); got != 0 {
		t.Errorf("Configure with GOMEMLIMIT set should be a no-op (0), got %d", got)
	}
}

// TestConfigureSetsLimit verifies that, absent an env override, Configure sets a
// positive soft limit below total memory (leaving headroom) and actually applies
// it to the runtime.
func TestConfigureSetsLimit(t *testing.T) {
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatalf("unset GOMEMLIMIT: %v", err)
	}
	// Restore whatever limit the test process had afterwards.
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	avail := detectAvailable()
	if avail <= 0 {
		t.Skip("no memory bound detectable on this host")
	}
	got := Configure()
	if got <= 0 {
		t.Fatalf("Configure returned %d; expected a positive limit", got)
	}
	if got >= avail {
		t.Errorf("soft limit %d must be below detected available %d (headroom)", got, avail)
	}
	if applied := debug.SetMemoryLimit(-1); applied != got {
		t.Errorf("runtime limit %d does not match returned %d", applied, got)
	}
}

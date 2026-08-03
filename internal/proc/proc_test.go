package proc

import (
	"testing"
	"time"
)

func TestTimeouts_DefaultsAndOverride(t *testing.T) {
	defer SetTimeouts(defaultParseTimeout, defaultBuildTimeout)

	if ParseTimeout() != defaultParseTimeout {
		t.Errorf("default parse timeout = %v, want %v", ParseTimeout(), defaultParseTimeout)
	}
	if BuildTimeout() != defaultBuildTimeout {
		t.Errorf("default build timeout = %v, want %v", BuildTimeout(), defaultBuildTimeout)
	}

	SetTimeouts(5*time.Second, 42*time.Second)
	if ParseTimeout() != 5*time.Second {
		t.Errorf("override parse timeout = %v, want 5s", ParseTimeout())
	}
	if BuildTimeout() != 42*time.Second {
		t.Errorf("override build timeout = %v, want 42s", BuildTimeout())
	}

	// A non-positive value leaves the current deadline unchanged.
	SetTimeouts(0, -1)
	if ParseTimeout() != 5*time.Second || BuildTimeout() != 42*time.Second {
		t.Errorf("non-positive override must be a no-op, got parse=%v build=%v",
			ParseTimeout(), BuildTimeout())
	}
}

func TestParseContext_HasDeadline(t *testing.T) {
	ctx, cancel := ParseContext()
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("ParseContext must carry a deadline")
	}
}

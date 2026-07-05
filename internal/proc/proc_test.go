package proc

import (
	"testing"
	"time"
)

func TestTimeouts_DefaultsAndOverride(t *testing.T) {
	if ParseTimeout() != defaultParseTimeout {
		t.Errorf("default parse timeout = %v, want %v", ParseTimeout(), defaultParseTimeout)
	}
	if BuildTimeout() != defaultBuildTimeout {
		t.Errorf("default build timeout = %v, want %v", BuildTimeout(), defaultBuildTimeout)
	}

	t.Setenv("GODZILLA_PARSE_TIMEOUT", "5s")
	if ParseTimeout() != 5*time.Second {
		t.Errorf("override parse timeout = %v, want 5s", ParseTimeout())
	}
	t.Setenv("GODZILLA_BUILD_TIMEOUT", "42s")
	if BuildTimeout() != 42*time.Second {
		t.Errorf("override build timeout = %v, want 42s", BuildTimeout())
	}

	// A garbage / non-positive value falls back to the default.
	t.Setenv("GODZILLA_PARSE_TIMEOUT", "nonsense")
	if ParseTimeout() != defaultParseTimeout {
		t.Errorf("garbage override should fall back to default, got %v", ParseTimeout())
	}
}

func TestParseContext_HasDeadline(t *testing.T) {
	ctx, cancel := ParseContext()
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("ParseContext must carry a deadline")
	}
}

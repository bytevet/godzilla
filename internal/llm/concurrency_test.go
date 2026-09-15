package llm

import "testing"

// The CLI pool is sized against memory because memory is what bounds it, and
// getting it wrong in the HIGH direction is worse than in the low: on one
// 17-finding scan, 4-wide took 3m15s, 8-wide 1m33s, and 16-wide went back up to
// 2m53s because 16 x ~1 GiB exceeded the 24 GiB host and it swapped.
func TestCommandConcurrencyScalesWithMemory(t *testing.T) {
	const gb = int64(1) << 30
	for _, c := range []struct {
		avail int64
		want  int
		why   string
	}{
		{0, 4, "undetectable memory keeps the conservative fixed default"},
		{2 * gb, 2, "a small container must not be sized to the host"},
		{8 * gb, 2, "a modest laptop stays at the floor"},
		{16 * gb, 5, "mid-range scales up"},
		{24 * gb, 8, "the measured sweet spot on the reference machine"},
		{256 * gb, 8, "capped: past this the vendor's rate limit dominates"},
	} {
		if got := commandConcurrency(c.avail); got != c.want {
			t.Errorf("commandConcurrency(%d GiB) = %d, want %d — %s", c.avail/gb, got, c.want, c.why)
		}
	}
}

// Never zero or negative: Filter's pool would either deadlock or silently
// serialise, and a serialised review reads as "just slow" rather than as a bug.
func TestCommandConcurrencyIsAlwaysUsable(t *testing.T) {
	for _, avail := range []int64{-1, 0, 1, 1 << 20, 1 << 30, 1 << 40} {
		if got := commandConcurrency(avail); got < 1 {
			t.Errorf("commandConcurrency(%d) = %d, must be >= 1", avail, got)
		}
	}
}

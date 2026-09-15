//go:build !darwin

package memlimit

// hostMemTotal has no portable answer outside the platforms with a specific
// implementation; Linux is served by /proc/meminfo in readMemTotal. 0 means
// "unknown", which every caller must already handle.
func hostMemTotal() int64 { return 0 }

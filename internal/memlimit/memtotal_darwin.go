//go:build darwin

package memlimit

import "golang.org/x/sys/unix"

// hostMemTotal reads physical memory from the kernel. /proc/meminfo does not
// exist here, so without this every detection path returns 0 and BOTH callers
// silently degrade: GOMEMLIMIT is never set (this package's whole purpose), and
// the LLM reviewer's memory-sized worker pool falls back to a fixed guess.
//
// unix.SysctlUint64 rather than syscall.Sysctl: the latter returns the raw
// bytes as a string and strips a trailing NUL, so decoding an 8-byte value by
// hand would silently truncate on exactly the round sizes real machines have.
func hostMemTotal() int64 {
	v, err := unix.SysctlUint64("hw.memsize")
	if err != nil || v > 1<<62 {
		return 0
	}
	return int64(v)
}

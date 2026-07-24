// Package memlimit sets a soft heap ceiling (GOMEMLIMIT) so a large scan makes
// the garbage collector work harder instead of OOM-killing the process.
//
// The Go GC's default target heap is ~2x the live set (GOGC=100). A whole-repo
// scan with dependency lowering can hold a large live set (observed ~8 GiB on
// gitea/argo-workflows during the SSA build+lower phase); doubling that reaches
// the host's RAM and the kernel SIGKILLs the process — even though the working
// set itself fits with headroom. Pinning GOMEMLIMIT to a fraction of available
// memory makes the collector keep the heap under the ceiling: slower under
// pressure, but the scan finishes instead of dying.
package memlimit

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// softFraction is the share of detected available memory used as the soft heap
// limit. The remainder is headroom for goroutine stacks, the runtime's own
// bookkeeping, non-heap and cgo allocations, and other processes.
const softFraction = 0.8

// Configure sets GOMEMLIMIT to softFraction of the memory available to the
// process, and returns the limit in bytes (0 if it left the runtime default in
// place). It is a no-op when GOMEMLIMIT is already set in the environment (Go
// reads that automatically, so an operator's deliberate choice is respected) or
// when available memory cannot be detected (e.g. a non-Linux host).
func Configure() int64 {
	if _, ok := os.LookupEnv("GOMEMLIMIT"); ok {
		return 0 // operator-controlled; do not clobber
	}
	avail := detectAvailable()
	if avail <= 0 {
		return 0
	}
	limit := int64(float64(avail) * softFraction)
	debug.SetMemoryLimit(limit)
	return limit
}

// detectAvailable returns the tightest positive memory bound that applies to
// this process: the smaller of the host's physical memory and any cgroup limit.
// Returns 0 when nothing can be read.
func detectAvailable() int64 {
	best := int64(0)
	consider := func(v int64) {
		if v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	memTotal := readMemTotal()
	consider(memTotal)
	consider(readCgroupLimit("/sys/fs/cgroup/memory.max", memTotal))                   // cgroup v2
	consider(readCgroupLimit("/sys/fs/cgroup/memory/memory.limit_in_bytes", memTotal)) // cgroup v1
	return best
}

// readMemTotal parses MemTotal (in kB) from /proc/meminfo into bytes.
func readMemTotal() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line) // ["MemTotal:", "16461176", "kB"]
		if len(fields) >= 2 {
			if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

// readCgroupLimit reads a cgroup memory limit file. It returns 0 for "max"
// (v2 unlimited) or a sentinel-huge v1 value, so an unlimited cgroup does not
// mask the real host bound.
func readCgroupLimit(path string, memTotal int64) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	// cgroup v1 encodes "unlimited" as a near-max int64 (e.g. PAGE_COUNTER_MAX);
	// anything at or above the host's physical memory is not a real constraint.
	if memTotal > 0 && v >= memTotal {
		return 0
	}
	return v
}

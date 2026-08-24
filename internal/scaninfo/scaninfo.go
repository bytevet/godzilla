// Package scaninfo carries the scan telemetry behind the HTML report's
// diagnostics panel: internal/scan fills it, internal/report renders it, and the
// CLI passes it across without translating.
//
// It is its own package so those two can share one type. internal/report cannot
// import internal/scan — that would pull all seven language frontends, including
// the cgo-gated C/C++ one, into a package whose whole job is rendering — and a
// parallel struct in each with a mapping between them drifts: a field added on
// one side is silently dropped on the other.
package scaninfo

import "time"

// Info is raw telemetry. Every value is unformatted; units, percentages and
// lines/s are the report layer's job.
//
// The counts describe different populations and cannot be divided into each
// other freely: Files and Lines cover the source under the scan root, while
// Functions and the call-site counts also cover lowered dependency bodies, which
// live outside it (the Go module cache) and so contribute no lines.
type Info struct {
	// Target is what was scanned, for the report masthead.
	Target string

	Files   int // source files under the frontends' own selection policy
	Skipped int // of those, how many a frontend could not lower
	Lines   int // their physical line count, blanks and comments included

	Packages  int
	Functions int // call-graph nodes

	// RulesLive is the subset of Rules the engine seeded, which is only the
	// dataflow rules — every `kind: secret` and `kind: dangerous-call` rule is
	// excluded yet is genuinely evaluated by the other passes.
	Rules     int
	RulesLive int

	// SourceSites and SinkSites count call sites whose callee matches a source or
	// sink glob. A workload figure, not a bound on findings: it ignores `#idx`
	// pinning and `when:` guards, and misses seeding that is not a call at all.
	SourceSites int
	SinkSites   int

	// Wall is the whole scan. Convert and Analysis partition most of it; Index,
	// RuleSel and Taint are disjoint sub-spans of Analysis. What is left of
	// Analysis is the passes that run CONCURRENTLY with the taint engine and so
	// add no measurable wall time of their own.
	Wall     time.Duration
	Convert  time.Duration
	Analysis time.Duration
	Index    time.Duration
	RuleSel  time.Duration
	Taint    time.Duration

	// DegradedNote is non-empty when a frontend ran at reduced depth — a Go
	// dependency closure trimmed to fit the source-byte budget. It is a note for
	// a reader, not a status: the scan still ran and its findings still hold, so
	// nothing derives a pass/fail from it.
	DegradedNote string

	// PeakBytes is runtime.MemStats.Sys — a Go-runtime high-water mark, not RSS.
	// Sys only grows, so a single late sample is a true peak; HeapAlloc is the
	// post-GC live heap and TotalAlloc is cumulative. Filled by the CLI, not by
	// the scan: reading it stops the world, which a library call made in a loop
	// must not do. Zero when nobody sampled.
	PeakBytes uint64
}

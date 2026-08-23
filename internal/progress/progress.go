// Package progress is the scan pipeline's live stage ledger: the frontends and
// the engine record what they are doing, and a display reads it back.
//
// It is deliberately a LEAF — stdlib only, no repo imports. Every producer is a
// converter or the analysis engine, several call layers below the command, and
// a package they can all import must not drag a terminal library into their
// builds (the cgo C/C++ frontend included). internal/tui holds the rendering
// and the only golang.org/x/term dependency; the same split internal/scaninfo
// makes so internal/report can render a scan's telemetry without importing
// internal/scan.
//
// Counters are PULLED, not pushed. A display polls Stages() on its own clock;
// nothing here has a callback. The Go lowerer advances once per function —
// tens of thousands of times, from every worker — so the write path has to be
// one atomic add, with no channel and no back-pressure policy for a display
// that falls behind. Elapsed time also has to keep moving while nothing at all
// is happening, which an event-driven design cannot do on its own.
//
// The registry is process-global and armed for one scan at a time
// (internal/scan's WithProgress), the same shape as proc.SetTimeouts and
// buildpolicy.SetAllowed. Unarmed, Start returns nil and every method on a nil
// *Stage is a no-op, so an instrumented hook costs one nil check when nobody is
// watching.
package progress

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// now is swapped by tests that need a deterministic elapsed time.
var now = time.Now

// Stage is one named unit of pipeline work, from Start to Done.
type Stage struct {
	id    string
	label string
	total int
	start time.Time

	// done is atomic rather than under mu: the Go lowerer advances once per
	// function from every worker, so this is the one genuinely hot write.
	done atomic.Int64

	mu       sync.Mutex
	end      time.Time
	finished bool
	failed   bool
}

// Snapshot is one stage as a display sees it. Elapsed runs live while the stage
// is Running and is final once it is not.
type Snapshot struct {
	ID      string
	Label   string
	Total   int // 0 when the stage has no measurable unit of work
	Done    int
	Elapsed time.Duration
	Running bool
	Failed  bool
}

var (
	mu     sync.Mutex
	armed  bool
	ledger []*Stage
)

// Enable arms the registry for one scan and returns the function that disarms
// it. Disarming stops new registrations but leaves the ledger readable, so a
// display can render its final summary after the scan has returned.
//
// A second Enable while one is active returns a no-op rather than resetting:
// two overlapping scans in one process would otherwise interleave into a single
// meaningless ledger, and silently dropping the second one's stages is the less
// confusing failure.
func Enable() (disable func()) {
	mu.Lock()
	defer mu.Unlock()
	if armed {
		return func() {}
	}
	armed = true
	ledger = nil
	return func() {
		mu.Lock()
		armed = false
		mu.Unlock()
	}
}

// Start registers a stage and starts its clock, returning nil unless the
// registry is armed. total is the denominator in whatever unit the stage counts
// — files, functions, rules — and 0 means the stage has no countable work and
// is reported by elapsed time alone.
func Start(id, label string, total int) *Stage {
	mu.Lock()
	defer mu.Unlock()
	if !armed {
		return nil
	}
	s := &Stage{id: id, label: label, total: total, start: now()}
	ledger = append(ledger, s)
	return s
}

// Advance records n more completed units.
func (s *Stage) Advance(n int) {
	if s == nil {
		return
	}
	s.done.Add(int64(n))
}

// Done stops the stage's clock. A non-nil err marks it failed; either way the
// stage stays in the ledger, because a frontend that failed after thirty
// seconds is precisely what someone watching the scan needs to see. Calling it
// twice keeps the first outcome.
func (s *Stage) Done(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}
	s.finished = true
	s.end = now()
	s.failed = err != nil
}

// Stages returns every registered stage in registration order.
func Stages() []Snapshot {
	mu.Lock()
	all := slices.Clone(ledger)
	mu.Unlock()

	out := make([]Snapshot, 0, len(all))
	for _, s := range all {
		out = append(out, s.snapshot())
	}
	return out
}

func (s *Stage) snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed := now().Sub(s.start)
	if s.finished {
		elapsed = s.end.Sub(s.start)
	}
	return Snapshot{
		ID:      s.id,
		Label:   s.label,
		Total:   s.total,
		Done:    int(s.done.Load()),
		Elapsed: elapsed,
		Running: !s.finished,
		Failed:  s.failed,
	}
}

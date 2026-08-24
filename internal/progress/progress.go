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
	unit  string
	start time.Time

	// done is atomic rather than under mu: the Go lowerer advances once per
	// function from every worker, so this is the one genuinely hot write.
	done atomic.Int64

	mu         sync.Mutex
	end        time.Time
	finished   bool
	failed     bool
	covered    int
	coverTotal int
}

// Warning is a diagnostic a producer wants shown, already broken into the parts
// a reader needs: which language it came from, what happened, and where. The
// display shows these; the raw text a frontend also writes to stderr stays the
// complete record.
type Warning struct {
	Lang     string
	Message  string
	Location string // "path:line", or empty
}

// Snapshot is one stage as a display sees it. Elapsed runs live while the stage
// is Running and is final once it is not; Offset is when the stage began,
// measured from the moment the ledger was armed, so a display can show where a
// stage sat in the run without quantising it to its own frame clock.
type Snapshot struct {
	ID      string
	Label   string
	Total   int    // 0 when the stage has no measurable unit of work
	Unit    string // what Total counts: "files", "funcs", "rules"
	Done    int
	Offset  time.Duration
	Elapsed time.Duration
	Running bool
	Failed  bool

	// Covered is how much of the stage's input actually made it through, of
	// CoverTotal. CoverTotal is 0 when the stage has nothing to report. This is
	// what lets a phase row carry its own completeness, instead of a separate
	// coverage line the reader has to map back onto the phases.
	Covered    int
	CoverTotal int
}

var (
	mu       sync.Mutex
	armed    bool
	armedAt  time.Time
	ledger   []*Stage
	warnings []Warning
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
	armed, armedAt, ledger, warnings = true, now(), nil, nil
	return func() {
		mu.Lock()
		armed = false
		mu.Unlock()
	}
}

// Start registers a stage and starts its clock, returning nil unless the
// registry is armed. total is the denominator and unit names what it counts —
// "files", "funcs", "rules". A bare number tells a reader nothing, so the unit
// is a parameter rather than something the display keeps its own table of:
// a new stage cannot then be added without saying what it counts. total of 0
// means no countable work, and the stage is reported by elapsed time alone.
func Start(id, label string, total int, unit string) *Stage {
	mu.Lock()
	defer mu.Unlock()
	if !armed {
		return nil
	}
	s := &Stage{id: id, label: label, total: total, unit: unit, start: now()}
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

// Cover records how much of the stage's input reached the engine. A frontend
// knows this only once it has collected its results, which is after the last
// Advance and before Done.
func (s *Stage) Cover(covered, total int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.covered, s.coverTotal = covered, total
	s.mu.Unlock()
}

// Warn records a diagnostic for the display. It is additive: a producer that
// calls it should still write its own text to stderr, which stays the record.
func Warn(lang, message, location string) {
	mu.Lock()
	defer mu.Unlock()
	if !armed {
		return
	}
	warnings = append(warnings, Warning{Lang: lang, Message: message, Location: location})
}

// Warnings returns every recorded diagnostic, in the order they were reported.
func Warnings() []Warning {
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(warnings)
}

// WarnTail returns the total recorded and the last n, which is what a display
// showing a capped tail actually needs. Cloning the whole log every frame is the
// one cost here that grows with the length of the scan.
func WarnTail(n int) (total int, tail []Warning) {
	mu.Lock()
	defer mu.Unlock()
	if n > len(warnings) {
		n = len(warnings)
	}
	return len(warnings), slices.Clone(warnings[len(warnings)-n:])
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
		ID:         s.id,
		Label:      s.label,
		Total:      s.total,
		Unit:       s.unit,
		Done:       int(s.done.Load()),
		Offset:     s.start.Sub(armedAt),
		Elapsed:    elapsed,
		Running:    !s.finished,
		Failed:     s.failed,
		Covered:    s.covered,
		CoverTotal: s.coverTotal,
	}
}

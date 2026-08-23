package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/bytevet/godzilla/internal/progress"
)

// The bar is one segment per pipeline stage, sized by that stage's share of the
// scan. A stage that has finished is weighted by what it ACTUALLY took; one
// that has not is weighted by a prior. So the first seconds of a scan are an
// estimate, and every stage that completes replaces its guess with a fact and
// re-scales what is left — which is the only way to show a bar at all, because
// the two phases that dominate a Go scan (`go list` and packages.Load) cannot
// report a fraction of themselves.
//
// Priors are SECONDS, not relative units, because a finished stage is re-weighted
// to the seconds it actually cost — the two have to be the same currency or a
// stage that completes shrinks instead of locking in, and the bar under-reports
// for the whole run. The numbers come from measuring test/go/gin_gorm and
// internal/: parse & lower is 71-85% of wall time, and inside it the Go
// frontend's load phase is the single largest piece.
var priors = map[string]float64{
	"walk":       0.02,
	"go.list":    0.10,
	"go.load":    0.55,
	"go.ssa":     0.25,
	"go.lower":   0.15,
	"index":      0.12,
	"ruleselect": 0.05,
	"taint":      0.02,
}

// convertPrior is the weight for a `<lang>.convert` stage, whose id is not known
// until that frontend starts.
const convertPrior = 0.30

// goStages always run together, so seeing any one of them means the other three
// are coming. Without this the bar would read 100% of "convert" the moment
// `go list` finished, then fall back as each later phase appeared.
var goStages = []string{"go.list", "go.load", "go.ssa", "go.lower"}

// alwaysStages run on every scan regardless of language, so they can be counted
// before they have registered.
var alwaysStages = []string{"walk", "index", "ruleselect", "taint"}

// pendingLabels name a stage the bar is counting but that has not registered
// yet. Without them the legend shows a raw id like "go.ssa" until the stage
// starts, which is the one moment the reader most needs it to read as English.
var pendingLabels = map[string]string{
	"walk":       "walk",
	"go.list":    "go list (metadata)",
	"go.load":    "go parse & typecheck",
	"go.ssa":     "go SSA build",
	"go.lower":   "go lowering",
	"index":      "index & call graph",
	"ruleselect": "rule selection",
	"taint":      "taint propagation",
}

// labelFor names a stage that has not registered yet.
func labelFor(id string) string {
	if l, ok := pendingLabels[id]; ok {
		return l
	}
	if lang, ok := strings.CutSuffix(id, ".convert"); ok {
		return lang + " parse & lower"
	}
	return id
}

func priorOf(id string) float64 {
	if w, ok := priors[id]; ok {
		return w
	}
	return convertPrior
}

// segment is one stage's share of the bar.
type segment struct {
	id       string
	label    string
	weight   float64
	fraction float64 // 0..1 completion
	started  bool
	running  bool
	failed   bool
	elapsed  time.Duration
	done     int
	total    int
}

// plan turns the live ledger into the bar's segments, in pipeline order. Stages
// that have not registered yet are included at their prior when the pipeline
// guarantees they are coming, so the denominator does not grow under the bar.
func plan(stages []progress.Snapshot) []segment {
	seen := make(map[string]progress.Snapshot, len(stages))
	var order []string
	sawGo := false
	for _, s := range stages {
		if _, dup := seen[s.ID]; !dup {
			order = append(order, s.ID)
		}
		seen[s.ID] = s
		if strings.HasPrefix(s.ID, "go.") {
			sawGo = true
		}
	}

	expected := append([]string{}, alwaysStages...)
	if sawGo {
		expected = append(expected, goStages...)
	}
	expected = append(expected, order...)

	var segs []segment
	placed := map[string]bool{}
	for _, id := range pipelineOrder(expected) {
		if placed[id] {
			continue
		}
		placed[id] = true
		seg := segment{id: id, label: labelFor(id), weight: priorOf(id)}
		s, ok := seen[id]
		if ok {
			seg.label, seg.started, seg.running = s.Label, true, s.Running
			seg.failed, seg.elapsed, seg.done, seg.total = s.Failed, s.Elapsed, s.Done, s.Total
			seg.fraction = completion(s)
			if !s.Running {
				// A finished stage is worth what it cost, not what we guessed.
				seg.weight = max(s.Elapsed.Seconds(), 0.001)
			} else if e := s.Elapsed.Seconds(); e > seg.weight {
				// Nor may a stage that has already outrun its prior keep it, or
				// the bar would stall at that segment's edge.
				seg.weight = e
			}
		}
		segs = append(segs, seg)
	}
	return segs
}

// completion is how far through a stage is. A stage that counts its work
// reports it directly; one that cannot is inferred from elapsed against its
// prior and capped below 1, so an estimate never claims a stage has finished.
func completion(s progress.Snapshot) float64 {
	if !s.Running {
		return 1
	}
	if s.Total > 0 {
		return min(float64(s.Done)/float64(s.Total), 1)
	}
	return min(s.Elapsed.Seconds()/priorOf(s.ID), 0.95)
}

// pipelineOrder sorts stage ids the way the scan runs them, so the bar reads
// left to right as time. Languages sort among themselves alphabetically for a
// stable display: their goroutines race to register.
func pipelineOrder(ids []string) []string {
	rank := func(id string) int {
		switch {
		case id == "walk":
			return 0
		case strings.HasPrefix(id, "go."):
			for i, g := range goStages {
				if g == id {
					return 10 + i
				}
			}
			return 19
		case strings.HasSuffix(id, ".convert"):
			return 20
		case id == "index":
			return 30
		case id == "ruleselect":
			return 31
		case id == "taint":
			return 32
		}
		return 25
	}
	out := append([]string{}, ids...)
	// Insertion sort: the list is a dozen entries and must be stable.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if rank(a) < rank(b) || (rank(a) == rank(b) && a <= b) {
				break
			}
			out[j-1], out[j] = b, a
		}
	}
	return out
}

// overall is the weighted completion across every segment.
func overall(segs []segment) float64 {
	var done, total float64
	for _, s := range segs {
		total += s.weight
		done += s.weight * s.fraction
	}
	if total == 0 {
		return 0
	}
	return min(done/total, 1)
}

// fmtDur renders a duration at the display's own resolution, so no digit is
// ever stale between ticks.
func fmtDur(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// clip truncates to n columns on a rune boundary. Every line the display
// AUTHORS is clipped, because a bar line that wraps would make the erase
// sequence's row count wrong and corrupt everything above it. Lines that merely
// pass THROUGH the display are never clipped — see writeLog.
func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

package tui

import (
	"fmt"
	"slices"
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
type stage struct {
	id    string
	label string  // used until the producer registers its own
	prior float64 // seconds — see the note above
	// always marks a stage that runs on every scan whatever the languages, so
	// the bar can count it before it has registered.
	always bool
	// group marks stages that run together, so seeing any one of them means the
	// rest are coming. Without it the bar would read 100% the moment `go list`
	// finished, then fall back as each later Go phase appeared.
	group string
}

// The four phase groups. The footer bar is one run per group rather than one
// per stage: thirteen segments in a forty-cell bar are two or three cells each,
// which reads as noise, and the group is the level at which "where did the time
// go" is actually answered.
const (
	groupFrontends = "frontends"
	groupGo        = "go"
	groupAnalysis  = "analysis"
	groupLLM       = "LLM"
)

// groupOrder is the order groups appear in the bar and the legend.
var groupOrder = []string{groupFrontends, groupGo, groupAnalysis, groupLLM}

// convertSlot holds the place of the `<lang>.convert` stages, whose ids are not
// known until a frontend starts. Every language's convert stage ranks here.
const convertSlot = "*.convert"

// pipeline is the ONE table the bar keeps about the pipeline, in pipeline ORDER —
// a stage's rank is its index, so the bar reads left to right as time. Adding a
// stage is a line here rather than an edit to a weight map, a label map and a
// sort. Its colour lives in palette.go, keyed by the same ids: a separate
// concern, because that has to be expressed three times over for three colour
// depths.
var pipeline = []stage{
	{id: "walk", label: "walk", prior: 0.02, always: true, group: groupFrontends},
	{id: "go.list", label: "go list (metadata)", prior: 0.10, group: groupGo},
	{id: "go.load", label: "go parse & typecheck", prior: 0.55, group: groupGo},
	{id: "go.ssa", label: "go SSA build", prior: 0.25, group: groupGo},
	{id: "go.lower", label: "go lowering", prior: 0.15, group: groupGo},
	{id: convertSlot, prior: 0.30, group: groupFrontends},
	{id: "index", label: "index & call graph", prior: 0.12, always: true, group: groupAnalysis},
	{id: "ruleselect", label: "rule selection", prior: 0.05, always: true, group: groupAnalysis},
	{id: "taint", label: "taint propagation", prior: 0.02, always: true, group: groupAnalysis},
	{id: "llm", label: "LLM review", prior: 6.0, group: groupLLM},
}

// index is every stage id's place in the table, resolved once. slot() is on the
// sort's comparison path, which runs a few hundred times a frame.
var index = func() map[string]int {
	out := make(map[string]int, len(pipeline))
	for i, st := range pipeline {
		out[st.id] = i
	}
	return out
}()

// slot maps a stage id onto its table entry. An unregistered language's convert
// stage and an id the table has never heard of both land on the convert slot,
// which is where an unknown frontend stage belongs in the run.
func slot(id string) (stage, int) {
	i, ok := index[id]
	if !ok {
		i = index[convertSlot]
	}
	return pipeline[i], i
}

// groupName is the phase group a stage belongs to.
func groupName(id string) string {
	st, _ := slot(id)
	if st.group == "" {
		return groupFrontends
	}
	return st.group
}

// labelFor names a stage that has not registered yet. Without it the bar shows a
// raw id like "go.ssa" until the stage starts, which is the one moment the
// reader most needs it to read as English.
func labelFor(id string) string {
	if st, _ := slot(id); st.id == id && st.label != "" {
		return st.label
	}
	if lang, ok := strings.CutSuffix(id, ".convert"); ok {
		return lang + " parse & lower"
	}
	return id
}

func priorOf(id string) float64 {
	st, _ := slot(id)
	return st.prior
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
// expect names stages only the caller knows are coming — the LLM review, which
// no scan stage implies.
func plan(stages []progress.Snapshot, expect []string) []segment {
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

	// A stage the pipeline guarantees is coming is counted before it registers,
	// so the denominator does not grow under the bar. Seeing any Go phase means
	// the other three are on their way.
	var expected []string
	for _, st := range pipeline {
		if st.always || (sawGo && st.group == groupGo) {
			expected = append(expected, st.id)
		}
	}
	expected = append(expected, expect...)
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
// left to right as time — a stage's rank is its index in the stages table.
// Languages sort among themselves alphabetically for a stable display: their
// goroutines race to register.
func pipelineOrder(ids []string) []string {
	out := append([]string{}, ids...)
	slices.SortStableFunc(out, func(a, b string) int {
		_, ra := slot(a)
		_, rb := slot(b)
		if ra != rb {
			return ra - rb
		}
		return strings.Compare(a, b)
	})
	return out
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

// barSeg is one group's run of cells in the footer bar.
type barSeg struct {
	group string
	cells int
}

// groupTime is a group's total cost, for the closing legend.
type groupTime struct {
	name    string
	elapsed time.Duration
}

// bars apportions the footer's filled cells among the phase groups and returns
// the overall percentage. Cells go by each group's COMPLETED weight, so the
// filled length IS the progress and the track is what remains — the bar cannot
// be full while work is outstanding.
func bars(segs []segment, cells int) ([]barSeg, float64) {
	done := map[string]float64{}
	var total, finished float64
	for _, s := range segs {
		total += s.weight
		d := s.weight * s.fraction
		finished += d
		done[groupName(s.id)] += d
	}
	if total <= 0 {
		return nil, 0
	}
	pct := min(finished/total, 1)

	// Cumulative rounding, so the runs sum to the filled length by CONSTRUCTION:
	// the last cumulative term is `finished`, which makes the final boundary
	// exactly `filled`. Apportioning largest-remainder instead needs a spent
	// marker and a guard against the hand-out loop not terminating.
	filled := int(float64(cells)*pct + 0.5)
	var out []barSeg
	var cum, prev float64
	for _, g := range groupOrder {
		if done[g] <= 0 {
			continue
		}
		cum += done[g]
		n := int(float64(filled)*cum/finished+0.5) - int(float64(filled)*prev/finished+0.5)
		prev = cum
		if n > 0 {
			out = append(out, barSeg{group: g, cells: n})
		}
	}
	return out, pct
}

// groupTimes totals what each group cost, in pipeline order.
func groupTimes(segs []segment) []groupTime {
	sum := map[string]time.Duration{}
	for _, s := range segs {
		if s.started {
			sum[groupName(s.id)] += s.elapsed
		}
	}
	out := make([]groupTime, 0, len(groupOrder))
	for _, g := range groupOrder {
		if sum[g] > 0 {
			out = append(out, groupTime{name: g, elapsed: sum[g]})
		}
	}
	return out
}

// runningLabel names what is in flight, for the footer's trailing field.
func runningLabel(segs []segment) string {
	for _, s := range segs {
		if s.running {
			return s.label
		}
	}
	return ""
}

// completed treats every segment as finished, for the closing frame: the bar has
// to read 100% when the run actually finished, not carry the estimate a stage
// that never registered was still holding a place for.
func completed(segs []segment) []segment {
	out := make([]segment, 0, len(segs))
	for _, s := range segs {
		if !s.started {
			continue
		}
		s.fraction = 1
		out = append(out, s)
	}
	return out
}

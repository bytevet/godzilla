package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bytevet/godzilla/internal/progress"
)

func snap(id, label string, total, done, ms int, running, failed bool) progress.Snapshot {
	return progress.Snapshot{
		ID: id, Label: label, Total: total, Done: done,
		Elapsed: time.Duration(ms) * time.Millisecond, Running: running, Failed: failed,
	}
}

func midScan() []progress.Snapshot {
	return []progress.Snapshot{
		snap("walk", "walk", 0, 0, 20, false, false),
		snap("go.list", "go list (metadata)", 0, 0, 310, false, false),
		snap("go.load", "go parse & typecheck", 0, 0, 420, true, false),
		snap("python.convert", "python parse & lower", 1180, 640, 280, true, false),
	}
}

// The erase sequence moves the cursor up by the row count of the last frame, so
// a bar line that wrapped would put every subsequent erase out by one and eat
// the scrollback above it. Nothing the display authors may exceed the width.
func TestAuthoredLinesNeverExceedTheWidth(t *testing.T) {
	long := []progress.Snapshot{
		snap("walk", strings.Repeat("very-long-stage-label ", 12), 0, 0, 20, false, false),
		snap("python.convert", strings.Repeat("x", 300), 10, 3, 90, true, false),
	}
	for _, w := range []int{120, 80, 60, 40, 24, 12, 6, 3, 1} {
		for _, mode := range []colorMode{colorNone, colorTrue} {
			p := palette{mode: mode, trueHex: map[string]string{"walk": "#2fbfa8"}}
			for _, st := range [][]progress.Snapshot{midScan(), long} {
				lines, _ := frame(st, w, p, time.Second, 0, nil)
				for _, line := range lines {
					if n := visibleWidth(line); n > w {
						t.Errorf("width %d mode %d: line is %d columns: %q", w, mode, n, line)
					}
				}
			}
		}
	}
}

// Truncation must not cut a multi-byte rune in half, or the terminal renders a
// replacement glyph and the column count is wrong too.
func TestTruncationIsRuneSafe(t *testing.T) {
	st := []progress.Snapshot{snap("python.convert", "解析与降级パース", 10, 4, 120, true, false)}
	for _, w := range []int{4, 8, 10, 16, 30} {
		lines, _ := frame(st, w, palette{mode: colorNone}, time.Second, 0, nil)
		for _, line := range lines {
			if !utf8.ValidString(line) {
				t.Errorf("width %d produced invalid UTF-8: %q", w, line)
			}
		}
	}
}

// Segments must sum to exactly the bar's interior, or the bar is a column short
// or long and the line wraps.
func TestSegmentsFillTheBarExactly(t *testing.T) {
	segs := plan(midScan(), nil)
	for _, w := range []int{1, 7, 13, 40, 64, 200} {
		got := cells(segs, w)
		sum := 0
		for _, c := range got {
			if c < 0 {
				t.Fatalf("width %d: negative cell count %v", w, got)
			}
			sum += c
		}
		if sum != w {
			t.Errorf("width %d: cells sum to %d, want %d (%v)", w, sum, w, got)
		}
	}
}

// A stage too fast to earn a column still has to appear, or the legend claims
// something happened that the bar does not show.
func TestAStartedStageAlwaysGetsAColumn(t *testing.T) {
	segs := plan(midScan(), nil)
	got := cells(segs, 40)
	for i, s := range segs {
		if s.started && got[i] == 0 {
			t.Errorf("started stage %q got no column: %v", s.id, got)
		}
	}
}

// The bar reads left to right as time, so the order is the pipeline's, not the
// order goroutines happened to register in.
func TestSegmentsAreInPipelineOrder(t *testing.T) {
	// Deliberately registered out of order, as concurrent frontends would.
	st := []progress.Snapshot{
		snap("taint", "taint propagation", 3, 1, 5, true, false),
		snap("python.convert", "python parse & lower", 4, 4, 30, false, false),
		snap("go.list", "go list (metadata)", 0, 0, 10, false, false),
		snap("walk", "walk", 0, 0, 2, false, false),
	}
	var ids []string
	for _, s := range plan(st, nil) {
		ids = append(ids, s.id)
	}
	want := []string{"walk", "go.list", "go.load", "go.ssa", "go.lower", "python.convert", "index", "ruleselect", "taint"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v\nwant  %v", ids, want)
	}
}

// Seeing any go.* stage means the other three are coming. Without that the bar
// would read as good as finished the moment `go list` returned.
func TestGoSubStagesAreCountedBeforeTheyStart(t *testing.T) {
	only := []progress.Snapshot{
		snap("walk", "walk", 0, 0, 20, false, false),
		snap("go.list", "go list (metadata)", 0, 0, 310, false, false),
	}
	segs := plan(only, nil)
	var pending []string
	for _, s := range segs {
		if !s.started {
			pending = append(pending, s.id)
		}
	}
	for _, want := range []string{"go.load", "go.ssa", "go.lower"} {
		if !strings.Contains(strings.Join(pending, ","), want) {
			t.Errorf("%s is not being counted yet; pending = %v", want, pending)
		}
	}
	if pct := overall(segs); pct > 0.5 {
		t.Errorf("overall = %.2f with only `go list` done; the later Go phases are not being counted", pct)
	}
}

// A stage that has not registered yet must still read as English.
func TestPendingStagesAreNamed(t *testing.T) {
	for _, s := range plan(midScan(), nil) {
		if strings.Contains(s.label, ".") && !strings.Contains(s.label, " ") {
			t.Errorf("stage %q shows a raw id as its label: %q", s.id, s.label)
		}
	}
}

// An estimate must never claim a stage finished; only Done may do that.
func TestAnEstimateNeverReachesComplete(t *testing.T) {
	running := snap("go.load", "go parse & typecheck", 0, 0, 60_000, true, false)
	if got := completion(running); got >= 1 {
		t.Errorf("completion = %v for a stage far past its prior, want < 1", got)
	}
	done := snap("go.load", "go parse & typecheck", 0, 0, 1, false, false)
	if got := completion(done); got != 1 {
		t.Errorf("completion = %v for a finished stage, want 1", got)
	}
}

// Finishing re-weights a stage to what it actually cost, which is what makes the
// bar re-scale rather than keep believing the prior.
func TestFinishingReweightsToActualCost(t *testing.T) {
	slow := []progress.Snapshot{snap("go.load", "go parse & typecheck", 0, 0, 30_000, false, false)}
	var w float64
	for _, s := range plan(slow, nil) {
		if s.id == "go.load" {
			w = s.weight
		}
	}
	if w <= priors["go.load"] {
		t.Errorf("weight = %v after a 30s run, want it re-scaled above the %v prior", w, priors["go.load"])
	}
}

// Colour is an enhancement; the breakdown has to survive without it.
func TestFailureIsVisibleWithoutColour(t *testing.T) {
	st := []progress.Snapshot{
		snap("walk", "walk", 0, 0, 20, false, false),
		snap("python.convert", "python parse & lower", 4, 4, 30, false, true),
	}
	lines, _ := frame(st, 80, palette{mode: colorNone}, time.Second, 0, nil)
	if !strings.Contains(lines[0], "!") {
		t.Errorf("a failed stage is indistinguishable in a colourless bar: %q", lines[0])
	}
}

// visibleWidth counts columns, stepping over SGR sequences the same way the
// renderer's own clip does.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// The sticky block is ONE line. Every finished stage is already promoted into
// the scrollback with its elapsed time, so a second legend row would spend a
// row of the user's terminal restating it.
func TestTheStickyBarIsASingleLine(t *testing.T) {
	for _, w := range []int{200, 120, 80, 60, 40} {
		for _, st := range [][]progress.Snapshot{midScan(), {snap("walk", "walk", 0, 0, 20, true, false)}} {
			if lines, _ := frame(st, w, palette{mode: colorTrue}, time.Second, 0, nil); len(lines) != 1 {
				t.Errorf("width %d: bar occupies %d lines, want 1: %q", w, len(lines), lines)
			}
		}
	}
}

// The line has to say where the scan is now — that is the job the legend row
// used to do, and the one thing the scrollback cannot show.
func TestTheBarNamesWhatIsRunning(t *testing.T) {
	st := []progress.Snapshot{snap("go.lower", "go lowering", 100, 40, 200, true, false)}
	lines, _ := frame(st, 80, palette{mode: colorNone}, time.Second, 0, nil)
	if !strings.Contains(lines[0], "lowering") {
		t.Errorf("bar does not name the running stage: %q", lines[0])
	}
}

// A stage no scan stage implies — the LLM review — has to be in the denominator
// from the first frame. Discovered only when it starts, it would leave the bar
// pinned near 100% for the longest wait in the run.
func TestAReservedStageIsCountedBeforeItRegisters(t *testing.T) {
	st := midScan()
	var found bool
	for _, s := range plan(st, []string{"llm"}) {
		if s.id == "llm" {
			found = true
			if s.started {
				t.Error("a reserved stage must not read as started")
			}
		}
	}
	if !found {
		t.Fatal("reserved stage llm is missing from the plan")
	}
	with, without := overall(plan(st, []string{"llm"})), overall(plan(st, nil))
	if with >= without {
		t.Errorf("reserving a stage did not grow the denominator: %v vs %v", with, without)
	}
}

// The scrollback line is what the user actually reads after the scan, so it has
// to answer its own questions: did it pass, how much work was it, what did this
// stage cost, and where in the run did it land.
func TestLedgerLineIsSelfExplanatory(t *testing.T) {
	p := palette{mode: colorNone}
	ok := progress.Snapshot{ID: "go.lower", Label: "go lowering", Total: 8626, Done: 8626,
		Unit: "funcs", Offset: 1280 * time.Millisecond, Elapsed: 140 * time.Millisecond}
	got := p.ledgerLine(ok, 100)
	for _, want := range []string{"✓", "go lowering", "8626 funcs", "+0.14s", "@1.42s"} {
		if !strings.Contains(got, want) {
			t.Errorf("ledger line is missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "ok") {
		t.Errorf("the outcome should be a mark, not a word: %q", got)
	}

	bad := progress.Snapshot{ID: "java.convert", Label: "java parse & lower",
		Failed: true, Offset: 500 * time.Millisecond, Elapsed: 940 * time.Millisecond}
	got = p.ledgerLine(bad, 100)
	if !strings.Contains(got, "✗") {
		t.Errorf("a failed stage is not marked: %q", got)
	}
	// A stage with nothing to count must not invent a zero.
	if strings.Contains(got, " 0 ") {
		t.Errorf("uncountable stage shows a bogus count: %q", got)
	}
}

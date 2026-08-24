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
		ID: id, Label: label, Total: total, Done: done, Unit: "files",
		Elapsed: time.Duration(ms) * time.Millisecond, Running: running, Failed: failed,
	}
}

func covered(s progress.Snapshot, got, want int) progress.Snapshot {
	s.Covered, s.CoverTotal = got, want
	return s
}

func midScan() []progress.Snapshot {
	return []progress.Snapshot{
		snap("walk", "walk", 281, 281, 20, false, false),
		covered(snap("javascript.convert", "javascript parse & lower", 87, 87, 40, false, false), 86, 87),
		covered(snap("rust.convert", "rust parse & lower", 24, 24, 330, false, true), 21, 24),
		snap("go.list", "go list (metadata)", 0, 0, 500, false, false),
		snap("go.load", "go parse & typecheck", 0, 0, 550, true, false),
	}
}

// The footer's fields are fixed so the bar cannot jitter as phase names change
// length. At full width that is exactly 80 columns: a 40-cell bar, percent in 4,
// elapsed in 6, label in 24, two spaces between each.
func TestFooterIsExactlyEightyColumns(t *testing.T) {
	segs := plan(midScan(), nil)
	for _, mode := range []colorMode{colorNone, color256, colorTrue} {
		p := palette{mode: mode}
		cells, withLabel := barCellsFor(80)
		if !withLabel || cells != barCells {
			t.Fatalf("mode %d: width 80 should carry a full bar and a label", mode)
		}
		runs, pct := bars(segs, cells)
		got := p.footer(runs, cells, pct, 6500*time.Millisecond, "go parse & typecheck", false)
		if n := visibleWidth(got); n != footerWidth {
			t.Errorf("mode %d: footer is %d columns, want %d:\n%q", mode, n, footerWidth, got)
		}
	}
}

// A phase name longer than its field truncates rather than pushing the layout
// out — that is what "fixed fields" buys.
func TestALongLabelDoesNotWidenTheFooter(t *testing.T) {
	segs := plan(midScan(), nil)
	runs, pct := bars(segs, barCells)
	got := palette{mode: colorTrue}.footer(runs, barCells, pct, time.Second,
		strings.Repeat("very-long-phase-name ", 6), false)
	if n := visibleWidth(got); n != footerWidth {
		t.Errorf("footer is %d columns, want %d:\n%q", n, footerWidth, got)
	}
}

// The bar's runs must sum to the filled length and never exceed the cell count,
// or the footer gains or loses a column and the erase arithmetic drifts.
func TestBarRunsNeverExceedTheCellCount(t *testing.T) {
	segs := plan(midScan(), nil)
	for _, cells := range []int{4, 9, 17, 40, 64} {
		runs, pct := bars(segs, cells)
		sum := 0
		for _, r := range runs {
			if r.cells < 0 {
				t.Fatalf("cells %d: negative run %v", cells, runs)
			}
			sum += r.cells
		}
		if want := int(float64(cells)*pct + 0.5); sum != want {
			t.Errorf("cells %d: runs sum to %d, want the filled length %d", cells, sum, want)
		}
		if sum > cells {
			t.Errorf("cells %d: runs overflow the bar: %d", cells, sum)
		}
	}
}

// Coverage decides the status glyph. This is the whole point of folding coverage
// onto the row: a frontend that ran but lowered only some of its files is
// PARTIAL, which the separate coverage line could only say somewhere else.
func TestStatusComesFromCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   progress.Snapshot
		want string
	}{
		{"all files lowered", covered(snap("ruby.convert", "ruby", 47, 47, 10, false, false), 47, 47), glyphOK},
		{"some files skipped", covered(snap("java.convert", "java", 48, 48, 10, false, false), 1, 48), glyphPartial},
		{"frontend gave up", covered(snap("rust.convert", "rust", 24, 24, 10, false, true), 21, 24), glyphFailed},
		{"nothing to count", snap("go.ssa", "go SSA build", 0, 0, 10, false, false), glyphOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := statusOf(tc.in); got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// A running row has no took and no coverage: only the elapsed clock moves, so
// the columns cannot reflow under the reader when the phase lands.
func TestARunningRowShowsNoFinalColumns(t *testing.T) {
	running := covered(snap("go.load", "go parse & typecheck", 10, 4, 550, true, false), 4, 10)
	got := palette{mode: colorNone}.row(running, 80, 0)
	if strings.Contains(got, "+0.55s") {
		t.Errorf("a running row must not show a took column: %q", got)
	}
	if strings.Contains(got, "4/10") {
		t.Errorf("a running row must not show coverage yet: %q", got)
	}
	if !strings.Contains(got, "@0.55s") {
		t.Errorf("a running row must show the elapsed clock: %q", got)
	}
}

// Four states stay distinct with no colour at all. Colour is a second channel
// carrying the same fact, never the only one.
func TestStatesAreDistinctWithoutColour(t *testing.T) {
	p := palette{mode: colorNone}
	rows := map[string]string{
		"ok":      p.row(covered(snap("a", "ruby", 4, 4, 10, false, false), 4, 4), 80, 0),
		"partial": p.row(covered(snap("b", "java", 4, 4, 10, false, false), 1, 4), 80, 0),
		"failed":  p.row(covered(snap("c", "rust", 4, 4, 10, false, true), 1, 4), 80, 0),
		"running": p.row(snap("d", "go", 4, 1, 10, true, false), 80, 0),
	}
	for name, got := range rows {
		if strings.ContainsRune(got, 0x1b) {
			t.Errorf("%s: colour escape leaked into a no-colour row: %q", name, got)
		}
	}
	markers := map[string]string{"ok": "[+]", "partial": "[!]", "failed": "[x]"}
	for name, want := range markers {
		if !strings.HasPrefix(rows[name], want) {
			t.Errorf("%s: row should lead with %q: %q", name, want, rows[name])
		}
	}
	if !strings.HasPrefix(rows["running"], "[") || rows["running"][:3] == "[+]" {
		t.Errorf("running should carry a spinner bracket: %q", rows["running"])
	}
}

// Columns drop in a fixed order as width falls: took first, then volume. Status,
// name, coverage and elapsed are the four that survive.
func TestColumnsDropInOrder(t *testing.T) {
	s := covered(snap("java.convert", "java parse & lower", 48, 48, 990, false, false), 1, 48)
	p := palette{mode: colorNone}

	full := p.row(s, 80, 0)
	for _, want := range []string{"48 files", "1/48", "+0.99s", "@0.99s"} {
		if !strings.Contains(full, want) {
			t.Errorf("full row is missing %q: %q", want, full)
		}
	}
	noTook := p.row(s, colStatus+colName+colVolume+colCovered+colElapsed+2, 0)
	if strings.Contains(noTook, "+0.99s") {
		t.Errorf("took should be the first column dropped: %q", noTook)
	}
	if !strings.Contains(noTook, "48 files") {
		t.Errorf("volume should outlast took: %q", noTook)
	}
	narrow := p.row(s, 44, 0)
	if strings.Contains(narrow, "48 files") {
		t.Errorf("volume should be the second column dropped: %q", narrow)
	}
	for _, want := range []string{"1/48", "@0.99s"} {
		if !strings.Contains(narrow, want) {
			t.Errorf("narrow row lost %q, which must survive: %q", want, narrow)
		}
	}
}

// Nothing the display AUTHORS may exceed the width. A line that wrapped would
// put every later erase out by a row and eat the scrollback above the block.
func TestAuthoredLinesNeverExceedTheWidth(t *testing.T) {
	long := covered(snap("python.convert", strings.Repeat("very-long-stage-label ", 12), 300, 3, 90, true, false), 3, 300)
	segs := plan(midScan(), nil)
	for _, w := range []int{120, 80, 62, 40, 24, 12, 6, 2} {
		for _, mode := range []colorMode{colorNone, colorTrue} {
			p := palette{mode: mode}
			for _, st := range append(midScan(), long) {
				if n := visibleWidth(p.row(st, w, 3)); n > w {
					t.Errorf("width %d mode %d: row is %d columns: %q", w, mode, n, p.row(st, w, 3))
				}
			}
			cells, withLabel := barCellsFor(w)
			runs, pct := bars(segs, cells)
			label := ""
			if withLabel {
				label = "go parse & typecheck"
			}
			f := p.footer(runs, cells, pct, time.Second, label, false)
			if n := visibleWidth(f); n > max(w, footerWidth) {
				t.Errorf("width %d mode %d: footer is %d columns: %q", w, mode, n, f)
			}
			if n := visibleWidth(p.legend(groupTimes(segs), w-1)); n > w {
				t.Errorf("width %d mode %d: legend is %d columns", w, mode, n)
			}
		}
	}
}

// Truncation must not cut a multi-byte rune in half, or the terminal renders a
// replacement glyph and the column count is wrong too.
func TestTruncationIsRuneSafe(t *testing.T) {
	st := covered(snap("python.convert", "解析与降级パース", 10, 4, 120, false, false), 4, 10)
	for _, w := range []int{4, 8, 10, 16, 30, 80} {
		got := palette{mode: colorTrue}.row(st, w, 0)
		if !utf8.ValidString(got) {
			t.Errorf("width %d produced invalid UTF-8: %q", w, got)
		}
	}
}

// On abort the percentage is replaced and the label dropped: a progress bar that
// races to 100% on a crash is a lie.
func TestAbortReplacesThePercentage(t *testing.T) {
	segs := plan(midScan(), nil)
	runs, pct := bars(segs, barCells)
	got := palette{mode: colorNone}.footer(runs, barCells, pct, 1180*time.Millisecond, "go SSA build", true)
	if !strings.Contains(got, abortedText) {
		t.Errorf("an aborted footer should say %q: %q", abortedText, got)
	}
	if strings.Contains(got, "%") {
		t.Errorf("an aborted footer must not claim a percentage: %q", got)
	}
	if strings.Contains(got, "go SSA build") {
		t.Errorf("an aborted footer drops the running label: %q", got)
	}
}

// The bar reads left to right as time, so groups appear in pipeline order.
func TestBarRunsAreInPipelineOrder(t *testing.T) {
	segs := plan([]progress.Snapshot{
		snap("llm", "LLM review", 39, 39, 5210, false, false),
		snap("taint", "taint propagation", 39, 39, 20, false, false),
		snap("go.list", "go list (metadata)", 0, 0, 500, false, false),
		snap("ruby.convert", "ruby parse & lower", 47, 47, 430, false, false),
	}, nil)
	runs, _ := bars(segs, barCells)
	var got []string
	for _, r := range runs {
		got = append(got, r.group)
	}
	want := []string{groupFrontends, groupGo, groupAnalysis, groupLLM}
	var filtered []string
	for _, w := range want {
		for _, g := range got {
			if g == w {
				filtered = append(filtered, w)
				break
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(filtered, ",") {
		t.Errorf("bar runs are out of pipeline order: %v", got)
	}
}

// The legend names only groups that actually ran, with what they cost.
func TestLegendCoversTheGroupsThatRan(t *testing.T) {
	segs := plan(midScan(), nil)
	got := palette{mode: colorNone}.legend(groupTimes(segs), 200)
	for _, want := range []string{groupFrontends, groupGo} {
		if !strings.Contains(got, want) {
			t.Errorf("legend is missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, groupLLM) {
		t.Errorf("legend names a group that never ran: %q", got)
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

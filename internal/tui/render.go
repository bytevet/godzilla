package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bytevet/godzilla/internal/progress"
)

type colorMode int

const (
	colorNone colorMode = iota
	color16
	color256
	colorTrue
)

// The status glyphs. Three OUTCOMES are distinguishable without colour, which
// matters for the no-colour build and for a red/green deficiency — the colour is
// a second channel carrying the same fact, never the only one.
const (
	glyphOK      = "✓"
	glyphPartial = "!"
	glyphFailed  = "✗"
)

// asciiStatus is the no-colour form. It widens to a three-character bracket so
// four states stay distinct with no colour at all; column positions shift by
// one, nothing else changes.
var asciiStatus = map[string]string{
	glyphOK: "[+]", glyphPartial: "[!]", glyphFailed: "[x]",
}

// spinFrames is the running marker. Braille reads as motion at a glance and
// costs one cell; the ASCII rung falls back to a rotating bar inside [*],
// because braille is not safe on a legacy console.
var (
	spinFrames  = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	spinASCII   = []rune{'|', '/', '-', '\\'}
	barFill     = '█'
	barTrack    = '░'
	legendBlock = "▪"
)

// The phase row's columns, in characters. Fixed widths are the point: the
// numbers line up down the block, so a slow phase is found by scanning one
// column rather than reading every row.
const (
	colStatus  = 3
	colName    = 26
	colVolume  = 11
	colCovered = 8
	colTook    = 9
	colElapsed = 9

	// The narrow tier, once volume and took are gone.
	narrowCovered = 10
	narrowElapsed = 8
)

// row is one phase line. Which columns survive depends on the width: took goes
// first, then volume, because they are the two a reader can do without — status,
// name, coverage and the elapsed clock are the four that answer "what happened
// and how far in".
func (p palette) row(s progress.Snapshot, width int, spin int) string {
	status, hex := statusOf(s)

	statusW := colStatus
	if p.mode == colorNone {
		statusW++
		if s.Running {
			status = "[" + string(spinASCII[spin%len(spinASCII)]) + "]"
		} else {
			status = asciiStatus[status]
		}
	} else if s.Running {
		status = string(spinFrames[spin%len(spinFrames)])
	}

	// A running row has no took and no coverage yet: only the elapsed clock
	// moves, so the columns cannot reflow under the reader when they land.
	took, covered := "", ""
	if !s.Running {
		took = "+" + fmtDur(s.Elapsed)
		covered = coverageOf(s)
	}
	// Two clocks, and they answer different questions: +took is what this phase
	// COST, @elapsed is where the run stood when it ended.
	elapsed := "@" + fmtDur(s.Offset+s.Elapsed)

	var b strings.Builder
	b.WriteString(p.paint(hex, pad(status, statusW)))
	switch {
	case width >= statusW+colName+colVolume+colCovered+colTook+colElapsed:
		b.WriteString(p.fg(pad(s.Label, colName)))
		b.WriteString(p.mut(rpad(volumeOf(s), colVolume)))
		b.WriteString(p.paint(hex, rpad(covered, colCovered)))
		b.WriteString(p.dim(rpad(took, colTook)))
		b.WriteString(p.mut(rpad(elapsed, colElapsed)))
	case width >= statusW+colName+colVolume+colCovered+colElapsed:
		b.WriteString(p.fg(pad(s.Label, colName)))
		b.WriteString(p.mut(rpad(volumeOf(s), colVolume)))
		b.WriteString(p.paint(hex, rpad(covered, colCovered)))
		b.WriteString(p.mut(rpad(elapsed, colElapsed)))
	default:
		// The four that survive: status, name, coverage, elapsed. The name gives
		// up whatever the width still needs.
		name := max(width-statusW-narrowCovered-narrowElapsed, 4)
		b.WriteString(p.fg(pad(s.Label, name)))
		b.WriteString(p.paint(hex, rpad(covered, narrowCovered)))
		b.WriteString(p.mut(rpad(elapsed, narrowElapsed)))
	}
	// Clipped unconditionally: a row that wrapped would put every later erase out
	// by a line and eat the scrollback above the block.
	return clipStyled(b.String(), width)
}

// statusOf reduces a stage to the one thing the row leads with. Coverage decides
// it: a frontend that ran but lowered only some of its files is PARTIAL, which
// the old display could not say at all — it reported the phase as done and left
// the completeness to a separate line further down.
func statusOf(s progress.Snapshot) (glyph, hex string) {
	switch {
	case s.Failed:
		return glyphFailed, badHex
	case s.Running:
		return glyphOK, accHex
	case s.CoverTotal > 0 && s.Covered < s.CoverTotal:
		return glyphPartial, partHex
	}
	return glyphOK, okHex
}

func coverageOf(s progress.Snapshot) string {
	if s.CoverTotal > 0 {
		return fmt.Sprintf("%d/%d", s.Covered, s.CoverTotal)
	}
	if s.Failed {
		return "failed"
	}
	return ""
}

// volumeOf is how much work the phase represents. While it runs the reader wants
// the fraction; once it is done the total is the durable fact.
func volumeOf(s progress.Snapshot) string {
	if s.Total <= 0 {
		return ""
	}
	if s.Running {
		return fmt.Sprintf("%d of %d", s.Done, s.Total)
	}
	return strings.TrimSpace(fmt.Sprintf("%d %s", s.Total, s.Unit))
}

// The footer is exactly footerWidth columns, always. Its fields are fixed so the
// bar cannot jitter as phase names change length: a label longer than its field
// truncates instead.
const (
	footerWidth = 80
	barCells    = 40
	pctWidth    = 4
	elapsedW    = 6
	labelWidth  = 24
	abortedText = "stopped"
)

// footer draws the bar, the percentage, the clock and the running phase. On
// abort the percentage is replaced by "stopped" and the label is dropped: a
// progress bar that races to 100% on a crash is a lie.
// barCellsFor is how wide the bar may be. The trailing label leaves the footer
// before the bar shortens — a two-character bar is worth less than the
// percentage — and below that the bar gives up cells one at a time.
func barCellsFor(width int) (cells int, withLabel bool) {
	if width >= footerWidth {
		return barCells, true
	}
	fixed := 2 + pctWidth + 2 + elapsedW
	if width >= barCells+fixed {
		return barCells, false
	}
	return max(width-fixed, 4), false
}

func (p palette) footer(segs []barSeg, cells int, pct float64, elapsed time.Duration, label string, aborted bool) string {
	var b strings.Builder
	b.WriteString(p.bar(segs, cells, aborted))
	b.WriteString("  ")
	if aborted {
		b.WriteString(p.bad(abortedText))
		b.WriteString("  ")
		b.WriteString(p.fg(rpad(fmtDur(elapsed), elapsedW)))
		return b.String()
	}
	b.WriteString(p.mut(rpad(fmt.Sprintf("%.0f%%", pct*100), pctWidth)))
	b.WriteString("  ")
	b.WriteString(p.mut(rpad(fmtDur(elapsed), elapsedW)))
	if label != "" {
		b.WriteString("  ")
		b.WriteString(p.acc(pad(clip(label, labelWidth), labelWidth)))
	}
	return b.String()
}

// bar is one run of cells per phase GROUP, sized by that group's share of the
// work done so far, with the remainder left as track. Without colour it
// collapses to a single bracketed run: per-group segments are a colour encoding,
// and colourless they would read as a bar with unexplained gaps.
func (p palette) bar(segs []barSeg, cells int, aborted bool) string {
	filled := 0
	for _, s := range segs {
		filled += s.cells
	}
	if p.mode == colorNone {
		inner := cells - 2
		filled = min(filled, inner)
		return "[" + strings.Repeat("=", filled) + strings.Repeat("-", inner-filled) + "]"
	}
	var b strings.Builder
	used := 0
	for i, s := range segs {
		hex := groupHex(s.group)
		if aborted && i == len(segs)-1 {
			hex = badHex
		}
		b.WriteString(p.paint(hex, strings.Repeat(string(barFill), s.cells)))
		used += s.cells
	}
	if used < cells {
		b.WriteString(p.track(strings.Repeat(string(barTrack), cells-used)))
	}
	return b.String()
}

// legend appears only at rest. Mid-run the reader is watching a bar move and the
// trailing label already names the phase; at the end there is time to read what
// the colours meant, and the per-group totals are the answer to "where did it
// go".
func (p palette) legend(groups []groupTime, width int) string {
	var parts []string
	for _, g := range groups {
		if g.elapsed <= 0 {
			continue
		}
		parts = append(parts, p.paint(groupHex(g.name), legendBlock)+
			p.dim(" "+g.name+" "+fmtDur(g.elapsed)))
	}
	if len(parts) == 0 {
		return ""
	}
	return clipStyled(strings.Join(parts, "  "), width)
}

// pad and rpad lay a cell out to a fixed COLUMN count. len() is bytes, and a
// glyph like ✓ is three of them, so the width has to be counted in runes or the
// columns drift the moment a non-ASCII marker appears.
func pad(s string, w int) string {
	if n := len([]rune(s)); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return clip(s, w)
}

func rpad(s string, w int) string {
	if n := len([]rune(s)); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return clip(s, w)
}

// clipStyled truncates to n VISIBLE columns, stepping over SGR sequences so an
// escape is never counted as width and never cut in half.
func clipStyled(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	seen := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		if seen == n {
			return b.String() + "\x1b[0m"
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		b.WriteString(s[i : i+size])
		i += size
		seen++
	}
	return b.String()
}

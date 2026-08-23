package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/bytevet/godzilla/internal/progress"
)

// colorMode is how much colour the terminal was found to support. Everything
// below plain still renders: the bar distinguishes stages by FILL GLYPH as well
// as by colour, so the breakdown survives NO_COLOR, a dumb terminal, and
// colour-vision deficiency alike. Colour is an enhancement, never the only
// channel carrying the information.
type colorMode int

const (
	colorNone colorMode = iota
	color16
	color256
	colorTrue
)

// segGlyphs distinguish adjacent segments without colour. They cycle, so two
// segments of the same glyph are never adjacent for the stage counts we draw.
var segGlyphs = []rune{'#', '=', '~', '+', 'o', 'x', '*', '%', '@', '&'}

// One glyph for every filled segment, so the bar is an unbroken rule and a
// boundary is a change of HUE only — nothing in the fill itself moves.
//
// That leaves colour carrying the segmentation on its own, and the palette's
// hues climb monotonically with pipeline position, so adjacent ones sit close
// together: under tritanopia, close enough to merge (ΔE 1.3). segGlyphs is what
// covers the no-colour case; a viewer with reduced colour discrimination and a
// colour terminal reads the bar as one length, plus the running stage's name.
const (
	fullBlock  = '█'
	emptyBlock = '░'
)

type palette struct {
	mode colorMode
	// codes maps a stage id to its SGR parameters, per mode. Filled in from the
	// chosen palette; a stage with no entry falls back to the default.
	trueHex map[string]string
	idx256  map[string]int
	ansi16  map[string]int
}

func (p palette) sgr(id string) string {
	switch p.mode {
	case colorTrue:
		if hex, ok := p.trueHex[key(id)]; ok {
			var r, g, b int
			if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err == nil {
				return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
			}
		}
	case color256:
		if i, ok := p.idx256[key(id)]; ok {
			return fmt.Sprintf("\x1b[38;5;%dm", i)
		}
	case color16:
		if c, ok := p.ansi16[key(id)]; ok {
			return fmt.Sprintf("\x1b[%dm", c)
		}
	}
	return ""
}

// paint wraps s in the stage's colour. With colour off it returns s unchanged,
// which is what lets every caller be written once.
func (p palette) paint(id, s string) string {
	code := p.sgr(id)
	if code == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

func (p palette) dim(s string) string {
	return p.wrap(s, trackHex, track256, trackAnsi16)
}

func (p palette) failed(s string) string {
	return p.wrap(s, failedHex, failed256, failedAnsi16)
}

func (p palette) wrap(s, hex string, idx, ansi int) string {
	var code string
	switch p.mode {
	case colorTrue:
		var r, g, b int
		if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err == nil {
			code = fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
		}
	case color256:
		code = fmt.Sprintf("\x1b[38;5;%dm", idx)
	case color16:
		code = fmt.Sprintf("\x1b[%dm", ansi)
	}
	if code == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

// cells apportions width columns across the segments by weight, giving every
// started segment at least one column so a stage in flight is never invisible,
// and making the widths sum to exactly width so the bar cannot wrap.
func cells(segs []segment, width int) []int {
	if width <= 0 || len(segs) == 0 {
		return make([]int, len(segs))
	}
	var total float64
	for _, s := range segs {
		total += s.weight
	}
	out := make([]int, len(segs))
	if total == 0 {
		out[0] = width
		return out
	}
	// A stage that ran too briefly to earn a column still gets one, or a fast
	// stage disappears from the bar while its legend entry says it happened.
	floor := 0
	for _, s := range segs {
		if s.started {
			floor++
		}
	}
	if floor > width {
		floor = 0 // too narrow to guarantee anything; fall back to pure weight
	}
	// Largest-remainder apportionment: floor everything, then hand the leftover
	// columns to the biggest fractional parts. Rounding each independently would
	// not sum to width.
	rem := make([]float64, len(segs))
	used := 0
	spare := width - floor
	for i, s := range segs {
		exact := float64(spare) * s.weight / total
		out[i] = int(exact)
		if s.started && floor > 0 {
			out[i]++
		}
		rem[i] = exact - float64(int(exact))
		used += out[i]
	}
	for used < width {
		best, bestVal := -1, -1.0
		for i := range segs {
			if rem[i] > bestVal {
				best, bestVal = i, rem[i]
			}
		}
		out[best]++
		rem[best] = -1
		used++
	}
	return out
}

// bar renders the segmented bar body, without brackets.
func (p palette) bar(segs []segment, width int) string {
	widths := cells(segs, width)
	var b strings.Builder
	for i, s := range segs {
		w := widths[i]
		if w == 0 {
			continue
		}
		filled := int(float64(w)*s.fraction + 0.5)
		if s.started && filled == 0 && s.fraction > 0 {
			filled = 1 // a stage in flight always shows at least one cell
		}
		glyph := segGlyphs[i%len(segGlyphs)]
		if p.mode != colorNone {
			glyph = fullBlock
		}
		if s.failed {
			// Colour alone must never be what tells you a frontend died.
			glyph = '!'
		}
		if filled > 0 {
			run := strings.Repeat(string(glyph), filled)
			if s.failed {
				b.WriteString(p.failed(run))
			} else {
				b.WriteString(p.paint(s.id, run))
			}
		}
		if w-filled > 0 {
			b.WriteString(p.dim(strings.Repeat(string(emptyBlock), w-filled)))
		}
	}
	return b.String()
}

// legend names each stage in its own colour, with its elapsed time once it has
// started. This is the "finished stage and the time it took" half of the
// display, live rather than only at the end.
// shortLabel drops the language prefix the running-stage text does not need — the
// colour and position already say which stage it is, and the legend has to fit
// several entries on one line.
func shortLabel(label string) string {
	label = strings.TrimSuffix(label, " parse & lower")
	for _, cut := range []string{"go list (metadata)", "go parse & typecheck", "go SSA build", "go lowering"} {
		if label == cut {
			return strings.TrimPrefix(cut, "go ")
		}
	}
	return label
}

// ledgerLine is what a finished stage leaves behind in the scrollback. It is
// deliberately plain text with an ASCII outcome token, so it reads the same in a
// terminal, in a screenshot and in a pasted bug report.
func (p palette) ledgerLine(s progress.Snapshot, width int) string {
	mark, paint := "✓", p.paint
	if s.Failed {
		mark, paint = "✗", func(_, str string) string { return p.failed(str) }
	}
	// A bare denominator says nothing on its own — 8626 of what? — so a stage
	// that counts anything names its unit, and one that counts nothing shows no
	// number at all rather than a zero.
	count := ""
	if s.Total > 0 {
		count = fmt.Sprintf("%d %s", s.Total, s.Unit)
		if s.Done != s.Total {
			count = fmt.Sprintf("%d/%d %s", s.Done, s.Total, s.Unit)
		}
	}
	// Two clocks, because they answer different questions: +d is what this stage
	// COST, @d is where the run stood when it ended.
	body := fmt.Sprintf("  %s %-24s %16s   %8s %9s", mark, s.Label, strings.TrimSpace(count),
		"+"+fmtDur(s.Elapsed), "@"+fmtDur(s.Offset+s.Elapsed))
	return paint(s.ID, clip(strings.TrimRight(body, " "), width))
}

// frame is the sticky block: the bar and its legend. Pure — a display can be
// exercised entirely through this with no terminal at all. elapsed is the
// scan's own wall clock, which cannot be derived from the stages: they overlap,
// so neither their sum nor their maximum is the answer.
func frame(stages []progress.Snapshot, width int, p palette, elapsed time.Duration, floor float64, expect []string) ([]string, float64) {
	segs := plan(stages, expect)
	if len(segs) == 0 {
		return nil, floor
	}
	// Clamped monotone: re-weighting a finished stage to its real cost can move
	// the arithmetic backwards, and a bar that retreats reads as a fault.
	pct := max(overall(segs), floor)

	// No brackets: the fill and the track already say where the bar ends.
	suffix := fmt.Sprintf(" %3.0f%% %8s", pct*100, fmtDur(elapsed))
	active, activeID := activeLabel(segs)
	inner := width - 1 - len(suffix) - len(active)
	if inner < 8 {
		// Too narrow for a segmented bar; a percentage still fits.
		return []string{clip(fmt.Sprintf("scanning %3.0f%% %s", pct*100, fmtDur(elapsed)), width-1)}, pct
	}
	return []string{p.bar(segs, inner) + suffix + p.paint(activeID, active)}, pct
}

// activeWidth caps the running-stage text so the bar itself keeps most of the
// line even when several frontends run at once.
const activeWidth = 30

// activeLabel names what is running at this instant. It is what the bar carries
// instead of a second legend row: a stage that has FINISHED is already written
// into the scrollback with its elapsed time, so the one thing the sticky line
// cannot get from anywhere else is where the scan is right now.
func activeLabel(segs []segment) (text, id string) {
	var names []string
	for _, s := range segs {
		if !s.running {
			continue
		}
		if id == "" {
			id = s.id
		}
		names = append(names, shortLabel(s.label))
	}
	if len(names) == 0 {
		return "", ""
	}
	return clip("  "+strings.Join(names, " + ")+"…", activeWidth), id
}

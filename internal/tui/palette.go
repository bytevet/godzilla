package tui

// Palette "pipeline sweep": hue climbs monotonically with position in the run,
// magenta through blue and teal to green and yellow, so where the scan has got
// to reads off the bar without consulting the legend.
//
// Every colour was re-luminanced to clear 3:1 contrast against BOTH a dark and a
// light terminal — 3.12:1 and 3.13:1 at worst. That is the constraint that rules
// out most terminal palettes, which assume black behind them.
//
// The sweep's cost is that adjacent hues are close by construction, and for
// tritanopia they are very close (adjacent ΔE 1.3, against 7.2 deuteranopic and
// 6.0 protanopic). segTexture is the answer: neighbouring segments alternate
// their fill block, so every boundary carries a luminance step as well as a hue
// step and the breakdown survives with no colour discrimination at all.
var (
	sweepTrueHex = map[string]string{
		"walk":       "#b763c4",
		"go.list":    "#7360d5",
		"go.load":    "#3691d6",
		"go.ssa":     "#147e89",
		"go.lower":   "#128167",
		"convert":    "#289e4f",
		"index":      "#499e2a",
		"ruleselect": "#6e7912",
		"taint":      "#ac7c0b",
	}
	sweepIdx256 = map[string]int{
		"walk": 133, "go.list": 27, "go.load": 32, "go.ssa": 30, "go.lower": 28,
		"convert": 66, "index": 64, "ruleselect": 137, "taint": 136,
	}
	sweepAnsi16 = map[string]int{
		"walk": 35, "go.list": 34, "go.load": 94, "go.ssa": 96, "go.lower": 36,
		"convert": 92, "index": 32, "ruleselect": 93, "taint": 33,
	}
)

// failedHex is the one hue outside the sweep, and deliberately so: a dead
// frontend has to read as an exception rather than as the next stage along.
const (
	failedHex    = "#ea5b51"
	failed256    = 131
	failedAnsi16 = 91
	trackHex     = "#71727c"
	track256     = 243
	trackAnsi16  = 90
)

func applyPalette(p *palette) {
	p.trueHex, p.idx256, p.ansi16 = sweepTrueHex, sweepIdx256, sweepAnsi16
}

// key resolves a stage id to a palette entry. Every frontend's convert stage
// shares one colour: they run CONCURRENTLY, so they are not steps along the
// sweep, and giving each language its own hue would break the "hue means
// position" reading the palette is built on.
func key(id string) string {
	if len(id) > 8 && id[len(id)-8:] == ".convert" {
		return "convert"
	}
	return id
}

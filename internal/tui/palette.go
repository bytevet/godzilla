package tui

import (
	"fmt"
	"strconv"
)

// The palette is SEMANTIC, not per-stage. A colour means an outcome — complete,
// partial, failed, running — and the only place a hue stands for a position in
// the run is the footer bar, where four phase groups are told apart.
//
// That is the whole reason it replaced a per-stage hue sweep: thirteen hues
// climbing through the spectrum encoded where you were, which the trailing label
// on the bar already says, and spent the one channel that could have carried
// whether a phase actually succeeded.
const (
	okHex    = "#2fbfa8" // complete
	accHex   = "#78e3d2" // running, and the LLM group
	partHex  = "#d3982f" // partial — it ran, but not everything got through
	badHex   = "#e0554a" // failed
	infoHex  = "#4c8dd0" // the Go group, and paths
	fgHex    = "#e9ebee"
	mutHex   = "#8b929e"
	dimHex   = "#5f6672"
	trackHex = "#252a32"
)

// 256-colour and 16-colour stand-ins, nearest by eye on a dark terminal. The
// 16-colour rung cannot separate ok from acc, which is why the glyphs carry the
// distinction too.
var (
	idx256 = map[string]int{
		okHex: 43, accHex: 122, partHex: 178, badHex: 167, infoHex: 68,
		fgHex: 255, mutHex: 246, dimHex: 241, trackHex: 236,
	}
	ansi16 = map[string]int{
		okHex: 36, accHex: 96, partHex: 33, badHex: 31, infoHex: 34,
		fgHex: 37, mutHex: 37, dimHex: 90, trackHex: 90,
	}
)

type palette struct{ mode colorMode }

// paint wraps text in the escape for one palette colour, or returns it bare when
// the terminal has no colour. Every rendering path goes through here, so a
// no-colour terminal never sees a stray escape.
func (p palette) paint(hex, text string) string {
	if p.mode == colorNone || text == "" {
		return text
	}
	return prefix[p.mode][hex] + text + "\x1b[0m"
}

// prefix resolves every palette colour to its escape ONCE. The colours are
// compile-time constants and a frame paints dozens of cells ten times a second;
// re-parsing a hex string for each of them is work with a known answer.
var prefix = func() map[colorMode]map[string]string {
	out := map[colorMode]map[string]string{
		colorTrue: {}, color256: {}, color16: {},
	}
	for hex := range idx256 {
		v, err := strconv.ParseUint(hex[1:], 16, 32)
		if err != nil {
			continue
		}
		r, g, b := v>>16&0xff, v>>8&0xff, v&0xff
		out[colorTrue][hex] = fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
		out[color256][hex] = fmt.Sprintf("\x1b[38;5;%dm", idx256[hex])
		out[color16][hex] = fmt.Sprintf("\x1b[%dm", ansi16[hex])
	}
	return out
}()

func (p palette) acc(s string) string   { return p.paint(accHex, s) }
func (p palette) bad(s string) string   { return p.paint(badHex, s) }
func (p palette) fg(s string) string    { return p.paint(fgHex, s) }
func (p palette) mut(s string) string   { return p.paint(mutHex, s) }
func (p palette) dim(s string) string   { return p.paint(dimHex, s) }
func (p palette) track(s string) string { return p.paint(trackHex, s) }

// groupHex is the footer bar's only use of colour as position. Four groups, in
// pipeline order.
func groupHex(g string) string {
	switch g {
	case groupGo:
		return infoHex
	case groupAnalysis:
		return partHex
	case groupLLM:
		return accHex
	}
	return okHex
}

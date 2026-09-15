package tui

import (
	"math"
	"strconv"
	"testing"
)

// The unfilled bar track was once #252a32 with a LIGHT-shade glyph, which is
// invisible on every common dark terminal — 1.01:1 against One Dark. Nothing
// caught it because contrast is not something a rendering test can see: the
// golden output is byte-identical whether the colour is legible or not. So the
// property is asserted arithmetically instead.
//
// A shade glyph is a stipple, so what the eye receives is the glyph colour
// blended with the background in proportion to the glyph's ink coverage. That
// blend is the whole reason colour alone could not fix it: at 25% coverage even
// dimHex reaches only ~1.24:1.
const trackInkCoverage = 0.50 // U+2592 MEDIUM SHADE; U+2591 LIGHT is 0.25

// darkBackgrounds are the terminal themes the palette is documented for.
var darkBackgrounds = map[string]string{
	"One Dark": "#282c34", "VS Code Dark+": "#1e1e1e", "iTerm2 default": "#000000",
	"Solarized Dark": "#002b36", "Dracula": "#282a36", "GitHub Dark": "#0d1117",
}

func srgbToLinear(c float64) float64 {
	c /= 255
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func channels(hex string) [3]float64 {
	var out [3]float64
	for i := range out {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			panic("bad hex in palette: " + hex)
		}
		out[i] = float64(v)
	}
	return out
}

func relativeLuminance(c [3]float64) float64 {
	return 0.2126*srgbToLinear(c[0]) + 0.7152*srgbToLinear(c[1]) + 0.0722*srgbToLinear(c[2])
}

func contrast(a, b [3]float64) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	hi, lo := math.Max(la, lb), math.Min(la, lb)
	return (hi + 0.05) / (lo + 0.05)
}

// A solid band needs roughly this much perceived contrast to read as a band at
// all. Below it the bar looks like it simply stops at the fill.
const minTrackContrast = 1.30

func TestTrackIsVisibleOnDarkTerminals(t *testing.T) {
	track := channels(trackHex)
	for name, bgHex := range darkBackgrounds {
		bg := channels(bgHex)
		var seen [3]float64
		for i := range seen {
			seen[i] = track[i]*trackInkCoverage + bg[i]*(1-trackInkCoverage)
		}
		if got := contrast(seen, bg); got < minTrackContrast {
			t.Errorf("track %s at %.0f%% ink is %.2f:1 on %s (%s), want >= %.2f:1 — "+
				"the unfilled bar will not be visible there",
				trackHex, trackInkCoverage*100, got, name, bgHex, minTrackContrast)
		}
	}
}

// The track must still recede: it marks absence, and reading as brightly as dim
// text would make the empty part of the bar compete with the labels beside it.
func TestTrackStaysDarkerThanDimText(t *testing.T) {
	if relativeLuminance(channels(trackHex)) >= relativeLuminance(channels(dimHex)) {
		t.Errorf("track %s is not darker than dim text %s", trackHex, dimHex)
	}
}

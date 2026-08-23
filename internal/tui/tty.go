package tui

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// isTTY is a variable so the composition in Enabled can be tested without a
// terminal; only this one call is left uncovered.
var isTTY = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// Enabled reports whether the interactive display should run.
//
// It keys off STDERR, not stdout: the display draws on stderr so that stdout —
// the coverage line and the findings, which tooling parses — stays byte for
// byte what it is today even while the bar is on screen.
//
// -quiet wins over everything, including the force-on env var. `godzilla scan
// -quiet` is contracted to emit literally nothing, and a display that could
// override that would break the gate's only silent mode.
func Enabled(quiet bool) bool {
	if quiet {
		return false
	}
	switch os.Getenv("GODZILLA_PROGRESS") {
	case "0", "off", "false":
		return false
	case "1", "on", "true":
		return true
	}
	// CI systems capture output rather than allocating a terminal, so the stderr
	// check usually settles it — but some allocate a PTY, and a progress bar
	// redrawing ten times a second into a captured log is noise nobody reads.
	if os.Getenv("CI") != "" {
		return false
	}
	return isTTY(os.Stderr)
}

// terminalSize is the live size of the terminal behind stderr. It is re-queried
// every frame rather than tracked through SIGWINCH: an ioctl ten times a second
// costs nothing, and it means a resize can never leave the display believing a
// stale width — which would make its erase sequence's row count wrong.
func terminalSize() (w, h int) {
	w, h, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return 80, 24
	}
	return w, h
}

// detectColor decides how much colour to use. The bar carries its breakdown in
// fill glyphs as well as colour, so colorNone is a complete display rather than
// a degraded one.
func detectColor() colorMode {
	if os.Getenv("NO_COLOR") != "" {
		return colorNone
	}
	t := os.Getenv("TERM")
	if t == "" || t == "dumb" {
		return colorNone
	}
	switch os.Getenv("COLORTERM") {
	case "truecolor", "24bit":
		return colorTrue
	}
	if strings.Contains(t, "256color") {
		return color256
	}
	return color16
}

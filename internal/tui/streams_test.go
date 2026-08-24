package tui

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bytevet/godzilla/internal/progress"
)

// Captured stderr never interleaves with the phase rows: it is the complete
// record, written in one block in arrival order when the display stops. The pane
// above the bar is a separate, structured thing — see the tests below.
func TestCapturedStderrIsOneOrderedBlock(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: 10 * time.Millisecond,
		Size: func() (int, int) { return 200, 24 }})

	stage := progress.Start("rust.convert", "rust parse & lower", 3, "files")
	stage.Advance(3)
	for i := range 6 {
		fmt.Fprintf(os.Stderr, "rust_converter: skipping file-%d\n", i)
	}
	stage.Done(nil) // no gap at all, exactly as the frontend does it
	ui.Stop()

	got := out.String()
	at := make([]int, 6)
	for i := range at {
		w := fmt.Sprintf("rust_converter: skipping file-%d", i)
		if at[i] = strings.Index(got, w); at[i] < 0 {
			t.Fatalf("warning %d was lost: %q", i, got)
		}
		if i > 0 && at[i] < at[i-1] {
			t.Errorf("warnings are out of arrival order at %d:\n%s", i, got)
		}
	}
}

// The pane carries what raw stderr could not: which language a diagnostic came
// from and the file it happened in. The position is otherwise buried in prose
// that names the converter three times before saying what the compiler found.
func TestThePaneNamesTheLanguageAndTheFile(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Tick: time.Hour,
		Size: func() (int, int) { return 100, 24 }})
	progress.Start("rust.convert", "rust parse & lower", 3, "files")
	progress.Warn("rust", "unresolved import `rouille`", "test/rust/webapp/src/main.rs:7")
	ui.render(false)
	got := out.String()
	ui.Stop()

	for _, want := range []string{"rust", "unresolved import", "→ test/rust/webapp/src/main.rs:7"} {
		if !strings.Contains(got, want) {
			t.Errorf("the pane is missing %q:\n%q", want, got)
		}
	}
}

// The tail is capped. Warnings run into the hundreds on a repository with
// unbuildable samples, and the block must not grow past what a reader can take
// in between frames — the full set lands at the end.
func TestThePaneCapsTheTail(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Tick: time.Hour,
		Size: func() (int, int) { return 100, 24 }})
	for i := range 9 {
		progress.Warn("rust", fmt.Sprintf("warn-%d", i), "")
	}
	ui.render(false)
	got := out.String()
	ui.Stop()

	if !strings.Contains(got, fmt.Sprintf("9 warnings · last %d", paneRows)) {
		t.Errorf("the pane does not say how much it is holding back:\n%q", got)
	}
	if !strings.Contains(got, "warn-8") {
		t.Errorf("the pane must hold the most recent warning:\n%q", got)
	}
	if strings.Contains(got, "warn-0") {
		t.Errorf("the pane should hold only the last %d:\n%q", paneRows, got)
	}
}

// A message longer than the terminal is wrapped by the display, never by the
// terminal: the erase sequence is a ROW COUNT, so a line that wrapped on its own
// would make that count wrong and eat the scrollback above the block.
func TestPaneWrapsRatherThanClips(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Tick: time.Hour,
		Size: func() (int, int) { return 44, 24 }})
	const long = "cannot find module or crate `reqwest` in this scope, add it to Cargo.toml"
	progress.Warn("rust", long, "")
	ui.render(false)
	got := out.String()
	ui.Stop()

	if strings.Contains(got, "…") {
		t.Errorf("the pane clipped a message instead of wrapping it:\n%q", got)
	}
	flat := strings.Join(strings.Fields(stripANSI(got)), "")
	if !strings.Contains(flat, strings.Join(strings.Fields(long), "")) {
		t.Errorf("wrapping lost part of the message:\n%q", got)
	}
}

// wrapRows owns the row count the erase sequence depends on, so no row it
// returns may exceed the width it was given.
func TestWrappedRowsNeverExceedTheWidth(t *testing.T) {
	for _, w := range []int{120, 80, 40, 20, 12, 6, 2, 1} {
		for _, line := range []string{
			strings.Repeat("x", 300),
			"解析与降级パース" + strings.Repeat("あ", 40),
			"short",
			"",
		} {
			for _, row := range wrapRows(line, w) {
				if n := len([]rune(row)); n > w {
					t.Errorf("width %d: row is %d columns: %q", w, n, row)
				}
			}
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

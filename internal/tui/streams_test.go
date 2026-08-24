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

// Captured stderr never interleaves with the stage lines: it is a live preview
// in the pane while the scan runs, and one complete block in arrival order when
// it stops. That is what makes the ordering question go away — a frontend prints
// its skip warnings and calls Done on the very next statement, a gap far smaller
// than the pipe reader's lag, so no timestamp could have separated them.
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

// The pane is what makes a skipped file visible while the scan is still
// running, since the full text does not land until Stop. It shows the NEWEST
// output — a burst pushes older lines out, not the other way round — and wraps
// rather than clips, so a message can be read as it streams past.
func TestThePaneShowsRecentWarningsWhileScanning(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 60, 24 }})
	progress.Start("rust.convert", "rust parse & lower", 3, "files")
	for i := range 9 {
		fmt.Fprintf(os.Stderr, "warn-%d\n", i)
	}
	for range 200 {
		ui.mu.Lock()
		n := len(ui.warnings)
		ui.mu.Unlock()
		if n == 9 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ui.render(false)
	got := out.String()
	ui.Stop()

	if !strings.Contains(got, "9 warning(s), last 7") {
		t.Errorf("the pane does not say how much it is holding back:\n%q", got)
	}
	// h/3 = 8 rows, one of them the header, so the last 7 lines fit.
	for _, want := range []string{"warn-2", "warn-8"} {
		if !strings.Contains(got, want) {
			t.Errorf("the pane is missing recent line %q:\n%q", want, got)
		}
	}
	if strings.Contains(got, "warn-0") {
		t.Errorf("the pane should hold only what its budget allows:\n%q", got)
	}
}

// A line longer than the terminal is wrapped by the display, never by the
// terminal: the erase sequence is a ROW COUNT, so a line that wrapped on its own
// would make that count wrong and eat the scrollback above the bar.
func TestPaneWrapsRatherThanClips(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 40, 24 }})
	const long = "rust_converter: skipping test/rust/db_rusqlite/src/lib.rs: unresolved import"
	fmt.Fprintln(os.Stderr, long)
	for range 200 {
		ui.mu.Lock()
		n := len(ui.warnings)
		ui.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ui.render(false)
	got := out.String()
	ui.Stop()

	if strings.Contains(got, "…") {
		t.Errorf("the pane clipped instead of wrapping:\n%q", got)
	}
	// Every fragment of the line has to be present across the wrapped rows.
	flat := strings.Join(strings.Fields(stripANSI(got)), "")
	if !strings.Contains(flat, strings.Join(strings.Fields(long), "")) {
		t.Errorf("wrapping lost part of the line:\n%q", got)
	}
}

// wrapRows owns the row count the erase sequence depends on, so no row it
// returns may exceed the width it was given.
func TestWrappedRowsNeverExceedTheWidth(t *testing.T) {
	for _, w := range []int{120, 80, 40, 20, 12, 6, 2} {
		for _, line := range []string{
			strings.Repeat("x", 300),
			"解析与降级パース" + strings.Repeat("あ", 40),
			"short",
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

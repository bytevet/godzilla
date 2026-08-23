package tui

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytevet/godzilla/internal/progress"
)

// -quiet is contracted to emit literally nothing, so it has to beat every other
// signal — including the force-on env var. Everything else is ordinary
// precedence.
func TestEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		quiet    bool
		tty      bool
		env      map[string]string
		expected bool
	}{
		{name: "a terminal, nothing set", tty: true, expected: true},
		{name: "not a terminal", tty: false, expected: false},
		{name: "quiet beats a terminal", quiet: true, tty: true, expected: false},
		{name: "quiet beats the force-on", quiet: true, tty: true,
			env: map[string]string{"GODZILLA_PROGRESS": "1"}, expected: false},
		{name: "CI is off even on a pty", tty: true,
			env: map[string]string{"CI": "true"}, expected: false},
		{name: "force-on beats CI", tty: false,
			env: map[string]string{"CI": "true", "GODZILLA_PROGRESS": "1"}, expected: true},
		{name: "force-off beats a terminal", tty: true,
			env: map[string]string{"GODZILLA_PROGRESS": "0"}, expected: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CI", "")
			t.Setenv("GODZILLA_PROGRESS", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			saved := isTTY
			isTTY = func(*os.File) bool { return tc.tty }
			defer func() { isTTY = saved }()

			if got := Enabled(tc.quiet); got != tc.expected {
				t.Errorf("Enabled(quiet=%v) = %v, want %v", tc.quiet, got, tc.expected)
			}
		})
	}
}

// The display owns the terminal, so everything the pipeline writes to stderr has
// to come back through it — whole, once, and in one piece. This is the property
// that lets warnings scroll above the bar instead of tearing through it.
func TestCaptureReturnsEveryLineIntact(t *testing.T) {
	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 100, 24 }})

	const writers, each = 4, 25
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				fmt.Fprintf(os.Stderr, "writer-%d-line-%d\n", w, i)
			}
		}()
	}
	wg.Wait()
	ui.Stop()

	// Counted as whole lines: "line-1" is a substring of "line-10".
	seen := map[string]int{}
	for _, l := range strings.Split(out.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			seen[l]++
		}
	}
	for w := range writers {
		for i := range each {
			want := fmt.Sprintf("writer-%d-line-%d", w, i)
			if seen[want] != 1 {
				t.Errorf("%q appears %d times, want exactly 1", want, seen[want])
			}
		}
	}
	if os.Stderr == nil {
		t.Fatal("os.Stderr was not restored")
	}
}

// bufio.Scanner would silently truncate at 64 KiB and then stop reading for the
// rest of the scan — and a packages.PrintErrors burst on a broken build is
// exactly one very long line.
func TestCaptureSurvivesALineLargerThanScannersLimit(t *testing.T) {
	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 100, 24 }})

	huge := strings.Repeat("z", 200_000)
	fmt.Fprintf(os.Stderr, "%s\n", huge)
	ui.Stop()

	if !strings.Contains(out.String(), huge) {
		t.Errorf("a %d-byte line did not survive capture intact (got %d bytes out)",
			len(huge), out.Len())
	}
}

// A log line passes THROUGH the display and must never be clipped: tooling greps
// stderr, and a truncated warning could hide the thing being grepped for.
func TestLogLinesAreNotTruncated(t *testing.T) {
	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 20, 24 }}) // far narrower than the line
	line := "warning: some Go packages failed to load cleanly; requires newer Go version"
	fmt.Fprintln(os.Stderr, line)
	ui.Stop()

	if !strings.Contains(out.String(), line) {
		t.Errorf("log line was clipped at the terminal width:\n%q", out.String())
	}
}

// Stop is deferred for the panic path AND called where normal output resumes,
// so it has to be safe twice — and safe on a nil UI, which is what the command
// holds when the display is off.
func TestStopIsIdempotentAndNilSafe(t *testing.T) {
	var nilUI *UI
	nilUI.Stop()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Tick: time.Hour, Size: func() (int, int) { return 80, 24 }})
	ui.Stop()
	ui.Stop()
}

// Every frame erases exactly the rows the previous one drew. If that count is
// ever wrong the cursor-up overshoots and eats the scrollback above the bar.
func TestEraseMatchesTheRowsLastDrawn(t *testing.T) {
	u := &UI{drawn: 0}
	var b strings.Builder
	u.erase(&b)
	if got := b.String(); got != "\r" {
		t.Errorf("first frame erase = %q, want a bare carriage return", got)
	}

	for _, rows := range []int{1, 2, 5} {
		u.drawn = rows
		b.Reset()
		u.erase(&b)
		got := b.String()
		if !strings.HasSuffix(got, "\x1b[0J") {
			t.Errorf("drawn=%d: erase does not clear to end of screen: %q", rows, got)
		}
		if rows > 1 && !strings.Contains(got, fmt.Sprintf("\x1b[%dA", rows-1)) {
			t.Errorf("drawn=%d: erase moves the wrong number of rows: %q", rows, got)
		}
		if rows == 1 && strings.Contains(got, "A") {
			t.Errorf("drawn=1: erase should not move the cursor up at all: %q", got)
		}
	}
}

// Captured stdout is re-emitted on the REAL stdout, never onto the stream the
// bar draws on. `godzilla scan > out.txt` from a terminal still puts the
// coverage line and the findings in the file.
func TestCapturedStdoutIsReemittedOnStdout(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = tmp
	defer func() { os.Stdout = saved }()

	var bar bytes.Buffer
	ui := Start(Options{Out: &bar, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 100, 24 }})
	const line = "coverage: go=ok python=ok"
	fmt.Fprintln(os.Stdout, line)
	fmt.Fprintln(os.Stderr, "warning: a frontend complained")
	ui.Stop()
	os.Stdout = saved

	got, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), line) {
		t.Errorf("stdout line did not reach the real stdout, got %q", got)
	}
	if strings.Contains(bar.String(), line) {
		t.Errorf("stdout line was diverted onto the bar's stream: %q", bar.String())
	}
	if !strings.Contains(bar.String(), "a frontend complained") {
		t.Errorf("stderr line did not scroll above the bar: %q", bar.String())
	}
}

// The scrollback has to read as a narrative. Promotion is only NOTICED on a
// tick, so a stage that ended before a log line was written must still print
// above it — ordering by arrival would put the coverage line above the analysis
// stages that finished first.
func TestScrollbackIsInHappenedOrder(t *testing.T) {
	defer progress.Enable()()

	var out bytes.Buffer
	ui := Start(Options{Out: &out, Capture: true, Tick: time.Hour,
		Size: func() (int, int) { return 120, 24 }})

	early := progress.Start("taint", "taint propagation", 2, "rules")
	early.Advance(2)
	early.Done(nil)
	time.Sleep(5 * time.Millisecond)
	fmt.Fprintln(os.Stderr, "a-line-written-after-the-stage-ended")
	ui.Stop()

	got := out.String()
	stage, line := strings.Index(got, "taint propagation"), strings.Index(got, "a-line-written-after")
	if stage < 0 || line < 0 {
		t.Fatalf("missing output: %q", got)
	}
	if stage > line {
		t.Errorf("the stage that finished first printed second:\n%q", got)
	}
}

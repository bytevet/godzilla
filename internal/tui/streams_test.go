package tui

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Interleaved stdout and stderr must reach the scrollback in the order they were
// written. Both are pointed at ONE file here so the merged order is observable.
//
// This is why stdout is routed through Stdout() rather than a second pipe. With
// two reader goroutines the order depends on which one the runtime schedules,
// and under a burst whole runs of one stream landed ahead of the other — an
// inversion spanning thirty lines, not a jittered pair.
//
// The residual limit, measured: writes separated by less than ~100µs can still
// swap, because a stderr line is timestamped when the reader goroutine wakes
// while a stdout line is timestamped at the call. Nothing in a scan writes to
// both streams that close together — the frontend warnings and the coverage line
// are hundreds of milliseconds apart — so the gap here is already a thousandfold
// tighter than the case it stands in for.
func TestInterleavedStreamsKeepTheirOrder(t *testing.T) {
	const gap = 100 * time.Microsecond

	f, err := os.CreateTemp(t.TempDir(), "merged")
	if err != nil {
		t.Fatal(err)
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	os.Stdout = f
	defer func() { os.Stdout, os.Stderr = savedOut, savedErr }()

	ui := Start(Options{Out: f, Capture: true, Tick: 5 * time.Millisecond,
		Size: func() (int, int) { return 200, 24 }})
	const lines = 60
	for i := range lines {
		if i%2 == 0 {
			fmt.Fprintf(ui.Stdout(), "seq-%02d-stdout\n", i)
		} else {
			fmt.Fprintf(os.Stderr, "seq-%02d-stderr\n", i)
		}
		time.Sleep(gap)
	}
	ui.Stop()
	os.Stdout, os.Stderr = savedOut, savedErr

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var seq []int
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.Index(l, "seq-"); i >= 0 {
			n, err := strconv.Atoi(l[i+4 : i+6])
			if err != nil {
				t.Fatalf("unparseable line %q", l)
			}
			seq = append(seq, n)
		}
	}
	if len(seq) != lines {
		t.Errorf("lost lines: got %d of %d", len(seq), lines)
	}
	for i := 1; i < len(seq); i++ {
		if seq[i] < seq[i-1] {
			t.Fatalf("stdout and stderr were reordered at %d: %v", i, seq)
		}
	}
}

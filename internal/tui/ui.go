// Package tui draws the scan's live progress: a sticky segmented bar at the
// bottom of the terminal, with log lines scrolling above it and each stage
// promoted into the scrollback with its elapsed time as it finishes.
//
// It reads internal/progress and is imported only by cmd/godzilla, which is
// what keeps golang.org/x/term out of every frontend's build.
//
// The display is erase-and-redraw, not a DECSTBM scroll region. A scroll region
// is terminal STATE: a process that dies without resetting it leaves the user's
// shell broken. Here every frame is (erase, draw), so the worst an abnormal exit
// can leave behind is a half-drawn line — the same thing a killed scan leaves
// today.
package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bytevet/godzilla/internal/progress"
)

// Options configures a UI. The zero value is the production one: stderr, the
// real terminal size, the real clock. The fields exist so the whole display can
// be exercised with no terminal at all.
type Options struct {
	Out     io.Writer         // nil means os.Stderr
	Size    func() (w, h int) // nil means the real terminal size
	Now     func() time.Time  // nil means time.Now
	Tick    time.Duration     // 0 means 100ms
	Capture bool              // route os.Stdout and os.Stderr through the display
	// Expect names stages that will run but that no scan stage implies, so the
	// bar can carry them in its denominator before they register.
	Expect []string
}

// UI is a running display. Every method is safe to call on a nil *UI, so the
// command can hold one variable and not branch at each use.
type UI struct {
	out  io.Writer
	size func() (w, h int)
	now  func() time.Time
	pal  palette

	start  time.Time
	expect []string
	ticker *time.Ticker
	stop   chan struct{}
	ticked sync.WaitGroup

	mu       sync.Mutex
	pending  []logLine       // log lines waiting to be flushed above the bar
	promoted map[string]bool // stages already written into the scrollback
	onStop   []func()

	// stdout is the real stdout, when the display has tapped it. Captured stdout
	// is re-emitted THERE and not onto the bar's stream, so `godzilla scan >
	// out.txt` on a terminal still puts the findings in the file.
	stdout io.Writer
	taps   []*tap

	// drawn is how many lines the last frame occupied — the erase sequence is
	// relative to the cursor, so this is the display's entire screen state.
	drawn   int
	lastPct float64

	stopOnce sync.Once
}

// tap routes one of the process's standard streams through the display for its
// lifetime, so the ticker goroutine stays the only thing writing to the
// terminal. target is the package-level variable to restore on Stop.
type tap struct {
	target **os.File
	orig   *os.File
	w      *os.File
	done   chan struct{}
}

// logLine is a captured line, which stream it came from, and when it arrived —
// the timestamp is what lets it be ordered against a stage's completion.
type logLine struct {
	text   string
	stdout bool
	at     time.Time
}

// Start begins drawing. It owns two goroutines: the frame ticker, which is the
// ONLY thing that ever writes to the terminal, and (under Capture) the pipe
// reader, which only appends to a buffer. That single-writer property is what
// makes a sticky bar correct at all.
func Start(opts Options) *UI {
	u := &UI{
		out:      opts.Out,
		size:     opts.Size,
		now:      opts.Now,
		pal:      palette{mode: detectColor()},
		promoted: map[string]bool{},
		stop:     make(chan struct{}),
		expect:   opts.Expect,
	}
	if u.out == nil {
		u.out = os.Stderr
	}
	if u.now == nil {
		u.now = time.Now
	}
	if u.size == nil {
		u.size = terminalSize
	}
	applyPalette(&u.pal)
	u.start = u.now()

	if opts.Capture {
		u.startCapture()
	}

	tick := opts.Tick
	if tick == 0 {
		tick = 100 * time.Millisecond
	}
	u.ticker = time.NewTicker(tick)
	u.ticked.Add(1)
	go func() {
		defer u.ticked.Done()
		for {
			select {
			case <-u.ticker.C:
				u.render(false)
			case <-u.stop:
				u.render(true)
				return
			}
		}
	}()
	return u
}

// OnStop registers a function to run when the display stops — the hook the
// command uses to disarm the stage ledger it armed for this window.
func (u *UI) OnStop(fn func()) {
	if u == nil || fn == nil {
		return
	}
	u.mu.Lock()
	u.onStop = append(u.onStop, fn)
	u.mu.Unlock()
}

// Stop erases the bar, restores stderr, flushes everything captured and joins
// its goroutines. Idempotent and nil-safe, so the command can both defer it for
// the panic path and call it where normal output resumes.
func (u *UI) Stop() {
	if u == nil {
		return
	}
	u.stopOnce.Do(func() {
		// Restore every stream first, so a straggler write lands on the real
		// terminal rather than a pipe nobody is reading; then close the write
		// ends so the readers see EOF; then join them, so nothing is still
		// arriving when the final frame is drawn.
		for _, t := range u.taps {
			*t.target = t.orig
		}
		for _, t := range u.taps {
			_ = t.w.Close()
		}
		for _, t := range u.taps {
			<-t.done
		}
		u.ticker.Stop()
		close(u.stop)
		u.ticked.Wait()
		u.mu.Lock()
		hooks := u.onStop
		u.onStop = nil
		u.mu.Unlock()
		for _, fn := range hooks {
			fn()
		}
	})
}

// startCapture routes both standard streams through pipes so the display owns
// the terminal. Swapping the variables is what catches packages.PrintErrors,
// which writes to os.Stderr from inside golang.org/x/tools with no writer
// parameter and is the burstiest output a scan has — and the coverage line on
// stdout, which is printed in the middle of the display's window. Runtime panics
// write to fd 2 directly and bypass this, which is what we want.
func (u *UI) startCapture() {
	u.tapStream(&os.Stderr, false)
	u.tapStream(&os.Stdout, true)
}

func (u *UI) tapStream(target **os.File, isStdout bool) {
	r, w, err := os.Pipe()
	if err != nil {
		return // no capture on this stream; its writes just interleave
	}
	t := &tap{target: target, orig: *target, w: w, done: make(chan struct{})}
	*target = w
	u.taps = append(u.taps, t)
	if isStdout {
		u.stdout = t.orig
	}

	go func() {
		defer close(t.done)
		defer func() { _ = r.Close() }()
		// ReadString, not bufio.Scanner: Scanner's 64 KiB token cap would
		// silently truncate one long line — a packages.PrintErrors burst is
		// exactly that — and then stop reading for the rest of the scan.
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				u.addLog(logLine{strings.TrimRight(line, "\n"), isStdout, u.now()})
			}
			if err != nil {
				return
			}
		}
	}()
}

func (u *UI) addLog(line logLine) {
	u.mu.Lock()
	u.pending = append(u.pending, line)
	u.mu.Unlock()
}

// render draws one frame. Only the ticker goroutine calls this.
func (u *UI) render(final bool) {
	w, h := u.size()
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	stages := progress.Stages()

	// A finished stage is written into the scrollback once and then forgotten,
	// rather than accumulating in the sticky block: seven frontends plus the Go
	// phases and the analysis passes would be a twenty-line block on a
	// twenty-four-row terminal.
	var promote []progress.Snapshot
	for _, s := range stages {
		if s.Running || u.promoted[s.ID] {
			continue
		}
		u.promoted[s.ID] = true
		promote = append(promote, s)
	}

	u.mu.Lock()
	logs := u.pending
	u.pending = nil
	u.mu.Unlock()

	var bar []string
	if !final {
		bar, u.lastPct = frame(stages, w, u.pal, u.now().Sub(u.start), u.lastPct, u.expect)
		if maxRows := h - 1; len(bar) > maxRows {
			bar = bar[:maxRows]
		}
	}

	if len(logs) == 0 && len(promote) == 0 && len(bar) == 0 && u.drawn == 0 {
		return
	}

	// A frame can span both streams — the bar is on stderr, a captured stdout
	// line goes back to the real stdout — so it is built as a sequence of runs
	// and emitted in order. Adjacent writes to one stream coalesce, which is what
	// keeps the erase and the redraw a single write and stops the bar tearing.
	// The scrollback is a narrative, so it is emitted in the order things
	// HAPPENED, not in the order this frame noticed them: a stage that ended at
	// 1.86s must not print under a line written at 1.90s merely because
	// promotion is only observed on the next tick.
	type event struct {
		at   time.Time
		w    io.Writer
		text string
	}
	events := make([]event, 0, len(logs)+len(promote))
	for _, s := range promote {
		events = append(events, event{u.start.Add(s.Offset + s.Elapsed), u.out, u.pal.ledgerLine(s, w-1)})
	}
	for _, l := range logs {
		events = append(events, event{l.at, u.streamOf(l), l.text})
	}
	slices.SortStableFunc(events, func(a, b event) int { return a.at.Compare(b.at) })

	var seq []*run
	add := func(w io.Writer, s string) {
		if n := len(seq); n > 0 && seq[n-1].w == w {
			seq[n-1].b.WriteString(s)
			return
		}
		r := &run{w: w}
		r.b.WriteString(s)
		seq = append(seq, r)
	}

	var b strings.Builder
	u.erase(&b)
	add(u.out, b.String())
	// A captured line passes through VERBATIM and is never clipped. Wrapping one
	// is harmless — it is written before the bar is redrawn — but truncating
	// could hide the tail of a warning that tooling greps for.
	for _, e := range events {
		add(e.w, e.text+"\n")
	}
	if final {
		add(u.out, fmt.Sprintf("  scanned in %s\n", fmtDur(u.now().Sub(u.start))))
		u.drawn = 0
	} else {
		// No trailing newline: the cursor stays on the last bar line, so the
		// next erase is relative to it and the terminal handles scrolling.
		add(u.out, strings.Join(bar, "\n"))
		u.drawn = len(bar)
	}
	for _, r := range seq {
		_, _ = io.WriteString(r.w, r.b.String())
	}
}

// run is one contiguous write to one stream.
type run struct {
	w io.Writer
	b strings.Builder
}

func (u *UI) streamOf(l logLine) io.Writer {
	if l.stdout && u.stdout != nil {
		return u.stdout
	}
	return u.out
}

// erase removes the previous frame. It is written relative to the cursor, which
// the draw step deliberately leaves on the frame's last line.
func (u *UI) erase(b *strings.Builder) {
	b.WriteString("\r")
	if u.drawn > 1 {
		fmt.Fprintf(b, "\x1b[%dA", u.drawn-1)
	}
	if u.drawn > 0 {
		b.WriteString("\x1b[0J")
	}
}

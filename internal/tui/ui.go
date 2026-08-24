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
	Capture bool              // route os.Stderr through the display
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
	pending  []logLine       // Stdout() lines waiting to be flushed above the bar
	warnings []string        // every captured stderr line, in arrival order
	shown    int             // how many of them have reached the real stderr
	promoted map[string]bool // stages already written into the scrollback
	onStop   []func()

	// stdout is the real stdout. Lines destined for it are re-emitted THERE and
	// not onto the bar's stream, so `godzilla scan > out.txt` on a terminal
	// still puts the coverage line and the findings in the file.
	stdout  io.Writer
	partial string // an incomplete stdout line, waiting for its newline

	// origStderr is restored on Stop; pipeW is closed to give the reader EOF.
	origStderr *os.File
	pipeW      *os.File
	readerDone chan struct{}

	// drawn is how many lines the last frame occupied — the erase sequence is
	// relative to the cursor, so this is the display's entire screen state.
	drawn   int
	lastPct float64

	stopOnce sync.Once
}

// logLine is a line the command wrote through Stdout(), and when it wrote it.
// The timestamp is exact — taken at the call — which is what lets it be ordered
// against a stage's completion.
type logLine struct {
	text string
	at   time.Time
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
	u.stdout = os.Stdout
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

// Stdout is where the command writes its own stdout output while the display is
// up: the line is held until the next frame, which erases the bar, writes it to
// the REAL stdout and redraws. On a nil UI — the display is off — it is plain
// os.Stdout, so the caller does not branch.
func (u *UI) Stdout() io.Writer {
	if u == nil {
		return os.Stdout
	}
	return stdoutWriter{u}
}

type stdoutWriter struct{ u *UI }

func (s stdoutWriter) Write(p []byte) (int, error) {
	u := s.u
	at := u.now()
	u.mu.Lock()
	u.partial += string(p)
	for {
		i := strings.IndexByte(u.partial, '\n')
		if i < 0 {
			break
		}
		u.pending = append(u.pending, logLine{u.partial[:i], at})
		u.partial = u.partial[i+1:]
	}
	u.mu.Unlock()
	return len(p), nil
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
		// Restore stderr first, so a straggler write lands on the real terminal
		// rather than a pipe nobody is reading; then close the write end so the
		// reader sees EOF; then join it, so nothing is still arriving when the
		// final frame is drawn.
		if u.pipeW != nil {
			os.Stderr = u.origStderr
			_ = u.pipeW.Close()
			<-u.readerDone
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

// startCapture routes os.Stderr through a pipe so the display owns the
// terminal. Swapping the variable is what catches packages.PrintErrors, which
// writes to os.Stderr from inside golang.org/x/tools with no writer parameter
// and is the burstiest output a scan has. Runtime panics write to fd 2 directly
// and bypass this, which is what we want.
//
// STDOUT is deliberately NOT tapped. A second pipe means a second reader
// goroutine, and then a line's position in the scrollback depends on which
// goroutine the runtime happened to schedule first — measurably so under a
// burst, where whole runs of one stream can land ahead of the other. Nothing
// below package main writes to stdout during a scan, so the command routes its
// own few writes through Stdout() instead, where they are timestamped at the
// call rather than whenever a reader wakes up.
func (u *UI) startCapture() {
	r, w, err := os.Pipe()
	if err != nil {
		return // no capture; warnings just interleave, as they do with no display
	}
	u.origStderr, u.pipeW = os.Stderr, w
	os.Stderr = w
	u.readerDone = make(chan struct{})

	go func() {
		defer close(u.readerDone)
		defer func() { _ = r.Close() }()
		// ReadString, not bufio.Scanner: Scanner's 64 KiB token cap would
		// silently truncate one long line — a packages.PrintErrors burst is
		// exactly that — and then stop reading for the rest of the scan.
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				u.addWarning(strings.TrimRight(line, "\n"))
			}
			if err != nil {
				return
			}
		}
	}()
}

// unflushed reports whether captured lines are still waiting for Stop to write
// them out. Without it a scan that drew no frame at all — everything finished
// inside one tick — would drop every warning it captured.
func (u *UI) unflushed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.shown < len(u.warnings)
}

func (u *UI) addWarning(line string) {
	u.mu.Lock()
	u.warnings = append(u.warnings, line)
	u.mu.Unlock()
}

// paneBudget is how many rows the live pane may take, including its header: a
// third of the terminal, floored so it is always worth having. The rest of the
// screen stays the user's.
func paneBudget(height int) int {
	return max(height/3, 4)
}

// pane is the warnings block above the bar — a tail of the captured stderr
// stream, newest last, as much of it as the budget allows.
//
// Lines are WRAPPED here rather than left to the terminal. The display's erase
// sequence is a row count, so a line the terminal wrapped on its own would make
// that count wrong and eat the scrollback above the bar. Wrapping rather than
// clipping is what makes a message readable while it streams past; the clipped
// form hid the half of a rustc diagnostic that says what went wrong.
func (u *UI) pane(width, height int) []string {
	u.mu.Lock()
	all := slices.Clone(u.warnings)
	u.mu.Unlock()

	// Blank lines are separators inside a compiler diagnostic. The full record
	// keeps them; the pane does not, because its budget is a handful of rows and
	// a blank one spends a row on nothing. Counting them would also make the
	// header lie — a blank line occupies no row, so "last 8" would name lines
	// that are not on screen.
	lines := make([]string, 0, len(all))
	for _, l := range all {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}

	n := len(lines)
	budget := paneBudget(height) - 1 // the header takes one
	if n == 0 || budget < 1 {
		return nil
	}

	// Filled from the NEWEST line backwards, so a burst pushes older output out
	// of the pane instead of the newest never reaching it.
	var rows []string
	shown := 0
	for i := n - 1; i >= 0 && len(rows) < budget; i-- {
		w := wrapRows(lines[i], width-1)
		if room := budget - len(rows); len(w) > room {
			w = w[len(w)-room:] // a single over-long line keeps its tail
		}
		rows = append(w, rows...)
		shown++
	}

	head := fmt.Sprintf("  %d warning(s)", n)
	if shown < n {
		head = fmt.Sprintf("  %d warning(s), last %d", n, shown)
	}
	out := make([]string, 0, len(rows)+1)
	out = append(out, u.pal.dim(clip(head, width-1)))
	for _, r := range rows {
		out = append(out, u.pal.dim(r))
	}
	return out
}

// wrapRows breaks one captured line into the rows it will occupy, indenting the
// continuations so a wrap reads as a wrap. It breaks on columns, not words: this
// is mostly paths and compiler diagnostics, where a word boundary is rare and
// the useful part is often at the end.
func wrapRows(line string, width int) []string {
	const head, cont = "    ", "      "
	r := []rune(line)
	var out []string
	for first := true; len(r) > 0; first = false {
		prefix := cont
		if first {
			prefix = head
		}
		room := width - len([]rune(prefix))
		if room < 8 {
			return append(out, clip(prefix+string(r), width))
		}
		out = append(out, prefix+string(r[:min(room, len(r))]))
		r = r[min(room, len(r)):]
	}
	return out
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
	if final && u.partial != "" {
		logs = append(logs, logLine{u.partial, u.now()})
		u.partial = ""
	}
	u.mu.Unlock()

	var block []string
	if !final {
		var bar []string
		bar, u.lastPct = frame(stages, w, u.pal, u.now().Sub(u.start), u.lastPct, u.expect)
		block = append(u.pane(w, h), bar...)
		// Trimmed from the TOP: the bar is the one row that must never be cut.
		if maxRows := h - 1; len(block) > maxRows {
			block = block[len(block)-maxRows:]
		}
	}

	if len(logs) == 0 && len(promote) == 0 && len(block) == 0 && u.drawn == 0 && !u.unflushed() {
		return
	}

	// A frame can span both streams — the bar is on stderr, a captured stdout
	// line goes back to the real stdout — so it is built as a sequence of runs
	// and emitted in order. Adjacent writes to one stream coalesce, which is what
	// keeps the erase and the redraw a single write and stops the bar tearing.
	// The scrollback carries only the two things with an EXACT clock: a stage
	// completion, timestamped in the ledger, and a line written through Stdout(),
	// timestamped at the call. Captured stderr has neither — it is timestamped
	// when the reader goroutine wakes, strictly after the write, by an amount
	// nothing here can bound — so it lives in the pane instead and is written out
	// in one piece by Stop. Merging all three by time is what put a frontend's ✓
	// above the skip warnings it printed a microsecond earlier.
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
		events = append(events, event{l.at, u.stdout, l.text})
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
		// The pane was a live preview; this is the record. Every captured line
		// goes to the real stderr in arrival order, so a warning is never lost
		// and `godzilla scan 2>&1 | grep` still finds it.
		u.mu.Lock()
		rest := slices.Clone(u.warnings[u.shown:])
		u.shown = len(u.warnings)
		u.mu.Unlock()
		for _, l := range rest {
			add(u.out, l+"\n")
		}
		add(u.out, fmt.Sprintf("  scanned in %s\n", fmtDur(u.now().Sub(u.start))))
		u.drawn = 0
	} else {
		// No trailing newline: the cursor stays on the last block line, so the
		// next erase is relative to it and the terminal handles scrolling.
		add(u.out, strings.Join(block, "\n"))
		u.drawn = len(block)
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

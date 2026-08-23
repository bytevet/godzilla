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
	Capture bool              // route os.Stderr through the display for its lifetime
}

// UI is a running display. Every method is safe to call on a nil *UI, so the
// command can hold one variable and not branch at each use.
type UI struct {
	out  io.Writer
	size func() (w, h int)
	now  func() time.Time
	pal  palette

	start  time.Time
	ticker *time.Ticker
	stop   chan struct{}
	ticked sync.WaitGroup

	mu       sync.Mutex
	pending  []string        // log lines waiting to be flushed above the bar
	promoted map[string]bool // stages already written into the scrollback

	// drawn is how many lines the last frame occupied — the erase sequence is
	// relative to the cursor, so this is the display's entire screen state.
	drawn   int
	lastPct float64

	origStderr *os.File
	pipeW      *os.File
	readerDone chan struct{}

	stopOnce sync.Once
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

// Stop erases the bar, restores stderr, flushes everything captured and joins
// its goroutines. Idempotent and nil-safe, so the command can both defer it for
// the panic path and call it where normal output resumes.
//
// The order is load-bearing: restore stderr first so a straggler writes to the
// real terminal rather than a pipe nobody is reading, then close the write end
// so the reader sees EOF, then join the reader so nothing is still arriving when
// the final frame is drawn.
func (u *UI) Stop() {
	if u == nil {
		return
	}
	u.stopOnce.Do(func() {
		if u.pipeW != nil {
			os.Stderr = u.origStderr
			_ = u.pipeW.Close()
			<-u.readerDone
		}
		u.ticker.Stop()
		close(u.stop)
		u.ticked.Wait()
	})
}

// startCapture routes os.Stderr through a pipe so the display owns the
// terminal. Swapping the variable is what catches packages.PrintErrors, which
// writes to os.Stderr from inside golang.org/x/tools with no writer parameter
// and is the burstiest source of output a scan has. Runtime panics write to
// fd 2 directly and bypass this, which is what we want.
func (u *UI) startCapture() {
	r, w, err := os.Pipe()
	if err != nil {
		return // no capture; warnings just interleave, as they do today
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
				u.addLog(strings.TrimRight(line, "\n"))
			}
			if err != nil {
				return
			}
		}
	}()
}

func (u *UI) addLog(line string) {
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
	var promote []string
	for _, s := range stages {
		if s.Running || u.promoted[s.ID] {
			continue
		}
		u.promoted[s.ID] = true
		promote = append(promote, u.pal.ledgerLine(s, w-1))
	}

	u.mu.Lock()
	logs := u.pending
	u.pending = nil
	u.mu.Unlock()

	var bar []string
	if !final {
		bar, u.lastPct = frame(stages, w, u.pal, u.now().Sub(u.start), u.lastPct)
		if maxRows := h - 1; len(bar) > maxRows {
			bar = bar[:maxRows]
		}
	}

	if len(logs) == 0 && len(promote) == 0 && len(bar) == 0 && u.drawn == 0 {
		return
	}

	var b strings.Builder
	u.erase(&b)
	// Log lines pass through VERBATIM and are never clipped. Wrapping one is
	// harmless — it is written before the bar is redrawn — but truncating could
	// hide the tail of a warning that tooling greps for.
	for _, l := range logs {
		fmt.Fprintf(&b, "%s\n", l)
	}
	for _, l := range promote {
		fmt.Fprintf(&b, "%s\n", l)
	}
	if final {
		fmt.Fprintf(&b, "  scanned in %s\n", fmtDur(u.now().Sub(u.start)))
		u.drawn = 0
	} else {
		// No trailing newline: the cursor stays on the last bar line, so the
		// next erase is relative to it and the terminal handles scrolling.
		b.WriteString(strings.Join(bar, "\n"))
		u.drawn = len(bar)
	}
	_, _ = io.WriteString(u.out, b.String())
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

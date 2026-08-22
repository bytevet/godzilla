package scan

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytevet/godzilla/internal/scaninfo"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// finishDiag completes the telemetry both entry points share: the whole-scan
// figures and the one process fact only the scan can observe. ReadMemStats stops
// the world, so this must run exactly once per scan.
func finishDiag(d *scaninfo.Info, start time.Time, convert time.Duration, prog *ir.Program, coverage []LangCoverage) {
	d.Convert = convert
	d.Packages = len(prog.GetModules())
	for _, c := range coverage {
		d.Skipped += c.Skipped
	}
	d.Wall = time.Since(start)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	d.PeakBytes = ms.Sys
}

// sourceFiles is the file list the frontends were given: for a directory scan
// the inventory under the frontends' own selection policy, for a single file
// that file.
//
// It uses Select, not Files: Files is the unfiltered walk, which also holds
// lockfiles, images and anything over the size cap — none of which any frontend
// reads. Select applies the same SkipFile/TooBig policy the frontends do, which
// is what makes Files and Skipped counts of one population. A walk error is
// swallowed and yields no files, because diagnostics must never turn a
// successful scan into a failed one.
func sourceFiles(path string, inv *walkignore.Inventory) []string {
	if inv != nil {
		files, err := inv.Select(isSourcePath)
		if err != nil {
			return nil
		}
		return files
	}
	if path == "" {
		return nil
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() || !isSourcePath(path) {
		return nil
	}
	return []string{path}
}

// countLines returns the physical line count of paths — every line, blanks and
// comments included; this is not SLOC.
//
// Files are streamed through one reused buffer per worker rather than read
// whole: this runs alongside the taint engine, and slurping a tree into memory
// would inflate the very peak-memory figure it is reported next to. The pool is
// small for the same reason — the work is I/O-bound and the engine already has
// the CPUs.
func countLines(paths []string) int {
	if len(paths) == 0 {
		return 0
	}
	// Leave a core for the taint engine, which this runs alongside: on a 2-core
	// CI container an 8-wide pool would be the whole machine.
	workers := min(8, max(1, runtime.GOMAXPROCS(0)-1), len(paths))
	var wg sync.WaitGroup
	var next, total atomic.Int64
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			n := 0
			for {
				i := int(next.Add(1)) - 1
				if i >= len(paths) {
					break
				}
				n += linesIn(paths[i], buf)
			}
			total.Add(int64(n))
		}()
	}
	wg.Wait()
	return int(total.Load())
}

func linesIn(path string, buf []byte) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	lines, lastByte := 0, byte('\n')
	for {
		n, err := f.Read(buf)
		if n > 0 {
			lines += bytes.Count(buf[:n], []byte{'\n'})
			lastByte = buf[n-1]
		}
		if err != nil {
			if err != io.EOF {
				return 0
			}
			break
		}
	}
	if lastByte != '\n' {
		lines++ // a final line with no trailing newline still counts
	}
	return lines
}

// Package frontend holds the batch-conversion skeleton shared by the per-file
// frontends (Python, JavaScript, Ruby, Rust, C/C++). Each of them starts a
// ConvertFile the same way — resolve the target with walkignore.CollectTarget,
// fail fast on a single file, tolerate per-file failures in a directory batch
// run across worker goroutines (runChunks), count skipped files, and error only
// when not a single file converted — so that skeleton lives here ONCE
// (Batch.Convert) and a frontend supplies only its language-specific pieces as
// fields/hooks. Copies of it drift silently: a frontend that loses the
// skipped-file accounting reports scan.LangCoverage.Skipped as 0, not as broken.
//
// Driver is the matching front half: the exported
// ConvertFile/ConvertInventory/Skipped surface internal/scan consumes, which a
// frontend gets by embedding instead of re-declaring.
//
// The Go and Java frontends do not fit this shape (Go lowers packages, not
// files; Java resolves a build first) and keep their own drivers.
package frontend

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

// Driver is the embeddable front half of a Batch-based Converter: the
// skipped-file counter plus the ConvertFile/ConvertInventory entry points every
// per-file frontend exposes to internal/scan. A frontend embeds it and supplies
// only NewBatch. A frontend with a pre-step that bypasses batching entirely
// (Rust's cargo path) wraps the promoted methods with its own and delegates.
type Driver[R any] struct {
	// NewBatch builds this frontend's Batch. It is invoked once per conversion,
	// so state a Batch's Setup resolves (interpreter paths, per-run maps) stays
	// in closure state private to that run.
	NewBatch func() *Batch[R]

	skipped int // files this Driver's runs could not lower; see Skipped
}

// Skipped reports how many source files this converter could not lower. The scan
// layer surfaces it per language, so a run that dropped most of a project is
// visible instead of reading as clean coverage (see scan.LangCoverage.Skipped).
func (d *Driver[R]) Skipped() int { return d.skipped }

// ConvertFile lowers the source at path — a single file or a directory (all of
// the frontend's files under it, recursively, one gIR Module per file) — via
// the shared Batch skeleton (see Batch.Convert for the failure semantics).
func (d *Driver[R]) ConvertFile(path string) (*ir.Program, error) {
	prog, skipped, err := d.NewBatch().Convert(path)
	d.skipped += skipped
	return prog, err
}

// ConvertInventory lowers the frontend's files of a pre-walked scan-root
// inventory (see walkignore.Inventory), skipping the directory walk
// ConvertFile's directory mode would repeat.
func (d *Driver[R]) ConvertInventory(inv *walkignore.Inventory) (*ir.Program, error) {
	prog, skipped, err := d.NewBatch().ConvertInventory(inv)
	d.skipped += skipped
	return prog, err
}

// Batch describes one frontend's per-file conversion for Convert. R is the
// frontend's per-file result type; it must at least record the file's lowered
// module or error (extracted via Result), and may carry extra per-file state
// for Finish/PostProgram (e.g. the parsed AST, a default-export name).
type Batch[R any] struct {
	// Label prefixes warnings and errors, naming the frontend ("py_converter").
	Label string
	// Lang is the human-readable language name for messages ("Python").
	Lang string
	// Mode is the produced ir.Program's Mode ("ast", "mir", "llvm").
	Mode string

	// Match reports whether a walked path is one of this frontend's source files
	// (see walkignore.CollectTarget).
	Match func(path string) bool

	// Setup, if non-nil, runs once after target collection succeeds and before
	// any parsing — toolchain lookup, helper-script materialization. A non-nil
	// returned cleanup runs when Convert finishes; a Setup error aborts the
	// conversion.
	Setup func() (cleanup func(), err error)

	// Parse converts a contiguous chunk of files, writing one result per file
	// into out (index-aligned with files). In directory mode chunks run
	// concurrently (see runChunks), so Parse must write only its own slots.
	// root is the scan root, for module naming (walkignore.ModuleName).
	Parse func(root string, files []string, out []R)

	// Finish, if non-nil, runs once after every chunk has parsed and before
	// modules are extracted — for work that needs the whole file set, e.g.
	// Python's cross-file handler-class lowering.
	Finish func(results []R)

	// Result extracts a file's lowered module or its conversion error from the
	// file's result. Exactly one of the two should be non-nil.
	Result func(r *R) (*ir.Module, error)

	// PostProgram, if non-nil, runs on the assembled program just before Convert
	// returns success — e.g. cross-module call resolution. isDir distinguishes a
	// directory batch from a single-file conversion.
	PostProgram func(prog *ir.Program, isDir bool)
}

// Convert runs the shared ConvertFile skeleton on path — a single source file
// or a directory. Module order is the sorted file order. It returns the
// program, the number of files skipped (directory mode only; also meaningful
// alongside the no-files-converted error), and an error.
//
// Single-file mode fails fast: a parse failure is the caller's only signal.
// Directory mode is resilient — one syntax error in an unrelated file must not
// hide every other file's findings — so a failed file is warned about on stderr,
// counted as skipped, and dropped; Convert errors only if not a single file in
// the tree converted.
func (b *Batch[R]) Convert(path string) (*ir.Program, int, error) {
	root, files, isDir, err := walkignore.CollectTarget(path, b.Match)
	if err != nil {
		return nil, 0, err
	}
	return b.run(root, files, isDir)
}

// ConvertInventory is Convert over a pre-walked directory inventory: the scan
// pipeline walks the scan root ONCE (walkignore.NewInventory) and every present
// frontend selects its files from that cache instead of re-walking the same
// tree. Selection (Inventory.Select) must apply exactly the per-file policy
// Convert's own walk applies — same match predicate, same SkipFile/TooBig caps,
// same abort-on-walk-error contract — so the two entry points lower identical
// file sets.
func (b *Batch[R]) ConvertInventory(inv *walkignore.Inventory) (*ir.Program, int, error) {
	files, err := inv.Select(b.Match)
	if err != nil {
		return nil, 0, err
	}
	return b.run(inv.Root(), files, true)
}

// run is the conversion skeleton shared by Convert and ConvertInventory, from
// resolved (root, files) to assembled program.
func (b *Batch[R]) run(root string, files []string, isDir bool) (*ir.Program, int, error) {
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no %s files found under %s", b.Lang, root)
	}
	if b.Setup != nil {
		cleanup, err := b.Setup()
		if err != nil {
			return nil, 0, err
		}
		if cleanup != nil {
			defer cleanup()
		}
	}

	results := make([]R, len(files))
	if !isDir {
		b.Parse(root, files, results)
		if _, err := b.Result(&results[0]); err != nil {
			return nil, 0, err
		}
		if b.Finish != nil {
			b.Finish(results)
		}
		mod, _ := b.Result(&results[0])
		prog := &ir.Program{Mode: b.Mode, Modules: []*ir.Module{mod}}
		if b.PostProgram != nil {
			b.PostProgram(prog, false)
		}
		return prog, 0, nil
	}

	// Results land at fixed indices, so module order stays the sorted file
	// order regardless of chunk completion order.
	runChunks(len(files), func(start, end int) {
		b.Parse(root, files[start:end], results[start:end])
	})
	if b.Finish != nil {
		b.Finish(results)
	}

	prog := &ir.Program{Mode: b.Mode}
	skipped := 0
	var convertErrs []string
	for i := range results {
		mod, err := b.Result(&results[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: skipping %s: %v\n", b.Label, files[i], err)
			skipped++
			convertErrs = append(convertErrs, err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, mod)
	}
	if len(prog.Modules) == 0 {
		return nil, skipped, fmt.Errorf("%s: no %s files under %s converted successfully (%d file(s) failed): %s",
			b.Label, b.Lang, root, len(convertErrs), strings.Join(convertErrs, "; "))
	}
	if b.PostProgram != nil {
		b.PostProgram(prog, true)
	}
	return prog, skipped, nil
}

// PerFile adapts a per-file conversion function to Batch.Parse, for frontends
// whose unit of work is a single file (JS, Rust, C/C++) rather than a batched
// helper-process invocation (Python, Ruby).
func PerFile[R any](fn func(root, file string) R) func(root string, files []string, out []R) {
	return func(root string, files []string, out []R) {
		for i, f := range files {
			out[i] = fn(root, f)
		}
	}
}

// runChunks splits [0,n) into up to GOMAXPROCS contiguous chunks and calls
// fn(start, end) for each on its own goroutine, waiting for all to finish. fn
// must write only to index-aligned slots so results stay deterministic.
func runChunks(n int, fn func(start, end int)) {
	workers := max(min(runtime.GOMAXPROCS(0), n), 1)
	size := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < n; start += size {
		end := min(start+size, n)
		wg.Add(1)
		go func(start, end int) { defer wg.Done(); fn(start, end) }(start, end)
	}
	wg.Wait()
}

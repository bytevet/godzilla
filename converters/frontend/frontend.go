// Package frontend holds the batch-conversion skeleton shared by the per-file
// frontends (Python, JavaScript, Ruby, Rust, C/C++). Each of them starts a
// ConvertFile the same way — resolve the target with walkignore.CollectTarget,
// fail fast on a single file, tolerate per-file failures in a directory batch
// run via internal/chunks, count skipped files, and error only when not a
// single file converted — so that skeleton lives here ONCE (Batch.Convert)
// and a frontend supplies only its language-specific pieces as fields/hooks.
// Before this, the skeleton was copied per frontend and the copies drifted:
// the Rust and C/C++ variants lacked the skipped-file accounting, so
// scan.LangCoverage.Skipped silently read 0 for them.
//
// The Go and Java frontends do not fit this shape (Go lowers packages, not
// files; Java resolves a build first) and keep their own drivers.
package frontend

import (
	"fmt"
	"os"
	"strings"

	"godzilla/internal/chunks"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

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
	// concurrently (see chunks.Run), so Parse must write only its own slots.
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
// Single-file mode fails fast: a parse failure is the caller's only signal, so
// it is surfaced immediately. Directory mode is resilient: one unparseable
// file must not abort the whole batch (a single syntax error in an unrelated
// file shouldn't hide every other file's findings), so a failed file is
// warned about on stderr, counted as skipped, and dropped; Convert errors
// only if not a single file in the tree converted.
func (b *Batch[R]) Convert(path string) (*ir.Program, int, error) {
	root, files, isDir, err := walkignore.CollectTarget(path, b.Match)
	if err != nil {
		return nil, 0, err
	}
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
	chunks.Run(len(files), func(start, end int) {
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

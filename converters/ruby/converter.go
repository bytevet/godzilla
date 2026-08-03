// Package ruby_converter lowers Ruby source into gIR so the shared taint engine
// can analyze it, mirroring the public shape of the other frontends
// (NewConverter / Converter.ConvertFile).
//
// Like the Python frontend, it has no in-process Ruby parser, so it shells out
// to an embedded helper (rbdump.rb, see //go:embed) that parses the file with
// the standard library's Ripper and prints its S-expression AST as JSON;
// lower.go turns that tree into gIR. Ripper ships with every MRI Ruby, so only
// `ruby` on PATH is required; ConvertFile returns a clear error if it is absent.
//
// Scope (deliberately narrow, taint-focused — like the Python frontend's
// documented limits): a real CFG via converters/ssabuild (if/elsif/while/until/
// case lower to blocks with PHI joins; a branch-free method stays one block). Covered
// expressions: literals, string interpolation, `+` concatenation, local
// variable reads/assignments, method/command calls (with and without a
// receiver), and index reads. The web request surface lowers to a synthetic
// source CALL so the engine seeds taint — the same opaque-base heuristic the
// JS/Python frontends use: a member read / `[]` off a method parameter or a
// free/unbound identifier named like a request object (`request.<accessor>`,
// `req.<accessor>`, `params[:x]`, `cookies[:x]`) becomes a base-scoped source
// CALL `ruby:<base>.<accessor>`, and the rulepack globs filter by framework,
// so any accessor — not a fixed member list — is covered. Unhandled nodes become an
// OP_CODE_INTRINSIC "ruby.unsupported" (expressions) or are dropped
// (statements) rather than aborting conversion.
package ruby_converter

import (
	_ "embed"
	"fmt"
	"os/exec"
	"strings"

	"godzilla/converters/frontend"
	"godzilla/internal/proc"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

//go:embed rbdump.rb
var rbDumpScript []byte

// Converter lowers Ruby source files/directories into gIR: the shared
// frontend.Driver surface (ConvertFile/ConvertInventory/Skipped) over Ruby's
// batch hooks (see batch). Requires `ruby` on PATH.
type Converter struct {
	frontend.Driver[rbFileResult]
}

// NewConverter returns a ready-to-use Ruby-to-gIR converter.
func NewConverter() *Converter {
	c := &Converter{}
	c.NewBatch = c.batch
	return c
}

// IsRubyFile reports whether path is a Ruby source file this frontend lowers.
// Exported so internal/scan's language detection and this frontend's own file
// selection share ONE predicate instead of drifting copies.
func IsRubyFile(path string) bool { return strings.HasSuffix(path, ".rb") }

// batch builds the shared frontend.Batch driver with Ruby's hooks. A fresh
// value per conversion: the Setup-resolved interpreter/helper paths are carried
// in closure state private to this batch.
//
// The single-file/directory-batch skeleton is the shared driver; what is
// Ruby's alone: parsing is chunked — one `ruby rbdump.rb --batch <chunk...>`
// invocation per chunk, so interpreter startup is paid per chunk, not per file.
func (c *Converter) batch() *frontend.Batch[rbFileResult] {
	var rubyExe, scriptPath string
	return &frontend.Batch[rbFileResult]{
		Label: "ruby_converter",
		Lang:  "Ruby",
		Mode:  "ast",
		Match: IsRubyFile,
		Setup: func() (func(), error) {
			exe, err := exec.LookPath("ruby")
			if err != nil {
				return nil, fmt.Errorf("ruby_converter: ruby not found on PATH (required to parse Ruby source): %w", err)
			}
			rubyExe = exe
			sp, cleanup, err := writeHelperScript()
			if err != nil {
				return nil, err
			}
			scriptPath = sp
			return cleanup, nil
		},
		Parse: func(root string, files []string, out []rbFileResult) {
			convertRubyChunk(rubyExe, scriptPath, root, files, out)
		},
		Result: func(r *rbFileResult) (*ir.Module, error) { return r.mod, r.err },
	}
}

// rbFileResult is one file's outcome within a batch chunk.
type rbFileResult struct {
	mod *ir.Module
	err error
}

// convertRubyChunk parses a contiguous chunk of files with a single
// `rbdump.rb --batch` invocation (one JSON document per file, argv order) via
// proc.RunBatchScript and lowers each, writing into out (index-aligned with
// files). A process-level failure marks every file in the chunk; a per-file
// parse failure marks only that file, mirroring the old file-at-a-time error
// semantics.
func convertRubyChunk(rubyExe, scriptPath, root string, files []string, out []rbFileResult) {
	proc.RunBatchScript("ruby_converter", "rbdump.rb", rubyExe, scriptPath, files, func(i int, doc any, err error) {
		if err != nil {
			out[i].err = err
			return
		}
		out[i].mod = convertModule(doc, files[i], moduleNameFor(root, files[i]))
	})
}

// writeHelperScript materializes the embedded rbdump.rb into a temp file.
func writeHelperScript() (string, func(), error) {
	path, cleanup, err := proc.WriteEmbeddedScript("godzilla-rbdump-*.rb", rbDumpScript)
	if err != nil {
		return "", nil, fmt.Errorf("ruby_converter: %w", err)
	}
	return path, cleanup, nil
}

// moduleNameFor derives a module name unique to the file: its path relative to
// the scan root, extension stripped, slash-normalized.
func moduleNameFor(root, file string) string {
	return walkignore.ModuleName(root, file)
}

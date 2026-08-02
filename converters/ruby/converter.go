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

// Converter lowers Ruby source files/directories into gIR.
type Converter struct {
	skipped int // files this run could not lower; see Skipped
}

// Skipped reports how many source files this converter could not lower. The scan
// layer surfaces it per language, so a run that dropped most of a project is
// visible instead of reading as clean coverage (see scan.LangCoverage.Skipped).
func (c *Converter) Skipped() int { return c.skipped }

// NewConverter returns a ready-to-use Ruby-to-gIR converter.
func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers the Ruby source at path into gIR. path may be a single
// .rb file or a directory (all *.rb files under it are converted recursively,
// one gIR Module per file). Requires `ruby` on PATH.
//
// The single-file/directory-batch skeleton is the shared frontend.Batch driver;
// what is Ruby's alone: parsing is chunked — one `ruby rbdump.rb --batch
// <chunk...>` invocation per chunk, so interpreter startup is paid per chunk,
// not per file.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	var rubyExe, scriptPath string
	b := frontend.Batch[rbFileResult]{
		Label: "ruby_converter",
		Lang:  "Ruby",
		Mode:  "ast",
		Match: func(p string) bool { return strings.HasSuffix(p, ".rb") },
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
	prog, skipped, err := b.Convert(path)
	c.skipped += skipped
	return prog, err
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

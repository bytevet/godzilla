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
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"godzilla/internal/chunks"
	"godzilla/internal/proc"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

//go:embed rbdump.rb
var rbDumpScript []byte

// Converter lowers Ruby source files/directories into gIR.
type Converter struct{}

// NewConverter returns a ready-to-use Ruby-to-gIR converter.
func NewConverter() *Converter { return &Converter{} }

// ConvertFile lowers the Ruby source at path into gIR. path may be a single
// .rb file or a directory (all *.rb files under it are converted recursively,
// one gIR Module per file). Requires `ruby` on PATH.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	// Module names are the file path relative to the scan root, so same-named
	// functions in different files get distinct canonical names instead of
	// colliding in the analyzer. For a single file the root is its own
	// directory, so its module name stays the bare filename (see
	// walkignore.CollectTarget).
	root, files, isDir, err := walkignore.CollectTarget(path, func(p string) bool { return strings.HasSuffix(p, ".rb") })
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no Ruby files found under %s", root)
	}

	rubyExe, err := exec.LookPath("ruby")
	if err != nil {
		return nil, fmt.Errorf("ruby_converter: ruby not found on PATH (required to parse Ruby source): %w", err)
	}
	scriptPath, cleanup, err := writeHelperScript()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if !isDir {
		results := make([]rbFileResult, 1)
		c.convertRubyChunk(rubyExe, scriptPath, root, files, results)
		if results[0].err != nil {
			return nil, results[0].err
		}
		return &ir.Program{Mode: "ast", Modules: []*ir.Module{results[0].mod}}, nil
	}

	// Directory batch: one unparseable file must not abort the whole batch.
	// Parsing is chunked — one `ruby rbdump.rb --batch <chunk...>` invocation
	// per chunk, run concurrently — so interpreter startup is paid per chunk,
	// not per file. Results land at fixed indices, keeping module order the
	// sorted file order.
	results := make([]rbFileResult, len(files))
	chunks.Run(len(files), func(start, end int) {
		c.convertRubyChunk(rubyExe, scriptPath, root, files[start:end], results[start:end])
	})

	prog := &ir.Program{Mode: "ast"}
	var convertErrs []string
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "ruby_converter: skipping %s: %v\n", files[i], r.err)
			convertErrs = append(convertErrs, r.err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, r.mod)
	}
	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("ruby_converter: no Ruby files under %s converted successfully (%d failed): %s",
			root, len(convertErrs), strings.Join(convertErrs, "; "))
	}
	return prog, nil
}

// rbFileResult is one file's outcome within a batch chunk.
type rbFileResult struct {
	mod *ir.Module
	err error
}

// convertRubyChunk parses a contiguous chunk of files with a single
// `rbdump.rb --batch` invocation (one JSON document per file, argv order) and
// lowers each, writing into out (index-aligned with files). A process-level
// failure marks every file in the chunk; a per-file parse failure marks only
// that file, mirroring the old file-at-a-time error semantics.
func (c *Converter) convertRubyChunk(rubyExe, scriptPath, root string, files []string, out []rbFileResult) {
	ctx, cancel := proc.ParseContext()
	defer cancel()
	args := append([]string{scriptPath, "--batch"}, files...)
	cmd := exec.CommandContext(ctx, rubyExe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		for i, f := range files {
			out[i].err = fmt.Errorf("ruby_converter: ruby failed parsing %s: %v (stderr: %s)", f, err, strings.TrimSpace(stderr.String()))
		}
		return
	}

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.UseNumber()
	for i, f := range files {
		var node interface{}
		if err := dec.Decode(&node); err != nil {
			out[i].err = fmt.Errorf("ruby_converter: failed to parse rbdump.rb output for %s: %w", f, err)
			continue
		}
		if obj, ok := node.(map[string]interface{}); ok {
			if msg, ok := obj["error"]; ok {
				out[i].err = fmt.Errorf("ruby_converter: failed to parse %s: %v", f, msg)
				continue
			}
		}
		out[i].mod = convertModule(node, f, moduleNameFor(root, f))
	}
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

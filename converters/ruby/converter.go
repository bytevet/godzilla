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
// documented limits): straight-line env-based lowering with no real CFG (one
// basic block per method/def, branch bodies flattened in source order). Covered
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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

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
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if walkignore.SkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, ".rb") && !walkignore.SkipFile(d.Name()) {
				if fi, e := d.Info(); e == nil && walkignore.TooBig(fi.Size()) {
					return nil
				}
				files = append(files, p)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
		sort.Strings(files)
	} else {
		files = []string{abs}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no Ruby files found under %s", abs)
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

	root := abs
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}

	if !info.IsDir() {
		mod, err := c.convertRubyFile(rubyExe, scriptPath, files[0], moduleNameFor(root, files[0]))
		if err != nil {
			return nil, err
		}
		return &ir.Program{Mode: "ast", Modules: []*ir.Module{mod}}, nil
	}

	// Directory batch: one unparseable file must not abort the whole batch.
	prog := &ir.Program{Mode: "ast"}
	var convertErrs []string
	for _, f := range files {
		mod, err := c.convertRubyFile(rubyExe, scriptPath, f, moduleNameFor(root, f))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ruby_converter: skipping %s: %v\n", f, err)
			convertErrs = append(convertErrs, err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, mod)
	}
	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("ruby_converter: no Ruby files under %s converted successfully (%d failed): %s",
			abs, len(convertErrs), strings.Join(convertErrs, "; "))
	}
	return prog, nil
}

// writeHelperScript materializes the embedded rbdump.rb into a temp file.
func writeHelperScript() (string, func(), error) {
	tmp, err := os.CreateTemp("", "godzilla-rbdump-*.rb")
	if err != nil {
		return "", nil, fmt.Errorf("ruby_converter: failed to create temp helper script: %w", err)
	}
	if _, err := tmp.Write(rbDumpScript); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("ruby_converter: failed to write temp helper script: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("ruby_converter: failed to close temp helper script: %w", err)
	}
	path := tmp.Name()
	return path, func() { _ = os.Remove(path) }, nil
}

// moduleNameFor derives a module name unique to the file: its path relative to
// the scan root, extension stripped, slash-normalized.
func moduleNameFor(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = filepath.Base(file)
	}
	return filepath.ToSlash(strings.TrimSuffix(rel, ".rb"))
}

// convertRubyFile runs rbdump.rb against file and lowers the JSON sexp to gIR.
func (c *Converter) convertRubyFile(rubyExe, scriptPath, file, moduleName string) (*ir.Module, error) {
	ctx, cancel := proc.ParseContext()
	defer cancel()
	cmd := exec.CommandContext(ctx, rubyExe, scriptPath, file)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ruby_converter: ruby failed parsing %s: %v (stderr: %s)", file, err, strings.TrimSpace(stderr.String()))
	}

	var root interface{}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("ruby_converter: failed to parse rbdump.rb output for %s: %w", file, err)
	}
	if obj, ok := root.(map[string]interface{}); ok {
		if msg, ok := obj["error"]; ok {
			return nil, fmt.Errorf("ruby_converter: failed to parse %s: %v", file, msg)
		}
	}
	return convertModule(root, file, moduleName), nil
}

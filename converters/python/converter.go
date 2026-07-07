// Package py_converter lowers Python source into gIR so the taint engine in
// internal/analysis can analyze it, mirroring the public shape of
// converters/go (NewConverter / Converter.ConvertFile).
//
// Unlike the Go converter, which builds on golang.org/x/tools' SSA form, this
// converter has no access to a Python compiler front end from Go without
// adding a dependency. Per the project's "prefer python3" decision, it shells
// out to an embedded helper script (pyast.py, see //go:embed below) that
// parses the file with the Python standard library's `ast` module and prints
// a compact JSON tree; convertModule/convertFunction/lowerStmt/lowerExpr
// below turn that JSON into gIR.
//
// A tree-sitter (or other pure-Go parser) fallback for environments without
// python3 is a documented FUTURE path, not implemented here: ConvertFile
// returns a clear error if python3 is not on PATH.
//
// Known limitations (see also the doc comment on lowerBody):
//   - No real control-flow graph: every function lowers to a single straight
//     -line basic block. if/for/while/with/try bodies are flattened into that
//     one block in source order, branch conditions are dropped, and loops
//     execute (conceptually) once. This trades path precision for recall,
//     which is the right tradeoff for a taint scanner focused on straight
//     -line handler code, but it can merge mutually exclusive branches and
//     will not model loop-carried taint beyond one iteration.
//   - Classes are only partially modeled: methods (`def` inside a `class`)
//     become functions named "<Class>.<method>", but other class-body
//     statements (class attributes, nested classes, decorators) are ignored.
//   - Expression coverage covers calls, attribute/subscript reads, binary/unary
//     and boolean operators, comprehensions, container literals, unpacking
//     assignment, walrus (`:=`), `await`, f-strings, str.format, constants, and
//     names. Lambdas, comparison operators, and decorators are not specifically
//     modeled; unhandled expression/statement kinds become an
//     OP_CODE_INTRINSIC "py.unsupported" node (expressions) or are silently
//     dropped (statements), rather than aborting conversion.
package py_converter

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"godzilla/internal/proc"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

//go:embed pyast.py
var pyASTScript []byte

// Converter lowers Python source files/directories into gIR.
type Converter struct{}

// NewConverter returns a ready-to-use Python-to-gIR converter.
func NewConverter() *Converter {
	return &Converter{}
}

// ConvertFile lowers the Python source at path into gIR. path may be either a
// single .py file or a directory (all *.py files under it are converted
// recursively, one gIR Module per file). Requires python3 on PATH; if it is
// not found, an error is returned (a tree-sitter based fallback is a
// documented future path, not implemented here).
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
			if strings.HasSuffix(p, ".py") && !walkignore.SkipFile(d.Name()) {
				if info, e := d.Info(); e == nil && walkignore.TooBig(info.Size()) {
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
		return nil, fmt.Errorf("no Python files found under %s", abs)
	}

	pythonExe, err := exec.LookPath("python3")
	if err != nil {
		return nil, fmt.Errorf("py_converter: python3 not found on PATH (required to parse Python source; a tree-sitter fallback is a documented future path but not implemented): %w", err)
	}

	scriptPath, cleanup, err := writeHelperScript()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Module names are the file path relative to the scan root, so that
	// same-named functions in different files (every sample is app.py) get
	// distinct canonical names instead of colliding in the analyzer.
	// Single-file mode: root is the file's directory, so the module name stays
	// the bare filename.
	root := abs
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}

	// Single-file mode (path pointed directly at a .py file): a parse/read
	// failure is the caller's only signal, so surface it immediately.
	if !info.IsDir() {
		mod, err := c.convertPythonFile(pythonExe, scriptPath, files[0], moduleNameFor(root, files[0]))
		if err != nil {
			return nil, err
		}
		return &ir.Program{Mode: "ast", Modules: []*ir.Module{mod}}, nil
	}

	// Directory batch mode: one unparseable .py file must not abort the whole
	// batch (a single syntax error in an unrelated file shouldn't hide every
	// other file's findings). Skip it, log a warning to stderr, and keep
	// going; only fail if not a single file in the tree converted.
	//
	// Parsing is batched: the file list is split into contiguous chunks — one
	// `python3 pyast.py --batch <chunk...>` invocation each, run concurrently —
	// so interpreter startup is paid per chunk, not per file (the dominant cost
	// of the old file-at-a-time loop). Results land at fixed indices, so module
	// order stays the sorted file order regardless of chunk completion order.
	results := make([]pyFileResult, len(files))
	nWorkers := runtime.GOMAXPROCS(0)
	if nWorkers > len(files) {
		nWorkers = len(files)
	}
	chunk := (len(files) + nWorkers - 1) / nWorkers
	var wg sync.WaitGroup
	for start := 0; start < len(files); start += chunk {
		end := start + chunk
		if end > len(files) {
			end = len(files)
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			c.convertPythonChunk(pythonExe, scriptPath, root, files[start:end], results[start:end])
		}(start, end)
	}
	wg.Wait()

	prog := &ir.Program{Mode: "ast"}
	var convertErrs []string
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "py_converter: skipping %s: %v\n", files[i], r.err)
			convertErrs = append(convertErrs, r.err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, r.mod)
	}

	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("py_converter: no Python files under %s converted successfully (%d file(s) failed): %s",
			abs, len(convertErrs), strings.Join(convertErrs, "; "))
	}

	return prog, nil
}

// pyFileResult is one file's outcome within a batch chunk.
type pyFileResult struct {
	mod *ir.Module
	err error
}

// convertPythonChunk parses a contiguous chunk of files with a single
// `pyast.py --batch` invocation (one JSON document per file, argv order) and
// lowers each, writing into out (index-aligned with files). A process-level
// failure marks every file in the chunk; a per-file parse failure marks only
// that file, mirroring the old file-at-a-time error semantics.
func (c *Converter) convertPythonChunk(pythonExe, scriptPath, root string, files []string, out []pyFileResult) {
	ctx, cancel := proc.ParseContext()
	defer cancel()
	args := append([]string{scriptPath, "--batch"}, files...)
	cmd := exec.CommandContext(ctx, pythonExe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		for i, f := range files {
			out[i].err = fmt.Errorf("py_converter: python3 failed parsing %s: %v (stderr: %s)", f, runErr, strings.TrimSpace(stderr.String()))
		}
		return
	}

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.UseNumber()
	for i, f := range files {
		var root_ astNode
		if err := dec.Decode(&root_); err != nil {
			out[i].err = fmt.Errorf("py_converter: failed to parse pyast.py output for %s: %w", f, err)
			continue
		}
		if errMsg, ok := root_["error"]; ok {
			out[i].err = fmt.Errorf("py_converter: failed to parse %s: %v", f, errMsg)
			continue
		}
		out[i].mod = convertModule(root_, f, moduleNameFor(root, f))
	}
}

// writeHelperScript materializes the embedded pyast.py into a temp file so it
// can be invoked as `python3 <path> <file.py>`. The caller must invoke the
// returned cleanup function once done.
func writeHelperScript() (string, func(), error) {
	tmp, err := os.CreateTemp("", "godzilla-pyast-*.py")
	if err != nil {
		return "", nil, fmt.Errorf("py_converter: failed to create temp helper script: %w", err)
	}
	if _, err := tmp.Write(pyASTScript); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("py_converter: failed to write temp helper script: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("py_converter: failed to close temp helper script: %w", err)
	}
	path := tmp.Name()
	return path, func() { _ = os.Remove(path) }, nil
}

// moduleNameFor derives a module name unique to the file: its path relative to
// the scan root, extension stripped, slash-normalized (e.g. "ssrf/app"). When
// root is the file's own directory (single-file scans) this is just the bare
// filename.
func moduleNameFor(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = filepath.Base(file)
	}
	return filepath.ToSlash(strings.TrimSuffix(rel, ".py"))
}

// convertPythonFile runs the embedded pyast.py helper against file and lowers
// the resulting JSON AST into one gIR Module.
func (c *Converter) convertPythonFile(pythonExe, scriptPath, file, moduleName string) (*ir.Module, error) {
	ctx, cancel := proc.ParseContext()
	defer cancel()
	cmd := exec.CommandContext(ctx, pythonExe, scriptPath, file)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		return nil, fmt.Errorf("py_converter: python3 failed parsing %s: %v (stderr: %s)", file, runErr, strings.TrimSpace(stderr.String()))
	}

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.UseNumber()
	var root astNode
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("py_converter: failed to parse pyast.py output for %s: %w", file, err)
	}
	if errMsg, ok := root["error"]; ok {
		return nil, fmt.Errorf("py_converter: failed to parse %s: %v", file, errMsg)
	}

	return convertModule(root, file, moduleName), nil
}

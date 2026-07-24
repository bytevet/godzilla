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
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"godzilla/internal/chunks"
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
// recursively, one gIR Module per file). Requires python3 on PATH.
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
		files, err = walkignore.CollectSources(abs, func(p string) bool { return strings.HasSuffix(p, ".py") })
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{abs}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no Python files found under %s", abs)
	}

	pythonExe, err := exec.LookPath("python3")
	if err != nil {
		return nil, fmt.Errorf("py_converter: python3 not found on PATH (required to parse Python source): %w", err)
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
		results := make([]pyFileResult, 1)
		c.convertPythonChunk(pythonExe, scriptPath, root, files, results)
		if results[0].err != nil {
			return nil, results[0].err
		}
		lowerAll(results)
		return &ir.Program{Mode: "ast", Modules: []*ir.Module{results[0].mod}}, nil
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
	chunks.Run(len(files), func(start, end int) {
		c.convertPythonChunk(pythonExe, scriptPath, root, files[start:end], results[start:end])
	})

	// Lower after every file is parsed, so the handler-class set spans all files.
	lowerAll(results)

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

	resolveCrossModuleCalls(prog)

	return prog, nil
}

// resolveCrossModuleCalls rewrites CALL callees that reference a function in
// ANOTHER file via its dotted import path (`from pkg.util import f; f(x)` lowers
// to callee "py:pkg.util.f") to that function's real canonical name, which the
// module frontend builds from the file's path relative to the scan root and thus
// uses "/" separators and may lack the import's leading package prefix (scanning
// inside a package). The engine resolves calls by EXACT canonical name, so
// without this a cross-subdir call never links and taint stops at the call --
// only same-directory calls (bare module name == import name) resolved before.
//
// Matching is by logical dotted path (module "/"→"."), taking the LONGEST
// dot-aligned suffix that names exactly ONE function; an ambiguous or absent
// match leaves the callee untouched. Single-component method callees ("x.execute")
// can never match (a function's logical path always has >=1 dot: module + name),
// so ordinary method/sink calls are unaffected -- only genuine multi-component
// import paths resolve. Runs only in directory scans (single-file scans have one
// module and nothing to cross-link).
func resolveCrossModuleCalls(prog *ir.Program) {
	// logical maps a "py:"-prefixed canonical name to its dotted logical path.
	logical := func(canon string) string {
		return strings.ReplaceAll(strings.TrimPrefix(canon, "py:"), "/", ".")
	}

	// Index every lowered function by its logical dotted path. A path shared by
	// two functions is ambiguous and never used as a rewrite target.
	rawByLogical := map[string]string{} // logical path -> raw canonical
	ambiguous := map[string]bool{}
	rawSet := map[string]bool{} // every function's raw canonical (exact-resolvable already)
	for _, m := range prog.Modules {
		for _, fn := range m.Functions {
			if fn.CanonicalName == "" {
				continue
			}
			rawSet[fn.CanonicalName] = true
			lp := logical(fn.CanonicalName)
			if _, seen := rawByLogical[lp]; seen {
				ambiguous[lp] = true
				continue
			}
			rawByLogical[lp] = fn.CanonicalName
		}
	}

	// resolve returns the raw canonical for a callee's logical path via the
	// longest unique dot-aligned suffix, or "" if none/ambiguous.
	resolve := func(calleeLogical string) string {
		s := calleeLogical
		for {
			if raw, ok := rawByLogical[s]; ok && !ambiguous[s] {
				return raw
			}
			i := strings.IndexByte(s, '.')
			if i < 0 {
				return ""
			}
			s = s[i+1:] // drop the leading package component and retry a shorter suffix
		}
	}

	for _, m := range prog.Modules {
		for _, fn := range m.Functions {
			for _, b := range fn.Blocks {
				for _, inst := range b.Instrs {
					cc := inst.GetCall()
					if cc == nil {
						continue
					}
					callee := cc.GetCallee()
					if callee == "" || rawSet[callee] {
						continue // unset, or already resolves by exact name
					}
					raw := resolve(logical(callee))
					if raw == "" {
						continue
					}
					cc.Callee = raw
					if fnv := cc.GetValue(); fnv != nil && fnv.GetFuncName() != "" {
						fnv.Kind = &ir.Value_FuncName{FuncName: raw}
					}
				}
			}
		}
	}
}

// pyFileResult is one file's outcome within a batch chunk. Parsing and lowering
// are two phases: convertPythonChunk fills doc/file/module (or err); lowerParsed
// then turns doc into mod, after a whole-program pass has computed the global
// request-handler class set (cross-file subclassing, see lowerAll).
type pyFileResult struct {
	doc    astNode
	file   string
	module string
	mod    *ir.Module
	err    error
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
		var doc astNode
		if err := dec.Decode(&doc); err != nil {
			out[i].err = fmt.Errorf("py_converter: failed to parse pyast.py output for %s: %w", f, err)
			continue
		}
		if errMsg, ok := doc["error"]; ok {
			out[i].err = fmt.Errorf("py_converter: failed to parse %s: %v", f, errMsg)
			continue
		}
		// Parse phase only: keep the AST; lowering happens in lowerParsed after the
		// global handler-class set is known (lowerAll).
		out[i].doc = doc
		out[i].file = f
		out[i].module = moduleNameFor(root, f)
	}
}

// lowerAll lowers every successfully-parsed result into a gIR Module. It first
// computes the request-handler class set across ALL files (Tornado/Flask handler
// subclassing frequently crosses file boundaries — e.g. ConfigHandler(BaseHandler)
// with BaseHandler(RequestHandler) in another module), so a handler's request
// accessors are seeded as taint sources regardless of where its base class lives.
func lowerAll(results []pyFileResult) {
	handlerSet := globalHandlerClasses(results)
	for i := range results {
		if results[i].err != nil || results[i].doc == nil {
			continue
		}
		results[i].mod = convertModule(results[i].doc, results[i].file, results[i].module, handlerSet)
	}
}

// globalHandlerClasses builds the transitive set of request-handler class names
// (by simple name) across every parsed file, so cross-file subclassing resolves.
func globalHandlerClasses(results []pyFileResult) map[string]bool {
	classBases := map[string][]string{}
	for i := range results {
		if results[i].err != nil || results[i].doc == nil {
			continue
		}
		collectClassBases(results[i].doc.list("body"), classBases)
	}
	return handlerClasses(classBases, handlerBaseClasses)
}

// writeHelperScript materializes the embedded pyast.py into a temp file so it
// can be invoked as `python3 <path> <file.py>`. The caller must invoke the
// returned cleanup function once done.
func writeHelperScript() (string, func(), error) {
	path, cleanup, err := proc.WriteEmbeddedScript("godzilla-pyast-*.py", pyASTScript)
	if err != nil {
		return "", nil, fmt.Errorf("py_converter: %w", err)
	}
	return path, cleanup, nil
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
	name := filepath.ToSlash(strings.TrimSuffix(rel, ".py"))
	// A package's `pkg/__init__.py` IS the module `pkg` in Python; drop the
	// implicit __init__ component so an import of `pkg` (callee "py:pkg.f")
	// resolves to its function's canonical name (see resolveCrossModuleCalls).
	name = strings.TrimSuffix(name, "/__init__")
	if name == "__init__" {
		name = "" // a bare __init__.py scanned at its own dir: the package root
	}
	return name
}

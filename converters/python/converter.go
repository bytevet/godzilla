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
//   - A real control-flow graph IS built, via converters/ssabuild: if/while/for/
//     try get their own basic blocks, and PHIs are inserted on demand (Braun et
//     al.) at the joins. A branch-free body still lowers to exactly one block,
//     which keeps the engine's linear fast path. What remains approximate is
//     exceptions and loop exits: lowerTry models a raise as ONE opaque edge from
//     the try body into a single merged handler block, with no exception typing
//     (every `except` clause's body is lowered into that one block), and `break`
//     /`continue` are dropped rather than re-routed, so a loop's exit edges are
//     the fall-through ones only.
//   - Classes are only partially modeled: methods (`def` inside a `class`)
//     become functions named "<Class>.<method>", but other class-body
//     statements (class attributes, nested classes, decorators) are ignored.
//   - Expression coverage covers calls, attribute/subscript reads, binary/unary
//     and boolean operators, comprehensions, container literals, unpacking
//     assignment, walrus (`:=`), `await`, f-strings, str.format, constants, and
//     names. Lambdas and decorators are not specifically modeled; unhandled
//     expression/statement kinds become an OP_CODE_INTRINSIC "py.unsupported"
//     node (expressions) or are silently dropped (statements), rather than
//     aborting conversion.
package py_converter

import (
	_ "embed"
	"fmt"
	"os/exec"
	"strings"

	"godzilla/converters/frontend"
	"godzilla/internal/irwalk"
	"godzilla/internal/proc"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

//go:embed pyast.py
var pyASTScript []byte

// Converter lowers Python source files/directories into gIR: the shared
// frontend.Driver surface (ConvertFile/ConvertInventory/Skipped) over Python's
// batch hooks (see batch). Requires python3 on PATH.
type Converter struct {
	frontend.Driver[pyFileResult]
}

// NewConverter returns a ready-to-use Python-to-gIR converter.
func NewConverter() *Converter {
	c := &Converter{}
	c.NewBatch = c.batch
	return c
}

// IsPythonFile reports whether path is a Python source file this frontend
// lowers. Exported so internal/scan's language detection and this frontend's
// own file selection share ONE predicate instead of drifting copies.
func IsPythonFile(path string) bool { return strings.HasSuffix(path, ".py") }

// batch builds the shared frontend.Batch driver with Python's hooks. A fresh
// value per conversion: the Setup-resolved interpreter/helper paths are carried
// in closure state private to this batch.
//
// The single-file/directory-batch skeleton is the shared driver; what is
// Python's alone: parsing is batched — one `python3 pyast.py --batch
// <chunk...>` invocation per chunk, so interpreter startup is paid per chunk,
// not per file — lowering waits for every file to parse so the handler-class
// set spans all files (lowerAll), and a directory scan gets cross-module call
// resolution (resolveCrossModuleCalls).
func (c *Converter) batch() *frontend.Batch[pyFileResult] {
	var pythonExe, scriptPath string
	return &frontend.Batch[pyFileResult]{
		Label: "py_converter",
		Lang:  "Python",
		Mode:  "ast",
		Match: IsPythonFile,
		Setup: func() (func(), error) {
			exe, err := exec.LookPath("python3")
			if err != nil {
				return nil, fmt.Errorf("py_converter: python3 not found on PATH (required to parse Python source): %w", err)
			}
			pythonExe = exe
			sp, cleanup, err := writeHelperScript()
			if err != nil {
				return nil, err
			}
			scriptPath = sp
			return cleanup, nil
		},
		Parse: func(root string, files []string, out []pyFileResult) {
			convertPythonChunk(pythonExe, scriptPath, root, files, out)
		},
		// Lower after every file is parsed, so the handler-class set spans all files.
		Finish: lowerAll,
		Result: func(r *pyFileResult) (*ir.Module, error) { return r.mod, r.err },
		PostProgram: func(prog *ir.Program, isDir bool) {
			// Single-file scans have one module and nothing to cross-link.
			if isDir {
				resolveCrossModuleCalls(prog)
			}
		},
	}
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

	// Index every lowered function by its logical dotted path AND by every
	// dot-aligned suffix of it. A path shared by two functions is ambiguous and
	// never used as a rewrite target.
	//
	// Indexing suffixes is what makes resolution independent of WHERE the scan
	// root sits. A module name is relative to the scan root, so scanning a repo
	// whose package lives under `src/` gives functions the logical path
	// `pyload.core.network.request_factory.get_url`, while the import inside that
	// package writes `network.request_factory.get_url`. Matching only full paths
	// against callee suffixes can never bridge that: no suffix of the callee
	// equals the longer function path. Scanning `src/pyload/core` happened to
	// line the two up, so the same code resolved from one root and silently
	// dropped every cross-module call from the other.
	//
	// The suffix walk deliberately stops before the LAST component, so a bare
	// name is never indexed. That preserves the property the resolver relies on:
	// a single-component method callee (`x.execute`) cannot match a function,
	// since every indexed key still carries at least `module.name`.
	rawByLogical := map[string]string{} // logical path (or suffix) -> raw canonical
	ambiguous := map[string]bool{}
	rawSet := map[string]bool{} // every function's raw canonical (exact-resolvable already)
	for _, m := range prog.Modules {
		for _, fn := range m.Functions {
			if fn.CanonicalName == "" {
				continue
			}
			rawSet[fn.CanonicalName] = true
			for s := logical(fn.CanonicalName); strings.IndexByte(s, '.') >= 0; {
				if prev, seen := rawByLogical[s]; seen && prev != fn.CanonicalName {
					ambiguous[s] = true
				} else {
					rawByLogical[s] = fn.CanonicalName
				}
				s = s[strings.IndexByte(s, '.')+1:]
			}
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

	for cc := range irwalk.Calls(prog) {
		callee := cc.GetCallee()
		if callee == "" || rawSet[callee] {
			continue // unset, or already resolves by exact name
		}
		raw := resolve(logical(callee))
		if raw == "" {
			continue
		}
		irwalk.SetCallee(cc, raw)
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
// `pyast.py --batch` invocation (one JSON document per file, argv order) via
// proc.RunBatchScript, writing into out (index-aligned with files). A
// process-level failure marks every file in the chunk; a per-file parse
// failure marks only that file, mirroring the old file-at-a-time error
// semantics.
func convertPythonChunk(pythonExe, scriptPath, root string, files []string, out []pyFileResult) {
	proc.RunBatchScript("py_converter", "pyast.py", pythonExe, scriptPath, files, func(i int, doc any, err error) {
		if err != nil {
			out[i].err = err
			return
		}
		m, ok := doc.(map[string]any)
		if !ok {
			out[i].err = fmt.Errorf("py_converter: failed to parse pyast.py output for %s: unexpected JSON document type %T", files[i], doc)
			return
		}
		// Parse phase only: keep the AST; lowering happens in lowerParsed after the
		// global handler-class set is known (lowerAll).
		out[i].doc = astNode(m)
		out[i].file = files[i]
		out[i].module = moduleNameFor(root, files[i])
	})
}

// lowerAll lowers every successfully-parsed result into a gIR Module. It first
// computes the request-handler class set across ALL files (Tornado/Flask handler
// subclassing frequently crosses file boundaries — e.g. ConfigHandler(BaseHandler)
// with BaseHandler(RequestHandler) in another module), so a handler's request
// accessors are seeded as taint sources regardless of where its base class lives.
func lowerAll(results []pyFileResult) {
	classes := globalRouteClasses(results)
	for i := range results {
		if results[i].err != nil || results[i].doc == nil {
			continue
		}
		results[i].mod = convertModule(results[i].doc, results[i].file, results[i].module, classes)
	}
}

// globalRouteClasses builds both class sets the route tables need, across every
// parsed file: request-handler classes (so cross-file subclassing resolves) and
// dispatch classes (so a class whose methods are split across files still tallies
// its full verb set).
func globalRouteClasses(results []pyFileResult) routeClasses {
	classBases := map[string][]string{}
	verbs := map[string]map[string]bool{}
	for i := range results {
		if results[i].err != nil || results[i].doc == nil {
			continue
		}
		body := results[i].doc.list("body")
		collectClassBases(body, classBases)
		collectDispatchVerbs(body, verbs)
	}
	return routeClasses{
		handler:  handlerClasses(classBases, handlerBaseClasses),
		dispatch: dispatchClasses(verbs, classBases),
	}
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
	name := walkignore.ModuleName(root, file)
	// A package's `pkg/__init__.py` IS the module `pkg` in Python; drop the
	// implicit __init__ component so an import of `pkg` (callee "py:pkg.f")
	// resolves to its function's canonical name (see resolveCrossModuleCalls).
	name = strings.TrimSuffix(name, "/__init__")
	if name == "__init__" {
		name = "" // a bare __init__.py scanned at its own dir: the package root
	}
	return name
}

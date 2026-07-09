// Package js_converter lowers JavaScript source into gIR so the taint engine
// in internal/analysis can analyze it, mirroring the public shape of
// converters/go and converters/python (NewConverter / Converter.ConvertFile)
// and, more specifically, the structural design of converters/python: parse
// with a language-native parser, then lower the AST to gIR with an
// env-based, per-function lowering pass (see lower.go).
//
// Parsing is done with github.com/dop251/goja's pure-Go ECMAScript
// parser/AST (github.com/dop251/goja/parser, .../ast, .../file) -- no cgo, no
// Node.js, no npm, no external process. goja's AST nodes expose source
// positions as file.Idx values, resolved to line/column via a file.FileSet
// (see posForIdx in lower.go), which is why every gIR Instruction/Function
// produced here carries a Pos.
//
// # Lowering model
//
// Every JS function (function declaration, function expression, or arrow
// function) becomes its own ir.Function containing exactly one straight-line
// ir.BasicBlock: like converters/python, this converter does not build a
// control-flow graph. if/for/while/do-while/try/switch/labelled/with bodies
// are flattened into the enclosing block in source order (conditions are
// evaluated for side effects and then dropped, loop bodies execute
// conceptually once). This trades path precision for recall, which is the
// right tradeoff for a taint scanner focused on straight-line handler code.
//
// Top-level statements in a file that are not function declarations are
// collected into one synthetic "<module>" ir.Function per file, the JS
// analogue of converters/python's module-init function.
//
// # The "opaque object" source heuristic
//
// A plain property read like `req.query.name` is not a call in JavaScript,
// but Godzilla's taint engine (internal/analysis) only ever introduces fresh
// taint at an OP_CODE_CALL/OP_CODE_INVOKE instruction whose CallCommon.Callee
// matches a rule's source glob (see taint.go/interproc.go, which this package
// must not modify). To make member-read-based sources like Express's
// `req.query`/`req.params`/`req.body` detectable without touching the
// engine, the FIRST property access off an "opaque" base -- a free/global
// identifier (e.g. `child_process`, `os`), or a function parameter (e.g. a
// route handler's `req`), since in both cases the value's origin is outside
// this function's own straight-line computation -- is lowered as an
// OP_CODE_CALL with a purely syntactic callee ("js:" + base + "." + field),
// exactly as if it were a getter call. Every subsequent hop in the same
// member-access chain (e.g. the trailing `.name` in `req.query.name`) is a
// normal OP_CODE_FIELD/OP_CODE_INDEX with the previous hop's register as
// operand 0, so taint set on the root hop propagates through the rest of the
// chain via the engine's existing FIELD/INDEX taint-propagation rule. See
// funcState.emitRootPropertyRead and funcState.isOpaqueBase in lower.go.
//
// Actual call expressions (`a.b.c(args)`, `f(args)`) always lower to
// OP_CODE_CALL with a purely syntactic dotted Callee built from the call's
// callee expression (Identifier/DotExpression/string-keyed BracketExpression
// chains only; anything else collapses to "<dynamic>"), mirroring
// converters/python's dottedName: the callee name reflects source syntax,
// not a value resolved through the environment. When the callee expression
// itself is or contains another call -- a chained call like
// `axios.get(url).then(cb)` or `foo(x).bar(y)` -- that inner call is lowered
// to its own OP_CODE_CALL first (funcState.lowerNestedCallees in lower.go),
// so its callee/args/taint are visible to the engine even though the outer
// call's own syntactic name still collapses that sub-path to "<dynamic>"
// (e.g. "<dynamic>.then"/"<dynamic>.bar").
//
// # Known limitations
//
//   - No control-flow graph (see above): branches/loops are flattened, and a
//     loop body's taint effects are only modeled for one (conceptual)
//     iteration.
//   - Closures are not modeled: each function's variable environment starts
//     empty (plus its own parameters), so a reference to an enclosing
//     function's or module's local variable always falls back to a
//     GlobalName value, exactly like converters/python's Name fallback. This
//     is why a locally `require()`d module (e.g. `const cp =
//     require('child_process')` at module scope) is still resolved
//     correctly when referenced by name in an unrelated function: callee
//     names are built purely syntactically (see above) and never depend on
//     environment/closure resolution.
//   - Classes are modeled at the method level: collectClass (wired into
//     collectStmt for ClassDeclaration and collectExpr for ClassLiteral) lowers
//     each class method as its own function named "<Class>.<method>", so
//     class-based handlers are analyzed. Only non-method class-body statements
//     (fields/static initializers) remain unmodeled. Function declarations,
//     function expressions, and arrow functions also become ir.Function values.
//   - Destructuring (ObjectPattern/ArrayPattern) binding targets and
//     parameters are not modeled: a destructured declaration's initializer
//     is still lowered (for its side effects / taint discovery) but the
//     bindings it would introduce are dropped.
//   - Promises/async/await/generators are not specially modeled: `await x`
//     and `yield x` lower to `x` itself (the wrapping is a no-op for taint
//     purposes).
//   - Container literals (array/object) collapse every element/property
//     value's taint into one OP_CODE_PHI-merged register rather than
//     tracking per-index/per-key taint.
//   - Logical `&&`/`||`/`??` are approximated as the bitwise BIN_OP_AND /
//     BIN_OP_OR / BIN_OP_OR kinds (there is no logical-op counterpart in
//     gIR's BinOpKind); this is safe for taint propagation (either operand
//     tainted still taints the result) but loses short-circuit semantics.
//   - Only function literals reachable from a statement's top-level
//     expression tree are discovered as separate functions (call arguments,
//     variable initializers, assignment right-hand sides, array/object
//     literal elements, etc. -- see the collector in lower.go). This covers
//     idiomatic patterns like `app.get(url, function(req, res) {...})` and
//     `const f = () => {...}`, but not more exotic placements.
package js_converter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/go-sourcemap/sourcemap"

	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

// Converter lowers JavaScript source files/directories into gIR.
type Converter struct{}

// NewConverter returns a ready-to-use JavaScript-to-gIR converter.
func NewConverter() *Converter {
	return &Converter{}
}

// ConvertFile lowers the JavaScript source at path into gIR. path may be
// either a single .js file or a directory (all *.js files under it are
// converted recursively, one gIR Module per file, skipping any
// "node_modules" directory).
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
			if IsJSFamily(p) && !walkignore.SkipFile(d.Name()) {
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
		return nil, fmt.Errorf("no JavaScript files found under %s", abs)
	}

	// Module names are the file path relative to the scan root, so same-named
	// functions in different files get distinct canonical names instead of
	// colliding in the analyzer. Single-file mode: root is the file's directory,
	// so the module name stays the bare filename.
	root := abs
	if !info.IsDir() {
		root = filepath.Dir(abs)
	}

	// Single-file mode (path pointed directly at a .js file): a parse/read
	// failure is the caller's only signal, so surface it immediately.
	if !info.IsDir() {
		mod, err := c.convertJSFile(files[0], moduleNameFor(root, files[0]))
		if err != nil {
			return nil, err
		}
		return &ir.Program{Mode: "ast", Modules: []*ir.Module{mod}}, nil
	}

	// Directory batch mode: one unparseable .js file must not abort the whole
	// batch (a single syntax error in an unrelated file shouldn't hide every
	// other file's findings). Skip it, log a warning to stderr, and keep
	// going; only fail if not a single file in the tree converted.
	//
	// Files are converted concurrently — the parse (goja), esbuild transform,
	// and lowering are all pure per-file CPU work with no shared state (the
	// Converter is stateless). Results land at fixed indices, so module order
	// stays the sorted file order regardless of completion order.
	type jsFileResult struct {
		mod *ir.Module
		err error
	}
	results := make([]jsFileResult, len(files))
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Add(1)
		go func(i int, f string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mod, err := c.convertJSFile(f, moduleNameFor(root, f))
			results[i] = jsFileResult{mod, err}
		}(i, f)
	}
	wg.Wait()

	prog := &ir.Program{Mode: "ast"}
	var convertErrs []string
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "js_converter: skipping %s: %v\n", files[i], r.err)
			convertErrs = append(convertErrs, r.err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, r.mod)
	}

	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("js_converter: no JavaScript files under %s converted successfully (%d file(s) failed): %s",
			abs, len(convertErrs), strings.Join(convertErrs, "; "))
	}

	return prog, nil
}

// convertJSFile parses a single JavaScript file with goja's parser and lowers
// the resulting AST into one gIR Module.
func (c *Converter) convertJSFile(path, moduleName string) (*ir.Module, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("js_converter: failed to read %s: %w", path, err)
	}

	// Vue/Svelte single-file components are compiled to plain JS by the SFC
	// extractor (script block + template directives as synthetic sink calls);
	// TypeScript / JSX / ES-module files are esbuild-transformed to plain CommonJS
	// JS (goja parses neither TS annotations nor top-level import/export). Both
	// return a sourcemap consumer that remaps positions back to the original file;
	// plain .js skips this entirely. SFCs must be intercepted before the generic
	// transform — esbuild has no .vue/.svelte loader.
	code := string(src)
	var consumer *sourcemap.Consumer
	var dirs []directivePos
	switch {
	case isSFC(path):
		var terr error
		code, consumer, dirs, terr = extractSFCToJS(path, src)
		if terr != nil {
			return nil, fmt.Errorf("js_converter: failed to extract %s: %w", path, terr)
		}
	case needsTransform(path):
		var terr error
		code, consumer, terr = transformToJS(path, src)
		if terr != nil {
			return nil, fmt.Errorf("js_converter: failed to transform %s: %w", path, terr)
		}
	}

	fset := &file.FileSet{}
	astProg, err := parser.ParseFile(fset, path, code, 0)
	if err != nil {
		return nil, fmt.Errorf("js_converter: failed to parse %s: %w", path, err)
	}

	mod := convertModule(astProg, fset, path, moduleName)
	remapPositions(mod, consumer)
	// Relocate template-directive sink findings from the appended synthetic calls
	// back to their positions in the .vue/.svelte template (no-op for non-SFCs).
	applyDirectivePositions(mod, dirs)
	return mod, nil
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
	return filepath.ToSlash(strings.TrimSuffix(rel, filepath.Ext(rel)))
}

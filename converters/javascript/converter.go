// Package js_converter lowers JavaScript source into gIR for the taint engine
// in internal/analysis, following converters/python's structure: parse with a
// language-native parser, then lower the AST per function (lower.go).
//
// Parsing uses github.com/dop251/goja's pure-Go ECMAScript parser -- no cgo, no
// Node.js, no external process. Its file.Idx positions resolve to line/column
// through a file.FileSet (posForIdx), which is how every emitted
// Instruction/Function gets its Pos.
//
// # Lowering model
//
// Every function (declaration, expression, or arrow) becomes its own ir.Function
// with a real CFG -- blocks, preds/succs, on-demand PHI -- built by
// converters/ssabuild. if/else lowers to a PHI-merged diamond; the loop forms
// lower to header/body/exit with a back-edge, so loop-carried taint flows
// through the header PHI; switch becomes a decision cascade with conservative
// case-to-case fall-through; try/catch adds a conservative exception edge. A
// branch-free function still emits exactly one block, keeping the engine's
// linear fast path. Top-level non-function statements collect into one synthetic
// "<module>" function per file.
//
// # The "opaque object" source heuristic
//
// The engine only introduces fresh taint at a CALL/INVOKE whose Callee matches a
// rule's source glob, but Express-style sources (`req.query.name`) are property
// reads, not calls. So the FIRST property access off an *opaque* base -- a
// free/global identifier or a function parameter, whose value originates outside
// this function -- is lowered as a CALL with the syntactic callee
// "js:<base>.<field>", as if it were a getter. Later hops in the chain are
// ordinary FIELD/INDEX instructions, so the engine's existing FIELD/INDEX
// propagation carries taint through the rest. See emitRootPropertyRead and
// isOpaqueBase in lower.go.
//
// Real call expressions lower to CALL with a syntactic dotted Callee built from
// the callee expression (Identifier/DotExpression/string-keyed Bracket chains;
// anything else is "<dynamic>") -- the name reflects source syntax, never a
// value resolved through the environment. A chained call
// (`axios.get(url).then(cb)`) has its inner call lowered first by
// lowerNestedCallees, so the inner callee and args stay visible even though the
// outer name collapses to "<dynamic>.then".
//
// # Known limitations
//
// All are conservative (they can only over-approximate reachable taint):
//
//   - break/continue are imprecise: a switch case falls through to the next, and
//     a labelled loop is lowered as its underlying loop.
//   - Closures are not modeled -- each function's environment starts with only
//     its parameters, so an enclosing scope's local falls back to a GlobalName.
//     A module-scope `require()` still resolves, because callee names are purely
//     syntactic and never consult the environment.
//   - Classes are modeled per method ("<Class>.<method>", via collectClass);
//     only non-method class-body statements (fields, static initializers) are
//     unmodeled.
//   - Destructuring targets and parameters are dropped, though the initializer
//     is still lowered for its side effects and taint.
//   - `await x` / `yield x` lower to `x`; the wrapping is a no-op for taint.
//   - Array/object literals collapse every element's taint into one PHI-merged
//     register rather than tracking it per index/key.
//   - Logical `&&`/`||`/`??` reuse the bitwise BIN_OP kinds (gIR has no logical
//     counterpart), losing short-circuit semantics but not taint.
//   - Only function literals reachable from a statement's top-level expression
//     tree are discovered (see the collector in lower.go) -- enough for
//     `app.get(url, function(req, res){...})` and `const f = () => {...}`, but
//     not more exotic placements.
package js_converter

import (
	"fmt"
	"os"
	"strings"

	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/go-sourcemap/sourcemap"

	"godzilla/internal/chunks"
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
	// Module names are the file path relative to the scan root, so same-named
	// functions in different files get distinct canonical names instead of
	// colliding in the analyzer. For a single file the root is its own
	// directory, so its module name stays the bare filename (see
	// walkignore.CollectTarget).
	root, files, isDir, err := walkignore.CollectTarget(path, IsJSFamily)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no JavaScript files found under %s", root)
	}

	// Single-file mode (path pointed directly at a .js file): a parse/read
	// failure is the caller's only signal, so surface it immediately.
	if !isDir {
		mod, defaultExport, err := c.convertJSFile(files[0], moduleNameFor(root, files[0]))
		if err != nil {
			return nil, err
		}
		prog := &ir.Program{Mode: "ast", Modules: []*ir.Module{mod}}
		resolveJSCrossModuleCalls(prog, map[string]string{mod.Name: defaultExport})
		return prog, nil
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
		mod           *ir.Module
		defaultExport string
		err           error
	}
	results := make([]jsFileResult, len(files))
	chunks.Run(len(files), func(start, end int) {
		for i := start; i < end; i++ {
			mod, defaultExport, err := c.convertJSFile(files[i], moduleNameFor(root, files[i]))
			results[i] = jsFileResult{mod, defaultExport, err}
		}
	})

	prog := &ir.Program{Mode: "ast"}
	// defaultExports maps each module name to its default-export function
	// canonical, so resolveJSCrossModuleCalls can rewrite cross-module markers
	// once every file has been lowered.
	defaultExports := map[string]string{}
	var convertErrs []string
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "js_converter: skipping %s: %v\n", files[i], r.err)
			convertErrs = append(convertErrs, r.err.Error())
			continue
		}
		prog.Modules = append(prog.Modules, r.mod)
		if r.defaultExport != "" {
			defaultExports[r.mod.Name] = r.defaultExport
		}
	}

	if len(prog.Modules) == 0 {
		return nil, fmt.Errorf("js_converter: no JavaScript files under %s converted successfully (%d file(s) failed): %s",
			root, len(convertErrs), strings.Join(convertErrs, "; "))
	}

	resolveJSCrossModuleCalls(prog, defaultExports)

	return prog, nil
}

// crossModuleMarker prefixes a callee emitted for a bare call to a relative-
// require default binding (see funcState.relativeDefaults); the suffix is the
// scan-root-relative module name whose default export is the real callee.
const crossModuleMarker = "js:@mod:"

// resolveJSCrossModuleCalls rewrites every "js:@mod:<module>" marker callee to
// the named module's default-export function canonical name, once all files are
// lowered (the callee may live in a file not yet seen at lowering time). It
// mirrors converters/python's resolveCrossModuleCalls: the engine resolves calls
// by EXACT canonical name, so without this a bare cross-file default-import call
// (`const f = require('./util'); f(x)`) never links and taint stops at the call.
//
// A marker with no single unambiguous default export (module.exports is a
// non-function, an object of named exports, or absent) is stripped back to a
// plain "js:<leaf>" bare name -- exactly what the callee would have been without
// the marker -- so nothing downstream trips on the marker syntax. Only ADDS an
// inter-procedural edge to an unambiguously-named exported function (FP-safe).
func resolveJSCrossModuleCalls(prog *ir.Program, defaultExports map[string]string) {
	setCallee := func(cc *ir.CallCommon, name string) {
		cc.Callee = name
		if fnv := cc.GetValue(); fnv != nil && fnv.GetFuncName() != "" {
			fnv.Kind = &ir.Value_FuncName{FuncName: name}
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
					if !strings.HasPrefix(callee, crossModuleMarker) {
						continue
					}
					modName := strings.TrimPrefix(callee, crossModuleMarker)
					if target := defaultExports[modName]; target != "" {
						setCallee(cc, target)
						continue
					}
					// Unresolved/ambiguous: fall back to a plain bare name.
					leaf := modName
					if i := strings.LastIndexByte(leaf, '/'); i >= 0 {
						leaf = leaf[i+1:]
					}
					setCallee(cc, "js:"+leaf)
				}
			}
		}
	}
}

// convertJSFile parses a single JavaScript file with goja's parser and lowers
// the resulting AST into one gIR Module.
func (c *Converter) convertJSFile(path, moduleName string) (*ir.Module, string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("js_converter: failed to read %s: %w", path, err)
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
			return nil, "", fmt.Errorf("js_converter: failed to extract %s: %w", path, terr)
		}
	case needsTransformSrc(path, src):
		var terr error
		code, consumer, terr = transformToJS(path, src)
		if terr != nil {
			return nil, "", fmt.Errorf("js_converter: failed to transform %s: %w", path, terr)
		}
	}

	fset := &file.FileSet{}
	astProg, err := parser.ParseFile(fset, path, code, 0)
	if err != nil {
		return nil, "", fmt.Errorf("js_converter: failed to parse %s: %w", path, err)
	}

	mod, defaultExport := convertModule(astProg, fset, path, moduleName)
	remapPositions(mod, consumer)
	// Relocate template-directive sink findings from the appended synthetic calls
	// back to their positions in the .vue/.svelte template (no-op for non-SFCs).
	applyDirectivePositions(mod, dirs)
	return mod, defaultExport, nil
}

// moduleNameFor derives a module name unique to the file: its path relative to
// the scan root, extension stripped, slash-normalized (e.g. "ssrf/app"). When
// root is the file's own directory (single-file scans) this is just the bare
// filename.
func moduleNameFor(root, file string) string {
	return walkignore.ModuleName(root, file)
}

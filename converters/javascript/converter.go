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
// A parameter is opaque whether it holds a framework request object or ordinary
// data, and the two want opposite things: the first must INTRODUCE taint (the
// request register is not itself tainted — see internal/analysis/doc.go), the
// second must CARRY the taint it already has. The callee name serves the first;
// the base register, kept in Call.Value and tagged builtin.member_read, serves
// the second. Before that, the base was discarded and reading a property off an
// already-tainted parameter produced a clean register — the shape most request
// data takes once it crosses a function boundary.
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

	"godzilla/converters/frontend"
	"godzilla/internal/irwalk"
	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

// Converter lowers JavaScript source files/directories into gIR: the shared
// frontend.Driver surface (ConvertFile/ConvertInventory/Skipped) over
// JavaScript's batch hooks (see batch). Directory scans skip any
// "node_modules" directory (walkignore).
type Converter struct {
	frontend.Driver[jsFileResult]
}

// NewConverter returns a ready-to-use JavaScript-to-gIR converter.
func NewConverter() *Converter {
	c := &Converter{}
	c.NewBatch = c.batch
	return c
}

// batch builds the shared frontend.Batch driver with JavaScript's hooks. A
// fresh value per conversion: the default-export map is closure state private
// to this batch.
//
// The single-file/directory-batch skeleton is the shared driver. Files convert
// concurrently — the parse (goja), esbuild transform, and lowering are all
// pure per-file CPU work with no shared state (the Converter is stateless).
// What is JavaScript's alone: each file's default export is collected so
// resolveJSCrossModuleCalls can rewrite cross-module markers once every file
// has been lowered.
func (c *Converter) batch() *frontend.Batch[jsFileResult] {
	// defaultExports maps each module name to its default-export function
	// canonical, filled after all files are parsed (Finish).
	defaultExports := map[string]string{}
	return &frontend.Batch[jsFileResult]{
		Label: "js_converter",
		Lang:  "JavaScript",
		Mode:  "ast",
		Match: IsJSFamily,
		Parse: frontend.PerFile(func(root, f string) jsFileResult {
			mod, defaultExport, err := c.convertJSFile(f, moduleNameFor(root, f))
			return jsFileResult{mod, defaultExport, err}
		}),
		Finish: func(results []jsFileResult) {
			for _, r := range results {
				if r.err == nil && r.defaultExport != "" {
					defaultExports[r.mod.Name] = r.defaultExport
				}
			}
		},
		Result: func(r *jsFileResult) (*ir.Module, error) { return r.mod, r.err },
		PostProgram: func(prog *ir.Program, _ bool) {
			resolveJSCrossModuleCalls(prog, defaultExports)
		},
	}
}

// jsFileResult is one file's outcome within a batch conversion.
type jsFileResult struct {
	mod           *ir.Module
	defaultExport string
	err           error
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
	for cc := range irwalk.Calls(prog) {
		callee := cc.GetCallee()
		if !strings.HasPrefix(callee, crossModuleMarker) {
			continue
		}
		modName := strings.TrimPrefix(callee, crossModuleMarker)
		if target := defaultExports[modName]; target != "" {
			irwalk.SetCallee(cc, target)
			continue
		}
		// Unresolved/ambiguous: fall back to a plain bare name.
		leaf := modName
		if i := strings.LastIndexByte(leaf, '/'); i >= 0 {
			leaf = leaf[i+1:]
		}
		irwalk.SetCallee(cc, "js:"+leaf)
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
	// extensions that always need one (.ts/.tsx/.jsx/.mjs/.cjs) are esbuild-
	// transformed to CommonJS up front. Both return a sourcemap consumer that
	// remaps positions back to the original file. SFCs must be intercepted before
	// the generic transform — esbuild has no .vue/.svelte loader.
	//
	// .js takes NEITHER branch here. It is the ambiguous extension — plain script,
	// ES modules, Flow and JSX all ship as .js — so rather than predict the
	// dialect, it goes straight to goja and the parse failure below decides.
	code := string(src)
	var consumer *sourcemap.Consumer
	var dirs []directivePos
	var transformed bool
	switch {
	case isSFC(path):
		var terr error
		code, consumer, dirs, terr = extractSFCToJS(path, src)
		if terr != nil {
			return nil, "", fmt.Errorf("js_converter: failed to extract %s: %w", path, terr)
		}
		transformed = true
	case needsTransform(path):
		var terr error
		code, consumer, terr = transformToJS(path, src)
		if terr != nil {
			return nil, "", fmt.Errorf("js_converter: failed to transform %s: %w", path, terr)
		}
		transformed = true
	}

	fset := &file.FileSet{}
	astProg, err := parser.ParseFile(fset, path, code, 0)
	if err != nil && !transformed {
		// goja could not read it as plain script, so it is one of the other .js
		// dialects: run the loader ladder. Letting the parse failure be the trigger
		// replaced a content sniff (a pair of regexps for import/export over every
		// .js file) that had to PREDICT this, and predicting failed both ways — it
		// missed Flow annotations in a file with no import/export, and its regexps
		// cost 7% of a scan on the common CommonJS file that needed no transform at
		// all. Failing first is exact, and is paid only by files that would
		// otherwise be lost, so it is never worth gating on a size heuristic.
		//
		// If the ladder cannot read it either, goja's original error is the one
		// reported: it describes the file as written.
		if tcode, tconsumer, terr := transformToJS(path, src); terr == nil {
			tfset := &file.FileSet{}
			if tprog, perr := parser.ParseFile(tfset, path, tcode, 0); perr == nil {
				fset, astProg, consumer, err = tfset, tprog, tconsumer, nil
			}
		}
	}
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

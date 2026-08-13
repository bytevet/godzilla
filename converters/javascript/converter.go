// Package js_converter lowers JavaScript source into gIR for the taint engine in
// internal/analysis: parse, then lower the AST per function (lower.go).
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
// Such a read carries BOTH a synthetic callee name and its base register (in
// Call.Value, tagged builtin.member_read), because a parameter is opaque whether
// it holds a framework request object or ordinary data; see emitRootPropertyRead
// for why each is needed.
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
//   - Destructuring ASSIGNMENT targets and (non-handler) destructured parameters
//     are dropped; a destructuring declaration does bind its names, but only for
//     flat identifier patterns.
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

	"github.com/bytevet/godzilla/converters/frontend"
	"github.com/bytevet/godzilla/internal/irwalk"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// Converter lowers JavaScript source files/directories into gIR: the shared
// frontend.Driver surface (ConvertFile/ConvertInventory/Skipped) over
// JavaScript's batch hooks (see batch). Directory scans skip any
// "node_modules" directory (walkignore).
type Converter struct {
	frontend.Driver[jsFileResult]
}

func NewConverter() *Converter {
	c := &Converter{}
	c.NewBatch = c.batch
	return c
}

// batch builds the shared frontend.Batch driver with JavaScript's hooks. A fresh
// value per conversion: the default-export map is closure state private to this
// batch, collected so resolveJSCrossModuleCalls can rewrite cross-module markers
// once every file has been lowered.
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
// lowered (the callee may live in a file not yet seen at lowering time). The
// engine resolves calls by EXACT canonical name, so without this a bare
// cross-file default-import call (`const f = require('./util'); f(x)`) never
// links and taint stops at the call.
//
// A marker with no single unambiguous default export is stripped back to a plain
// "js:<leaf>" bare name -- what the callee would have been without the marker --
// so nothing downstream trips on the marker syntax. This only ever ADDS an
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

	// Vue/Svelte SFCs are compiled to plain JS by the SFC extractor; extensions
	// that always need one (.ts/.tsx/.jsx/.mjs/.cjs) are esbuild-transformed to
	// CommonJS up front. Both return a sourcemap consumer that remaps positions
	// back to the original file. SFCs must be intercepted BEFORE the generic
	// transform — esbuild has no .vue/.svelte loader.
	//
	// .js takes NEITHER branch: it is the ambiguous extension (plain script, ESM,
	// Flow and JSX all ship as .js), so it goes straight to goja and the parse
	// failure below decides.
	code := string(src)
	var consumer *sourcemap.Consumer
	var dirs []directivePos
	var transformed bool
	switch {
	case isSFC(path):
		var terr error
		code, consumer, dirs, terr = extractSFCToJS(path, src, primaryTarget)
		if terr != nil {
			return nil, "", fmt.Errorf("js_converter: failed to extract %s: %w", path, terr)
		}
		transformed = true
	case needsTransform(path):
		var terr error
		code, consumer, terr = transformToJS(path, src, primaryTarget)
		if terr != nil {
			return nil, "", fmt.Errorf("js_converter: failed to transform %s: %w", path, terr)
		}
		transformed = true
	}

	fset := &file.FileSet{}
	astProg, err := parser.ParseFile(fset, path, code, 0)
	if err != nil {
		// goja could not read this, so re-lower and try again. The PARSE FAILURE is
		// the trigger rather than a content sniff, because predicting fails both ways
		// — it misses Flow annotations in a file with no import/export, and it costs
		// every ordinary CommonJS file a scan it did not need. Failing first is exact
		// and is paid only by files that would otherwise be lost, so it needs no size
		// gate.
		//
		// Two things can be wrong, and the rungs answer them in that order: WHICH
		// DIALECT (the loader ladder, inside each attempt) and WHICH ES LEVEL goja can
		// actually spell (fallbackTargets). The level is escalated only here, never up
		// front, so a file that already parses keeps its modern syntax intact.
		//
		// If no rung can be read either, goja's original error is reported: it
		// describes the file as written.
		for _, target := range fallbackTargets(transformed) {
			tcode, tconsumer, tdirs, terr := lowerAt(path, src, target)
			if terr != nil {
				continue
			}
			tfset := &file.FileSet{}
			tprog, perr := parser.ParseFile(tfset, path, tcode, 0)
			if perr != nil {
				continue
			}
			fset, astProg, consumer, err = tfset, tprog, tconsumer, nil
			if tdirs != nil {
				dirs = tdirs
			}
			break
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

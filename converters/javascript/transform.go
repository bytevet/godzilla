package js_converter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/go-sourcemap/sourcemap"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// IsJSFamily reports whether path is a JavaScript-family source file the frontend
// handles. It is the single source of truth for the extension set — the
// converter's own directory walk and internal/scan's dispatch/detection table
// both call it — and is DERIVED from the two predicates that actually decide how
// a file is read (isSFC, needsTransform) plus plain .js, so adding an extension
// to either extends this set automatically rather than leaving a third list to
// forget.
func IsJSFamily(path string) bool {
	return isSFC(path) || needsTransform(path) || strings.ToLower(filepath.Ext(path)) == ".js"
}

// isSFC reports whether path is a component single-file format (Vue/Svelte) that
// needs SFC block extraction — the <script> block plus a template compiled to
// synthetic sink calls — before goja can read it. esbuild has no .vue/.svelte
// loader, so these must NOT take the generic needsTransform path.
func isSFC(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".vue", ".svelte":
		return true
	}
	return false
}

// needsTransform reports whether an extension ALONE is enough to know an esbuild
// preprocessing pass is required — TypeScript type-stripping and/or lowering ES
// modules to CommonJS — before goja (which parses neither TS annotations nor
// top-level import/export) can read it.
//
// It is a fast path, not the decision: .js files also routinely need a transform
// (ES modules, Flow and JSX all ship under that extension), and convertJSFile
// discovers that from goja's own parse failure rather than by predicting it. So a
// false NEGATIVE here costs one doomed parse, never the file.
func needsTransform(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".tsx", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// transformToJS runs esbuild to strip TypeScript types and lower ES modules to
// the CommonJS the lowering already understands, returning the transformed JS
// plus a sourcemap consumer mapping transformed positions back to the original
// file. A build error is returned so the directory merge treats the file as a
// skipped/failed conversion, exactly like a parse error.
func transformToJS(path string, src []byte, target api.Target) (string, *sourcemap.Consumer, error) {
	// Hoisted: converting per rung re-copies the whole source, and a file that
	// fails every rung is exactly the large one.
	code, base := string(src), filepath.Base(path)
	var firstErr error
	for _, loader := range loaderLadder(path) {
		out, cons, err := runESBuild(code, loader, base, target)
		if err == nil {
			return out, cons, nil
		}
		if firstErr == nil {
			firstErr = err // the primary loader's error is the honest one
		}
	}
	// Last rung: Flow. esbuild has no Flow loader and Flow is not valid TypeScript,
	// so no loader recovers these -- the source itself has to change (flowstrip.go).
	// Retrying the WHOLE ladder rather than one loader keeps the dialect question
	// open: a Flow file may also be an ES module or use JSX.
	if stripped, ok := stripFlow(code); ok && stripped != code {
		for _, loader := range loaderLadder(path) {
			if out, cons, err := runESBuild(stripped, loader, base, target); err == nil {
				return out, cons, nil
			}
		}
	}
	return "", nil, firstErr
}

// loaderLadder returns the esbuild loaders to try for path, in order, stopping at
// the first that parses.
//
// An extension is a hint, not a contract: .js in the wild holds plain script, ES
// modules, Flow annotations and JSX. Committing to a guess costs the WHOLE file
// when it is wrong, so this turns "predict the dialect" into "find the one that
// parses" — an unanticipated dialect costs an extra attempt instead. Attempts are
// only ever paid on failure, and a failed esbuild parse is cheap next to losing
// the source. The FIRST loader's error is the one reported, since a later loader
// failing says nothing useful about a file it was never meant to read.
func loaderLadder(path string) []api.Loader {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts":
		return []api.Loader{api.LoaderTS, api.LoaderTSX}
	case ".tsx":
		return []api.Loader{api.LoaderTSX}
	case ".jsx":
		return []api.Loader{api.LoaderJSX, api.LoaderTSX}
	default: // .js / .mjs / .cjs — plain script, ESM, Flow, or JSX
		return []api.Loader{api.LoaderJS, api.LoaderTS, api.LoaderTSX}
	}
}

// esbuildSupported names the constructs esbuild must downlevel because the
// consumer is GOJA, not a browser. Hoisted out of runESBuild so the map is not
// reallocated per transform.
//
// Declaring one costs nothing when it is absent -- esbuild rewrites only what the
// file actually contains -- which is why this is always on rather than a ladder
// rung. Left at ESNext, esbuild counts these as supported and passes them
// through, so the file dies at PARSE time and reads as a broken transform when it
// is really a construct goja cannot spell.
//
// Keyed to goja's gaps rather than to an ES year, because its support is RAGGED:
// it reads ES2022 class fields, private methods and static blocks but not
// ES2018's `for await`. The only year low enough to catch that is ES2017, which
// would also rewrite object spread into a helper and lose the taint through it.
// gojacaps_test.go pins each entry; when a goja bump makes one parse natively the
// test fails and the entry should be REMOVED.
//
// Not here: top-level await. esbuild's Transform API refuses to downlevel it at
// every target and format (it can only emulate TLA while bundling), so declaring
// it unsupported would turn a parse failure into a transform failure without
// rescuing the file.
var esbuildSupported = map[string]bool{
	"dynamic-import": false,
	"decorators":     false, // Ember/Angular `@service`; also covers ES2025 auto-accessors
	"for-await":      false,
	"using":          false,
}

// The ES level esbuild emits. primaryTarget keeps modern syntax intact, since
// goja reads nearly all of it and every downlevel is a chance to lose a flow.
// fallbackTarget is the catch-all rung: it downlevels EVERYTHING above it, which
// is what covers a construct esbuildSupported does not name -- including syntax
// that does not exist yet. It costs precision (object spread becomes a helper
// call taint does not survive), so it is reached only after goja has already
// rejected the primary output, never speculatively.
const (
	primaryTarget  = api.ESNext
	fallbackTarget = api.ES2017
)

// fallbackTargets returns the ES targets to re-lower at when goja cannot read the
// first attempt's output. Each rung re-lowers the ORIGINAL source, so every
// attempt carries its own sourcemap and none are ever composed (flowstrip.go).
func fallbackTargets(transformed bool) []api.Target {
	if transformed {
		return []api.Target{fallbackTarget} // primary already ran
	}
	// A plain .js goja could not read has not been through esbuild at all yet, so
	// the primary target is itself a rung.
	return []api.Target{primaryTarget, fallbackTarget}
}

// lowerAt produces the JS goja will read, at the given ES target: the SFC
// extractor for .vue/.svelte, the loader ladder otherwise. dirs is nil for
// everything but an SFC.
func lowerAt(path string, src []byte, target api.Target) (string, *sourcemap.Consumer, []directivePos, error) {
	if isSFC(path) {
		return extractSFCToJS(path, src, target)
	}
	code, consumer, err := transformToJS(path, src, target)
	return code, consumer, nil, err
}

// runESBuild is the shared esbuild pass behind transformToJS and the SFC
// extractor, so both use identical options. The returned consumer is nil if the
// map is missing or unparseable — non-fatal, positions then stay in transformed
// coordinates.
func runESBuild(code string, loader api.Loader, sourcefile string, target api.Target) (string, *sourcemap.Consumer, error) {
	res := api.Transform(code, api.TransformOptions{
		Loader:      loader,
		Format:      api.FormatCommonJS,
		Target:      target,
		Sourcemap:   api.SourceMapExternal,
		Sourcefile:  sourcefile,
		Supported:   esbuildSupported,
		TsconfigRaw: `{"compilerOptions":{"experimentalDecorators":true}}`,
	})
	if len(res.Errors) > 0 {
		return "", nil, fmt.Errorf("esbuild: %s", res.Errors[0].Text)
	}
	consumer, err := sourcemap.Parse("", res.Map)
	if err != nil {
		consumer = nil
	}
	return string(res.Code), consumer, nil
}

// remapPositions rewrites every Position in a module from transformed (esbuild
// output) coordinates back to the original source. Type-stripping reflows lines
// and source positions are mandatory (CLAUDE.md), so this is required, not
// optional, for TS/ESM files. goja columns are 1-based while sourcemap columns
// are 0-based, hence the -1/+1. Positions that do not map are left unchanged; a
// nil consumer (plain .js, or an unparseable map) is a no-op.
func remapPositions(mod *ir.Module, c *sourcemap.Consumer) {
	if mod == nil || c == nil {
		return
	}
	remap := func(p *ir.Position) {
		if p == nil || p.GetLine() <= 0 {
			return
		}
		if _, _, line, col, ok := c.Source(int(p.GetLine()), int(p.GetColumn())-1); ok && line > 0 {
			p.Line = int32(line)
			p.Column = int32(col + 1)
		}
	}
	for _, g := range mod.Globals {
		if g != nil {
			remap(g.Pos)
		}
	}
	for _, f := range mod.Functions {
		if f == nil {
			continue
		}
		remap(f.Pos)
		for _, b := range f.Blocks {
			if b == nil {
				continue
			}
			for _, in := range b.Instrs {
				if in != nil {
					remap(in.Pos)
				}
			}
		}
	}
}

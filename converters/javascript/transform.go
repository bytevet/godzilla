package js_converter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/go-sourcemap/sourcemap"

	ir "godzilla/pkg/ir/v1"
)

// isJSFamily reports whether path is a JavaScript/TypeScript source file the
// frontend handles: plain JS, TypeScript, JSX/TSX, and the ES-module / CommonJS
// variants.
func isJSFamily(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

// needsTransform reports whether an extension requires an esbuild preprocessing
// pass — TypeScript type-stripping and/or lowering ES modules to CommonJS —
// before goja (which parses neither TS annotations nor top-level import/export)
// can read it. Plain .js takes the fast path with no transform and no sourcemap.
func needsTransform(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".tsx", ".jsx", ".mjs", ".cjs":
		return true
	}
	return false
}

func loaderFor(path string) api.Loader {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts":
		return api.LoaderTS
	case ".tsx":
		return api.LoaderTSX
	case ".jsx":
		return api.LoaderJSX
	default: // .mjs / .cjs
		return api.LoaderJS
	}
}

// transformToJS runs esbuild to strip TypeScript types and lower ES modules to
// CommonJS — which the existing lowering already understands via
// require/exports/module.exports — returning the transformed JS plus a sourcemap
// consumer that maps transformed positions back to the original file. esbuild
// does NOT type-check (it only strips), which keeps it fast, matching the
// project's speed goal. Target ESNext minimizes syntax downleveling so the
// output stays close to source. A build error is returned so the directory
// merge treats the file as a skipped/failed conversion, exactly like a parse
// error.
func transformToJS(path string, src []byte) (string, *sourcemap.Consumer, error) {
	res := api.Transform(string(src), api.TransformOptions{
		Loader:      loaderFor(path),
		Format:      api.FormatCommonJS,
		Target:      api.ESNext,
		Sourcemap:   api.SourceMapExternal,
		Sourcefile:  filepath.Base(path),
		TsconfigRaw: `{"compilerOptions":{"experimentalDecorators":true}}`,
	})
	if len(res.Errors) > 0 {
		return "", nil, fmt.Errorf("esbuild: %s", res.Errors[0].Text)
	}
	// A missing/unparseable map is non-fatal: fall back to transformed positions
	// (still better than not analyzing the file at all).
	consumer, err := sourcemap.Parse("", res.Map)
	if err != nil {
		consumer = nil
	}
	return string(res.Code), consumer, nil
}

// remapPositions rewrites every Position in a module from transformed (esbuild
// output) coordinates back to the original source, using the sourcemap consumer.
// Source positions are mandatory (CLAUDE.md), and type-stripping reflows lines,
// so this remap is required — not optional — for TS/ESM files. goja columns are
// 1-based while sourcemap generated/original columns are 0-based, hence the
// -1/+1. Positions that do not map are left unchanged. A nil consumer (plain
// .js, or a map that failed to parse) is a no-op.
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

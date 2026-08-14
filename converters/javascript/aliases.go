package js_converter

import (
	"path"
	"strings"

	jsast "github.com/bytevet/esbuild-jsast"
)

// collectRequireAliases builds a module-level map from a locally-bound name to
// the canonical module (or module.member) path of the CommonJS module it was
// required from (FE-2). This lets the lowering resolve module-anchored sink
// rules through the ubiquitous Node idioms:
//
//	const cp = require('child_process');  cp.exec(x)      -> child_process.exec
//	const { exec } = require('child_process'); exec(x)    -> child_process.exec
//	const ex = require('child_process').exec; ex(x)       -> child_process.exec
//
// Only top-level require bindings are tracked (the conventional placement);
// relative/local requires (./foo) simply resolve to paths no rule matches.
func collectRequireAliases(f *jsast.File) map[string]string {
	aliases := map[string]string{}
	for _, d := range topLevelDecls(f) {
		mod, member, ok := requireTarget(f, d.ValueOrNil)
		if !ok {
			continue
		}
		// Skip relative/absolute requires: those are the project's OWN modules,
		// already matched by the module-name mechanism (a caller's `db.run` links to
		// the lowered `js:db.run`), and rewriting them breaks that cross-file
		// resolution. Only bare package specifiers are aliased.
		if isRelativeSpecifier(mod) {
			continue
		}
		switch t := d.Binding.Data.(type) {
		case *jsast.BIdentifier:
			canon := mod
			if member != "" {
				canon = mod + "." + member
			}
			aliases[f.NameOf(t.Ref)] = canon
		case *jsast.BObject:
			// `const { exec, spawn } = require('m')` binds each name to m.<name>.
			// Only meaningful for a direct module require (not require().x).
			if member != "" {
				continue
			}
			for _, b := range objectPatternBindings(f, t) {
				aliases[b.Local] = mod + "." + b.Key
			}
		}
	}
	return aliases
}

// collectImportAliases augments the alias table with ES-module imports, which
// bind the same names the require idioms do:
//
//	import cp from 'child_process'          cp    -> child_process
//	import * as cp from 'child_process'     cp    -> child_process
//	import { exec } from 'child_process'    exec  -> child_process.exec
//	import { exec as run } from 'm'         run   -> m.exec
//	import { default as X } from 'm'        X     -> m
//
// `{default as X}` maps to the bare module, not `m.default`: the default export
// IS the module's value to a rule keyed on `js:m*`, and `m.default` matches
// nothing. A side-effect-only import binds no name and contributes nothing.
func collectImportAliases(f *jsast.File, aliases map[string]string) {
	for _, s := range f.Stmts {
		imp, ok := s.Data.(*jsast.SImport)
		if !ok {
			continue
		}
		spec := importPath(f, imp.ImportRecordIndex)
		// A relative import names a project module, resolved by
		// collectRelativeDefaults instead — aliasing it would break that.
		if spec == "" || isRelativeSpecifier(spec) {
			continue
		}
		if imp.DefaultName != nil {
			aliases[f.NameOf(imp.DefaultName.Ref)] = spec
		}
		if imp.StarNameLoc != nil {
			aliases[f.NameOf(imp.NamespaceRef)] = spec
		}
		if imp.Items == nil {
			continue
		}
		for _, it := range *imp.Items {
			local := f.NameOf(it.Name.Ref)
			if it.Alias == "default" {
				aliases[local] = spec
				continue
			}
			aliases[local] = spec + "." + it.Alias
		}
	}
}

// importPath returns the specifier an import record index refers to.
func importPath(f *jsast.File, i uint32) string {
	if int(i) >= len(f.Imports) {
		return ""
	}
	return f.Imports[i]
}

// isRelativeSpecifier reports whether a module specifier names a file rather
// than a package.
func isRelativeSpecifier(spec string) bool {
	return strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/")
}

// requireTarget reports whether e is `require('m')` (member "") or
// `require('m').x` (member "x"), returning the module string and member.
func requireTarget(f *jsast.File, e jsast.Expr) (mod, member string, ok bool) {
	switch v := unwrap(e).Data.(type) {
	case *jsast.ECall:
		if m, ok := requireCallModule(f, v); ok {
			return m, "", true
		}
	case *jsast.EDot:
		if call, ok := unwrap(v.Target).Data.(*jsast.ECall); ok {
			if m, ok := requireCallModule(f, call); ok {
				return m, v.Name, true
			}
		}
	}
	return "", "", false
}

// requireCallModule returns the string-literal module of a `require('m')` call.
func requireCallModule(f *jsast.File, call *jsast.ECall) (string, bool) {
	if name, ok := identName(f, call.Target); !ok || name != "require" || len(call.Args) != 1 {
		return "", false
	}
	if s, ok := unwrap(call.Args[0]).Data.(*jsast.EString); ok {
		return jsast.UTF16ToString(s.Value), true
	}
	return "", false
}

// identityWrappers is the whitelist of memoize/identity higher-order wrappers
// whose single-argument application returns a function that behaves like the
// argument: `const memoizedParse = mem(parse)` makes `memoizedParse(x)`
// equivalent to `parse(x)`. Matched by the callee's TRAILING name, so
// `lodash.memoize`/`_.memoize`/`pMemoize` all match on their last component.
var identityWrappers = map[string]bool{
	"mem":        true,
	"memoize":    true,
	"moize":      true,
	"once":       true,
	"pMemoize":   true,
	"memoizeOne": true,
}

// collectIdentityWrapperAliases augments the alias table in place with
// identity-wrapper bindings: `const X = W(g)` where W's trailing name is a known
// memoize/identity wrapper (see identityWrappers) and g is a single identifier
// records X as an alias for whatever g resolves to (g's own alias if it has one,
// else g itself). resolveRequire then rewrites an `X(...)` call through the
// wrapper to the wrapped function's canonical name, so with
// `parse = require("url").parse`, `const memoizedParse = mem(parse)` makes
// `memoizedParse(url)` resolve to `url.parse`. FP-safe: the wrapper whitelist
// leaves arbitrary `x = f(y)` untouched.
func collectIdentityWrapperAliases(f *jsast.File, aliases map[string]string) {
	for _, d := range topLevelDecls(f) {
		id, ok := d.Binding.Data.(*jsast.BIdentifier)
		if !ok {
			continue
		}
		call, ok := unwrap(d.ValueOrNil).Data.(*jsast.ECall)
		if !ok || len(call.Args) != 1 {
			continue
		}
		if !identityWrappers[calleeTrailingName(f, call.Target)] {
			continue
		}
		arg, ok := identName(f, call.Args[0])
		if !ok {
			continue
		}
		if canon, ok := aliases[arg]; ok {
			arg = canon
		}
		aliases[f.NameOf(id.Ref)] = arg
	}
}

// calleeTrailingName returns the final name component of a call's callee
// expression (`mem` for `mem`, `memoize` for `lodash.memoize`/`_.memoize`), or
// "" for any other callee shape.
func calleeTrailingName(f *jsast.File, e jsast.Expr) string {
	if dot, ok := unwrap(e).Data.(*jsast.EDot); ok {
		return dot.Name
	}
	name, _ := identName(f, e)
	return name
}

// resolveRelativeModule resolves a relative module specifier against the current
// module's name. Both are scan-root-relative, slash-separated paths with the
// extension stripped (matching moduleNameFor), so module "middleware" +
// "./utils/getFilenameFromUrl" -> "utils/getFilenameFromUrl", and module
// "a/b/mod" + "../util" -> "a/util".
//
// Only a MODULE extension is stripped, and it is IsJSFamily that decides — the
// same predicate the walk used to name the target module, so `./Comp.vue` and
// `./util.JS` resolve to the modules those files were actually lowered as.
// Stripping any extension instead would break `./config.prod`, an extensionless
// import of config.prod.js, by resolving it to "config".
func resolveRelativeModule(moduleName, spec string) string {
	if IsJSFamily(spec) {
		spec = strings.TrimSuffix(spec, path.Ext(spec))
	}
	return path.Join(path.Dir(moduleName), spec)
}

// collectRelativeDefaults maps a locally-bound name to the scan-root-relative
// module name of the PROJECT module it was default-imported from:
//
//	const getFilenameFromUrl = require("./utils/getFilenameFromUrl");
//	import getFilenameFromUrl from "./utils/getFilenameFromUrl";
//
// The alias tables deliberately skip relative specifiers, so these default
// bindings are otherwise untracked and a bare call `getFilenameFromUrl(x)`
// lowers to callee "js:getFilenameFromUrl", which never matches the target
// function's real canonical name "js:utils/getFilenameFromUrl.<name>". The
// lowering emits a "js:@mod:<module>" marker for such a call (see lowerCall),
// which resolveJSCrossModuleCalls later rewrites to the module's default export.
func collectRelativeDefaults(f *jsast.File, moduleName string) map[string]string {
	defaults := map[string]string{}
	for _, d := range topLevelDecls(f) {
		id, ok := d.Binding.Data.(*jsast.BIdentifier)
		if !ok {
			continue
		}
		mod, member, ok := requireTarget(f, d.ValueOrNil)
		if !ok || member != "" {
			continue // only a plain `require('./x')`, not require('./x').member
		}
		if !strings.HasPrefix(mod, ".") {
			continue // only relative (project) modules; bare packages are aliases
		}
		defaults[f.NameOf(id.Ref)] = resolveRelativeModule(moduleName, mod)
	}
	for _, s := range f.Stmts {
		imp, ok := s.Data.(*jsast.SImport)
		if !ok || imp.DefaultName == nil {
			continue
		}
		spec := importPath(f, imp.ImportRecordIndex)
		if !strings.HasPrefix(spec, ".") {
			continue
		}
		defaults[f.NameOf(imp.DefaultName.Ref)] = resolveRelativeModule(moduleName, spec)
	}
	return defaults
}

// collectDefaultExport returns a module's default export target as a function
// canonical name, for the cross-module call resolution:
//
//	module.exports = getFilenameFromUrl   -> "js:<mod>.getFilenameFromUrl"
//	module.exports = function foo(){}      -> that function's canonical name
//	export default (x) => ...              -> that arrow's canonical name
//
// It returns "" when there is no default export, when the exported value is not
// a function (e.g. `module.exports = app` or `module.exports = { run }`, which
// resolve via other mechanisms), or when there is more than one default-export
// assignment (ambiguous). localFuncs supplies the canonical name of a top-level
// function referenced by identifier; nameOf supplies it for an inline literal.
func collectDefaultExport(f *jsast.File, localFuncs map[string]string, nameOf map[fnID]string) string {
	found := ""
	count := 0
	record := func(canon string) {
		if canon == "" {
			return
		}
		count++
		found = canon
	}
	for _, s := range f.Stmts {
		switch v := s.Data.(type) {
		case *jsast.SExpr:
			asn, ok := unwrap(v.Value).Data.(*jsast.EBinary)
			if !ok || asn.Op != jsast.BinOpAssign || !isModuleExports(f, asn.Left) {
				continue
			}
			record(functionCanonical(f, unwrap(asn.Right), localFuncs, nameOf))
		case *jsast.SExportDefault:
			switch inner := v.Value.Data.(type) {
			case *jsast.SExpr:
				record(functionCanonical(f, unwrap(inner.Value), localFuncs, nameOf))
			case *jsast.SFunction:
				record(nameOf[fnID(inner)])
			}
		}
	}
	if count != 1 {
		return "" // none, or ambiguous
	}
	return found
}

// functionCanonical resolves an exported value to a function canonical name: a
// bare identifier through the top-level function table, an inline literal
// through the collector's node map. Anything else yields "".
func functionCanonical(f *jsast.File, e jsast.Expr, localFuncs map[string]string, nameOf map[fnID]string) string {
	switch v := e.Data.(type) {
	case *jsast.EIdentifier:
		return localFuncs[f.NameOf(v.Ref)]
	case *jsast.EImportIdentifier:
		return localFuncs[f.NameOf(v.Ref)]
	case *jsast.EFunction:
		return nameOf[fnID(v)]
	case *jsast.EArrow:
		return nameOf[fnID(v)]
	}
	return ""
}

func isModuleExports(f *jsast.File, e jsast.Expr) bool {
	dot, ok := unwrap(e).Data.(*jsast.EDot)
	if !ok || dot.Name != "exports" {
		return false
	}
	base, ok := identName(f, dot.Target)
	return ok && base == "module"
}

// topLevelDecls flattens the declarators of every top-level var/let/const
// declaration in a module body (the conventional placement for require idioms).
func topLevelDecls(f *jsast.File) []jsast.Decl {
	var out []jsast.Decl
	for _, s := range f.Stmts {
		if v, ok := s.Data.(*jsast.SLocal); ok {
			out = append(out, v.Decls...)
		}
	}
	return out
}

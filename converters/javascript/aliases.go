package js_converter

import (
	"path"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
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
func collectRequireAliases(body []ast.Statement) map[string]string {
	aliases := map[string]string{}
	for _, b := range topLevelBindings(body) {
		mod, member, ok := requireTarget(b.Initializer)
		if !ok {
			continue
		}
		// Skip relative/absolute requires (./db, ../x, /abs): those are the
		// project's OWN modules, whose functions are lowered and already matched
		// by the module-name mechanism (a caller's `db.run` links to the lowered
		// `js:db.run`). Rewriting them would break that cross-file resolution.
		// Only bare package specifiers (child_process, express, …) are aliased.
		if strings.HasPrefix(mod, ".") || strings.HasPrefix(mod, "/") {
			continue
		}
		switch t := b.Target.(type) {
		case *ast.Identifier:
			canon := mod
			if member != "" {
				canon = mod + "." + member
			}
			aliases[string(t.Name)] = canon
		case *ast.ObjectPattern:
			// `const { exec, spawn } = require('m')` binds each name to m.<name>.
			// Only meaningful for a direct module require (not require().x).
			if member != "" {
				continue
			}
			for _, p := range t.Properties {
				switch prop := p.(type) {
				case *ast.PropertyShort:
					aliases[string(prop.Name.Name)] = mod + "." + string(prop.Name.Name)
				case *ast.PropertyKeyed:
					if id, ok := prop.Value.(*ast.Identifier); ok {
						aliases[string(id.Name)] = mod + "." + propertyKeyName(prop.Key)
					}
				}
			}
		}
	}
	return aliases
}

// requireTarget reports whether e is `require('m')` (member "") or
// `require('m').x` (member "x"), returning the module string and member.
func requireTarget(e ast.Expression) (mod, member string, ok bool) {
	switch v := e.(type) {
	case *ast.CallExpression:
		if m, ok := requireCallModule(v); ok {
			return m, "", true
		}
	case *ast.DotExpression:
		if call, ok := v.Left.(*ast.CallExpression); ok {
			if m, ok := requireCallModule(call); ok {
				return m, string(v.Identifier.Name), true
			}
		}
	}
	return "", "", false
}

// requireCallModule returns the string-literal module of a `require('m')` call.
func requireCallModule(call *ast.CallExpression) (string, bool) {
	id, ok := call.Callee.(*ast.Identifier)
	if !ok || string(id.Name) != "require" || len(call.ArgumentList) != 1 {
		return "", false
	}
	if sl, ok := call.ArgumentList[0].(*ast.StringLiteral); ok {
		return string(sl.Value), true
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

// collectIdentityWrapperAliases augments the require-alias table in place with
// identity-wrapper bindings: `const X = W(g)` where W's trailing name is a known
// memoize/identity wrapper (see identityWrappers) and g is a single Identifier
// records X as an alias for whatever g resolves to (g's own require alias if it
// has one, else g itself). resolveRequire then rewrites an `X(...)` call through
// the wrapper to the wrapped function's canonical name, so
// webpack-dev-middleware's `const memoizedParse = mem(parse)` (parse =
// require("url").parse) makes `memoizedParse(url)` resolve to `url.parse`.
// FP-safe: the wrapper whitelist leaves arbitrary `x = f(y)` untouched.
func collectIdentityWrapperAliases(body []ast.Statement, aliases map[string]string) {
	for _, b := range topLevelBindings(body) {
		id, ok := b.Target.(*ast.Identifier)
		if !ok {
			continue
		}
		call, ok := b.Initializer.(*ast.CallExpression)
		if !ok || len(call.ArgumentList) != 1 {
			continue
		}
		if !identityWrappers[calleeTrailingName(call.Callee)] {
			continue
		}
		arg, ok := call.ArgumentList[0].(*ast.Identifier)
		if !ok {
			continue
		}
		resolved := string(arg.Name)
		if canon, ok := aliases[resolved]; ok {
			resolved = canon
		}
		aliases[string(id.Name)] = resolved
	}
}

// calleeTrailingName returns the final name component of a call's callee
// expression (`mem` for `mem`, `memoize` for `lodash.memoize`/`_.memoize`), or
// "" for any other callee shape.
func calleeTrailingName(e ast.Expression) string {
	switch v := e.(type) {
	case *ast.Identifier:
		return string(v.Name)
	case *ast.DotExpression:
		return string(v.Identifier.Name)
	}
	return ""
}

// jsFamilyExts are the module extensions stripped when resolving a relative
// require specifier to a scan-root-relative module name (matching moduleNameFor,
// which strips the source file's own extension).
var jsFamilyExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".jsx": true,
}

// resolveRelativeModule resolves a relative require specifier against the
// current module's name. Both are scan-root-relative, slash-separated paths with
// the extension stripped (matching moduleNameFor), so module "middleware" +
// "./utils/getFilenameFromUrl" -> "utils/getFilenameFromUrl", and module
// "a/b/mod" + "../util" -> "a/util".
func resolveRelativeModule(moduleName, spec string) string {
	if ext := path.Ext(spec); jsFamilyExts[ext] {
		spec = strings.TrimSuffix(spec, ext)
	}
	return path.Join(path.Dir(moduleName), spec)
}

// collectRelativeDefaults maps a locally-bound name to the scan-root-relative
// module name of the PROJECT module it was default-imported from via a plain
// relative require:
//
//	const getFilenameFromUrl = require("./utils/getFilenameFromUrl");
//
// collectRequireAliases deliberately skips relative requires, so these default
// bindings are otherwise untracked and a bare call `getFilenameFromUrl(x)`
// lowers to callee "js:getFilenameFromUrl", which never matches the target
// function's real canonical name "js:utils/getFilenameFromUrl.<name>". The
// lowering emits a "js:@mod:<module>" marker for such a call (see lowerCall),
// which resolveJSCrossModuleCalls later rewrites to the module's default export.
func collectRelativeDefaults(body []ast.Statement, moduleName string) map[string]string {
	defaults := map[string]string{}
	for _, b := range topLevelBindings(body) {
		id, ok := b.Target.(*ast.Identifier)
		if !ok {
			continue
		}
		mod, member, ok := requireTarget(b.Initializer)
		if !ok || member != "" {
			continue // only a plain `require('./x')`, not require('./x').member
		}
		if !strings.HasPrefix(mod, ".") {
			continue // only relative (project) requires; bare packages are aliases
		}
		defaults[string(id.Name)] = resolveRelativeModule(moduleName, mod)
	}
	return defaults
}

// collectDefaultExport returns a module's CommonJS default export target as a
// function canonical name, for the cross-module call resolution:
//
//	module.exports = getFilenameFromUrl   -> "js:<mod>.getFilenameFromUrl"
//	module.exports = function foo(){}      -> that function's canonical name
//	module.exports = (x) => ...            -> that arrow's canonical name
//
// It returns "" when there is no default export, when the exported value is not
// a function (e.g. `module.exports = app` or `module.exports = { run }`, which
// resolve via other mechanisms), or when there is more than one default-export
// assignment (ambiguous). localFuncs supplies the canonical name of a top-level
// function referenced by identifier; nameOf supplies it for an inline literal.
func collectDefaultExport(body []ast.Statement, localFuncs map[string]string, nodeNames map[ast.Node]string) string {
	found := ""
	count := 0
	for _, s := range body {
		es, ok := s.(*ast.ExpressionStatement)
		if !ok {
			continue
		}
		asn, ok := es.Expression.(*ast.AssignExpression)
		if !ok || asn.Operator != token.ASSIGN || !isModuleExports(asn.Left) {
			continue
		}
		canon := ""
		switch rhs := asn.Right.(type) {
		case *ast.Identifier:
			canon = localFuncs[string(rhs.Name)]
		case *ast.FunctionLiteral:
			canon = nodeNames[rhs]
		case *ast.ArrowFunctionLiteral:
			canon = nodeNames[rhs]
		}
		if canon == "" {
			continue // module.exports = <non-function>
		}
		count++
		found = canon
	}
	if count != 1 {
		return "" // none, or ambiguous
	}
	return found
}

// isModuleExports reports whether an assignment target is `module.exports`.
func isModuleExports(e ast.Expression) bool {
	dot, ok := e.(*ast.DotExpression)
	if !ok || string(dot.Identifier.Name) != "exports" {
		return false
	}
	base, ok := dot.Left.(*ast.Identifier)
	return ok && string(base.Name) == "module"
}

// topLevelBindings flattens the bindings of every top-level var/let/const
// declaration in a module body (the conventional placement for require idioms).
func topLevelBindings(body []ast.Statement) []*ast.Binding {
	var out []*ast.Binding
	for _, s := range body {
		switch v := s.(type) {
		case *ast.VariableStatement:
			out = append(out, v.List...)
		case *ast.LexicalDeclaration:
			out = append(out, v.List...)
		}
	}
	return out
}

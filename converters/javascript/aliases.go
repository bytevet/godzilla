package js_converter

import (
	"strings"

	"github.com/dop251/goja/ast"
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
	for _, s := range body {
		var bindings []*ast.Binding
		switch v := s.(type) {
		case *ast.VariableStatement:
			bindings = v.List
		case *ast.LexicalDeclaration:
			bindings = v.List
		default:
			continue
		}
		for _, b := range bindings {
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

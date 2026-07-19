package js_converter

import (
	"strconv"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"

	ir "godzilla/pkg/ir/v1"
)

// pendingFunc is a function AST node discovered by the collector, queued for
// lowering into its own ir.Function once every function in the file has been
// discovered and named.
type pendingFunc struct {
	// node is either *ast.FunctionLiteral (function declaration or function
	// expression) or *ast.ArrowFunctionLiteral.
	node       ast.Node
	qualname   string
	objectName string
}

// collector walks a file's AST once, before any lowering happens, to find
// every function declaration / function expression / arrow function
// reachable from a statement's top-level expression tree (see the package
// doc comment for the exact coverage) and assign each one a qualified name
// and canonical name, mirroring converters/python's convertModule.collect.
//
// Unlike Python (where `def` only ever appears as a statement), JS functions
// are frequently expression values (`const f = function(){}`,
// `app.get(url, function(req,res){...})`), so collection here also walks
// expression trees, not just statement lists.
type collector struct {
	moduleName string
	anonSeq    map[string]int
	nameOf     map[ast.Node]string // node -> canonical name ("js:<module>.<qualname>")
	order      []pendingFunc
	handlers   map[ast.Node]bool // function nodes registered as HTTP route handlers
}

func newCollector(moduleName string) *collector {
	return &collector{
		moduleName: moduleName,
		anonSeq:    map[string]int{},
		nameOf:     map[ast.Node]string{},
		handlers:   map[ast.Node]bool{},
	}
}

// routingVerbs are the HTTP-router methods whose function argument is a request
// handler (Express/Koa/Fastify/Hapi: app.get/post/put/…/use, router.METHOD).
// A handler's FIRST parameter is the framework request object regardless of its
// name, so lowering can bind property reads off it as request-taint sources even
// when it is not named the conventional `req`/`request`/`ctx` — the JS analogue
// of the Python route-handler-parameter source (COV-11).
var routingVerbs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "options": true, "all": true, "use": true,
}

// parentLabel derives the "<parent>" component of an anonymous function's
// name from the enclosing qualname prefix (e.g. "outer." -> "outer"; "" (top
// level) -> "<module>").
func parentLabel(qualPrefix string) string {
	if qualPrefix == "" {
		return "<module>"
	}
	return qualPrefix[:len(qualPrefix)-1] // trim trailing "."
}

// nextAnon returns the next "<parent>$anon<N>" name for an anonymous
// function found directly within qualPrefix's scope.
func (c *collector) nextAnon(qualPrefix string) string {
	label := parentLabel(qualPrefix)
	n := c.anonSeq[label]
	c.anonSeq[label]++
	return label + "$anon" + strconv.Itoa(n)
}

// bindingName returns the plain identifier name of a binding target, or ""
// if the target is a destructuring pattern (unsupported; see package doc).
func bindingName(t ast.BindingTarget) string {
	if id, ok := t.(*ast.Identifier); ok {
		return string(id.Name)
	}
	return ""
}

// addFunctionLiteral registers a function declaration or function expression
// node under qualname, records its canonical name, and recurses into its
// body to find nested functions.
func (c *collector) addFunctionLiteral(lit *ast.FunctionLiteral, qualname string) {
	c.nameOf[lit] = "js:" + c.moduleName + "." + qualname
	c.order = append(c.order, pendingFunc{node: lit, qualname: qualname, objectName: leafName(qualname)})
	if lit.Body != nil {
		c.collectStmts(lit.Body.List, qualname+".")
	}
}

// addArrow registers an arrow function node under qualname, records its
// canonical name, and recurses into its body (block or concise-expression
// form) to find nested functions.
func (c *collector) addArrow(fn *ast.ArrowFunctionLiteral, qualname string) {
	c.nameOf[fn] = "js:" + c.moduleName + "." + qualname
	c.order = append(c.order, pendingFunc{node: fn, qualname: qualname, objectName: leafName(qualname)})
	switch body := fn.Body.(type) {
	case *ast.BlockStatement:
		c.collectStmts(body.List, qualname+".")
	case *ast.ExpressionBody:
		c.collectExpr(body.Expression, qualname+".", "")
	}
}

// collectClass registers each method of a class body as its own function under
// "<qualPrefix><ClassName>.<method>", so class-based handlers are analyzed at all
// and `this.method(x)` can resolve to a sibling method (see lowerCall). The class
// name comes from the literal, or fallbackName for an anonymous class bound to a
// name (const C = class {}).
func (c *collector) collectClass(cl *ast.ClassLiteral, qualPrefix, fallbackName string) {
	if cl == nil {
		return
	}
	className := fallbackName
	if cl.Name != nil {
		className = string(cl.Name.Name)
	}
	prefix := qualPrefix
	if className != "" {
		prefix = qualPrefix + className + "."
	}
	for _, el := range cl.Body {
		if md, ok := el.(*ast.MethodDefinition); ok && md.Body != nil {
			if name := propertyKeyName(md.Key); name != "" {
				c.addFunctionLiteral(md.Body, prefix+name)
			}
		}
	}
}

func leafName(qualname string) string {
	if i := strings.LastIndexByte(qualname, '.'); i >= 0 {
		return qualname[i+1:]
	}
	return qualname
}

// collectStmts walks a statement list, recursing into control-flow compounds
// to find nested statements/functions (without changing qualPrefix, since
// blocks/loops/etc. do not introduce a new function scope) and into
// function-defining statements (which do).
func (c *collector) collectStmts(stmts []ast.Statement, qualPrefix string) {
	for _, s := range stmts {
		c.collectStmt(s, qualPrefix)
	}
}

func (c *collector) collectStmt(s ast.Statement, qualPrefix string) {
	switch v := s.(type) {
	case *ast.FunctionDeclaration:
		name := qualPrefix
		if v.Function.Name != nil {
			name += string(v.Function.Name.Name)
		} else {
			name = c.nextAnon(qualPrefix)
		}
		c.addFunctionLiteral(v.Function, name)
	case *ast.VariableStatement:
		c.collectBindings(v.List, qualPrefix)
	case *ast.LexicalDeclaration:
		c.collectBindings(v.List, qualPrefix)
	case *ast.ExpressionStatement:
		c.collectExpr(v.Expression, qualPrefix, "")
	case *ast.ReturnStatement:
		c.collectExpr(v.Argument, qualPrefix, "")
	case *ast.ThrowStatement:
		c.collectExpr(v.Argument, qualPrefix, "")
	case *ast.IfStatement:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Consequent), qualPrefix)
		if v.Alternate != nil {
			c.collectStmts(stmtList(v.Alternate), qualPrefix)
		}
	case *ast.ForStatement:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.ForInStatement:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.ForOfStatement:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.WhileStatement:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.DoWhileStatement:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.BlockStatement:
		c.collectStmts(v.List, qualPrefix)
	case *ast.TryStatement:
		if v.Body != nil {
			c.collectStmts(v.Body.List, qualPrefix)
		}
		if v.Catch != nil && v.Catch.Body != nil {
			c.collectStmts(v.Catch.Body.List, qualPrefix)
		}
		if v.Finally != nil {
			c.collectStmts(v.Finally.List, qualPrefix)
		}
	case *ast.SwitchStatement:
		c.collectExpr(v.Discriminant, qualPrefix, "")
		for _, cs := range v.Body {
			c.collectExpr(cs.Test, qualPrefix, "")
			c.collectStmts(cs.Consequent, qualPrefix)
		}
	case *ast.LabelledStatement:
		c.collectStmts(stmtList(v.Statement), qualPrefix)
	case *ast.WithStatement:
		c.collectExpr(v.Object, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *ast.ClassDeclaration:
		c.collectClass(v.Class, qualPrefix, "")
	default:
		// EmptyStatement, BranchStatement, DebuggerStatement, BadStatement:
		// nothing to collect.
	}
}

// collectBindings walks the initializers of a `var`/`let`/`const` declaration
// list, preferring each binding's target name for an anonymous function
// assigned to it (e.g. `const f = function(){}` names the literal "f").
func (c *collector) collectBindings(list []*ast.Binding, qualPrefix string) {
	for _, b := range list {
		c.collectExpr(b.Initializer, qualPrefix, bindingName(b.Target))
	}
}

// stmtList normalizes a statement that may or may not be a BlockStatement
// (e.g. an `if` consequent, a `for` body) into a flat statement list.
func stmtList(s ast.Statement) []ast.Statement {
	if s == nil {
		return nil
	}
	if b, ok := s.(*ast.BlockStatement); ok {
		return b.List
	}
	return []ast.Statement{s}
}

// collectExpr walks an expression tree looking for FunctionLiteral /
// ArrowFunctionLiteral nodes. preferredName, if non-empty, names an
// anonymous function literal found directly at this call (e.g. the RHS of
// `const f = function(){}` prefers the name "f"); it is not propagated into
// recursive calls.
func (c *collector) collectExpr(e ast.Expression, qualPrefix, preferredName string) {
	if e == nil {
		return
	}
	switch v := e.(type) {
	case *ast.ClassLiteral:
		c.collectClass(v, qualPrefix, preferredName)
	case *ast.FunctionLiteral:
		name := qualPrefix
		switch {
		case v.Name != nil:
			name += string(v.Name.Name)
		case preferredName != "":
			name += preferredName
		default:
			name = c.nextAnon(qualPrefix)
		}
		c.addFunctionLiteral(v, name)
	case *ast.ArrowFunctionLiteral:
		name := qualPrefix
		if preferredName != "" {
			name += preferredName
		} else {
			name = c.nextAnon(qualPrefix)
		}
		c.addArrow(v, name)
	case *ast.CallExpression:
		c.collectCall(v.Callee, v.ArgumentList, qualPrefix)
	case *ast.NewExpression:
		c.collectCall(v.Callee, v.ArgumentList, qualPrefix)
	case *ast.AssignExpression:
		c.collectExpr(v.Left, qualPrefix, "")
		c.collectExpr(v.Right, qualPrefix, assignTargetName(v.Left))
	case *ast.BinaryExpression:
		c.collectExpr(v.Left, qualPrefix, "")
		c.collectExpr(v.Right, qualPrefix, "")
	case *ast.ConditionalExpression:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectExpr(v.Consequent, qualPrefix, "")
		c.collectExpr(v.Alternate, qualPrefix, "")
	case *ast.SequenceExpression:
		for _, x := range v.Sequence {
			c.collectExpr(x, qualPrefix, "")
		}
	case *ast.ArrayLiteral:
		for _, x := range v.Value {
			c.collectExpr(x, qualPrefix, "")
		}
	case *ast.ObjectLiteral:
		for _, p := range v.Value {
			c.collectExpr(propertyValue(p), qualPrefix, "")
		}
	case *ast.UnaryExpression:
		c.collectExpr(v.Operand, qualPrefix, "")
	case *ast.TemplateLiteral:
		for _, x := range v.Expressions {
			c.collectExpr(x, qualPrefix, "")
		}
	case *ast.DotExpression:
		c.collectExpr(v.Left, qualPrefix, "")
	case *ast.BracketExpression:
		c.collectExpr(v.Left, qualPrefix, "")
		c.collectExpr(v.Member, qualPrefix, "")
	case *ast.SpreadElement:
		c.collectExpr(v.Expression, qualPrefix, "")
	case *ast.YieldExpression:
		c.collectExpr(v.Argument, qualPrefix, "")
	case *ast.AwaitExpression:
		c.collectExpr(v.Argument, qualPrefix, "")
	default:
		// Identifier, literals, ThisExpression, etc: no children to walk.
	}
}

// collectCall walks a call/new expression's callee and argument list for
// nested function literals (shared by the CallExpression and NewExpression
// cases, which are structurally identical here).
func (c *collector) collectCall(callee ast.Expression, args []ast.Expression, qualPrefix string) {
	c.collectExpr(callee, qualPrefix, "")
	// Route-handler registration: `X.<verb>("/path", …, handler)` where <verb> is
	// an HTTP router method, a STRING-LITERAL route path is present, and a function
	// argument is the handler. Record each such function so its request parameter
	// is treated as a taint source (COV-11). Requiring the route-path string keeps
	// same-named non-router calls that take a callback — lodash `_.get(obj, fn)`,
	// Vue `app.use(plugin)` — from being mistaken for a route.
	if dot, ok := callee.(*ast.DotExpression); ok && routingVerbs[string(dot.Identifier.Name)] {
		hasPath, hasFn := false, false
		for _, a := range args {
			switch a.(type) {
			case *ast.StringLiteral:
				hasPath = true
			case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
				hasFn = true
			}
		}
		if hasPath && hasFn {
			for _, a := range args {
				switch a.(type) {
				case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
					c.handlers[a] = true
				}
			}
		}
	}
	for _, a := range args {
		c.collectExpr(a, qualPrefix, "")
	}
}

// assignTargetName returns the plain identifier name of an assignment's
// left-hand side, used to prefer that name for an anonymous function
// assigned to it (e.g. `handler = function(){}`).
func assignTargetName(left ast.Expression) string {
	if id, ok := left.(*ast.Identifier); ok {
		return string(id.Name)
	}
	return ""
}

// propertyValue extracts the value expression from an object literal
// property (keyed, shorthand, or spread).
func propertyValue(p ast.Property) ast.Expression {
	switch pv := p.(type) {
	case *ast.PropertyKeyed:
		return pv.Value
	case *ast.PropertyShort:
		if pv.Initializer != nil {
			return pv.Initializer
		}
		return &pv.Name
	case *ast.SpreadElement:
		return pv.Expression
	}
	return nil
}

// convertModule turns one parsed JavaScript file into a gIR Module. Every
// function declaration / function expression / arrow function discovered by
// the collector becomes its own ir.Function; the file's top-level statements
// (excluding function bodies, which are lowered separately) become one
// synthetic "<module>" ir.Function, mirroring converters/python.
func convertModule(prog *ast.Program, fset *file.FileSet, filename, moduleName string) (*ir.Module, string) {
	mod := &ir.Module{
		Name:     moduleName,
		Language: "javascript",
	}

	c := newCollector(moduleName)
	c.collectStmts(prog.Body, "")

	// Top-level named functions: a bare call to one (helper(x)) must resolve to
	// its canonical name so byKey matches and taint flows through the local
	// helper. Nested functions (qualname contains ".") and anonymous ones
	// ("$anon") are excluded — the straight-line lowering does not model JS
	// lexical scoping.
	localFuncs := map[string]string{}
	for _, pf := range c.order {
		if !strings.Contains(pf.qualname, ".") && !strings.Contains(pf.qualname, "$anon") {
			localFuncs[pf.qualname] = "js:" + moduleName + "." + pf.qualname
		}
	}

	// Module-level require-alias table for FE-2 (cp.exec -> child_process.exec),
	// augmented with identity/memoize-wrapper aliases (memoizedParse -> url.parse).
	moduleAliases := collectRequireAliases(prog.Body)
	collectIdentityWrapperAliases(prog.Body, moduleAliases)

	// Relative-require default bindings (const f = require('./util')) so a bare
	// call f(x) becomes a cross-module marker resolved after all files lower.
	relativeDefaults := collectRelativeDefaults(prog.Body, moduleName)

	// This module's default export (module.exports = <fn>), the rewrite target
	// for a "js:@mod:<thisModule>" marker in some other file.
	defaultExport := collectDefaultExport(prog.Body, localFuncs, c.nameOf)

	var functions []*ir.Function
	for _, pf := range c.order {
		functions = append(functions, lowerFunction(pf, filename, moduleName, fset, c.nameOf, localFuncs, moduleAliases, relativeDefaults, c.handlers))
	}

	moduleFn := &ir.Function{
		Name:          moduleName + ".<module>",
		ObjectName:    "<module>",
		PackageName:   moduleName,
		CanonicalName: "js:" + moduleName + ".<module>",
		Synthetic:     true,
	}
	fs := newFuncState(filename, fset, c.nameOf, localFuncs)
	fs.moduleName = moduleName
	fs.moduleAliases = moduleAliases
	fs.relativeDefaults = relativeDefaults
	fs.lowerBody(prog.Body)
	moduleFn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}

	mod.Functions = append([]*ir.Function{moduleFn}, functions...)
	return mod, defaultExport
}

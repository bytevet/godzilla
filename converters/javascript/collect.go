package js_converter

import (
	"strconv"
	"strings"

	jsast "github.com/bytevet/esbuild-jsast"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// pendingFunc is a function AST node discovered by the collector, queued for
// lowering into its own ir.Function once every function in the file has been
// discovered and named. loc is carried here because an esbuild node holds no
// position of its own — only the Expr/Stmt wrapper reached it does.
type pendingFunc struct {
	node       fnID
	loc        jsast.Loc
	qualname   string
	objectName string
}

// collector walks a file's AST once, before any lowering, to find every function
// declaration / function expression / arrow function reachable from a statement's
// top-level expression tree (the package doc has the exact coverage) and assign
// each a qualified and canonical name. It walks EXPRESSION trees as well as
// statement lists, because JS functions are frequently expression values
// (`const f = function(){}`, `app.get(url, function(req,res){...})`).
type collector struct {
	src        *jsast.File
	moduleName string
	anonSeq    map[string]int
	nameOf     map[fnID]string // node -> canonical name ("js:<module>.<qualname>")
	order      []pendingFunc
	handlers   map[fnID]bool // function nodes registered as HTTP route handlers
}

func newCollector(src *jsast.File, moduleName string) *collector {
	return &collector{
		src:        src,
		moduleName: moduleName,
		anonSeq:    map[string]int{},
		nameOf:     map[fnID]string{},
		handlers:   map[fnID]bool{},
	}
}

// routingVerbs are the HTTP-router methods whose function argument is a request
// handler (Express/Koa/Fastify/Hapi: app.get/post/put/…/use, router.METHOD). A
// handler's FIRST parameter is the framework request object regardless of its
// name, which is what lets lowering treat property reads off it as request-taint
// sources even when it is not named `req`/`request`/`ctx` (COV-11).
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
func bindingName(f *jsast.File, b jsast.Binding) string {
	if id, ok := b.Data.(*jsast.BIdentifier); ok {
		return f.NameOf(id.Ref)
	}
	return ""
}

// addFunction registers one function node under qualname, records its canonical
// name, and recurses into its body to find nested functions.
//
// The idempotence guard is load-bearing: the same node is reachable through more
// than one walk (an exported declaration, a default export's inner statement),
// and registering it twice would emit two ir.Functions with the same canonical
// name.
func (c *collector) addFunction(node fnID, loc jsast.Loc, qualname string, body []jsast.Stmt) {
	if _, seen := c.nameOf[node]; seen {
		return
	}
	c.nameOf[node] = "js:" + c.moduleName + "." + qualname
	c.order = append(c.order, pendingFunc{node: node, loc: loc, qualname: qualname, objectName: leafName(qualname)})
	c.collectStmts(body, qualname+".")
}

// collectClass registers each method of a class body as its own function under
// "<qualPrefix><ClassName>.<method>", so class-based handlers are analyzed at all
// and `this.method(x)` can resolve to a sibling method (see lowerCall). The class
// name comes from the class itself, or fallbackName for an anonymous class bound
// to a name (const C = class {}).
func (c *collector) collectClass(cl jsast.Class, qualPrefix, fallbackName string) {
	className := fallbackName
	if cl.Name != nil {
		className = c.src.NameOf(cl.Name.Ref)
	}
	prefix := qualPrefix
	if className != "" {
		prefix = qualPrefix + className + "."
	}
	for _, p := range cl.Properties {
		if !p.Kind.IsMethodDefinition() {
			continue
		}
		fn, ok := unwrap(p.ValueOrNil).Data.(*jsast.EFunction)
		if !ok {
			continue
		}
		if name := propertyKeyName(p.Key); name != "" {
			c.addFunction(fn, p.ValueOrNil.Loc, prefix+name, fn.Fn.Body.Block.Stmts)
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
func (c *collector) collectStmts(stmts []jsast.Stmt, qualPrefix string) {
	for _, s := range stmts {
		c.collectStmt(s, qualPrefix)
	}
}

func (c *collector) collectStmt(s jsast.Stmt, qualPrefix string) {
	switch v := s.Data.(type) {
	case *jsast.SFunction:
		name := qualPrefix
		if v.Fn.Name != nil {
			name += c.src.NameOf(v.Fn.Name.Ref)
		} else {
			name = c.nextAnon(qualPrefix)
		}
		c.addFunction(v, s.Loc, name, v.Fn.Body.Block.Stmts)
	case *jsast.SLocal:
		for _, d := range v.Decls {
			c.collectExpr(d.ValueOrNil, qualPrefix, bindingName(c.src, d.Binding))
		}
	case *jsast.SExpr:
		c.collectExpr(v.Value, qualPrefix, "")
	case *jsast.SReturn:
		c.collectExpr(v.ValueOrNil, qualPrefix, "")
	case *jsast.SThrow:
		c.collectExpr(v.Value, qualPrefix, "")
	case *jsast.SIf:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Yes), qualPrefix)
		c.collectStmts(stmtList(v.NoOrNil), qualPrefix)
	case *jsast.SFor:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SForIn:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SForOf:
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SWhile:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SDoWhile:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SBlock:
		c.collectStmts(v.Stmts, qualPrefix)
	case *jsast.STry:
		c.collectStmts(v.Block.Stmts, qualPrefix)
		if v.Catch != nil {
			c.collectStmts(v.Catch.Block.Stmts, qualPrefix)
		}
		if v.Finally != nil {
			c.collectStmts(v.Finally.Block.Stmts, qualPrefix)
		}
	case *jsast.SSwitch:
		c.collectExpr(v.Test, qualPrefix, "")
		for _, cs := range v.Cases {
			c.collectExpr(cs.ValueOrNil, qualPrefix, "")
			c.collectStmts(cs.Body, qualPrefix)
		}
	case *jsast.SLabel:
		c.collectStmts(stmtList(v.Stmt), qualPrefix)
	case *jsast.SWith:
		c.collectExpr(v.Value, qualPrefix, "")
		c.collectStmts(stmtList(v.Body), qualPrefix)
	case *jsast.SClass:
		c.collectClass(v.Class, qualPrefix, "")
	case *jsast.SExportDefault:
		// The export is a wrapper around an ordinary declaration or expression;
		// its DefaultName is the only name an anonymous default has.
		c.collectDefaultExportStmt(v, qualPrefix)
	case *jsast.SExportEquals:
		c.collectExpr(v.Value, qualPrefix, "")
	default:
		// SEmpty, SBreak, SContinue, SDebugger, SImport and the remaining export
		// forms: nothing to collect.
	}
}

// collectDefaultExportStmt names what `export default` wraps. A declaration is
// collected as itself; a bare expression prefers the parser-assigned default
// name, so an anonymous `export default (req, res) => {}` is not an $anon.
func (c *collector) collectDefaultExportStmt(v *jsast.SExportDefault, qualPrefix string) {
	if e, ok := v.Value.Data.(*jsast.SExpr); ok {
		c.collectExpr(e.Value, qualPrefix, c.src.NameOf(v.DefaultName.Ref))
		return
	}
	c.collectStmt(v.Value, qualPrefix)
}

// stmtList normalizes a statement that may or may not be a block (e.g. an `if`
// consequent, a `for` body) into a flat statement list.
func stmtList(s jsast.Stmt) []jsast.Stmt {
	if s.Data == nil {
		return nil
	}
	if b, ok := s.Data.(*jsast.SBlock); ok {
		return b.Stmts
	}
	return []jsast.Stmt{s}
}

// collectExpr walks an expression tree looking for function/arrow nodes.
// preferredName, if non-empty, names an anonymous function literal found
// directly at this call (e.g. the RHS of `const f = function(){}` prefers the
// name "f"); it is not propagated into recursive calls.
func (c *collector) collectExpr(e jsast.Expr, qualPrefix, preferredName string) {
	e = unwrap(e)
	if e.Data == nil {
		return
	}
	switch v := e.Data.(type) {
	case *jsast.EClass:
		c.collectClass(v.Class, qualPrefix, preferredName)
	case *jsast.EFunction:
		name := qualPrefix
		switch {
		case v.Fn.Name != nil:
			name += c.src.NameOf(v.Fn.Name.Ref)
		case preferredName != "":
			name += preferredName
		default:
			name = c.nextAnon(qualPrefix)
		}
		c.addFunction(v, e.Loc, name, v.Fn.Body.Block.Stmts)
	case *jsast.EArrow:
		name := qualPrefix
		if preferredName != "" {
			name += preferredName
		} else {
			name = c.nextAnon(qualPrefix)
		}
		c.addFunction(v, e.Loc, name, v.Body.Block.Stmts)
	case *jsast.ECall:
		c.collectCall(v.Target, v.Args, qualPrefix)
	case *jsast.ENew:
		c.collectCall(v.Target, v.Args, qualPrefix)
	case *jsast.EBinary:
		if isAssignOp(v.Op) {
			c.collectExpr(v.Left, qualPrefix, "")
			c.collectExpr(v.Right, qualPrefix, c.assignTargetName(v.Left))
			return
		}
		c.collectExpr(v.Left, qualPrefix, "")
		c.collectExpr(v.Right, qualPrefix, "")
	case *jsast.EIf:
		c.collectExpr(v.Test, qualPrefix, "")
		c.collectExpr(v.Yes, qualPrefix, "")
		c.collectExpr(v.No, qualPrefix, "")
	case *jsast.EArray:
		for _, x := range v.Items {
			c.collectExpr(x, qualPrefix, "")
		}
	case *jsast.EObject:
		for _, p := range v.Properties {
			c.collectExpr(p.ValueOrNil, qualPrefix, "")
			c.collectExpr(p.InitializerOrNil, qualPrefix, "")
		}
	case *jsast.EUnary:
		c.collectExpr(v.Value, qualPrefix, "")
	case *jsast.ETemplate:
		for _, p := range v.Parts {
			c.collectExpr(p.Value, qualPrefix, "")
		}
	case *jsast.EDot:
		c.collectExpr(v.Target, qualPrefix, "")
	case *jsast.EIndex:
		c.collectExpr(v.Target, qualPrefix, "")
		c.collectExpr(v.Index, qualPrefix, "")
	case *jsast.ESpread:
		c.collectExpr(v.Value, qualPrefix, "")
	case *jsast.EYield:
		c.collectExpr(v.ValueOrNil, qualPrefix, "")
	case *jsast.EAwait:
		c.collectExpr(v.Value, qualPrefix, "")
	case *jsast.EImportCall:
		c.collectExpr(v.Expr, qualPrefix, "")
	default:
		// Identifiers, literals, `this`, etc: no children to walk.
	}
}

// collectCall walks a call/new expression's callee and argument list for
// nested function literals (shared by the call and new cases, which are
// structurally identical here).
func (c *collector) collectCall(callee jsast.Expr, args []jsast.Expr, qualPrefix string) {
	c.collectExpr(callee, qualPrefix, "")
	// Route-handler registration: `X.<verb>("/path", …, handler)` where <verb> is
	// an HTTP router method, a STRING-LITERAL route path is present, and a function
	// argument is the handler. Record each such function so its request parameter
	// is treated as a taint source (COV-11). Requiring the route-path string keeps
	// same-named non-router calls that take a callback — lodash `_.get(obj, fn)`,
	// Vue `app.use(plugin)` — from being mistaken for a route.
	if dot, ok := unwrap(callee).Data.(*jsast.EDot); ok && routingVerbs[dot.Name] {
		hasPath, hasFn := false, false
		for _, a := range args {
			switch unwrap(a).Data.(type) {
			case *jsast.EString:
				hasPath = true
			case *jsast.EFunction, *jsast.EArrow:
				hasFn = true
			}
		}
		if hasPath && hasFn {
			for _, a := range args {
				switch fn := unwrap(a).Data.(type) {
				case *jsast.EFunction:
					c.handlers[fn] = true
				case *jsast.EArrow:
					c.handlers[fn] = true
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
func (c *collector) assignTargetName(left jsast.Expr) string {
	switch v := unwrap(left).Data.(type) {
	case *jsast.EIdentifier:
		return c.src.NameOf(v.Ref)
	case *jsast.EImportIdentifier:
		return c.src.NameOf(v.Ref)
	}
	return ""
}

// convertModule turns one parsed JavaScript file into a gIR Module. Every
// function declaration / function expression / arrow function discovered by
// the collector becomes its own ir.Function; the file's top-level statements
// (excluding function bodies, which are lowered separately) become one
// synthetic "<module>" ir.Function, mirroring converters/python.
func convertModule(src *jsast.File, li *lineIndex, moduleName string) (*ir.Module, string) {
	mod := &ir.Module{
		Name:     moduleName,
		Language: "javascript",
	}

	c := newCollector(src, moduleName)
	c.collectStmts(src.Stmts, "")

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

	// Module-level import-alias table for FE-2 (cp.exec -> child_process.exec),
	// augmented with identity/memoize-wrapper aliases (memoizedParse -> url.parse).
	moduleAliases := collectRequireAliases(src)
	collectImportAliases(src, moduleAliases)
	collectIdentityWrapperAliases(src, moduleAliases)

	// Relative default bindings (const f = require('./util'), import f from './util')
	// so a bare call f(x) becomes a cross-module marker resolved after all files lower.
	relativeDefaults := collectRelativeDefaults(src, moduleName)

	// This module's default export, the rewrite target for a
	// "js:@mod:<thisModule>" marker in some other file.
	defaultExport := collectDefaultExport(src, localFuncs, c.nameOf)

	mctx := &moduleCtx{
		src: src, li: li, moduleName: moduleName, nameOf: c.nameOf,
		localFuncs: localFuncs, moduleAliases: moduleAliases,
		relativeDefaults: relativeDefaults, handlers: c.handlers,
	}

	var functions []*ir.Function
	for _, pf := range c.order {
		functions = append(functions, lowerFunction(mctx, pf))
	}

	moduleFn := &ir.Function{
		Name:          moduleName + ".<module>",
		ObjectName:    "<module>",
		PackageName:   moduleName,
		CanonicalName: "js:" + moduleName + ".<module>",
		Synthetic:     true,
	}
	fs := mctx.newFuncState()
	fs.lowerBody(src.Stmts)
	moduleFn.Blocks = fs.b.Finish()

	mod.Functions = append([]*ir.Function{moduleFn}, functions...)
	return mod, defaultExport
}

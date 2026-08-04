package py_converter

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"godzilla/converters/ssabuild"
	ir "godzilla/pkg/ir/v1"
)

// modCtx bundles the file-scoped facts every lowered function in a module needs:
// the source filename (for positions), the module name (for canonical names) and
// the three module-level name tables (top-level defs, import aliases, imported
// names). It is built once in convertModule and threaded into convertModuleInit
// and convertFunction, which previously took them as five positional parameters
// each and then repeated the same field-copy block.
type modCtx struct {
	filename   string
	moduleName string
	localFuncs map[string]bool
	aliases    map[string]string
	imported   map[string]bool
	// constGlobals are module-level names provably bound once to a string
	// literal; lookupName inlines their value instead of emitting a GlobalName
	// the engine cannot read. See constglobal.go.
	constGlobals map[string]*ir.Constant
}

// newFuncState creates a funcState for a function in this module. The single
// place the module-scoped fields are set.
func (m *modCtx) newFuncState() *funcState {
	fs := newFuncState(m.filename)
	fs.moduleName = m.moduleName
	fs.localFuncs = m.localFuncs
	fs.constGlobals = m.constGlobals
	fs.aliases = m.aliases
	fs.importedNames = m.imported
	return fs
}

// convertModule turns one parsed Python file (root = the {"kind":"Module", ...}
// node from pyast.py) into a gIR Module. Every `def` (including nested defs
// and methods) becomes its own ir.Function; module-level statements that are
// not defs/classes are collected into one synthetic "<module>" function, the
// Python analogue of Go's package-init/main flattening in converters/go.
func convertModule(root astNode, filename, moduleName string, classes routeClasses) *ir.Module {
	mod := &ir.Module{
		Name:     moduleName,
		Language: "python",
	}

	var functions []*ir.Function

	// collect walks the statement tree looking for FunctionDef/ClassDef nodes
	// (at any nesting depth reachable via defs/classes) and lowers each into
	// its own ir.Function, tracking a dotted qualname prefix as it descends
	// (e.g. "MyClass." for methods, "outer." for a closure nested in outer).
	// Top-level `def` names: a bare call to one of these (helper(x)) resolves to
	// the module-level function, so lowerCall qualifies its callee with the
	// module name to match the function's CanonicalName. (Nested defs called by
	// bare name are a documented limitation — the straight-line lowering does not
	// model Python's lexical scoping.)
	localFuncs := map[string]bool{}
	for _, s := range root.list("body") {
		if s.kind() == "FunctionDef" {
			localFuncs[s.str("name")] = true
		}
	}

	// Module-level import aliases resolve aliased/from-imported sink modules (FE-2).
	aliases := collectImportAliases(root.list("body"))
	imported := collectImportedNames(root.list("body"))
	ctx := &modCtx{filename: filename, moduleName: moduleName, localFuncs: localFuncs, aliases: aliases, imported: imported,
		constGlobals: constStringGlobals(root)}

	// Route-handler taint sources (COV-11): web frameworks deliver untrusted input
	// as HANDLER PARAMETERS, not `request.X` accessor calls, so a handler's params
	// must be seeded as sources or the flow is never tainted. Recognition is
	// data-driven (see the handler-recognition tables below), so it is not tied to
	// any one framework. handlerClassSet — the set of request-handler class names
	// (by simple name) — is computed across ALL files (lowerAll/globalHandlerClasses)
	// so handler subclassing that crosses file boundaries still resolves.
	// inClass marks a FunctionDef whose immediate enclosing scope is a class body,
	// i.e. a real method (not a module function or a closure nested in a def). The
	// engine's cross-object CHA dispatch indexes such functions by method name, so
	// a call `obj.method(x)` resolves to it (see interproc buildMethodImpls).
	var collect func(stmts []astNode, qualPrefix string, cls classCtx, inClass bool)
	collect = func(stmts []astNode, qualPrefix string, cls classCtx, inClass bool) {
		for _, s := range stmts {
			switch s.kind() {
			case "FunctionDef":
				srcParams := routeHandlerParams(s, cls)
				fn := convertFunction(ctx, s, qualPrefix, srcParams, cls.handler, inClass)
				functions = append(functions, fn)
				// A nested def inside a handler/method is not itself a verb method of
				// the class, so its handler-class and method context reset.
				collect(s.list("body"), qualPrefix+s.str("name")+".", classCtx{}, false)
			case "ClassDef":
				// Only methods (nested FunctionDefs) are modeled; other
				// class-body statements are a documented limitation.
				cn := s.str("name")
				collect(s.list("body"), qualPrefix+cn+".", classes.ctxFor(cn), true)
			}
		}
	}
	collect(root.list("body"), "", classCtx{}, false)

	// Module-level constant bindings (NAME = <literal>) are Python module
	// globals. The env-based lowering keeps such a literal only in the
	// <module> function's register map (a bare-Name assign emits no
	// instruction), so a constant referenced from another function — or never
	// referenced at all — is invisible to passes that inspect the IR for
	// literals, most importantly the hardcoded-secret scanner. Surface each as
	// a gIR Global with an init value (the proto's intended home for a module
	// constant), mirroring how package-level vars appear in the Go frontend.
	eachModuleConstAssign(root, func(name string, c *ir.Constant, val astNode) {
		mod.Globals = append(mod.Globals, &ir.Global{
			Name:      name,
			InitValue: c,
			Pos:       posFromNode(filename, val),
		})
	})

	moduleFn := convertModuleInit(ctx, root)
	mod.Functions = append([]*ir.Function{moduleFn}, functions...)

	return mod
}

// convertModuleInit lowers a file's top-level straight-line statements
// (skipping nested def/class bodies, which become their own functions) into a
// synthetic entry-point function, analogous to converters/go treating
// package-level init code as part of the SSA program.
func convertModuleInit(ctx *modCtx, root astNode) *ir.Function {
	fn := &ir.Function{
		Name:          ctx.moduleName + ".<module>",
		ObjectName:    "<module>",
		PackageName:   ctx.moduleName,
		CanonicalName: "py:" + ctx.moduleName + ".<module>",
		Synthetic:     true,
	}
	fs := ctx.newFuncState()
	fs.lowerBody(root.list("body"))
	fn.Blocks = fs.b.Finish()
	return fn
}

// convertFunction lowers a single `def` (module-level, nested, or method) into
// an ir.Function whose blocks are built by the ssabuild Builder (a branch-free
// body yields exactly one block). srcParams names this function's route-handler
// parameters (see routeHandlerParams): each is an untrusted taint source and is
// seeded with a synthetic source CALL below.
func convertFunction(ctx *modCtx, node astNode, qualPrefix string, srcParams []string, inHandlerClass, isMethod bool) *ir.Function {
	name := node.str("name")
	qualname := qualPrefix + name

	fn := &ir.Function{
		Name:          qualname,
		ObjectName:    name,
		PackageName:   ctx.moduleName,
		CanonicalName: "py:" + ctx.moduleName + "." + qualname,
		Pos:           posFromNode(ctx.filename, node),
	}
	// Tag a real method (def directly in a class body) with its bare name so the
	// engine can resolve a cross-object call `obj.method(x)` to it via CHA.
	if isMethod {
		fn.MethodName = name
	}

	fs := ctx.newFuncState()
	fs.inHandlerClass = inHandlerClass
	params := node.strList("params")
	for _, p := range params {
		v := ssabuild.Reg(p)
		fn.Params = append(fn.Params, v)
		fs.write(p, v)
		fs.paramRegs[p] = true
	}
	// A method's first parameter is conventionally `self` (or `cls`); record it
	// and the class qualname prefix so `self.method(x)` calls resolve to the
	// sibling method. Guarding on the self/cls name keeps this from misfiring in
	// ordinary functions.
	if hasSelfReceiver(params) {
		fs.selfName = params[0]
		fs.methodPrefix = qualPrefix
	}

	// RW-1: seed each route-handler parameter as a taint source. A synthetic
	// source CALL (canonical name "py:@http.param", a source glob in the Python
	// rulepacks) is emitted at function entry and the param name is rebound to its
	// tainted result, so every subsequent read of the param carries taint — the
	// same frontend trick JS/Python opaque-base reads and the Java @RequestParam
	// source use, needing no gIR/engine change.
	for _, p := range srcParams {
		if !fs.assigned[p] {
			continue // defensive: name not an actual parameter
		}
		fs.write(p, fs.emitParamSource(p, node))
	}

	fs.lowerBody(node.list("body"))
	fn.Blocks = fs.b.Finish()
	return fn
}

// --- Web-route-handler recognition (COV-11): the single extension point -------
//
// Frameworks deliver untrusted input as handler PARAMETERS, not `request.X`
// accessor calls. Rather than special-case each framework in the detection
// LOGIC, the frontend recognizes two generic SHAPES driven by the declarative
// tables below — so adding a framework (aiohttp, Sanic, Django CBV, Falcon, …)
// is a data edit here, not new code:
//
//  1. a function decorated `<receiver>.<verb>`, verb in routeDecoratorVerbs
//     (FastAPI @app.get, @router.post, aiohttp @routes.get, Sanic @app.get, …);
//  2. a `<verb>`-named method, verb in handlerMethodVerbs, of a class
//     subclassing one of handlerBaseClasses (Tornado RequestHandler, Flask
//     MethodView, … — matched by simple base name, transitively);
//
// Shape 1 covers the class-based APIs too, because a decorator NAME is the
// signal there rather than the method's: Flask-AppBuilder routes @expose("/data")
// to a method called `data`, DRF routes @action(detail=True) to one called
// `upload_example`. Neither name is an HTTP verb and neither is a registration on
// an app/router object, so both were invisible -- the handler's parameters stayed
// clean and NO rule could fire downstream of them, which is why a campaign miss
// in superset, label-studio or pyload showed the expected class firing zero times
// across the entire project rather than firing at the wrong line.
//
// routeParamSource is the canonical name of the synthetic source CALL seeded at
// each recognized parameter; it is a source glob in every Python taint rulepack,
// so any dangerous flow off a handler param is covered.
const routeParamSource = "py:@http.param"

var (
	// routeDecorators mark a route function/method by its decorator. The VALUE is
	// whether a BARE occurrence counts: an HTTP verb must carry a receiver prefix
	// (@app.get), since a bare @get is far too likely to be something else, while
	// an imported routing symbol (@expose, @action) is specific enough on its own
	// and is never written with one. `route` is both -- Flask/Bottle/Sanic write
	// @app.route, flask-classful writes a bare @route -- which is exactly the
	// per-entry difference this map's value exists to express.
	//
	// handlerMethodVerbs mark a verb method of a handler class (get/post/…); no
	// `websocket`, which is a distinct handler class rather than a method name.
	// handlerBaseClasses are the base classes (by simple name) whose subclasses
	// are request handlers.
	routeDecorators = map[string]bool{
		"get": false, "post": false, "put": false, "delete": false, "patch": false,
		"head": false, "options": false, "websocket": false,
		"route":      true, // Flask/Bottle/Sanic @app.route; flask-classful bare @route
		"expose":     true, // Flask-AppBuilder @expose("/data") on BaseApi/BaseView
		"expose_api": true, // Flask-AppBuilder legacy alias
		"action":     true, // Django REST Framework @action(detail=True) on a ViewSet
	}
	handlerMethodVerbs = map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true, "head": true, "options": true}
	handlerBaseClasses = map[string]bool{
		"RequestHandler": true, // Tornado
		"MethodView":     true, // Flask pluggable views
		// Django class-based views + DRF APIView. A verb method (get/post/…) of a
		// subclass takes the URL captures as params after (self, request); those
		// captures are untrusted route input. Listed by simple base name (matched
		// transitively), covering both direct `View` subclasses and the concrete
		// generic views (whose own base `View` is declared in Django, not user
		// code, so it cannot be resolved by the transitive closure alone).
		"View":           true, // django.views.generic.View — base of all Django CBVs
		"TemplateView":   true,
		"ListView":       true,
		"DetailView":     true,
		"CreateView":     true,
		"UpdateView":     true,
		"DeleteView":     true,
		"FormView":       true,
		"RedirectView":   true,
		"APIView":        true, // Django REST Framework
		"GenericAPIView": true, // Django REST Framework
		// DRF ViewSets. Their STANDARD actions (list/create/retrieve/…) are
		// deliberately NOT added to handlerMethodVerbs: those take the request
		// object plus a `pk`, and request.data/.query_params are already precise
		// source globs, so seeding them would buy almost nothing while making
		// every helper method named `create`/`update` in any handler class a
		// taint origin. A ViewSet's CUSTOM actions are what carry untrusted
		// input, and shape 3 catches those by their @action decorator. Listing
		// the bases still matters: it makes `self.request` resolve inside them.
		"ViewSet":              true,
		"GenericViewSet":       true,
		"ModelViewSet":         true,
		"ReadOnlyModelViewSet": true,
		"Resource":             true, // flask-restful / flask-restx
		"HTTPEndpoint":         true, // Starlette
		"BaseApi":              true, // Flask-AppBuilder
		"BaseView":             true, // Flask-AppBuilder
		"ModelRestApi":         true, // Flask-AppBuilder
	}
	// requestObjectParams name a handler parameter that holds the framework
	// REQUEST OBJECT itself rather than an untrusted URL capture. Django/DRF verb
	// methods take it as the first positional after self (`get(self, request,
	// pk)`); it is excluded from synthetic param sources because request.GET/
	// .POST/.data accessors are already precise source globs, and seeding the
	// whole object would be both broader than needed and less precise
	// (request.user / request.method are not injection sources).
	requestObjectParams = map[string]bool{"request": true, "websocket": true}
)

// routeHandlerParams returns the untrusted parameter names of a `def` when it is
// a web-route handler (one of the two shapes above), or nil otherwise. Detection
// is deliberately conservative to avoid false positives: a decorated route's
// params exclude self/cls, request/websocket, and Depends()/Security()-injected
// params; a handler-class verb method contributes its params after self/cls (the
// URL route captures).
func routeHandlerParams(node astNode, cls classCtx) []string {
	params := node.strList("params")
	if len(params) == 0 {
		return nil
	}
	if hasRouteDecorator(node, cls.dispatch) {
		return decoratedRouteParams(node, params)
	}
	if cls.handler && handlerMethodVerbs[node.str("name")] {
		return positionalAfterSelf(params)
	}
	return nil
}

// hasRouteDecorator reports whether any decorator is a routing decorator. A
// dotted decorator matches on its last component; a bare one matches only if
// routeDecorators marks it as valid bare (see that map).
// A bare HTTP verb counts only inside a dispatch class (see routeClasses).
func hasRouteDecorator(node astNode, inDispatchClass bool) bool {
	for _, d := range node.strList("decorators") {
		name, dotted := simpleName(d)
		bare, ok := routeDecorators[name]
		if !ok {
			continue
		}
		if dotted || bare || inDispatchClass {
			return true
		}
	}
	return false
}

// bareVerbDecorators returns the bare HTTP verbs decorating a def -- an
// undotted decorator naming a verb that routeDecorators does NOT accept on its
// own. These are the evidence routeClasses tallies.
func bareVerbDecorators(node astNode) []string {
	var out []string
	for _, d := range node.strList("decorators") {
		name, dotted := simpleName(d)
		if bare, ok := routeDecorators[name]; ok && !dotted && !bare {
			out = append(out, name)
		}
	}
	return out
}

// simpleName splits a dotted name into its last component and reports whether it
// was dotted at all — the match rule for every decorator and base-class table in
// this file, which key on the simple name.
func simpleName(s string) (string, bool) {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:], true
	}
	return s, false
}

// decoratedRouteParams filters a decorated route function's params down to the
// untrusted ones: everything except self/cls, request/websocket, and
// Depends()/Security() dependency-injected params.
func decoratedRouteParams(node astNode, params []string) []string {
	excluded := map[string]bool{"self": true, "cls": true, "request": true, "websocket": true}
	for _, d := range node.strList("depends_params") {
		excluded[d] = true
	}
	var out []string
	for _, p := range params {
		if !excluded[p] {
			out = append(out, p)
		}
	}
	return out
}

// positionalAfterSelf returns the untrusted params of a handler-class verb
// method: those after a leading self/cls receiver (the URL route captures for a
// Tornado / MethodView / Django CBV verb method), minus any that hold the
// framework request object (see requestObjectParams). Tornado/MethodView methods
// carry no request param, so the filter is a no-op there; a Django/DRF
// `get(self, request, pk)` keeps only `pk`.
func positionalAfterSelf(params []string) []string {
	if hasSelfReceiver(params) {
		params = params[1:]
	}
	out := make([]string, 0, len(params))
	for _, p := range params {
		if !requestObjectParams[p] {
			out = append(out, p)
		}
	}
	return out
}

// hasSelfReceiver reports whether params begins with a conventional method
// receiver (`self` or `cls`).
func hasSelfReceiver(params []string) bool {
	return len(params) > 0 && (params[0] == "self" || params[0] == "cls")
}

// collectClassBases records every class's declared base names (dotted) into out,
// recursing through nested classes and function bodies so a handler class
// declared anywhere in the module is discoverable.
func collectClassBases(stmts []astNode, out map[string][]string) {
	for _, s := range stmts {
		switch s.kind() {
		case "ClassDef":
			// Append (union) rather than overwrite so a class name defined in more
			// than one file (collectClassBases is also called across all files to
			// resolve cross-file handler subclassing) keeps every base it declares.
			out[s.str("name")] = append(out[s.str("name")], s.strList("bases")...)
			collectClassBases(s.list("body"), out)
		case "FunctionDef":
			collectClassBases(s.list("body"), out)
		}
	}
}

// handlerClasses returns the set of class names that subclass one of targetBases
// (matched by simple base name) directly or transitively. The transitive closure
// is computed to a fixpoint so `class B(A)` where `class A(RequestHandler)` is
// also detected.
func handlerClasses(classBases map[string][]string, targetBases map[string]bool) map[string]bool {
	result := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for cls, bases := range classBases {
			if result[cls] {
				continue
			}
			for _, b := range bases {
				simple, _ := simpleName(b)
				if targetBases[simple] || result[simple] {
					result[cls] = true
					changed = true
					break
				}
			}
		}
	}
	return result
}

// routeClasses is the per-class context the route tables need, computed across
// ALL files so subclassing and dispatch layers that span modules still resolve.
type routeClasses struct {
	// handler holds request-handler class names (Tornado RequestHandler, Django
	// CBVs, …), by simple name.
	handler map[string]bool
	// dispatch holds classes that are their OWN routing layer. An app that does
	// not use `@app.post` writes its routes as a bare `@post`, which is far too
	// weak a marker on its own -- `post` is an ordinary word. What is not weak is
	// the SET: a class whose methods carry two or more DISTINCT bare HTTP verbs
	// is dispatching, because a one-off helper decorator does not come with a
	// sibling named after a different verb.
	//
	// This replaced a list of access-control decorator names (`@permission`,
	// `@login_required`, …) used as a co-signal. That list was unbounded, and
	// worse, ANTI-CORRELATED with risk: pyload has 84 bare verbs of which 73
	// carry @permission, so keying on the co-signal excluded exactly the 11
	// UNAUTHENTICATED endpoints -- the ones most worth seeding. The verb set
	// admits all 84 and needs no vocabulary to maintain.
	dispatch map[string]bool
}

// classCtx is one class's flags, resolved once at the ClassDef.
type classCtx struct{ handler, dispatch bool }

func (rc routeClasses) ctxFor(class string) classCtx {
	return classCtx{handler: rc.handler[class], dispatch: rc.dispatch[class]}
}

// collectDispatchVerbs records, per class, the set of distinct bare HTTP verbs
// its methods are decorated with, recursing so a class nested in another class
// or in a function is still seen. Keyed by simple class name, and unioned across
// files by the caller, matching collectClassBases.
func collectDispatchVerbs(stmts []astNode, out map[string]map[string]bool) {
	for _, s := range stmts {
		switch s.kind() {
		case "ClassDef":
			name := s.str("name")
			for _, m := range s.list("body") {
				if m.kind() != "FunctionDef" {
					continue
				}
				for _, verb := range bareVerbDecorators(m) {
					if out[name] == nil {
						out[name] = map[string]bool{}
					}
					out[name][verb] = true
				}
			}
			collectDispatchVerbs(s.list("body"), out)
		case "FunctionDef":
			collectDispatchVerbs(s.list("body"), out)
		}
	}
}

// dispatchClasses selects the classes carrying two or more distinct bare verbs,
// then propagates that down the class hierarchy. Two is the threshold because
// one verb is a coincidence a helper decorator can produce; a `@get` AND a
// `@post` on sibling methods of one class is a routing table.
//
// The hierarchy step is what covers the common framework shape: a base class
// holds the routing surface and each subclass adds a handful of handlers, often
// with a SINGLE verb, which on its own evidence would not qualify. Inheriting
// from a confirmed dispatch layer is that evidence.
func dispatchClasses(verbs map[string]map[string]bool, classBases map[string][]string) map[string]bool {
	seed := map[string]bool{}
	for class, vs := range verbs {
		if len(vs) >= 2 {
			seed[class] = true
		}
	}
	out := handlerClasses(classBases, seed)
	maps.Copy(out, seed) // handlerClasses returns only the SUBclasses it derived
	return out
}

// emitRouteSource emits the synthetic source CALL every route-handler taint
// origin is built from: a CALL to the canonical @http.param name whose RESULT
// register the engine seeds. Defined once here; the wrappers below are its only
// producers.
func (fs *funcState) emitRouteSource(n astNode, comment string, args ...*ir.Value) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Comment = comment
	inst.Call = &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: routeParamSource}},
		Callee: routeParamSource,
		Args:   args,
	}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// emitParamSource is emitRouteSource for a route-handler parameter. The param
// is passed as the call's sole argument for readability only; taint lands on the
// call RESULT, which convertFunction rebinds to the param name.
func (fs *funcState) emitParamSource(param string, n astNode) *ir.Value {
	return fs.emitRouteSource(n, "route-param-source:"+param, ssabuild.Reg(param))
}

// emitHandlerSource emits a synthetic source CALL (routeParamSource) for a
// request accessor reached through `self` in a handler-class method (Tornado
// self.get_argument / self.request.body); its result register carries taint. The
// canonical name is the same @http.param glob every Python taint rulepack already
// treats as a source, so no rule change is needed beyond the accessor's own sink.
func (fs *funcState) emitHandlerSource(n astNode, label string) *ir.Value {
	return fs.emitRouteSource(n, "handler-request-source:"+label)
}

// Tornado request accessors reached via `self` inside a handler-class method.
// tornadoArgMethods are call accessors (self.get_argument(...)); the *.body /
// *.arguments members of self.request are attribute reads (tornadoRequestAttrs).
var (
	tornadoArgMethods = map[string]bool{
		"get_argument": true, "get_arguments": true,
		"get_body_argument": true, "get_body_arguments": true,
		"get_query_argument": true, "get_query_arguments": true,
	}
	tornadoRequestAttrs = map[string]bool{
		"body": true, "arguments": true,
		"body_arguments": true, "query_arguments": true, "files": true,
	}
)

// selfRequestAccessor reports whether n is `self.request.<attr>` with attr an
// untrusted Tornado request member, for a handler-class method (fs.selfName set).
func (fs *funcState) selfRequestAccessor(n astNode) (attr string, ok bool) {
	if !fs.inHandlerClass || fs.selfName == "" || n.kind() != "Attribute" {
		return "", false
	}
	if !tornadoRequestAttrs[n.str("attr")] {
		return "", false
	}
	req := n.node("value") // the `self.request` part
	if req == nil || req.kind() != "Attribute" || req.str("attr") != "request" {
		return "", false
	}
	base := req.node("value")
	if !fs.isNameRef(base) {
		return "", false
	}
	return n.str("attr"), true
}

// isNameRef reports whether node is a `Name` expression referencing this
// function's self/cls receiver.
func (fs *funcState) isNameRef(node astNode) bool {
	return node != nil && node.kind() == "Name" && node.str("id") == fs.selfName
}

// selfArgMethod reports whether funcNode is `self.<get_argument-family>` for a
// handler-class method, i.e. a Tornado request-argument accessor call.
func (fs *funcState) selfArgMethod(funcNode astNode) bool {
	if !fs.inHandlerClass || fs.selfName == "" || funcNode == nil || funcNode.kind() != "Attribute" {
		return false
	}
	if !tornadoArgMethods[funcNode.str("attr")] {
		return false
	}
	base := funcNode.node("value")
	return fs.isNameRef(base)
}

// funcState holds the per-function lowering state. Variable values and the
// per-block instruction stream are owned by an ssabuild.Builder (real CFG +
// on-demand PHI insertion, Braun et al.); `cur` is the block currently being
// lowered into (threaded through the AST walk instead of appending to one flat
// instruction list). `assigned` tracks which Python names have been written as
// a local SO FAR in the traversal — it replaces the old env's key-presence
// test (is this bare name a bound local, or a free identifier / module global /
// import?) that the Builder's per-block value map cannot answer directly.
// `paramRegs` is the set of register names that are this function's own
// parameters (see isOpaqueBase); `terminated` reports whether the current block
// has already emitted a block-terminating RET (an explicit `return`), so a
// returning arm is not wired into a merge / loop header as a predecessor.
type funcState struct {
	filename   string
	counter    int
	b          *ssabuild.Builder
	cur        ssabuild.BlockID
	assigned   map[string]bool
	paramRegs  map[string]bool
	terminated bool

	// moduleName and localFuncs let lowerCall qualify a bare local call
	// (helper(x)) with the module name so its callee "py:<module>.helper"
	// matches the callee function's CanonicalName — without this the call is
	// unresolved and inter-procedural taint through the local helper is lost.
	moduleName string
	localFuncs map[string]bool

	// constGlobals are the module's provably-immutable string constants, inlined
	// at their use sites by lookupName. See constglobal.go.
	constGlobals map[string]*ir.Constant

	// selfName and methodPrefix let lowerCall qualify a `self.method(x)` call
	// inside a class method to the sibling method's canonical name
	// ("py:<module>.<Class>.method"). selfName is the receiver param ("self" or
	// "cls"); methodPrefix is the class qualname prefix (e.g. "UserAPI."). Both
	// are empty for non-methods.
	selfName     string
	methodPrefix string

	// inHandlerClass marks that this function is a method of a web request-handler
	// class (Tornado RequestHandler / Flask MethodView subclass; see
	// handlerClassSet). In such a method the request object reached via `self`
	// (`self.request.body`, `self.get_argument(...)`) is untrusted input, so those
	// reads are lowered to a synthetic source CALL — the same @http.param trick the
	// verb-method/route parameters use, but for the accessor style Tornado uses
	// (CVE-2025-47782 motioneye: json.loads(self.request.body) -> shell pipeline).
	inHandlerClass bool

	// aliases maps a locally-bound import name to its canonical dotted path
	// (FE-2): "sp" -> "subprocess" for `import subprocess as sp`, "system" ->
	// "os.system" for `from os import system`. resolveDotted rewrites a callee's
	// root through it so module-anchored sink rules match regardless of aliasing.
	aliases map[string]string

	// localAlias maps a local variable to the request-rooted attribute path it was
	// assigned (`a` -> "request.args" for `a = request.args`), per function. It lets
	// resolveDotted rewrite `a.get(...)` to `request.args.get` so the existing
	// request source globs match the aliased form (mlflow CVE-2025-52967), not just
	// the inline `request.args.get(...)`. Narrow to request-rooted chains to stay FP-safe.
	localAlias map[string]string

	// importedNames is the module's set of import-bound names (see
	// collectImportedNames). A method call on one of these is a library call, not an
	// object method, so lowerCall does not turn it into a CHA INVOKE.
	importedNames map[string]bool
}

func newFuncState(filename string) *funcState {
	b := ssabuild.NewBuilder()
	entry := b.NewBlock()
	b.Seal(entry) // the entry block has no predecessors, so it is sealed at once.
	return &funcState{
		filename:   filename,
		b:          b,
		cur:        entry,
		assigned:   map[string]bool{},
		paramRegs:  map[string]bool{},
		localAlias: map[string]string{},
	}
}

// emit appends an instruction to the block currently being lowered.
func (fs *funcState) emit(inst *ir.Instruction) { fs.b.AddInstr(fs.cur, inst) }

// read returns the SSA value current for a Python local in the current block,
// inserting PHIs on demand (branch joins / loop headers) via the Builder.
func (fs *funcState) read(name string) *ir.Value { return fs.b.ReadVariable(name, fs.cur) }

// write records val as the current value of a Python local name in the current
// block and marks the name as assigned (so a later bare read resolves it as a
// variable rather than a free identifier / module global / import).
func (fs *funcState) write(name string, val *ir.Value) {
	fs.b.WriteVariable(name, fs.cur, val)
	fs.assigned[name] = true
}

// requestAliasPath returns the request-rooted attribute path a variable is being
// aliased to when an assignment's RHS is a `request.<...>` chain (or a ternary
// between such chains), else "". Used to resolve `a = request.args; a.get("k")`
// to the `request.args.get` source the inline form already matches.
func requestAliasPath(n astNode) string {
	if n == nil {
		return ""
	}
	switch n.kind() {
	case "Attribute", "Name":
		if d := dottedName(n); d == "request" || strings.HasPrefix(d, "request.") {
			return d
		}
	case "IfExp":
		if p := requestAliasPath(n.node("body")); p != "" {
			return p
		}
		return requestAliasPath(n.node("orelse"))
	}
	return ""
}

// resolveDotted rewrites the root component of a dotted callee name through the
// per-function request-alias table (`a` -> "request.args") and the import alias
// table (`sp` -> "subprocess"), so `a.get` becomes `request.args.get` and
// `sp.call` becomes `subprocess.call` (FE-2). Names with no alias pass through.
func (fs *funcState) resolveDotted(dotted string) string {
	if len(fs.aliases) == 0 && len(fs.localAlias) == 0 {
		return dotted
	}
	root, rest, hasRest := strings.Cut(dotted, ".")
	canon, ok := fs.localAlias[root]
	if !ok {
		if canon, ok = fs.aliases[root]; !ok {
			return dotted
		}
	}
	if hasRest {
		return canon + "." + rest
	}
	return canon
}

// collectImportedNames returns the set of local names bound by Import/ImportFrom
// statements — INCLUDING plain `import subprocess` (bound name "subprocess"),
// which collectImportAliases does not record. A method call whose receiver root
// is an imported name is a library/module call (subprocess.run, os.system, a
// module's function), matched by sink globs on its callee; it must NOT be lowered
// to a CHA INVOKE, which would fan the (often tainted) argument into every
// same-named user method. Used by lowerCall to gate INVOKE emission.
func collectImportedNames(body []astNode) map[string]bool {
	names := map[string]bool{}
	for _, s := range body {
		switch s.kind() {
		case "Import":
			for _, a := range s.list("names") {
				name, as := a.str("name"), a.str("asname")
				switch {
				case as != "":
					names[as] = true
				case name != "":
					// `import a.b.c` binds the top-level package name `a`.
					names[strings.SplitN(name, ".", 2)[0]] = true
				}
			}
		case "ImportFrom":
			for _, a := range s.list("names") {
				name, as := a.str("name"), a.str("asname")
				if name == "*" {
					continue
				}
				if as != "" {
					names[as] = true
				} else if name != "" {
					names[name] = true
				}
			}
		}
	}
	return names
}

// collectImportAliases scans a module body for Import/ImportFrom statements and
// returns the local-name -> canonical-dotted-path map (FE-2). `import x as y`
// binds y->x; `from m import n as a` binds a->m.n; relative imports are skipped.
func collectImportAliases(body []astNode) map[string]string {
	aliases := map[string]string{}
	for _, s := range body {
		switch s.kind() {
		case "Import":
			for _, a := range s.list("names") {
				name, as := a.str("name"), a.str("asname")
				if as != "" && name != "" {
					aliases[as] = name // `import a.b.c as x` -> x resolves to a.b.c
				}
			}
		case "ImportFrom":
			mod := s.str("module")
			if mod == "" { // relative (`from . import x`) or unresolved
				continue
			}
			for _, a := range s.list("names") {
				name, as := a.str("name"), a.str("asname")
				if name == "" || name == "*" {
					continue
				}
				bound := as
				if bound == "" {
					bound = name
				}
				aliases[bound] = mod + "." + name
			}
		}
	}
	return aliases
}

func (fs *funcState) newReg() string {
	r := fmt.Sprintf("t%d", fs.counter)
	fs.counter++
	return r
}

// newValueInst allocates a fresh instruction with a result register (for
// value-producing ops: CALL, FIELD, INDEX, BIN_OP, UN_OP, INTRINSIC), mirroring
// how converters/go only sets Instruction.Name for ssa.Value instructions.
func (fs *funcState) newValueInst(n astNode) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: posFromNode(fs.filename, n)}
}

// newVoidInst allocates a fresh instruction with no result register (for
// STORE/RET), matching converters/go leaving Instruction.Name empty for
// non-ssa.Value instructions.
func (fs *funcState) newVoidInst(n astNode) *ir.Instruction {
	return &ir.Instruction{Pos: posFromNode(fs.filename, n)}
}

// emitKwargMarker tags a constant keyword-argument value with the name it was
// passed under, as a `builtin.kwarg(<name>, <value>)` intrinsic whose result
// stands in for the value in the call's argument list. gIR carries positional
// arguments only, so this is what lets a rule guard tell `shell=True` from
// `check=True`. Callers wrap constants only, so the marker never hides taint.
func (fs *funcState) emitKwargMarker(name string, v *ir.Value, n astNode) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = "builtin.kwarg"
	inst.Call = &ir.CallCommon{
		Callee: "builtin.kwarg",
		Args:   []*ir.Value{ssabuild.Str(name), v},
	}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// emitAggregate builds a `builtin.aggregate` container-construction intrinsic
// over the given element values, giving the container a REGISTER of its own.
// The engine lists this intrinsic in intrinsicPropagators (see
// internal/analysis/taint.go), so taint on any element flows to that register
// and a later whole-container use — json.dumps(d), a template context, a
// response body — observes it.
//
// Elements go in Operands, not Call.Args: visitIntrinsic propagates with
// markTaintFromOperands, which reads Operands.
//
// Emitted even for an EMPTY container. The register is the point: `d = {}`
// previously lowered to a constant, and a constant destination makes visitStore
// early-return (it needs an address register), which is why `d[k] = tainted`
// used to drop taint even before any element existed.
func (fs *funcState) emitAggregate(intrinsic string, elts []*ir.Value, n astNode) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = intrinsic
	inst.Operands = elts
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// Canonical container constructions. Both propagate taint identically; the map
// form additionally promises its operands run key,value,key,value, which is what
// lets a guard address an entry by key.
const (
	aggregateIntrinsic    = "builtin.aggregate"
	aggregateMapIntrinsic = "builtin.aggregate_map"
)

// lowerAggregate lowers each element expression and builds the container from
// the results. Shared by the two places a container is built in place — a
// literal and a comprehension — which differ only in where their elements come
// from.
func (fs *funcState) lowerAggregate(intrinsic string, elts []astNode, n astNode) *ir.Value {
	vals := make([]*ir.Value, 0, len(elts))
	for _, e := range elts {
		vals = append(vals, fs.lowerExpr(e))
	}
	return fs.emitAggregate(intrinsic, vals, n)
}

// selfFieldGlobal returns the synthetic global key for a one-level `self.<field>`
// access inside a method, or "" when node is not such an access. It is the
// cross-method channel for instance-field taint: keyed per (module, class,
// field), `self.f = tainted` in one method and a read of `self.f` in a sibling
// method of the same class link through the engine's existing global-taint
// propagation with NO engine change (the store/read carry this key as a
// GlobalName operand, which recordGlobalStore / readGlobalTaint already handle).
// Object-insensitive (all instances of the class share the key) and scoped to
// the method's own class+module, so a same-named field on an unrelated class in
// another file cannot alias.
func (fs *funcState) selfFieldGlobal(node astNode) string {
	if fs.selfName == "" || fs.methodPrefix == "" || node.kind() != "Attribute" {
		return ""
	}
	base := node.node("value")
	if !fs.isNameRef(base) {
		return ""
	}
	attr := node.str("attr")
	if attr == "" {
		return ""
	}
	// methodPrefix ends with '.', e.g. "Runner." -> "pyfield:mod.Runner.field".
	return "pyfield:" + fs.moduleName + "." + fs.methodPrefix + attr
}

// emitBinOp emits an OP_CODE_BIN_OP over (left, right) and returns its result
// register. Positioned at node n.
func (fs *funcState) emitBinOp(kind ir.BinOpKind, left, right *ir.Value, n astNode) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = kind
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// foldBinOp accumulates val into acc with a BIN_OP of the given kind, seeding
// the fold on the first element (acc == nil) without emitting anything.
func (fs *funcState) foldBinOp(kind ir.BinOpKind, acc, val *ir.Value, n astNode) *ir.Value {
	if acc == nil {
		return val
	}
	return fs.emitBinOp(kind, acc, val, n)
}

// lowerIterTarget lowers the `iter` of a for-loop / comprehension generator and
// binds its `target` to that value (element taint == container taint), so taint
// in the iterable reaches the loop variable and a source in the iterable is not
// dropped.
func (fs *funcState) lowerIterTarget(n astNode) {
	it := n.node("iter")
	if it == nil {
		return
	}
	iterVal := fs.lowerExpr(it)
	if tgt := n.node("target"); tgt != nil {
		fs.assign(tgt, iterVal)
	}
}

// lookupName resolves a bare Name reference through the Builder, falling back to
// a GlobalName reference for an unbound name (module global, builtin, or
// imported symbol) -- the same rule the "Name" case of lowerExpr applies,
// factored out here so the Subscript case (see isOpaqueBase) can classify a
// chain's root before deciding what to emit.
//
// It is NOT side-effect free: an assigned name goes through
// ssabuild.ReadVariable, which memoises the result into the block's currentDef
// and, in an unsealed or multi-predecessor block, may park or populate a PHI.
// That is nonetheless safe for the speculative classification probe, for two
// reasons: (1) the memoised value is exactly what the subsequent real read in
// lowerExpr returns, so probing cannot change the lowering; and (2) a PHI
// register is never in paramRegs, so a probe that materialises one can only
// classify the root as NON-opaque -- it can never invent an opaque base.
func (fs *funcState) lookupName(id string) *ir.Value {
	if fs.assigned[id] {
		return fs.read(id)
	}
	// A bare reference to a module-level function used as a VALUE (passed as a
	// callback, `Thread(target=fn)`, `walk(data, fn)`) resolves to its canonical
	// FuncName so the engine can identify which concrete function was handed off —
	// the ingredient for higher-order-callback taint. This mirrors the callee
	// qualification lowerCall already does for a direct `fn(x)` call. Gated on
	// localFuncs membership, so a non-function global/builtin/import is untouched
	// (still a GlobalName).
	if fs.localFuncs[id] {
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: "py:" + fs.moduleName + "." + id}}
	}
	// A module-level string constant is inlined as its literal rather than left
	// as an opaque GlobalName, so every consumer that reads constant text sees it
	// -- notably the SSRF host check, which proves a URL's host is fixed from its
	// constant prefix and otherwise read `BASE + "/" + user` as attacker
	// controllable. Only names constStringGlobals proved immutable get here.
	if c, ok := fs.constGlobals[id]; ok {
		return &ir.Value{Kind: &ir.Value_Constant{Constant: c}}
	}
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: id}}
}

// isOpaqueBase reports whether v is a value whose origin is outside this
// function's own straight-line computation: either a free/global identifier
// (Value_GlobalName, e.g. an unbound module global or imported symbol like
// `request` or `os`) or one of this function's own parameters (Value_RegName
// for a name in fs.paramRegs). Mirrors converters/javascript's
// funcState.isOpaqueBase (see that package's doc comment, "the opaque object
// source heuristic"): a Subscript read rooted at either kind of value is the
// first opportunity to introduce taint, since the engine only ever seeds
// taint at a CALL matching a source glob (see
// internal/analysis/interproc.go's handleCall).
func (fs *funcState) isOpaqueBase(v *ir.Value) (name string, ok bool) {
	if v == nil {
		return "", false
	}
	if g := v.GetGlobalName(); g != "" {
		return g, true
	}
	if r := v.GetRegName(); r != "" && fs.paramRegs[r] {
		return r, true
	}
	return "", false
}

// rootName walks a Name/Attribute chain -- the same shape dottedName walks --
// down to its root and returns the root Name node's identifier, or "" if the
// chain bottoms out in something other than a plain Name (e.g. a nested Call
// or Subscript). Used by the Subscript case of lowerExpr to find the name to
// classify with isOpaqueBase.
func rootName(n astNode) string {
	for n != nil {
		switch n.kind() {
		case "Name":
			return n.str("id")
		case "Attribute":
			n = n.node("value")
		default:
			return ""
		}
	}
	return ""
}

// lowerBody lowers a statement list, building a REAL CFG (blocks + preds/succs +
// PHI) via the Builder for control-flow compounds (If/For/While/Try) and lowering
// straight-line statements (and non-branching With) into the current block, so a
// function with no branches still emits exactly ONE block (the engine's linear
// fast path). FunctionDef/ClassDef are skipped (each becomes its own ir.Function
// via convertModule.collect).
func (fs *funcState) lowerBody(stmts []astNode) {
	for _, s := range stmts {
		switch s.kind() {
		case "FunctionDef", "ClassDef":
			// Converted separately; do not inline.
		case "If":
			fs.lowerIf(s)
		case "While":
			fs.lowerWhile(s)
		case "For":
			fs.lowerFor(s)
		case "With":
			// `with EXPR as VAR:` lowers as `VAR = EXPR`: lower each context-manager
			// expression (so a sink/source CALL such as open(...) is emitted, not
			// dropped) and bind its `as` target, then lower the body — straight into
			// the current block (its body may itself branch, which lowerBody handles).
			// Without this the whole `with open(tainted) as f: ...` idiom was invisible.
			for _, it := range s.list("items") {
				ctx := it.node("context")
				if ctx == nil {
					continue
				}
				val := fs.lowerExpr(ctx)
				if v := it.node("vars"); v != nil {
					fs.assign(v, val)
				}
			}
			fs.lowerBody(s.list("body"))
		case "Try":
			fs.lowerTry(s)
		default:
			fs.lowerStmt(s)
		}
	}
}

// lowerIf lowers `if cond: body [elif/else: orelse]` into a REAL CFG diamond
// via the Builder's IfDiamond scaffold, so any variable rebound on one or both
// arms reconciles automatically via an on-demand ReadVariable PHI (retiring the
// manual env-merge path — including the ubiquitous "default if empty" idiom
// `if not x: x = "d"`, whose pre-branch tainted value is now kept by the merge
// PHI). Python's `elif` is an `If` node in the parent's `orelse`, so an
// arbitrarily long chain becomes nested diamonds via the recursive lowerBody.
func (fs *funcState) lowerIf(s astNode) {
	cond := fs.lowerTest(s) // condition, lowered in the current block
	fs.b.IfDiamond(&fs.cur, &fs.terminated, cond,
		func() { fs.lowerBody(s.list("body")) },
		func() { fs.lowerBody(s.list("orelse")) })
}

// lowerTest lowers a statement's `test` condition in the current block, for
// its side effects and as the branch value: a source bound by a walrus
// (if (x := request.args.get(...)):) or a sink/source call in the test would
// otherwise be dropped. A missing test yields an opaque placeholder.
func (fs *funcState) lowerTest(s astNode) *ir.Value {
	if t := s.node("test"); t != nil {
		return fs.lowerExpr(t)
	}
	return ssabuild.Str("")
}

// lowerWhile lowers `while cond: body [else: orelse]` into a REAL loop CFG via
// the Builder's HeaderLoop scaffold (header/body/exit; the header PHI is what
// carries loop-carried taint — see the scaffold's doc). The `else` clause runs
// after normal loop completion, so it is lowered into the exit block.
func (fs *funcState) lowerWhile(s astNode) {
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return fs.lowerTest(s) }, // condition, lowered in the (unsealed) header
		func() { fs.lowerBody(s.list("body")) })
	fs.lowerBody(s.list("orelse")) // while-else: runs after normal completion
}

// lowerFor lowers `for target in iter: body [else: orelse]` into the same
// HeaderLoop CFG as lowerWhile. The iterable is lowered once in the pre-loop
// block; the loop target is bound to the iterable's value at the top of the
// BODY block each iteration (element taint == container taint, so a tainted
// iterable taints the target). Reassignments/accumulations in the body flow
// through the header PHI, modeling loop-carried taint. The iteration condition
// is opaque (a placeholder), so the engine traverses both the body and the exit.
func (fs *funcState) lowerFor(s astNode) {
	var iterVal *ir.Value
	if it := s.node("iter"); it != nil {
		iterVal = fs.lowerExpr(it) // evaluate the iterable in the pre-loop block
	}
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return ssabuild.Str("") }, // opaque iteration condition
		func() {
			if tgt := s.node("target"); tgt != nil && iterVal != nil {
				fs.assign(tgt, iterVal) // bind the loop variable each iteration
			}
			fs.lowerBody(s.list("body"))
		})
	fs.lowerBody(s.list("orelse")) // for-else: runs after normal completion
}

// lowerTry lowers `try: body [else: orelse] except ...: handler [finally: fin]`
// conservatively (a may-analysis; no exception typing). The try body (and its
// `else`, which runs on normal completion) is lowered into the current block. An
// EXCEPTION EDGE then models that an exception may occur anywhere in the body:
// the body-end block branches to a single handler block (all `except` clauses
// lowered sequentially into it — conservative) or to an after block, so taint a
// source in the try body assigned reaches the handler via that predecessor edge
// (and, through the after block, code following the try). `finally` runs on both
// paths, so it is lowered into the after block.
//
// A block that RETURNS still gets its outgoing edge: `try: return fast()` can
// raise before it returns, and a `finally` runs on the returning path too. The
// edge is what carries the bindings — a sealed block with zero predecessors
// resolves every variable read to __undef (ssabuild), so skipping it would strip
// the handler (and everything after the try) of names bound BEFORE the try, not
// just of names bound inside its body: a silent, total taint loss on the very
// common `try: return cached() except KeyError: <sink>(untrusted)` shape.
func (fs *funcState) lowerTry(s astNode) {
	fs.lowerBody(s.list("body"))
	fs.lowerBody(s.list("orelse"))
	bodyEnd := fs.cur
	bodyTerm := fs.terminated

	handlers := s.list("handlers")
	finalbody := s.list("finalbody")

	if len(handlers) == 0 {
		// try/finally with no except clause: finally is a straight-line
		// continuation of the body.
		fs.lowerBody(finalbody)
		return
	}

	handlerB := fs.b.NewBlock()
	after := fs.b.NewBlock()
	if !bodyTerm {
		// Exception edge: the body may branch into the handler, else fall through
		// to the after block. The condition is opaque (both edges are traversed).
		fs.b.SetIf(bodyEnd, ssabuild.Str(""), handlerB, after)
	} else {
		// The body ends in a return/raise, so its only non-terminating successor is
		// the handler (the raise-before-return path) — an unconditional edge, not a
		// branch. `after` still gets its predecessor from the handler below.
		fs.b.SetJump(bodyEnd, handlerB)
	}
	fs.b.Seal(handlerB) // sole predecessor (bodyEnd) now known

	fs.cur = handlerB
	fs.terminated = false
	for _, h := range handlers {
		fs.lowerBody(h.list("body"))
	}
	handlerTerm := fs.terminated
	// Unconditional for the same reason as the body edge: even when every handler
	// returns, `finally` — lowered into the after block — runs on that path and
	// must see the bindings the try/except made.
	fs.b.SetJump(fs.cur, after)

	fs.b.Seal(after)
	fs.cur = after
	fs.terminated = bodyTerm && handlerTerm
	fs.lowerBody(finalbody) // finally runs on both the normal and handler paths
}

// lowerStmt lowers one leaf statement; control-flow compounds get their own
// basic blocks in lowerBody.
func (fs *funcState) lowerStmt(s astNode) {
	switch s.kind() {
	case "Assign":
		valNode := s.node("value")
		val := fs.lowerExpr(valNode)
		aliasPath := requestAliasPath(valNode)
		for _, target := range s.list("targets") {
			fs.assign(target, val)
			// Track/untrack a request-attribute alias so `a = request.args;
			// a.get(k)` resolves its callee to request.args.get. A rebind to a
			// non-request value clears any stale alias.
			if target.kind() == "Name" {
				if aliasPath != "" {
					fs.localAlias[target.str("id")] = aliasPath
				} else {
					delete(fs.localAlias, target.str("id"))
				}
			}
		}
	case "AugAssign":
		target := s.node("target")
		cur := fs.lowerExpr(target)
		rhs := fs.lowerExpr(s.node("value"))
		fs.assign(target, fs.emitBinOp(binOpKind(s.str("op")), cur, rhs, s))
	case "ExprStmt":
		fs.lowerExpr(s.node("value"))
	case "Return":
		inst := fs.newVoidInst(s)
		inst.Op = ir.OpCode_OP_CODE_RET
		if v := s.node("value"); v != nil {
			inst.Operands = []*ir.Value{fs.lowerExpr(v)}
		}
		fs.emit(inst)
		// The current block ends here: no fall-through edge to a merge / loop
		// header (an arm that returns must not feed its values into the join).
		fs.terminated = true
	case "Pass", "Import", "ImportFrom", "Global", "Nonlocal", "Break", "Continue", "Raise", "Assert", "Delete", "Unknown":
		// No-ops / unsupported: dropped. Unlike unsupported expressions
		// (which must still yield a value for their parent), a dropped
		// statement leaves no gap in the IR.
	default:
		// Should not happen given pyast.py's schema, but stay defensive.
	}
}

// assign binds a lowered value to an assignment target. A bare Name target
// rebinds the environment (the SSA-like "current register for this Python
// variable" mapping). An Attribute/Subscript target (obj.attr = v / arr[i] =
// v) emits a STORE with the base object as the address operand, matching how
// converters/go lowers ssa.Store; this is what lets a tainted value written
// into a container mark that container tainted. A Tuple/List (unpacking) target
// binds EACH element to the whole RHS value — element taint == container taint,
// mirroring for-loop targets and conservative for recall — and nested unpacking
// recurses; any other target shape is still dropped.
func (fs *funcState) assign(target astNode, val *ir.Value) {
	switch target.kind() {
	case "Name":
		fs.write(target.str("id"), val)
	case "Attribute", "Subscript":
		base := fs.lowerExpr(target.node("value"))
		inst := fs.newVoidInst(target)
		inst.Op = ir.OpCode_OP_CODE_STORE
		inst.Operands = []*ir.Value{base, val}
		fs.emit(inst)
		// Instance-field heap: `self.<field> = v` also stores into a per-(class,
		// field) synthetic global so a sibling method that reads `self.<field>`
		// observes the taint cross-method (see selfFieldGlobal). The register
		// STORE above still handles intra-method / whole-object flow.
		if g := fs.selfFieldGlobal(target); g != "" {
			s := fs.newVoidInst(target)
			s.Op = ir.OpCode_OP_CODE_STORE
			s.Operands = []*ir.Value{ssabuild.Global(g), val}
			fs.emit(s)
		}
	case "Sequence":
		// Unpacking `a, b = rhs` (or `[a, b] = rhs`): bind each target element to
		// the RHS value (element taint == container taint, mirroring for-loop
		// targets and conservative for recall). Nested unpacking recurses.
		for _, elt := range target.list("elts") {
			fs.assign(elt, val)
		}
	case "Starred":
		// `a, *rest = rhs`: bind the starred target to the RHS value.
		fs.assign(target.node("value"), val)
	default:
		// Other unsupported target shape: dropped.
	}
}

// lowerExpr lowers an expression to a gIR Value, emitting whatever
// instructions are needed to compute it (into the current block). Names
// assigned as locals resolve through the Builder to their current SSA value
// (constant, register, or an on-demand PHI); unbound names (module globals like
// `request`, `os`, imported symbols) fall back to a GlobalName reference.
func (fs *funcState) lowerExpr(n astNode) *ir.Value {
	if n == nil {
		return nil
	}
	switch n.kind() {
	case "Constant":
		return constantValue(n)

	case "Name":
		return fs.lookupName(n.str("id"))

	case "Attribute":
		// self.request.body / .arguments / ... in a handler-class method is the
		// untrusted Tornado request payload: emit a synthetic source instead of a
		// plain field read (CVE-2025-47782 motioneye).
		if attr, ok := fs.selfRequestAccessor(n); ok {
			return fs.emitHandlerSource(n, "self.request."+attr)
		}
		base := fs.lowerExpr(n.node("value"))
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_FIELD
		inst.Operands = []*ir.Value{base}
		inst.Comment = "attr:" + n.str("attr")
		// Instance-field heap: a one-level `self.<field>` read also carries the
		// per-(class, field) synthetic global as an operand, so readGlobalTaint
		// seeds the result when a sibling method tainted that field (see
		// selfFieldGlobal). visitFieldRead keys on operand 0 (the base) only, so
		// the extra operand is inert to intra-method field-sensitivity.
		if g := fs.selfFieldGlobal(n); g != "" {
			inst.Operands = append(inst.Operands, ssabuild.Global(g))
		}
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)

	case "Subscript":
		return fs.lowerSubscript(n)

	case "BinOp":
		left := fs.lowerExpr(n.node("left"))
		right := fs.lowerExpr(n.node("right"))
		return fs.emitBinOp(binOpKind(n.str("op")), left, right, n)

	case "UnaryOp":
		operand := fs.lowerExpr(n.node("operand"))
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_UN_OP
		inst.UnOp = unOpKind(n.str("op"))
		inst.Operands = []*ir.Value{operand}
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)

	case "BoolOp":
		// `a or b` / `a and b`: the result is one of the operands, so taint from
		// any operand can reach it. Fold the operands with BIN_OP_OR so the
		// engine's BIN_OP propagation taints the result if any operand is
		// tainted (mirrors JS lowering `||`/`&&` as a BIN_OP). This is what makes
		// the common `request.args.get("x") or default` defaulting idiom carry
		// taint.
		var acc *ir.Value
		for _, v := range n.list("values") {
			acc = fs.foldBinOp(ir.BinOpKind_BIN_OP_OR, acc, fs.lowerExpr(v), n)
		}
		if acc == nil {
			return ssabuild.Str("")
		}
		return acc

	case "IfExp":
		// ternary `a if cond else b`: the result is a or b, so taint from either
		// branch can reach it. Lower `test` for its side effects (it may contain
		// a call), then merge the two value branches with BIN_OP_OR so taint
		// propagates from either.
		fs.lowerExpr(n.node("test"))
		body := fs.lowerExpr(n.node("body"))
		orelse := fs.lowerExpr(n.node("orelse"))
		return fs.emitBinOp(ir.BinOpKind_BIN_OP_OR, body, orelse, n)

	case "NamedExpr":
		// walrus `target := value`: the expression evaluates to `value` and also
		// binds `target`, so both the result and the bound name carry taint.
		val := fs.lowerExpr(n.node("value"))
		fs.assign(n.node("target"), val)
		return val

	case "Await":
		// `await x` yields x's resolved value; transparent for taint.
		return fs.lowerExpr(n.node("value"))

	case "Sequence":
		// List/tuple/set literal — and a flattened dict literal, whose keys and
		// values pyast.py emits as one `elts` run — as a VALUE. Lower each
		// element and build the container as a `builtin.aggregate`, so element
		// taint reaches a later whole-container use (`json.dumps({"k": tainted})`
		// into a response body: the label-studio CVE-2025-47783 shape).
		//
		// Command injection keeps its argv precision through py-command-injection's
		// `when:` guard rather than by erasing the container.
		//
		// pyast.py marks a literal that cannot pair its keys as "list".
		intrinsic := aggregateIntrinsic
		if n.str("container") == "dict" {
			intrinsic = aggregateMapIntrinsic
		}
		return fs.lowerAggregate(intrinsic, n.list("elts"), n)

	case "Starred":
		// `*x` spread (e.g. func(*args)): the spread carries x's value/taint into
		// the call, so lower to x.
		return fs.lowerExpr(n.node("value"))

	case "Comprehension":
		// [elt for t in iter if cond ...] and dict/set/generator forms. Lower
		// each generator (bind the loop target to the iterable's taint, like a
		// for-loop; lower filter conditions) then the element/key/value
		// expression, so a source or sink INSIDE the comprehension
		// (e.g. [cursor.execute(q) for q in ...]) is lowered and fires. The
		// result is a container built from those element expressions, so — like
		// a literal — it carries their taint via builtin.aggregate.
		for _, g := range n.list("generators") {
			fs.lowerIterTarget(g)
			for _, cond := range g.list("ifs") {
				fs.lowerExpr(cond)
			}
		}
		elts := make([]astNode, 0, 3)
		for _, key := range []string{"elt", "key", "value"} {
			if e := n.node(key); e != nil {
				elts = append(elts, e)
			}
		}
		intrinsic := aggregateIntrinsic
		if n.node("key") != nil {
			intrinsic = aggregateMapIntrinsic
		}
		return fs.lowerAggregate(intrinsic, elts, n)

	case "JoinedStr":
		// f-string: fold parts left-to-right with BIN_OP_ADD (string
		// concatenation) so taint carried by any {expr} slot propagates to
		// the final value, same as Python's runtime semantics.
		var acc *ir.Value
		for _, part := range n.list("values") {
			acc = fs.foldBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(part), n)
		}
		if acc == nil {
			acc = ssabuild.Str("")
		}
		return acc

	case "FormattedValue":
		return fs.lowerExpr(n.node("value"))

	case "Call":
		return fs.lowerCall(n)

	case "Compare":
		// `a < b` / `x == y` / `k in d`: lower every operand so a source/sink/
		// validator call inside the comparison fires; the boolean result does not
		// carry operand taint, so emit an inert builtin.compare intrinsic over the
		// operands (this also gives a branch condition a def-use edge for the
		// engine's guard analysis).
		ops := []*ir.Value{fs.lowerExpr(n.node("left"))}
		for _, c := range n.list("comparators") {
			ops = append(ops, fs.lowerExpr(c))
		}
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "builtin.compare"
		inst.Operands = ops
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)

	default:
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "py.unsupported"
		inst.Comment = "unsupported python expression: " + n.kind()
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)
	}
}

// lowerSubscript lowers a Subscript expression. base["key"] rooted at a
// global/imported name or a function parameter (and never reassigned to a
// locally-computed value) is the first opportunity to introduce taint, e.g.
// request.args["cmd"]. Lower it to a synthetic source CALL
// "py:<dotted-base>.__getitem__" instead of a plain OP_CODE_INDEX, so it
// matches a source glob like "py:*request.args.__getitem__" exactly like the
// equivalent request.args.get("cmd") call already does (see dottedName and
// lowerCall). The base is deliberately NOT run through the general
// fs.lowerExpr (which would emit an unconditional OP_CODE_FIELD chain for
// e.g. the ".args" hop) -- like lowerCall never lowers its own callee
// expression, only the purely syntactic dotted name is needed here; arg0 is a
// symbolic reference carrying that same name.
//
// When the chain is rooted at one of THIS function's own parameters, the
// parameter may already be tainted by an inter-procedural caller (e.g. a
// request dict passed into a helper: config.add_camera(device_details) then
// device_details['path'] -- CVE-2025-47782 motioneye). The synthetic getitem
// source only seeds taint when its dotted name matches a source glob, so by
// itself it would DROP that incoming taint. Carry the parameter register in
// Call.Value and tag the call builtin.member_read -- the cross-frontend
// contract for exactly this shape (see internal/analysis memberReadIntrinsic
// and converters/javascript emitRootPropertyRead): the engine forwards the
// base's taint to the result, while the callee glob keeps INTRODUCING taint
// for a request-object base. A global/free root has no register to carry, so
// it keeps the plain FuncName form.
//
// A Subscript rooted at a local variable (e.g. `local_list[i]`) is
// deliberately left as OP_CODE_INDEX -- it is not itself a source, but taint
// still flows through it via propagatingOps if the container was tainted some
// other way.
func (fs *funcState) lowerSubscript(n astNode) *ir.Value {
	baseNode := n.node("value")
	var idx *ir.Value
	if sl := n.node("slice"); sl != nil {
		idx = fs.lowerExpr(sl)
	} else {
		// a[i:j] slice: no single index expression: propagate taint
		// through the base only via a nil-constant placeholder index.
		idx = ssabuild.Nil()
	}

	if root := rootName(baseNode); root != "" {
		base := fs.lookupName(root)
		if _, ok := fs.isOpaqueBase(base); ok {
			dotted := dottedName(baseNode)
			callee := "py:" + dotted + ".__getitem__"
			inst := fs.newValueInst(n)
			inst.Op = ir.OpCode_OP_CODE_CALL
			inst.Comment = "subscript-read"
			inst.Call = &ir.CallCommon{
				Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
				Callee: callee,
				Args:   []*ir.Value{{Kind: &ir.Value_GlobalName{GlobalName: dotted}}, idx},
			}
			// Parameter-rooted base: the root register rides in Call.Value and
			// the call is tagged builtin.member_read so incoming taint on the
			// parameter reaches the result (see the doc comment above).
			if base.GetRegName() != "" {
				inst.Call.Value = base
				inst.Intrinsic = "builtin.member_read"
			}
			fs.emit(inst)
			return ssabuild.Reg(inst.Name)
		}
	}

	base := fs.lowerExpr(baseNode)
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{base, idx}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerCall lowers a Call node. `"...".format(args)` is special-cased into a
// BIN_OP_ADD concatenation chain (mirroring JoinedStr) instead of an actual
// OP_CODE_CALL, per the task's guidance that string formatting should carry
// taint through the engine's BIN_OP auto-propagation; this means a
// .format(...) call does not appear as a call in the IR (a documented
// tradeoff: call-graph fidelity for .format sites is traded for guaranteed
// taint propagation without needing a propagator rule).
//
// funcValueOf resolves an AST expression used as a callback TARGET to the gIR
// value the engine can resolve to a concrete function: a bare Name that is a
// module-level function or a function-holding parameter/local (via lookupName),
// or a `self.method` reference (to the sibling method's canonical name). Anything
// else — a lambda, an unresolvable import — yields nil, so the dispatch is skipped.
func (fs *funcState) funcValueOf(node astNode) *ir.Value {
	if node == nil {
		return nil
	}
	switch node.kind() {
	case "Name":
		if v := fs.lookupName(node.str("id")); v.GetFuncName() != "" || v.GetRegName() != "" {
			return v
		}
	case "Attribute":
		if fs.selfName != "" {
			if base := node.node("value"); fs.isNameRef(base) {
				return &ir.Value{Kind: &ir.Value_FuncName{FuncName: "py:" + fs.moduleName + "." + fs.methodPrefix + node.str("attr")}}
			}
		}
	}
	return nil
}

// emitDeferredDispatch recognizes a thread/process dispatch construct and, when it
// matches, emits a synthesized INDIRECT call target(forwarded-args...) so taint
// flows into the worker the runtime will invoke later, then returns true to signal
// that it has fully consumed the call (the caller returns an opaque handle without
// re-lowering it — which is what keeps the forwarded args from being lowered
// twice). The recognized APIs and their argument layouts are library knowledge
// that belongs in the frontend; the engine only ever sees a generic indirect call
// (empty Callee, function value in Call.Value).
//
// Scoped to threading.Thread / multiprocessing.Process, whose `target=`/`args=`
// keyword shape is highly distinctive, and gated on the target resolving to a
// concrete named function or self-method (a FuncName). A same-named method on an
// unrelated object, or a target that is merely a parameter holding some value, is
// not treated as a dispatch — the unambiguous-only discipline, so a miss is a
// false negative, never a false positive. (Executor.submit / run_in_executor use
// the far more common `submit`/`run_in_executor` method names and need executor-
// receiver type tracking to be FP-safe; they are a deliberate follow-up.)
func (fs *funcState) emitDeferredDispatch(n, funcNode astNode) bool {
	if funcNode == nil {
		return false
	}
	var leaf string
	switch funcNode.kind() {
	case "Attribute":
		leaf = funcNode.str("attr")
	case "Name":
		leaf = funcNode.str("id")
	default:
		return false
	}
	if leaf != "Thread" && leaf != "Process" {
		return false
	}

	var targetNode astNode
	var argNodes []astNode
	for _, kw := range n.list("keywords") {
		switch kw.str("arg") {
		case "target":
			targetNode = kw.node("value")
		case "args":
			if t := kw.node("value"); t != nil && t.kind() == "Sequence" {
				argNodes = t.list("elts")
			}
		}
	}
	if targetNode == nil {
		return false
	}
	targetVal := fs.funcValueOf(targetNode)
	if targetVal == nil || targetVal.GetFuncName() == "" {
		return false
	}

	cc := &ir.CallCommon{Value: targetVal} // empty Callee marks the indirect call
	// A self.method target takes the receiver as param 0; prepend it so the forwarded
	// args line up with params 1..n (the engine binds an indirect call's args to the
	// target's FRONT params with no receiver shift), mirroring the direct self-method
	// call path — without this args[0] would bind to the `self` slot, tainting the
	// receiver and dropping the real first argument.
	if targetNode.kind() == "Attribute" && fs.selfName != "" {
		if base := targetNode.node("value"); fs.isNameRef(base) {
			cc.Args = append(cc.Args, ssabuild.Reg(fs.selfName))
		}
	}
	for _, a := range argNodes {
		cc.Args = append(cc.Args, fs.lowerExpr(a)) // forwarded args: lowered exactly once
	}
	inst := fs.newVoidInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = cc
	fs.emit(inst)

	// Lower the remaining arguments (any positionals, other keywords, and a
	// non-tuple args= value) for their side effects, since the caller returns
	// without the normal call lowering. The forwarded tuple elements were already
	// lowered above and must not be lowered again.
	for _, a := range n.list("args") {
		fs.lowerExpr(a)
	}
	for _, kw := range n.list("keywords") {
		switch kw.str("arg") {
		case "target":
		case "args":
			if v := kw.node("value"); v != nil && v.kind() != "Sequence" {
				fs.lowerExpr(v)
			}
		default:
			fs.lowerExpr(kw.node("value"))
		}
	}
	return true
}

func (fs *funcState) lowerCall(n astNode) *ir.Value {
	funcNode := n.node("func")
	if funcNode != nil && funcNode.kind() == "Attribute" && funcNode.str("attr") == "format" {
		return fs.lowerFormatCall(n, funcNode)
	}

	// Tornado request-argument accessor via `self` in a handler-class method
	// (self.get_argument(...) / self.get_body_argument(...)): untrusted input.
	// Lower the arguments for their side effects, then return a synthetic source
	// (CVE-2025-47782 motioneye). Checked before self-method resolution so it wins
	// over an (accidental) sibling-method match.
	if fs.selfArgMethod(funcNode) {
		for _, a := range n.list("args") {
			fs.lowerExpr(a)
		}
		for _, kw := range n.list("keywords") {
			fs.lowerExpr(kw.node("value"))
		}
		return fs.emitHandlerSource(n, "self."+funcNode.str("attr"))
	}

	// Thread/process DISPATCH: threading.Thread(target=run, args=(x,)) hands a
	// callback + its arguments to a worker the runtime invokes later. Model it as a
	// deferred call run(x) so taint flows into the worker's parameters (the
	// pyload-class miss). Library knowledge (which APIs defer, argument layout) lives
	// here in the frontend; the engine sees only a generic indirect call. When it
	// matches, the whole construct is consumed — return an opaque handle for the
	// worker object so `t = Thread(...); t.start()` stays inert and the forwarded
	// args are not lowered a second time by the normal call path below.
	if fs.emitDeferredDispatch(n, funcNode) {
		return ssabuild.Reg(fs.newReg())
	}

	c := fs.classifyCallee(funcNode)

	if c.shape == callDirect || c.shape == callSelfMethod {
		// Lower any call embedded in the callee chain, so a chained call like
		// requests.get(url).json() still emits the inner requests.get call (an SSRF
		// sink) even though the outer call is `.json()`. For an INVOKE the receiver
		// was lowered during classification, which already recurses through embedded
		// calls (and an indirect callee is a bare Name — nothing nested).
		fs.lowerNestedCallees(funcNode)
	}

	cc := &ir.CallCommon{Callee: c.callee}
	op := ir.OpCode_OP_CODE_CALL
	switch c.shape {
	case callInvoke:
		cc.Value = c.value // receiver -> callee param 0 (CHA seedInvokeArgs)
		cc.MethodName = funcNode.str("attr")
		cc.IsInvoke = true // the engine gates CHA dispatch on this field
		// Python has no static receiver type, so this INVOKE is resolved by bare
		// method NAME. Flag it so the engine dispatches it only when the name is
		// unambiguous (a type-resolved invoke would fan out) — the dispatch
		// discipline is thus chosen from IR, not a language check in the engine.
		cc.UntypedDispatch = true
		op = ir.OpCode_OP_CODE_INVOKE
	case callIndirect:
		// c.callee is empty — that marks the indirect call; the function value is
		// the resolution target the engine reads from Call.Value.
		cc.Value = c.value
	case callSelfMethod:
		cc.Value = &ir.Value{Kind: &ir.Value_FuncName{FuncName: c.callee}}
		// Pass the receiver as the first argument so the call's arguments line up
		// with the method's parameters (param[0] == self), matching how Go SSA
		// passes a method receiver — without this the explicit args map one slot
		// too low (x -> self) and taint is lost.
		cc.Args = append(cc.Args, ssabuild.Reg(fs.selfName))
	case callDirect:
		cc.Value = &ir.Value{Kind: &ir.Value_FuncName{FuncName: c.callee}}
	}
	appendArg := func(a astNode) {
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	for _, a := range n.list("args") {
		appendArg(a)
	}
	for _, kw := range n.list("keywords") {
		// A keyword argument's NAME is otherwise lost: gIR carries positional args
		// only, and a call site may pass keywords in any order, so `shell=True` and
		// `check=True` lower identically. Tag a CONSTANT-valued keyword with a
		// builtin.kwarg marker so a rule guard can read `.Name` and distinguish a
		// dangerous configuration flag from an innocuous one. Only constants are
		// wrapped: a constant carries no taint, so the marker can never hide a
		// tainted value from the engine (`**kwargs` splats have no name and are
		// left alone).
		a := kw.node("value")
		name := kw.str("arg")
		// A `**kwargs` splat has no name to record, so it stays a plain argument.
		if name == "" {
			appendArg(a)
			continue
		}
		v := fs.lowerExpr(a)
		if v.GetConstant() != nil {
			v = fs.emitKwargMarker(name, v, kw)
		}
		cc.Args = append(cc.Args, v)
	}

	inst := fs.newValueInst(n)
	inst.Op = op
	inst.Call = cc
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// callShape classifies a Call's callee into one of the four shapes lowerCall
// emits. classifyCallee decides it ONCE, with one early return per shape (the
// emitDeferredDispatch style), so mutual exclusivity is structural rather than
// implicit in a chain of accumulated boolean flags.
type callShape int

const (
	// callDirect: a call through a resolved/syntactic callee name (module
	// function, builtin, imported name). Call.Value names the callee.
	callDirect callShape = iota
	// callSelfMethod: `self.method(x)` resolved to the sibling method's
	// canonical name; lowerCall prepends the receiver to the args
	// (param[0] == self).
	callSelfMethod
	// callInvoke: `obj.method(a)` on a genuine object — a CHA INVOKE with the
	// lowered receiver in Call.Value and the bare method in Call.MethodName.
	callInvoke
	// callIndirect: `fn(x)` through a function VALUE — empty Callee, the
	// resolution target in Call.Value.
	callIndirect
)

// classifiedCall is the sum classifyCallee returns: the shape constant plus
// its associated values — the callee name (empty for callIndirect, the
// engine's indirect-call marker) and, for callInvoke/callIndirect, the value
// that goes in Call.Value (the lowered receiver / the function value).
type classifiedCall struct {
	shape  callShape
	callee string
	value  *ir.Value
}

// classifyCallee classifies a Call's `func` node. It is NOT side-effect free:
// for callInvoke it lowers the receiver expression (which recurses through any
// call embedded in the chain), and for callIndirect the fs.read probe may
// materialise a PHI — both exactly the work the shape's lowering needs anyway,
// done at the same point in instruction order as before.
func (fs *funcState) classifyCallee(funcNode astNode) classifiedCall {
	callee := "py:" + fs.resolveDotted(dottedName(funcNode))
	if funcNode == nil {
		return classifiedCall{shape: callDirect, callee: callee}
	}
	switch funcNode.kind() {
	case "Name":
		id := funcNode.str("id")
		// A bare call to a module-level function (helper(x)) must carry the module
		// name so its callee matches the function's CanonicalName
		// ("py:<module>.helper"); otherwise byKey never resolves it and taint does
		// not flow through the local helper. Builtins (open, print) and imported
		// names are not in localFuncs, so they are left unqualified.
		if fs.localFuncs[id] {
			return classifiedCall{shape: callDirect, callee: "py:" + fs.moduleName + "." + id}
		}
		// Indirect call through a function VALUE the current function holds — `fn(x)`
		// where `fn` is a parameter (the higher-order-callback case) or a local bound
		// to a function reference. The syntactic callee `py:fn` names no lowered
		// function, so a plain CALL would drop taint at the boundary; instead emit an
		// INDIRECT call (empty Callee, the function value in Call.Value) that the
		// engine resolves through its function-value points-to set. Excludes local
		// functions (already resolved to their canonical name above) and
		// imported/builtin names (they must keep their resolved callee so sink/source
		// globs match).
		if !fs.importedNames[id] && fs.assigned[id] {
			if v := fs.read(id); fs.paramRegs[id] || v.GetFuncName() != "" {
				return classifiedCall{shape: callIndirect, value: v}
			}
		}
	case "Attribute":
		// `self.method(x)` inside a class method: qualify to the sibling method's
		// canonical name so byKey resolves it (like a local-function call). This is
		// optimistic — if the attribute is not actually a method, the qualified name
		// matches no function and the call simply stays unresolved (harmless).
		if fs.selfName != "" {
			if base := funcNode.node("value"); fs.isNameRef(base) {
				return classifiedCall{shape: callSelfMethod, callee: "py:" + fs.moduleName + "." + fs.methodPrefix + funcNode.str("attr")}
			}
		}
		// Object-method call `obj.method(a, b)` on a genuine object — the receiver is
		// rooted in a local/param/self value, NOT an imported module and NOT resolved
		// through an import/request alias. Lower it as a CHA INVOKE (receiver in
		// Call.Value, bare method in Call.MethodName) so the engine dispatches it to
		// every same-named user method (methodImpls), like a Go/Java instance call.
		// Without this, taint drops at every object-method boundary because the
		// syntactic callee `py:obj.method` names no lowered function. Library calls
		// (subprocess.run, os.system, a module function) are excluded via importedNames
		// and still match sink globs as plain CALLs; sink globs also match an INVOKE's
		// Callee, so a method-named sink like `cursor.execute` still fires.
		recvNode := funcNode.node("value")
		if root := rootName(funcNode); root != "" && !fs.importedNames[root] {
			_, isAlias := fs.aliases[root]
			_, isLocal := fs.localAlias[root]
			if !isAlias && !isLocal {
				return classifiedCall{shape: callInvoke, callee: callee, value: fs.lowerExpr(recvNode)}
			}
		} else if recvNode != nil && (recvNode.kind() == "Call" || recvNode.kind() == "Subscript") {
			// Chained method call whose receiver is a computed VALUE, e.g.
			// `p.strip().split(",")` or `items[0].strip()`. rootName is "" for a
			// call/subscript-rooted chain, so the name-based branch above misses it;
			// capture the receiver as Call.Value so a method propagator (the callee
			// is "py:<dynamic>.<method>", which still matches "py:*.<method>") can
			// forward taint through the chain instead of dropping it.
			return classifiedCall{shape: callInvoke, callee: callee, value: fs.lowerExpr(recvNode)}
		}
	}
	return classifiedCall{shape: callDirect, callee: callee}
}

// lowerNestedCallees lowers any call embedded in a callee's base chain (the
// `value` side of an Attribute), so the inner call in a chained expression like
// requests.get(u).json() is emitted as its own instruction — and can match a
// source/sink glob — even though only the outermost call reaches lowerCall
// directly. Recursion through lowerExpr -> lowerCall handles deeper chains
// (a.b(x).c(y).d()).
func (fs *funcState) lowerNestedCallees(funcNode astNode) {
	if funcNode == nil {
		return
	}
	switch funcNode.kind() {
	case "Attribute":
		fs.lowerNestedCallees(funcNode.node("value"))
	case "Call":
		fs.lowerExpr(funcNode) // emits the inner call; its result is unused here
	}
}

func (fs *funcState) lowerFormatCall(n, funcNode astNode) *ir.Value {
	// "...".format(a, b=c) concatenates the format string with every positional
	// and keyword argument value, so taint from any of them reaches the result.
	acc := fs.lowerExpr(funcNode.node("value"))
	for _, a := range n.list("args") {
		acc = fs.emitBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(a), n)
	}
	for _, kw := range n.list("keywords") {
		acc = fs.emitBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(kw.node("value")), n)
	}
	return acc
}

// dottedName builds a canonical, purely syntactic dotted callee name from a
// Call's `func` AST node, e.g. Attribute(Attribute(Name("request"),"args"),
// "get") -> "request.args.get". It does not resolve values through the
// environment (a callee name reflects source syntax, not runtime identity),
// matching how the task describes building sink/source names. A callee
// rooted in something other than a plain Name/Attribute chain (e.g. a nested
// Call, Subscript, or Lambda) resolves to "<dynamic>" for that sub-path, so
// e.g. `get_cursor().execute(x)` yields "<dynamic>.execute" -- glob patterns
// like "py:*.execute" still match it.
func dottedName(n astNode) string {
	if n == nil {
		return "<dynamic>"
	}
	switch n.kind() {
	case "Name":
		return n.str("id")
	case "Attribute":
		return dottedName(n.node("value")) + "." + n.str("attr")
	default:
		return "<dynamic>"
	}
}

// constantValue converts a pyast.py Constant node into a gIR constant Value.
func constantValue(n astNode) *ir.Value {
	c := &ir.Constant{}
	switch n.str("value_type") {
	case "bool":
		b, _ := n.raw("value").(bool)
		c.Value = &ir.Constant_BoolVal{BoolVal: b}
	case "int":
		if num, ok := n.raw("value").(json.Number); ok {
			if i, err := num.Int64(); err == nil {
				c.Value = &ir.Constant_IntVal{IntVal: i}
			}
		}
	case "float":
		if num, ok := n.raw("value").(json.Number); ok {
			if f, err := num.Float64(); err == nil {
				c.Value = &ir.Constant_FloatVal{FloatVal: f}
			}
		}
	case "str":
		s, _ := n.raw("value").(string)
		c.Value = &ir.Constant_StringVal{StringVal: s}
	case "none":
		c.IsNil = true
	default: // "other": best-effort string representation (repr()).
		if s, ok := n.raw("value").(string); ok {
			c.Value = &ir.Constant_StringVal{StringVal: s}
		}
	}
	return &ir.Value{Kind: &ir.Value_Constant{Constant: c}}
}

func binOpKind(op string) ir.BinOpKind {
	switch op {
	case "ADD":
		return ir.BinOpKind_BIN_OP_ADD
	case "SUB":
		return ir.BinOpKind_BIN_OP_SUB
	case "MUL":
		return ir.BinOpKind_BIN_OP_MUL
	case "QUO":
		return ir.BinOpKind_BIN_OP_QUO
	case "REM":
		return ir.BinOpKind_BIN_OP_REM
	case "AND":
		return ir.BinOpKind_BIN_OP_AND
	case "OR":
		return ir.BinOpKind_BIN_OP_OR
	case "XOR":
		return ir.BinOpKind_BIN_OP_XOR
	case "SHL":
		return ir.BinOpKind_BIN_OP_SHL
	case "SHR":
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

func unOpKind(op string) ir.UnOpKind {
	switch op {
	case "NOT":
		return ir.UnOpKind_UN_OP_NOT
	case "NEG":
		return ir.UnOpKind_UN_OP_NEG
	case "POS":
		return ir.UnOpKind_UN_OP_POS
	case "BIT_NOT":
		return ir.UnOpKind_UN_OP_BIT_NOT
	}
	return ir.UnOpKind_UN_OP_UNSPECIFIED
}

// posFromNode reads the {"line","col"} pos object pyast.py attaches to every
// node and converts it to a gIR Position. Returns nil if unavailable (e.g. a
// zero position), matching converters/go's convertPos returning nil for
// invalid token.Pos.
func posFromNode(filename string, n astNode) *ir.Position {
	p := n.node("pos")
	if p == nil {
		return nil
	}
	line := numberField(p, "line")
	col := numberField(p, "col")
	if line == 0 && col == 0 {
		return nil
	}
	return &ir.Position{
		Filename: filename,
		Line:     int32(line),
		Column:   int32(col),
	}
}

func numberField(n astNode, key string) int64 {
	num, ok := n.raw(key).(json.Number)
	if !ok {
		return 0
	}
	i, err := num.Int64()
	if err != nil {
		return 0
	}
	return i
}

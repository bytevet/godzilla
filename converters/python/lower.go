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
// the module-level name tables. Built once in convertModule and threaded into
// convertModuleInit and convertFunction.
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

// convertModule turns one parsed Python file (root = pyast.py's
// {"kind":"Module", ...} node) into a gIR Module. Every `def` — nested defs and
// methods included — becomes its own ir.Function; the remaining module-level
// statements are collected into one synthetic "<module>" function.
func convertModule(root astNode, filename, moduleName string, classes routeClasses) *ir.Module {
	mod := &ir.Module{
		Name:     moduleName,
		Language: "python",
	}

	var functions []*ir.Function

	// Top-level `def` names, consumed by classifyCallee to qualify a bare call.
	// A nested def called by bare name is a documented limitation: the lowering
	// does not model Python's lexical scoping.
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

	// collect walks the statement tree, lowering each FunctionDef/ClassDef at any
	// nesting depth into its own ir.Function and tracking a dotted qualname prefix
	// ("MyClass." for a method, "outer." for a closure nested in outer). `classes`
	// carries the route-handler recognition tables (see below).
	//
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

	// A bare-Name assign emits no instruction, so a module-level `NAME = <literal>`
	// would live only in the <module> function's register map and stay invisible to
	// passes that inspect the IR for literals — above all the hardcoded-secret
	// scanner. Surface each as a gIR Global with its init value instead.
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

// convertModuleInit lowers a file's top-level straight-line statements (skipping
// def/class bodies, which become their own functions) into the synthetic
// entry-point function.
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
// parameters (see routeHandlerParams), each seeded as a taint source below.
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
	// Guarding on the conventional self/cls name keeps sibling-method resolution
	// from misfiring in an ordinary function.
	if hasSelfReceiver(params) {
		fs.selfName = params[0]
		fs.methodPrefix = qualPrefix
	}

	// Seed each route-handler parameter as a taint source: emit the synthetic
	// source CALL at function entry and rebind the param name to its tainted
	// result, so every subsequent read of the param carries taint.
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
// accessor calls, so a handler's params must be seeded as sources or the flow is
// never tainted. Rather than special-case each framework in the detection LOGIC,
// the frontend recognizes three generic SHAPES driven by the declarative tables
// below — so adding a framework (aiohttp, Sanic, Django CBV, Falcon, …) is a data
// edit here, not new code:
//
//  1. a function carrying a routeDecorators decorator — a dotted HTTP verb
//     (@app.get, @routes.post) or a bare routing symbol (@route, @expose,
//     @action). The decorator NAME is what covers the class-based APIs, whose
//     methods are named `data`/`upload_example` rather than after a verb;
//  2. a `<verb>`-named method, verb in handlerMethodVerbs, of a class
//     subclassing one of handlerBaseClasses (matched by simple base name,
//     transitively);
//  3. a BARE HTTP verb decorator inside a dispatch class (see routeClasses).
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
		// Django CBVs + DRF APIView. A verb method of a subclass takes the URL
		// captures as params after (self, request). The concrete generic views are
		// listed alongside `View` because their own base is declared in Django, not
		// user code, so the transitive closure alone cannot reach them.
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
		// deliberately NOT in handlerMethodVerbs: request.data/.query_params
		// already cover them as precise source globs, so seeding would buy almost
		// nothing while making every helper method named `create`/`update` in any
		// handler class a taint origin. A ViewSet's CUSTOM actions carry the
		// untrusted input and shape 1 catches those by their @action decorator.
		// Listing the bases still makes `self.request` resolve inside them.
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
	// requestObjectParams name a handler parameter holding the framework REQUEST
	// OBJECT itself rather than an untrusted URL capture. Excluded from synthetic
	// param sources: the request.GET/.POST/.data accessors are already precise
	// source globs, and seeding the whole object is less precise (request.user /
	// request.method are not injection sources).
	requestObjectParams = map[string]bool{"request": true, "websocket": true}
)

// routeHandlerParams returns the untrusted parameter names of a `def` when it is
// a web-route handler (one of the shapes above), or nil otherwise. Detection is
// deliberately conservative to avoid false positives: a decorated route's params
// exclude self/cls, request/websocket, and Depends()/Security()-injected params;
// a handler-class verb method contributes its params after self/cls (the URL
// route captures).
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
			// Union rather than overwrite: this runs across ALL files, so a class
			// name declared in more than one keeps every base it declares.
			out[s.str("name")] = append(out[s.str("name")], s.strList("bases")...)
			collectClassBases(s.list("body"), out)
		case "FunctionDef":
			collectClassBases(s.list("body"), out)
		}
	}
}

// handlerClasses returns the class names that subclass one of targetBases
// (matched by simple base name) directly or transitively, to a fixpoint.
//
// The result holds only the DERIVED subclasses, never the seeds: the original
// caller's seeds are external framework names (`RequestHandler`, `View`) the
// program does not define, and folding them in would make a program's own
// unrelated `class View:` a request handler. A caller whose seeds ARE program
// classes unions them back in itself.
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
	// Do not reintroduce an access-control decorator co-signal (`@permission`,
	// `@login_required`): it is ANTI-correlated with risk, excluding exactly the
	// unauthenticated endpoints most worth seeding.
	dispatch map[string]bool
}

type classCtx struct{ handler, dispatch bool }

func (rc routeClasses) ctxFor(class string) classCtx {
	return classCtx{handler: rc.handler[class], dispatch: rc.dispatch[class]}
}

// collectDispatchVerbs records, per class, the distinct bare HTTP verbs its
// methods are decorated with, recursing into nested classes and functions. Keyed
// by simple class name and unioned across files by the caller, like
// collectClassBases.
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
// `@post` on sibling methods of one class is a routing table. The hierarchy step
// covers the common shape where a base holds the routing surface and each
// subclass adds handlers with a SINGLE verb, too little evidence on its own.
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
// origin is built from: a CALL to routeParamSource whose RESULT register the
// engine seeds. The wrappers below are its only producers.
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

// emitParamSource is emitRouteSource for a route-handler parameter. The param is
// passed as the sole argument for readability only: taint lands on the call
// RESULT, which convertFunction rebinds to the param name.
func (fs *funcState) emitParamSource(param string, n astNode) *ir.Value {
	return fs.emitRouteSource(n, "route-param-source:"+param, ssabuild.Reg(param))
}

// emitHandlerSource is emitRouteSource for a request accessor reached through
// `self` in a handler-class method (Tornado self.get_argument /
// self.request.body).
func (fs *funcState) emitHandlerSource(n astNode, label string) *ir.Value {
	return fs.emitRouteSource(n, "handler-request-source:"+label)
}

// Tornado request accessors reached via `self` inside a handler-class method:
// call accessors (self.get_argument(...)) and attribute reads off self.request.
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
// lowered into. `assigned` answers what the Builder's per-block value map cannot
// — is this bare name a bound local, or a free identifier / module global /
// import? `paramRegs` is the set of register names that are this function's own
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

	// moduleName and localFuncs let classifyCallee qualify a bare local call.
	moduleName string
	localFuncs map[string]bool

	// constGlobals are the module's provably-immutable string constants, inlined
	// at their use sites by lookupName. See constglobal.go.
	constGlobals map[string]*ir.Constant

	// selfName is the receiver param ("self" or "cls"); methodPrefix is the class
	// qualname prefix ("UserAPI."). Together they resolve `self.method(x)` to the
	// sibling method's canonical name. Both empty for non-methods.
	selfName     string
	methodPrefix string

	// inHandlerClass marks that this function is a method of a web request-handler
	// class (see routeClasses.handler), which is what makes a request read via
	// `self` untrusted input — see selfRequestAccessor / selfArgMethod.
	inHandlerClass bool

	// aliases maps a locally-bound import name to its canonical dotted path
	// ("sp" -> "subprocess"). resolveDotted rewrites a callee's root through it so
	// module-anchored sink rules match regardless of aliasing.
	aliases map[string]string

	// localAlias maps a local variable to the request-rooted attribute path it was
	// assigned (`a` -> "request.args" for `a = request.args`), per function. It lets
	// resolveDotted rewrite `a.get(...)` to `request.args.get` so the existing
	// request source globs match the aliased form (CVE-2025-52967). Narrow to
	// request-rooted chains to stay FP-safe.
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

// requestAliasPath returns the request-rooted attribute path an assignment's RHS
// names (`request.<...>`, or a ternary between such chains), else "" — what lets
// `a = request.args; a.get("k")` resolve to the same `request.args.get` source
// the inline form matches.
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
// per-function request-alias table and the import alias table, so `a.get`
// becomes `request.args.get` and `sp.call` becomes `subprocess.call`. Names with
// no alias pass through.
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
// statements — INCLUDING plain `import subprocess`, which collectImportAliases
// does not record. A method call whose receiver root is an imported name is a
// library/module call matched by sink globs on its callee; it must NOT become a
// CHA INVOKE, which would fan the (often tainted) argument into every same-named
// user method. classifyCallee gates INVOKE emission on this.
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

// collectImportAliases returns the local-name -> canonical-dotted-path map for a
// module body: `import x as y` binds y->x, `from m import n as a` binds a->m.n;
// relative imports are skipped.
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

// newValueInst allocates a fresh instruction with a result register, for
// value-producing ops (CALL, FIELD, INDEX, BIN_OP, UN_OP, INTRINSIC).
func (fs *funcState) newValueInst(n astNode) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: posFromNode(fs.filename, n)}
}

// newVoidInst allocates a fresh instruction with no result register (STORE/RET).
func (fs *funcState) newVoidInst(n astNode) *ir.Instruction {
	return &ir.Instruction{Pos: posFromNode(fs.filename, n)}
}

// emitKwargMarker tags a constant keyword-argument value with the name it was
// passed under, as a `builtin.kwarg(<name>, <value>)` intrinsic whose result
// stands in for the value in the call's argument list. gIR carries positional
// arguments only, so this is what lets a rule guard tell `shell=True` from
// `check=True`. Only CONSTANTS may be wrapped: a constant carries no taint, so
// the marker can never hide a tainted value from the engine.
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
// The engine lists this intrinsic in intrinsicPropagators (internal/analysis/
// taint.go), so taint on any element flows to that register and a later
// whole-container use — json.dumps(d), a template context, a response body —
// observes it.
//
// Elements go in Operands, not Call.Args: visitIntrinsic propagates with
// markTaintFromOperands, which reads Operands.
//
// Emitted even for an EMPTY container, because the register is the point:
// visitStore early-returns on a constant destination, so `d = {}` lowered as a
// constant would drop `d[k] = tainted`.
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
// the results — shared by the literal and comprehension cases.
func (fs *funcState) lowerAggregate(intrinsic string, elts []astNode, n astNode) *ir.Value {
	vals := make([]*ir.Value, 0, len(elts))
	for _, e := range elts {
		vals = append(vals, fs.lowerExpr(e))
	}
	return fs.emitAggregate(intrinsic, vals, n)
}

// selfFieldGlobal returns the synthetic global key for a one-level `self.<field>`
// access inside a method, or "" when node is not such an access. It is the
// cross-method channel for instance-field taint: the store/read carry this key as
// a GlobalName operand, which the engine's recordGlobalStore / readGlobalTaint
// already handle, so `self.f = tainted` in one method reaches a sibling's read of
// `self.f` with NO engine change. Object-insensitive (all instances share the
// key) but scoped to the method's own class+module, so a same-named field on an
// unrelated class cannot alias.
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
// binds its `target` to that value (element taint == container taint).
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
// imported symbol). Factored out of lowerExpr's "Name" case so the Subscript
// case (see isOpaqueBase) can classify a chain's root before deciding what to
// emit.
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
	// A module-level string constant is inlined as its literal so every consumer
	// of constant text can read it; only names constStringGlobals proved
	// immutable reach here. See constglobal.go.
	if c, ok := fs.constGlobals[id]; ok {
		return &ir.Value{Kind: &ir.Value_Constant{Constant: c}}
	}
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: id}}
}

// isOpaqueBase reports whether v is a value whose origin is outside this
// function's own straight-line computation: either a free/global identifier
// (Value_GlobalName, e.g. `request` or `os`) or one of this function's own
// parameters (Value_RegName for a name in fs.paramRegs). Mirrors
// converters/javascript's funcState.isOpaqueBase (see that package's doc, "the
// opaque object source heuristic"): a Subscript read rooted at either kind of
// value is the first opportunity to introduce taint, since the engine only ever
// seeds taint at a CALL matching a source glob.
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
// chain bottoms out in something else (a nested Call or Subscript). Gives
// lowerSubscript / classifyCallee the name to classify with isOpaqueBase.
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
// PHI) via the Builder for the control-flow compounds and lowering straight-line
// statements into the current block, so a function with no branches still emits
// exactly ONE block (the engine's linear fast path). FunctionDef/ClassDef are
// skipped — each becomes its own ir.Function via convertModule.collect.
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
			// `with EXPR as VAR:` lowers as `VAR = EXPR`, so a sink/source CALL such
			// as open(...) is emitted rather than dropped. The body goes straight
			// into the current block (it may itself branch; lowerBody handles that).
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

// lowerIf lowers `if cond: body [elif/else: orelse]` into a REAL CFG diamond via
// the Builder's IfDiamond scaffold, so a variable rebound on either arm
// reconciles via an on-demand ReadVariable PHI — which is what keeps the
// pre-branch tainted value alive through the "default if empty" idiom
// `if not x: x = "d"`. Python's `elif` is an `If` node in the parent's `orelse`,
// so a chain becomes nested diamonds via the recursive lowerBody.
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
// block and the target rebound to its value at the top of the BODY block each
// iteration (element taint == container taint). The iteration condition is an
// opaque placeholder, so the engine traverses both the body and the exit.
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
// conservatively (a may-analysis; no exception typing). The body and its `else`
// go into the current block; an EXCEPTION EDGE then models that an exception may
// occur anywhere in the body, branching to a single handler block (every `except`
// clause lowered sequentially into it) or to an after block. `finally` runs on
// both paths, so it is lowered into the after block.
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
			// Track the request-attribute alias (see requestAliasPath); a rebind
			// to a non-request value must CLEAR any stale one.
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
		// The current block ends here: an arm that returns must not feed its
		// values into a merge / loop header.
		fs.terminated = true
	case "Pass", "Import", "ImportFrom", "Global", "Nonlocal", "Break", "Continue", "Raise", "Assert", "Delete", "Unknown":
		// No-ops / unsupported: dropped. Unlike an unsupported EXPRESSION, which
		// must still yield a value for its parent, a dropped statement leaves no
		// gap in the IR.
	default:
		// Should not happen given pyast.py's schema, but stay defensive.
	}
}

// assign binds a lowered value to an assignment target. A bare Name rebinds the
// variable. An Attribute/Subscript target (obj.attr = v / arr[i] = v) emits a
// STORE with the base object as the address operand, which is what lets a
// tainted value written into a container mark that container tainted. Any target
// shape not handled below is dropped.
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
		// `self.<field> = v` also stores into the per-(class, field) synthetic
		// global (see selfFieldGlobal); the STORE above still carries intra-method
		// / whole-object flow.
		if g := fs.selfFieldGlobal(target); g != "" {
			s := fs.newVoidInst(target)
			s.Op = ir.OpCode_OP_CODE_STORE
			s.Operands = []*ir.Value{ssabuild.Global(g), val}
			fs.emit(s)
		}
	case "Sequence":
		// Unpacking `a, b = rhs`: bind each element to the whole RHS value
		// (element taint == container taint, conservative for recall).
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

// lowerExpr lowers an expression to a gIR Value, emitting whatever instructions
// are needed to compute it into the current block.
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
		// The untrusted Tornado request payload: a synthetic source, not a plain
		// field read (CVE-2025-47782).
		if attr, ok := fs.selfRequestAccessor(n); ok {
			return fs.emitHandlerSource(n, "self.request."+attr)
		}
		base := fs.lowerExpr(n.node("value"))
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_FIELD
		inst.Operands = []*ir.Value{base}
		inst.Comment = "attr:" + n.str("attr")
		// A one-level `self.<field>` read carries the per-(class, field) synthetic
		// global as an extra operand, so readGlobalTaint seeds the result when a
		// sibling method tainted it (see selfFieldGlobal). visitFieldRead keys on
		// operand 0 only, so the extra operand is inert to field-sensitivity.
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
		// `a or b` / `a and b` evaluates to one of its operands, so fold them with
		// BIN_OP_OR and let the engine's BIN_OP propagation carry any operand's
		// taint — what makes `request.args.get("x") or default` stay tainted.
		var acc *ir.Value
		for _, v := range n.list("values") {
			acc = fs.foldBinOp(ir.BinOpKind_BIN_OP_OR, acc, fs.lowerExpr(v), n)
		}
		if acc == nil {
			return ssabuild.Str("")
		}
		return acc

	case "IfExp":
		// ternary `a if cond else b`: `test` is lowered for its side effects, then
		// the two arms merge through BIN_OP_OR so taint propagates from either.
		fs.lowerExpr(n.node("test"))
		body := fs.lowerExpr(n.node("body"))
		orelse := fs.lowerExpr(n.node("orelse"))
		return fs.emitBinOp(ir.BinOpKind_BIN_OP_OR, body, orelse, n)

	case "NamedExpr":
		// walrus `target := value`: evaluates to `value` and also binds `target`.
		val := fs.lowerExpr(n.node("value"))
		fs.assign(n.node("target"), val)
		return val

	case "Await":
		// `await x` yields x's resolved value; transparent for taint.
		return fs.lowerExpr(n.node("value"))

	case "Sequence":
		// A list/tuple/set literal — or a flattened dict literal, whose keys and
		// values pyast.py emits as one `elts` run — used as a VALUE, built as a
		// `builtin.aggregate` so element taint reaches a later whole-container use
		// (`json.dumps({"k": tainted})` into a response body, CVE-2025-47783).
		// Command injection keeps its argv precision through py-command-injection's
		// `when:` guard rather than by erasing the container. pyast.py marks a
		// literal that cannot pair its keys as "list".
		intrinsic := aggregateIntrinsic
		if n.str("container") == "dict" {
			intrinsic = aggregateMapIntrinsic
		}
		return fs.lowerAggregate(intrinsic, n.list("elts"), n)

	case "Starred":
		// `*x` spread (func(*args)) carries x's taint into the call.
		return fs.lowerExpr(n.node("value"))

	case "Comprehension":
		// [elt for t in iter if cond ...] and the dict/set/generator forms. Each
		// generator and filter is lowered so a source or sink INSIDE the
		// comprehension (`[cursor.execute(q) for q in ...]`) fires; the result is
		// a builtin.aggregate over the element expressions, like a literal.
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
		// f-string: fold the parts with BIN_OP_ADD so any {expr} slot's taint
		// propagates to the final value.
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
		// A boolean result carries influence, not content, so the operands go into
		// the inert builtin.compare intrinsic rather than a BIN_OP — which is what
		// stops `fmt.Sprint(user == "admin")` reading as an injection. The operands
		// are still lowered (a validator call inside the comparison must fire) and
		// the intrinsic gives a branch condition its def-use edge.
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

// lowerSubscript lowers a Subscript expression. A read rooted at an OPAQUE base
// (a global/imported name or one of this function's parameters) is the first
// opportunity to introduce taint, e.g. request.args["cmd"], so it becomes a
// synthetic source CALL "py:<dotted-base>.__getitem__" rather than a plain
// OP_CODE_INDEX — matching a source glob like "py:*request.args.__getitem__"
// exactly as the equivalent request.args.get("cmd") call does. The base is
// deliberately NOT run through fs.lowerExpr (which would emit an OP_CODE_FIELD
// chain for the ".args" hop): as with a callee, only the syntactic dotted name
// is needed, and arg0 is a symbolic reference carrying it.
//
// A PARAMETER-rooted chain may already be tainted by an inter-procedural caller
// (CVE-2025-47782), and the synthetic source only INTRODUCES taint when its
// dotted name matches a source glob — so by itself it would drop the incoming
// taint. Carrying the parameter register in Call.Value and tagging the call
// builtin.member_read is the cross-frontend contract for this shape (see
// internal/analysis memberReadIntrinsic and converters/javascript
// emitRootPropertyRead): the engine forwards the base's taint to the result. A
// global/free root has no register to carry, so it keeps the plain FuncName form.
//
// A Subscript rooted at a local variable (`local_list[i]`) stays OP_CODE_INDEX:
// not a source, but taint still flows through it via propagatingOps.
func (fs *funcState) lowerSubscript(n astNode) *ir.Value {
	baseNode := n.node("value")
	var idx *ir.Value
	if sl := n.node("slice"); sl != nil {
		idx = fs.lowerExpr(sl)
	} else {
		// a[i:j] slice: no single index expression, so a nil-constant placeholder
		// keeps taint flowing through the base alone.
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
			// Parameter-rooted base: see the doc comment above.
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

// emitDeferredDispatch recognizes a thread/process dispatch construct
// (threading.Thread / multiprocessing.Process) and, when it matches, emits a
// synthesized INDIRECT call target(forwarded-args...) so taint flows into the
// worker the runtime will invoke later, then returns true: it has fully CONSUMED
// the call, and the caller must not re-lower it or the forwarded args are lowered
// twice. Which APIs defer, and their argument layouts, are library knowledge that
// belongs in the frontend; the engine sees only a generic indirect call (empty
// Callee, function value in Call.Value).
//
// Gated on the target resolving to a concrete named function or self-method (a
// FuncName): a same-named method on an unrelated object, or a target that is
// merely a parameter holding some value, is not a dispatch. Unambiguous-only, so
// a miss is a false negative, never a false positive. (Executor.submit /
// run_in_executor need executor-receiver type tracking to be FP-safe.)
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

	// The caller returns without the normal call lowering, so lower the remaining
	// arguments here for their side effects — but never the forwarded tuple
	// elements, already lowered above.
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

// lowerCall lowers a Call node. `"...".format(args)` is special-cased into a
// BIN_OP_ADD concatenation chain (see lowerFormatCall): a .format call therefore
// does NOT appear as a call in the IR — call-graph fidelity at those sites is
// traded for taint propagation that needs no propagator rule.
func (fs *funcState) lowerCall(n astNode) *ir.Value {
	funcNode := n.node("func")
	if funcNode != nil && funcNode.kind() == "Attribute" && funcNode.str("attr") == "format" {
		return fs.lowerFormatCall(n, funcNode)
	}

	// A Tornado request-argument accessor via `self` is untrusted input
	// (CVE-2025-47782); its arguments are lowered for their side effects. Checked
	// before self-method resolution so it wins over an accidental sibling-method
	// match.
	if fs.selfArgMethod(funcNode) {
		for _, a := range n.list("args") {
			fs.lowerExpr(a)
		}
		for _, kw := range n.list("keywords") {
			fs.lowerExpr(kw.node("value"))
		}
		return fs.emitHandlerSource(n, "self."+funcNode.str("attr"))
	}

	// Thread/process DISPATCH (see emitDeferredDispatch). When it matches, the
	// whole construct is consumed: return an opaque handle for the worker object
	// so `t = Thread(...); t.start()` stays inert and the normal call path below
	// does not lower the forwarded args a second time.
	if fs.emitDeferredDispatch(n, funcNode) {
		return ssabuild.Reg(fs.newReg())
	}

	c := fs.classifyCallee(funcNode)

	if c.shape == callDirect || c.shape == callSelfMethod {
		// For an INVOKE the receiver was already lowered during classification
		// (which recurses through embedded calls), and an indirect callee is a bare
		// Name with nothing nested.
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
// emits. classifyCallee decides it ONCE, with one early return per shape, so
// mutual exclusivity is structural rather than implicit in a chain of
// accumulated boolean flags.
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
		// Indirect call through a function VALUE this function holds — `fn(x)` where
		// `fn` is a parameter (higher-order callback) or a local bound to a function
		// reference. The syntactic callee `py:fn` names no lowered function, so a
		// plain CALL would drop taint at the boundary. Imported/builtin names are
		// excluded: they must keep their resolved callee so sink/source globs match.
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
		// Object-method call `obj.method(a, b)` on a genuine object — receiver rooted
		// in a local/param/self value, NOT an imported module and NOT an
		// import/request alias. A CHA INVOKE dispatches it to every same-named user
		// method (methodImpls), like a Go/Java instance call; without it taint drops
		// at every object-method boundary, since `py:obj.method` names no lowered
		// function. Library calls stay plain CALLs via importedNames, and sink globs
		// match an INVOKE's Callee too, so `cursor.execute` still fires.
		recvNode := funcNode.node("value")
		if root := rootName(funcNode); root != "" && !fs.importedNames[root] {
			_, isAlias := fs.aliases[root]
			_, isLocal := fs.localAlias[root]
			if !isAlias && !isLocal {
				return classifiedCall{shape: callInvoke, callee: callee, value: fs.lowerExpr(recvNode)}
			}
		} else if recvNode != nil && (recvNode.kind() == "Call" || recvNode.kind() == "Subscript") {
			// Chained method call whose receiver is a computed VALUE
			// (`p.strip().split(",")`, `items[0].strip()`). rootName is "" for such a
			// chain, so the branch above misses it; capturing the receiver in
			// Call.Value lets a method propagator forward taint through the chain
			// (the callee "py:<dynamic>.<method>" still matches "py:*.<method>").
			return classifiedCall{shape: callInvoke, callee: callee, value: fs.lowerExpr(recvNode)}
		}
	}
	return classifiedCall{shape: callDirect, callee: callee}
}

// lowerNestedCallees lowers any call embedded in a callee's base chain (the
// `value` side of an Attribute), so the inner call in `requests.get(u).json()`
// is emitted as its own instruction — and can match a source/sink glob — even
// though only the outermost call reaches lowerCall directly. Recursion through
// lowerExpr -> lowerCall handles deeper chains.
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

// lowerFormatCall lowers `"...".format(a, b=c)` as a concatenation of the format
// string with every positional and keyword value, so taint from any of them
// reaches the result.
func (fs *funcState) lowerFormatCall(n, funcNode astNode) *ir.Value {
	acc := fs.lowerExpr(funcNode.node("value"))
	for _, a := range n.list("args") {
		acc = fs.emitBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(a), n)
	}
	for _, kw := range n.list("keywords") {
		acc = fs.emitBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(kw.node("value")), n)
	}
	return acc
}

// dottedName builds a canonical, purely SYNTACTIC dotted callee name from a
// Call's `func` node: Attribute(Attribute(Name("request"),"args"),"get") ->
// "request.args.get". It does not resolve values through the environment — a
// callee name reflects source syntax, not runtime identity. A chain rooted in
// something other than a plain Name/Attribute (a nested Call, Subscript, Lambda)
// resolves to "<dynamic>" for that sub-path, so `get_cursor().execute(x)` yields
// "<dynamic>.execute", which glob patterns like "py:*.execute" still match.
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

// posFromNode converts the {"line","col"} pos object pyast.py attaches to every
// node into a gIR Position, or nil when it is unavailable (a zero position).
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

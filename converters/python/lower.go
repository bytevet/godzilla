package py_converter

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	ir "godzilla/pkg/ir/v1"
)

// convertModule turns one parsed Python file (root = the {"kind":"Module", ...}
// node from pyast.py) into a gIR Module. Every `def` (including nested defs
// and methods) becomes its own ir.Function; module-level statements that are
// not defs/classes are collected into one synthetic "<module>" function, the
// Python analogue of Go's package-init/main flattening in converters/go.
func convertModule(root astNode, filename, moduleName string, handlerClassSet map[string]bool) *ir.Module {
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
	var collect func(stmts []astNode, qualPrefix string, inHandlerClass, inClass bool)
	collect = func(stmts []astNode, qualPrefix string, inHandlerClass, inClass bool) {
		for _, s := range stmts {
			switch s.kind() {
			case "FunctionDef":
				srcParams := routeHandlerParams(s, inHandlerClass)
				fn := convertFunction(s, filename, moduleName, qualPrefix, localFuncs, aliases, imported, srcParams, inHandlerClass, inClass)
				functions = append(functions, fn)
				// A nested def inside a handler/method is not itself a verb method of
				// the class, so its handler-class and method context reset.
				collect(s.list("body"), qualPrefix+s.str("name")+".", false, false)
			case "ClassDef":
				// Only methods (nested FunctionDefs) are modeled; other
				// class-body statements are a documented limitation.
				cn := s.str("name")
				collect(s.list("body"), qualPrefix+cn+".", handlerClassSet[cn], true)
			}
		}
	}
	collect(root.list("body"), "", false, false)

	// Module-level constant bindings (NAME = <literal>) are Python module
	// globals. The env-based lowering keeps such a literal only in the
	// <module> function's register map (a bare-Name assign emits no
	// instruction), so a constant referenced from another function — or never
	// referenced at all — is invisible to passes that inspect the IR for
	// literals, most importantly the hardcoded-secret scanner. Surface each as
	// a gIR Global with an init value (the proto's intended home for a module
	// constant), mirroring how package-level vars appear in the Go frontend.
	for _, s := range root.list("body") {
		if s.kind() != "Assign" {
			continue
		}
		val := s.node("value")
		if val.kind() != "Constant" {
			continue
		}
		c := constantValue(val).GetConstant()
		if c == nil {
			continue
		}
		for _, target := range s.list("targets") {
			if target.kind() != "Name" {
				continue
			}
			mod.Globals = append(mod.Globals, &ir.Global{
				Name:      target.str("id"),
				InitValue: c,
				Pos:       posFromNode(filename, val),
			})
		}
	}

	moduleFn := convertModuleInit(root, filename, moduleName, localFuncs, aliases, imported)
	mod.Functions = append([]*ir.Function{moduleFn}, functions...)

	return mod
}

// convertModuleInit lowers a file's top-level straight-line statements
// (skipping nested def/class bodies, which become their own functions) into a
// synthetic entry-point function, analogous to converters/go treating
// package-level init code as part of the SSA program.
func convertModuleInit(root astNode, filename, moduleName string, localFuncs map[string]bool, aliases map[string]string, imported map[string]bool) *ir.Function {
	fn := &ir.Function{
		Name:          moduleName + ".<module>",
		ObjectName:    "<module>",
		PackageName:   moduleName,
		CanonicalName: "py:" + moduleName + ".<module>",
		Synthetic:     true,
	}
	fs := newFuncState(filename)
	fs.moduleName = moduleName
	fs.localFuncs = localFuncs
	fs.aliases = aliases
	fs.importedNames = imported
	fs.lowerBody(root.list("body"))
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
	return fn
}

// convertFunction lowers a single `def` (module-level, nested, or method)
// into an ir.Function containing one straight-line basic block. srcParams names
// this function's route-handler parameters (see routeHandlerParams): each is an
// untrusted taint source and is seeded with a synthetic source CALL below.
func convertFunction(node astNode, filename, moduleName, qualPrefix string, localFuncs map[string]bool, aliases map[string]string, imported map[string]bool, srcParams []string, inHandlerClass, isMethod bool) *ir.Function {
	name := node.str("name")
	qualname := qualPrefix + name

	fn := &ir.Function{
		Name:          qualname,
		ObjectName:    name,
		PackageName:   moduleName,
		CanonicalName: "py:" + moduleName + "." + qualname,
		Pos:           posFromNode(filename, node),
	}
	// Tag a real method (def directly in a class body) with its bare name so the
	// engine can resolve a cross-object call `obj.method(x)` to it via CHA.
	if isMethod {
		fn.MethodName = name
	}

	fs := newFuncState(filename)
	fs.moduleName = moduleName
	fs.localFuncs = localFuncs
	fs.aliases = aliases
	fs.importedNames = imported
	fs.inHandlerClass = inHandlerClass
	params := node.strList("params")
	for _, p := range params {
		v := &ir.Value{Kind: &ir.Value_RegName{RegName: p}}
		fn.Params = append(fn.Params, v)
		fs.env[p] = v
		fs.paramRegs[p] = true
	}
	// A method's first parameter is conventionally `self` (or `cls`); record it
	// and the class qualname prefix so `self.method(x)` calls resolve to the
	// sibling method. Guarding on the self/cls name keeps this from misfiring in
	// ordinary functions.
	if len(params) > 0 && (params[0] == "self" || params[0] == "cls") {
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
		if _, ok := fs.env[p]; !ok {
			continue // defensive: name not an actual parameter
		}
		fs.env[p] = fs.emitParamSource(p, node)
	}

	fs.lowerBody(node.list("body"))
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
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
//     MethodView, … — matched by simple base name, transitively).
//
// routeParamSource is the canonical name of the synthetic source CALL seeded at
// each recognized parameter; it is a source glob in every Python taint rulepack,
// so any dangerous flow off a handler param is covered.
const routeParamSource = "py:@http.param"

var (
	// routeDecoratorVerbs mark a route function via its decorator (@app.get,
	// @router.websocket, …). handlerMethodVerbs mark a verb method of a handler
	// class (get/post/…); no `websocket`, which is a distinct handler class
	// rather than a method name. handlerBaseClasses are the base classes (by
	// simple name) whose subclasses are request handlers.
	routeDecoratorVerbs = map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true, "head": true, "options": true, "websocket": true}
	handlerMethodVerbs  = map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true, "head": true, "options": true}
	handlerBaseClasses  = map[string]bool{"RequestHandler": true, "MethodView": true}
)

// routeHandlerParams returns the untrusted parameter names of a `def` when it is
// a web-route handler (one of the two shapes above), or nil otherwise. Detection
// is deliberately conservative to avoid false positives: a decorated route's
// params exclude self/cls, request/websocket, and Depends()/Security()-injected
// params; a handler-class verb method contributes its params after self/cls (the
// URL route captures).
func routeHandlerParams(node astNode, inHandlerClass bool) []string {
	params := node.strList("params")
	if len(params) == 0 {
		return nil
	}
	if hasRouteDecorator(node) {
		return decoratedRouteParams(node, params)
	}
	if inHandlerClass && handlerMethodVerbs[node.str("name")] {
		return positionalAfterSelf(params)
	}
	return nil
}

// hasRouteDecorator reports whether any decorator is a routing decorator: a
// dotted name whose last component is a routing verb and which has a receiver
// prefix (so a bare @get is not mistaken for one).
func hasRouteDecorator(node astNode) bool {
	for _, d := range node.strList("decorators") {
		if i := strings.LastIndex(d, "."); i >= 0 && routeDecoratorVerbs[d[i+1:]] {
			return true
		}
	}
	return false
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

// positionalAfterSelf returns the params after a leading self/cls receiver (the
// URL route captures for a Tornado / MethodView verb method).
func positionalAfterSelf(params []string) []string {
	if len(params) > 0 && (params[0] == "self" || params[0] == "cls") {
		return params[1:]
	}
	return params
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
				simple := b
				if i := strings.LastIndex(b, "."); i >= 0 {
					simple = b[i+1:]
				}
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

// emitParamSource emits a synthetic source CALL (routeParamSource) whose result
// register carries taint, for a route-handler parameter param. The param value
// is passed as the call's sole argument for readability; the engine seeds taint
// on the call RESULT (which convertFunction rebinds to the param name).
func (fs *funcState) emitParamSource(param string, n astNode) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Comment = "route-param-source:" + param
	inst.Call = &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: routeParamSource}},
		Callee: routeParamSource,
		Args:   []*ir.Value{regValue(param)},
	}
	fs.emit(inst)
	return regValue(inst.Name)
}

// emitHandlerSource emits a synthetic source CALL (routeParamSource) for a
// request accessor reached through `self` in a handler-class method (Tornado
// self.get_argument / self.request.body); its result register carries taint. The
// canonical name is the same @http.param glob every Python taint rulepack already
// treats as a source, so no rule change is needed beyond the accessor's own sink.
func (fs *funcState) emitHandlerSource(n astNode, label string) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Comment = "handler-request-source:" + label
	inst.Call = &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: routeParamSource}},
		Callee: routeParamSource,
	}
	fs.emit(inst)
	return regValue(inst.Name)
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
	if base == nil || base.kind() != "Name" || base.str("id") != fs.selfName {
		return "", false
	}
	return n.str("attr"), true
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
	return base != nil && base.kind() == "Name" && base.str("id") == fs.selfName
}

// funcState holds the per-function lowering state: a monotonically
// increasing temp-register counter, an environment mapping the current
// Python variable name to its most recent gIR value (constant or register),
// the set of register names that are this function's own parameters (see
// isOpaqueBase), and the flat instruction list for the function's single
// basic block.
type funcState struct {
	filename  string
	counter   int
	env       map[string]*ir.Value
	paramRegs map[string]bool
	instrs    []*ir.Instruction

	// moduleName and localFuncs let lowerCall qualify a bare local call
	// (helper(x)) with the module name so its callee "py:<module>.helper"
	// matches the callee function's CanonicalName — without this the call is
	// unresolved and inter-procedural taint through the local helper is lost.
	moduleName string
	localFuncs map[string]bool

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
	return &funcState{filename: filename, env: map[string]*ir.Value{}, paramRegs: map[string]bool{}, localAlias: map[string]string{}}
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

func (fs *funcState) emit(inst *ir.Instruction) {
	fs.instrs = append(fs.instrs, inst)
}

func regValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
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
	if base == nil || base.kind() != "Name" || base.str("id") != fs.selfName {
		return ""
	}
	attr := node.str("attr")
	if attr == "" {
		return ""
	}
	// methodPrefix ends with '.', e.g. "Runner." -> "pyfield:mod.Runner.field".
	return "pyfield:" + fs.moduleName + "." + fs.methodPrefix + attr
}

func globalValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: name}}
}

func stringValue(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
}

func nilValue() *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{IsNil: true}}}
}

// emitBinOp emits an OP_CODE_BIN_OP over (left, right) and returns its result
// register. Positioned at node n.
func (fs *funcState) emitBinOp(kind ir.BinOpKind, left, right *ir.Value, n astNode) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = kind
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return regValue(inst.Name)
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

// lookupName resolves a bare Name reference through the current environment,
// falling back to a GlobalName reference for an unbound name (module global,
// builtin, or imported symbol) -- the same rule the "Name" case of lowerExpr
// applies, factored out here so the Subscript case (see isOpaqueBase) can
// classify a chain's root without emitting anything: a Name lookup has no
// side effects.
func (fs *funcState) lookupName(id string) *ir.Value {
	if v, ok := fs.env[id]; ok {
		return v
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

// lowerBody lowers a statement list, flattening control-flow compounds
// (If/For/While/With/Try) into the enclosing straight-line block and skipping
// FunctionDef/ClassDef (handled separately as their own ir.Function by
// convertModule.collect). See the package doc comment for the rationale and
// tradeoffs of this approximation.
func (fs *funcState) lowerBody(stmts []astNode) {
	for _, s := range stmts {
		switch s.kind() {
		case "FunctionDef", "ClassDef":
			// Converted separately; do not inline.
		case "If":
			// Lower the condition for its side effects: a source bound by a
			// walrus (if (x := request.args.get(...)):) or a sink/source call in
			// the test would otherwise be dropped.
			if t := s.node("test"); t != nil {
				fs.lowerExpr(t)
			}
			fs.lowerIfMerge(s)
		case "While":
			if t := s.node("test"); t != nil {
				fs.lowerExpr(t)
			}
			fs.lowerBody(s.list("body"))
			fs.lowerBody(s.list("orelse"))
		case "For":
			// `for x in iter:` — lower the iterable and bind the loop target to it.
			fs.lowerIterTarget(s)
			fs.lowerBody(s.list("body"))
			fs.lowerBody(s.list("orelse"))
		case "With":
			// `with EXPR as VAR:` lowers as `VAR = EXPR`: lower each context-manager
			// expression (so a sink/source CALL such as open(...) is emitted, not
			// dropped) and bind its `as` target, then lower the body. Without this
			// the whole `with open(tainted) as f: ...` idiom was invisible.
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
			fs.lowerBody(s.list("body"))
			for _, h := range s.list("handlers") {
				fs.lowerBody(h.list("body"))
			}
			fs.lowerBody(s.list("orelse"))
			fs.lowerBody(s.list("finalbody"))
		default:
			fs.lowerStmt(s)
		}
	}
}

// lowerIfMerge lowers a flattened If's body and orelse and PHI-merges the names
// each branch rebinds, instead of the previous last-write-wins overwrite (FE-5).
// Without this, the ubiquitous "default if empty" branch (`if not x: x = "d"`)
// dropped the attacker-controlled value bound before the branch — a real,
// deterministic false negative. A PHI over the two branch values keeps taint
// from EITHER path (the taint engine treats PHI as a propagator).
func (fs *funcState) lowerIfMerge(s astNode) {
	before := maps.Clone(fs.env)

	fs.lowerBody(s.list("body"))
	afterBody := maps.Clone(fs.env)

	// Lower the else branch from the pre-branch bindings (the two branches are
	// mutually exclusive), keeping the already-emitted body instructions.
	fs.env = maps.Clone(before)
	fs.lowerBody(s.list("orelse"))
	afterElse := fs.env

	merged := maps.Clone(afterElse)
	names := map[string]bool{}
	for k := range afterBody {
		names[k] = true
	}
	for k := range afterElse {
		names[k] = true
	}
	for name := range names {
		bv, ev := afterBody[name], afterElse[name]
		if bv == nil {
			bv = before[name] // else-only rebind: body kept the pre-branch value
		}
		if ev == nil {
			ev = before[name] // body-only rebind: else kept the pre-branch value
		}
		if bv == ev || bv == nil || ev == nil {
			continue // unchanged on both paths, or only ever bound on one path
		}
		phi := fs.newValueInst(s)
		phi.Op = ir.OpCode_OP_CODE_PHI
		phi.Operands = []*ir.Value{bv, ev}
		fs.emit(phi)
		merged[name] = regValue(phi.Name)
	}
	fs.env = merged
}

// lowerStmt lowers one leaf statement (i.e. not a control-flow compound;
// those are flattened by lowerBody).
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
// into a container mark that container tainted. Tuple/List (unpacking)
// targets are a documented limitation: silently dropped.
func (fs *funcState) assign(target astNode, val *ir.Value) {
	switch target.kind() {
	case "Name":
		fs.env[target.str("id")] = val
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
			s.Operands = []*ir.Value{globalValue(g), val}
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
// instructions are needed to compute it (appended to fs.instrs). Names bound
// in fs.env resolve to their current value directly (constant or register);
// unbound names (module globals like `request`, `os`, imported symbols) fall
// back to a GlobalName reference.
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
			inst.Operands = append(inst.Operands, globalValue(g))
		}
		fs.emit(inst)
		return regValue(inst.Name)

	case "Subscript":
		baseNode := n.node("value")
		var idx *ir.Value
		if sl := n.node("slice"); sl != nil {
			idx = fs.lowerExpr(sl)
		} else {
			// a[i:j] slice: no single index expression: propagate taint
			// through the base only via a nil-constant placeholder index.
			idx = nilValue()
		}

		// base["key"] rooted at a global/imported name or a function
		// parameter (and never reassigned to a locally-computed value) is the
		// first opportunity to introduce taint, e.g. request.args["cmd"].
		// Lower it to a synthetic source CALL "py:<dotted-base>.__getitem__"
		// instead of a plain OP_CODE_INDEX, so it matches a source glob like
		// "py:*request.args.__getitem__" exactly like the equivalent
		// request.args.get("cmd") call already does (see dottedName and
		// lowerCall). The base is deliberately NOT run through the general
		// fs.lowerExpr (which would emit an unconditional OP_CODE_FIELD chain
		// for e.g. the ".args" hop) -- like lowerCall never lowers its own
		// callee expression, only the purely syntactic dotted name is needed
		// here; arg0 is a symbolic reference carrying that same name. A
		// Subscript rooted at a local variable (e.g. `local_list[i]`) is
		// deliberately left as OP_CODE_INDEX -- it is not itself a source,
		// but taint still flows through it via propagatingOps if the
		// container was tainted some other way.
		if root := rootName(baseNode); root != "" {
			if _, ok := fs.isOpaqueBase(fs.lookupName(root)); ok {
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
				fs.emit(inst)
				src := regValue(inst.Name)
				// When the base is one of THIS function's own parameters read
				// directly (`param[key]`, not `param.attr[key]`), the param may
				// already be tainted by an inter-procedural caller (e.g. a request
				// dict passed into a helper: config.add_camera(device_details) then
				// device_details['path']). The synthetic getitem source above only
				// seeds taint when its dotted name matches a source glob, so it does
				// NOT forward that incoming taint; also index the parameter and merge
				// (BIN_OP_OR) so a tainted-param subscript still propagates, while a
				// request-object glob source keeps firing via the call. Restricted to
				// a plain-Name param base so global/attribute opaque bases are
				// untouched (CVE-2025-47782 motioneye).
				if baseNode.kind() == "Name" && fs.paramRegs[baseNode.str("id")] {
					idxInst := fs.newValueInst(n)
					idxInst.Op = ir.OpCode_OP_CODE_INDEX
					idxInst.Operands = []*ir.Value{fs.lookupName(root), idx}
					fs.emit(idxInst)
					return fs.emitBinOp(ir.BinOpKind_BIN_OP_OR, src, regValue(idxInst.Name), n)
				}
				return src
			}
		}

		base := fs.lowerExpr(baseNode)
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_INDEX
		inst.Operands = []*ir.Value{base, idx}
		fs.emit(inst)
		return regValue(inst.Name)

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
		return regValue(inst.Name)

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
			return stringValue("")
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
		// List/tuple literal as a VALUE: lower each element so a source/sink
		// inside it fires, but return an untainted placeholder — a freshly built
		// container does not itself carry element taint (consistent with
		// comprehensions and list literals; subprocess_argv_safe relies on this).
		for _, e := range n.list("elts") {
			fs.lowerExpr(e)
		}
		return stringValue("")

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
		// result is a freshly built container, so — like a list literal — it
		// does not itself carry element taint (consistent, precise container
		// handling; see subprocess_argv_safe).
		for _, g := range n.list("generators") {
			fs.lowerIterTarget(g)
			for _, cond := range g.list("ifs") {
				fs.lowerExpr(cond)
			}
		}
		for _, key := range []string{"elt", "key", "value"} {
			if e := n.node(key); e != nil {
				fs.lowerExpr(e)
			}
		}
		return stringValue("")

	case "JoinedStr":
		// f-string: fold parts left-to-right with BIN_OP_ADD (string
		// concatenation) so taint carried by any {expr} slot propagates to
		// the final value, same as Python's runtime semantics.
		var acc *ir.Value
		for _, part := range n.list("values") {
			acc = fs.foldBinOp(ir.BinOpKind_BIN_OP_ADD, acc, fs.lowerExpr(part), n)
		}
		if acc == nil {
			acc = stringValue("")
		}
		return acc

	case "FormattedValue":
		return fs.lowerExpr(n.node("value"))

	case "Call":
		return fs.lowerCall(n)

	default:
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "py.unsupported"
		inst.Comment = "unsupported python expression: " + n.kind()
		fs.emit(inst)
		return regValue(inst.Name)
	}
}

// lowerCall lowers a Call node. `"...".format(args)` is special-cased into a
// BIN_OP_ADD concatenation chain (mirroring JoinedStr) instead of an actual
// OP_CODE_CALL, per the task's guidance that string formatting should carry
// taint through the engine's BIN_OP auto-propagation; this means a
// .format(...) call does not appear as a call in the IR (a documented
// tradeoff: call-graph fidelity for .format sites is traded for guaranteed
// taint propagation without needing a propagator rule).
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
			if base := node.node("value"); base != nil && base.kind() == "Name" && base.str("id") == fs.selfName {
				return &ir.Value{Kind: &ir.Value_FuncName{FuncName: "py:" + fs.moduleName + "." + fs.methodPrefix + node.str("attr")}}
			}
		}
	}
	return nil
}

// emitDeferredDispatch recognizes a thread/async dispatch construct and emits a
// synthesized INDIRECT call target(forwarded-args...) so taint flows into the
// worker the runtime will invoke later. The recognized APIs and their argument
// layouts are library knowledge that belongs in the frontend; the engine only
// ever sees a generic indirect call (empty Callee, function value in Call.Value).
// The forwarded args are spread here (dispatch-locally), never by changing the
// global sequence lowering that a direct-argv subprocess call relies on. Emitted
// as a void instruction (fire-and-forget): the worker's return is not consumed.
func (fs *funcState) emitDeferredDispatch(n, funcNode astNode) {
	if funcNode == nil {
		return
	}
	var leaf string
	switch funcNode.kind() {
	case "Attribute":
		leaf = funcNode.str("attr")
	case "Name":
		leaf = funcNode.str("id")
	default:
		return
	}

	var targetNode astNode
	var argNodes []astNode
	switch leaf {
	case "Thread", "Process":
		// threading.Thread(target=run, args=(x, y)) — target/args are keywords.
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
	case "submit":
		// Executor.submit(run, x, y) — target is the first positional arg.
		if pos := n.list("args"); len(pos) >= 1 {
			targetNode = pos[0]
			argNodes = pos[1:]
		}
	case "run_in_executor":
		// loop.run_in_executor(executor, run, x) — target is the second positional.
		if pos := n.list("args"); len(pos) >= 2 {
			targetNode = pos[1]
			argNodes = pos[2:]
		}
	default:
		return
	}
	if targetNode == nil {
		return
	}
	targetVal := fs.funcValueOf(targetNode)
	if targetVal == nil {
		return
	}

	cc := &ir.CallCommon{Value: targetVal} // empty Callee marks the indirect call
	for _, a := range argNodes {
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	inst := fs.newVoidInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = cc
	fs.emit(inst)
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

	// Thread/async DISPATCH: a construct that hands a callback + its arguments to a
	// worker the runtime invokes later — threading.Thread(target=run, args=(x,)),
	// executor.submit(run, x), loop.run_in_executor(None, run, x). Model it as a
	// deferred call run(x) so taint flows into the worker's parameters (the
	// pyload-class miss). Library knowledge (which APIs defer, argument layout) lives
	// here in the frontend; the engine sees only a generic indirect call. Emitted as
	// a side-effect linkage; the actual construction call still lowers below so its
	// result object (`t = Thread(...); t.start()`) is unaffected.
	fs.emitDeferredDispatch(n, funcNode)

	callee := "py:" + fs.resolveDotted(dottedName(funcNode))
	// A bare call to a module-level function (helper(x)) must carry the module
	// name so its callee matches the function's CanonicalName
	// ("py:<module>.helper"); otherwise byKey never resolves it and taint does
	// not flow through the local helper. Builtins (open, print) and imported
	// names are not in localFuncs, so they are left unqualified.
	if funcNode != nil && funcNode.kind() == "Name" && fs.localFuncs[funcNode.str("id")] {
		callee = "py:" + fs.moduleName + "." + funcNode.str("id")
	}
	// `self.method(x)` inside a class method: qualify to the sibling method's
	// canonical name so byKey resolves it (like a local-function call). This is
	// optimistic — if the attribute is not actually a method, the qualified name
	// matches no function and the call simply stays unresolved (harmless).
	isSelfMethod := false
	if fs.selfName != "" && funcNode != nil && funcNode.kind() == "Attribute" {
		if base := funcNode.node("value"); base != nil && base.kind() == "Name" && base.str("id") == fs.selfName {
			callee = "py:" + fs.moduleName + "." + fs.methodPrefix + funcNode.str("attr")
			isSelfMethod = true
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
	invoke := false
	var recvVal *ir.Value
	if !isSelfMethod && funcNode != nil && funcNode.kind() == "Attribute" {
		recvNode := funcNode.node("value")
		if root := rootName(funcNode); root != "" && !fs.importedNames[root] {
			_, isAlias := fs.aliases[root]
			_, isLocal := fs.localAlias[root]
			if !isAlias && !isLocal {
				recvVal = fs.lowerExpr(recvNode)
				invoke = true
			}
		} else if recvNode != nil && (recvNode.kind() == "Call" || recvNode.kind() == "Subscript") {
			// Chained method call whose receiver is a computed VALUE, e.g.
			// `p.strip().split(",")` or `items[0].strip()`. rootName is "" for a
			// call/subscript-rooted chain, so the name-based branch above misses it;
			// capture the receiver as Call.Value so a method propagator (the callee
			// is "py:<dynamic>.<method>", which still matches "py:*.<method>") can
			// forward taint through the chain instead of dropping it.
			recvVal = fs.lowerExpr(recvNode)
			invoke = true
		}
	}
	// Indirect call through a function VALUE the current function holds — `fn(x)`
	// where `fn` is a parameter (the higher-order-callback case) or a local bound to
	// a function reference. The syntactic callee `py:fn` names no lowered function,
	// so a plain CALL would drop taint at the boundary; instead emit an INDIRECT call
	// (empty Callee, the function value in Call.Value) that the engine resolves
	// through its function-value points-to set. Excludes local functions (already
	// resolved to their canonical name above) and imported/builtin names (they must
	// keep their resolved callee so sink/source globs match).
	indirect := false
	var indirectVal *ir.Value
	if !invoke && !isSelfMethod && funcNode != nil && funcNode.kind() == "Name" {
		id := funcNode.str("id")
		if !fs.localFuncs[id] && !fs.importedNames[id] {
			if v, ok := fs.env[id]; ok && (fs.paramRegs[id] || v.GetFuncName() != "") {
				indirect = true
				indirectVal = v
			}
		}
	}

	if !invoke && !indirect {
		// Lower any call embedded in the callee chain, so a chained call like
		// requests.get(url).json() still emits the inner requests.get call (an SSRF
		// sink) even though the outer call is `.json()`. For an INVOKE the receiver
		// is lowered above, which already recurses through embedded calls.
		fs.lowerNestedCallees(funcNode)
	}

	cc := &ir.CallCommon{Callee: callee}
	switch {
	case invoke:
		cc.Value = recvVal // receiver -> callee param 0 (CHA seedInvokeArgs)
		cc.MethodName = funcNode.str("attr")
		cc.IsInvoke = true // the engine gates CHA dispatch on this field
		// Python has no static receiver type, so this INVOKE is resolved by bare
		// method NAME. Flag it so the engine dispatches it only when the name is
		// unambiguous (a type-resolved invoke would fan out) — the dispatch
		// discipline is thus chosen from IR, not a language check in the engine.
		cc.UntypedDispatch = true
	case indirect:
		// Empty Callee marks an indirect call; the function value is the resolution
		// target the engine reads from Call.Value.
		cc.Callee = ""
		cc.Value = indirectVal
	default:
		cc.Value = &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}}
	}
	// For a resolved `self.method(x)` call, pass the receiver as the first
	// argument so the call's arguments line up with the method's parameters
	// (param[0] == self), matching how Go SSA passes a method receiver — without
	// this the explicit args map one slot too low (x -> self) and taint is lost.
	if isSelfMethod {
		cc.Args = append(cc.Args, &ir.Value{Kind: &ir.Value_RegName{RegName: fs.selfName}})
	}
	// An `ast.*` node constructor (ast.Module/ast.Expression/ast.Interactive/...)
	// builds a new AST node from its child nodes; a node assembled from tainted
	// parts is itself tainted. Its children are commonly wrapped in a list
	// (`ast.Module(body=[node], type_ignores=[])`, CVE-2025-3248 langflow), but a
	// list literal is lowered to an untainted placeholder on purpose (a direct-argv
	// subprocess list must NOT be flagged -- see the Sequence case and the
	// subprocess_argv_safe sentinel). So for ast constructors ONLY, spread a
	// sequence argument's elements as direct call args, letting element taint reach
	// the constructor (a rulepack propagator) without touching the general
	// list-taint behavior any sink relies on.
	astCtor := strings.HasPrefix(callee, "py:ast.")
	appendArg := func(a astNode) {
		if astCtor && a != nil && a.kind() == "Sequence" {
			for _, e := range a.list("elts") {
				cc.Args = append(cc.Args, fs.lowerExpr(e))
			}
			return
		}
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	for _, a := range n.list("args") {
		appendArg(a)
	}
	for _, kw := range n.list("keywords") {
		appendArg(kw.node("value"))
	}

	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	if invoke {
		inst.Op = ir.OpCode_OP_CODE_INVOKE
	}
	inst.Call = cc
	fs.emit(inst)
	return regValue(inst.Name)
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

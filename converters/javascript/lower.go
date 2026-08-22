package js_converter

import (
	"fmt"
	"math"
	"strings"

	jsast "github.com/bytevet/esbuild-jsast"

	"github.com/bytevet/godzilla/converters/ssabuild"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// fnID identifies a function node across the collector and the lowering.
//
// An esbuild Expr/Stmt is a VALUE struct {Loc, Data}, so two wrappers around the
// same node are distinct values while their Data interfaces compare equal (the
// node types implement their marker interface on pointer receivers only). Keying
// on Data is therefore the only identity that survives being reached twice; key
// the wrapper and the collector's name is invisible to the lowering, which then
// emits js.unsupported.
//
// The concrete values stored are *jsast.EFunction, *jsast.EArrow and
// *jsast.SFunction.
type fnID any

// unwrap strips the transparent wrappers a TypeScript parse can leave around an
// expression, so collect and lower key the same node pointer.
func unwrap(e jsast.Expr) jsast.Expr {
	for {
		switch v := e.Data.(type) {
		case *jsast.EInlinedEnum:
			e = v.Value
		case *jsast.EAnnotation:
			e = v.Value
		default:
			return e
		}
	}
}

// funcState holds the per-function lowering state. Variable values and the
// per-block instruction stream are owned by an ssabuild.Builder (real CFG +
// on-demand PHI insertion, Braun et al.); `cur` is the block currently being
// lowered into. `assigned` answers what the Builder's per-block value map
// cannot: is this bare name a bound local, or a free identifier / global /
// import? `paramRegs` is the set of registers that are this function's own
// parameters (see isOpaqueBase); `terminated` reports whether the current block
// already emitted a RET, so a returning arm is not wired into a merge / loop
// header / switch fall-through as a predecessor. `nameOf` is the collector's
// shared node->canonical-name map, so an inline function expression/arrow used
// as a value resolves to a FuncName reference to its already-lowered
// ir.Function instead of being inlined again. `src` resolves a symbol Ref to
// its source name (esbuild stores identifiers as Refs, never strings).
type funcState struct {
	src        *jsast.File
	li         *lineIndex
	nameOf     map[fnID]string
	counter    int
	b          *ssabuild.Builder
	cur        ssabuild.BlockID
	assigned   map[string]bool
	paramRegs  map[string]bool
	terminated bool

	// localFuncs maps a top-level function name to its canonical name so
	// lowerCall can qualify a bare call (helper(x)) to "js:<module>.helper" and
	// match the callee function's CanonicalName; otherwise byKey never resolves
	// it and inter-procedural taint through the local helper is lost.
	localFuncs map[string]string

	// moduleName and methodClass let lowerCall qualify a `this.method(x)` call
	// inside a class method to the sibling method's canonical name
	// ("js:<module>.<Class>.method"). methodClass is the class qualname prefix
	// (e.g. "UserController."), empty for non-methods.
	moduleName  string
	methodClass string

	// moduleAliases maps an import-bound name to its canonical module(.member)
	// path (FE-2): "cp" -> "child_process" for `const cp = require('child_process')`,
	// "exec" -> "child_process.exec" for a destructured require or a named ESM
	// import. resolveRequire rewrites a callee's root through it so
	// module-anchored sink rules match.
	moduleAliases map[string]string

	// relativeDefaults maps a name default-imported from a relative (project)
	// module -- `const f = require('./util')` -> f -> "util" (the scan-root-
	// relative module name) -- so a bare call `f(x)` lowers to a resolvable
	// "js:@mod:<module>" marker instead of the unmatchable "js:f".
	// resolveJSCrossModuleCalls rewrites that marker to the module's default
	// export after all files are lowered.
	relativeDefaults map[string]string

	// isHandler marks this function as an HTTP route handler (collected in
	// collect.go); reqParam is the register name of its first parameter — the
	// framework request object. Property reads off reqParam are canonicalized to
	// the conventional `req` base so an arbitrarily-named handler request
	// parameter (`(rq, res) => ...`) still matches the request-source globs (COV-11).
	isHandler bool
	reqParam  string

	// isComponent marks this function as usable as a React component (see
	// isComponentName), which makes its first parameter the props object.
	isComponent bool
}

// reqConventionNames are the request-object parameter names the source globs
// already match by name (req.*/request.*/ctx.*); a handler param already named
// one of these needs no canonicalization.
var reqConventionNames = map[string]bool{"req": true, "request": true, "ctx": true}

// resolveRequire rewrites the root component of a dotted callee name through the
// module-alias table, so `cp.exec` becomes `child_process.exec` and a
// destructured `exec` becomes `child_process.exec` (FE-2). Unaliased roots and
// "<dynamic>" pass through unchanged.
func (fs *funcState) resolveRequire(dotted string) string {
	if len(fs.moduleAliases) == 0 {
		return dotted
	}
	root, rest, hasRest := strings.Cut(dotted, ".")
	canon, ok := fs.moduleAliases[root]
	if !ok {
		return dotted
	}
	if hasRest {
		return canon + "." + rest
	}
	return canon
}

func (fs *funcState) newReg() string {
	r := fmt.Sprintf("t%d", fs.counter)
	fs.counter++
	return r
}

// newValueInst allocates a fresh instruction with a result register (for
// value-producing ops: CALL, FIELD, INDEX, BIN_OP, UN_OP, PHI, INTRINSIC).
func (fs *funcState) newValueInst(loc jsast.Loc) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: fs.li.pos(loc)}
}

// newVoidInst allocates a fresh instruction with no result register (STORE/RET).
func (fs *funcState) newVoidInst(loc jsast.Loc) *ir.Instruction {
	return &ir.Instruction{Pos: fs.li.pos(loc)}
}

func (fs *funcState) emit(inst *ir.Instruction) { fs.b.AddInstr(fs.cur, inst) }

// read returns the SSA value current for a JS local in the current block,
// inserting PHIs on demand (branch joins / loop headers) via the Builder.
func (fs *funcState) read(name string) *ir.Value { return fs.b.ReadVariable(name, fs.cur) }

// write records val as the current value of a JS local, marking the name
// assigned so a later bare read resolves it as a variable rather than a free
// identifier / global / import.
func (fs *funcState) write(name string, val *ir.Value) {
	fs.b.WriteVariable(name, fs.cur, val)
	fs.assigned[name] = true
}

// identName returns the source name of an identifier expression (a plain
// identifier or an ES-module import binding, which esbuild spells as its own
// node), and whether e was one. Identifiers reach the tree as symbol Refs, so
// this is the only route back to what the source actually said.
func identName(f *jsast.File, e jsast.Expr) (string, bool) {
	switch v := unwrap(e).Data.(type) {
	case *jsast.EIdentifier:
		return f.NameOf(v.Ref), true
	case *jsast.EImportIdentifier:
		return f.NameOf(v.Ref), true
	}
	return "", false
}

// calleeCommon builds a CallCommon naming callee both as its FuncName value and
// its Callee (the syntactic name the engine matches against rule globs).
func calleeCommon(callee string) *ir.CallCommon {
	return &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
	}
}

// emitCall emits an OP_CODE_CALL to callee with no receiver, lowering args in
// order, and returns its result register. A caller that needs the instruction
// itself goes through emitCallRecvInst instead.
func (fs *funcState) emitCall(callee string, args []jsast.Expr, loc jsast.Loc) *ir.Value {
	return ssabuild.Reg(fs.emitCallRecvInst(callee, nil, args, loc).Name)
}

// emitCallRecvInst is emitCall returning the instruction, so a caller that needs
// the LOWERED argument values (rather than re-lowering the expressions, which
// would duplicate their side effects) can read them off Call.Args.
func (fs *funcState) emitCallRecvInst(callee string, receiver *ir.Value, args []jsast.Expr, loc jsast.Loc) *ir.Instruction {
	cc := calleeCommon(callee)
	if receiver != nil {
		cc.Value = receiver
	}
	for _, a := range args {
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = cc
	fs.emit(inst)
	return inst
}

// emitPromiseContinuation models `p.then(cb)` by emitting the call it actually
// performs at runtime: cb(<p's resolved value>). Without it a promise is a wall
// taint cannot cross, and in modern Node that wall sits across the middle of
// most request handling.
//
// The continuation is emitted as an INDIRECT call (no callee name, the callback
// in Call.Value), the shape the engine's higher-order machinery already resolves
// through its points-to set — so this needs no engine change, and it inherits
// that path's singleton-only discipline: a `.then` whose callback cannot be
// resolved unambiguously binds nothing rather than guessing.
//
// The receiver stands in for the resolved value, which is what makes the chain
// work: a tainted promise yields a tainted callback parameter. Only `.then`'s
// FIRST argument is treated this way — its second argument, and `.catch`, receive
// the rejection reason, not the value.
func (fs *funcState) emitPromiseContinuation(callee string, receiver *ir.Value, call *ir.Instruction, loc jsast.Loc) {
	if receiver == nil || !strings.HasSuffix(callee, ".then") {
		return
	}
	args := call.Call.GetArgs()
	if len(args) == 0 || args[0] == nil {
		return
	}
	cc := calleeCommon("") // empty callee == indirect; the engine resolves Call.Value
	cc.Value = args[0]
	cc.Args = []*ir.Value{receiver}
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = cc
	fs.emit(inst)
}

// emitStore emits an OP_CODE_STORE of val into the address computed from
// baseExpr (`obj.attr = v` / `arr[i] = v`), so a tainted value written into a
// container marks that container tainted (see visitStore in the taint engine).
func (fs *funcState) emitStore(baseExpr jsast.Expr, val *ir.Value, loc jsast.Loc) {
	base := fs.lowerExpr(baseExpr)
	inst := fs.newVoidInst(loc)
	inst.Op = ir.OpCode_OP_CODE_STORE
	inst.Operands = []*ir.Value{base, val}
	fs.emit(inst)
}

// emitUnsupported emits the generic "js.unsupported" intrinsic placeholder for
// an expression the converter does not model, returning its result register so
// the parent expression still has a value to consume.
func (fs *funcState) emitUnsupported(loc jsast.Loc, comment string) *ir.Value {
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = "js.unsupported"
	inst.Comment = comment
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// moduleCtx bundles the file-scoped state every function lowered from one JS
// module needs, so the module-scoped funcState fields are primed in exactly ONE
// place (newFuncState below) rather than once per call site.
type moduleCtx struct {
	src              *jsast.File
	li               *lineIndex
	moduleName       string
	nameOf           map[fnID]string
	localFuncs       map[string]string
	moduleAliases    map[string]string
	relativeDefaults map[string]string
	handlers         map[fnID]bool
}

// newFuncState creates a funcState for a function in this module, priming the
// module-scoped fields. isHandler is NOT set here: it is per-function and the
// synthetic <module> function is never a handler.
func (m *moduleCtx) newFuncState() *funcState {
	b := ssabuild.NewBuilder()
	entry := b.NewBlock()
	b.Seal(entry) // the entry block has no predecessors, so it is sealed at once.
	return &funcState{
		src:              m.src,
		li:               m.li,
		nameOf:           m.nameOf,
		b:                b,
		cur:              entry,
		assigned:         map[string]bool{},
		paramRegs:        map[string]bool{},
		localFuncs:       m.localFuncs,
		moduleName:       m.moduleName,
		moduleAliases:    m.moduleAliases,
		relativeDefaults: m.relativeDefaults,
	}
}

// lowerFunction lowers one collected function (declaration, function expression,
// or arrow function) into an ir.Function whose body is a REAL CFG built by an
// ssabuild.Builder.
func lowerFunction(m *moduleCtx, pf pendingFunc) *ir.Function {
	fn := &ir.Function{
		Name:          pf.qualname,
		ObjectName:    pf.objectName,
		PackageName:   m.moduleName,
		CanonicalName: "js:" + m.moduleName + "." + pf.qualname,
		Pos:           m.li.pos(pf.loc),
	}

	fs := m.newFuncState()
	fs.isHandler = m.handlers[pf.node]
	// Derived, not carried: unlike isHandler -- a fact only the route
	// registration elsewhere in the AST knows -- this is a pure function of the
	// function's own name, which pendingFunc already holds.
	fs.isComponent = isComponentName(pf.objectName)
	// A method's qualname is "<Class>.<method>" (or nested "<a>.<b>"); record the
	// prefix so `this.method(x)` resolves to the sibling method.
	if i := strings.LastIndexByte(pf.qualname, '.'); i >= 0 {
		fs.methodClass = pf.qualname[:i+1]
	}

	switch node := pf.node.(type) {
	case *jsast.SFunction:
		fs.lowerFnBody(fn, node.Fn)
	case *jsast.EFunction:
		fs.lowerFnBody(fn, node.Fn)
	case *jsast.EArrow:
		fs.bindParams(fn, node.Args, node.HasRestArg)
		fs.lowerBody(node.Body.Block.Stmts)
	}

	fn.Blocks = fs.b.Finish()
	return fn
}

func (fs *funcState) lowerFnBody(fn *ir.Function, f jsast.Fn) {
	fs.bindParams(fn, f.Args, f.HasRestArg)
	fs.lowerBody(f.Body.Block.Stmts)
}

// bindParams binds each parameter (and the rest parameter, if any) to a
// register named after the parameter itself. Destructuring parameters get a
// synthetic "_argN" name so the parameter list stays positionally aligned; the
// pattern's own bindings are not modeled.
//
// esbuild puts the rest parameter LAST in Args with HasRestArg set, rather than
// in a field of its own.
func (fs *funcState) bindParams(fn *ir.Function, args []jsast.Arg, hasRest bool) {
	bind := func(name string) {
		v := ssabuild.Reg(name)
		fn.Params = append(fn.Params, v)
		fs.write(name, v)
		fs.paramRegs[name] = true
	}
	for i, a := range args {
		name := bindingName(fs.src, a.Binding)
		if hasRest && i == len(args)-1 {
			if name != "" {
				bind(name)
			}
			continue
		}
		if name == "" {
			name = fmt.Sprintf("_arg%d", i)
		}
		bind(name)
		// A route handler's first parameter is the framework request object;
		// remember it so property reads off it are canonicalized to `req` and match
		// the request-source globs regardless of the parameter's actual name.
		if i == 0 {
			pat, destructured := a.Binding.Data.(*jsast.BObject)
			switch {
			case fs.isHandler:
				fs.reqParam = name
				// A signature-destructured request object — `({ query, body }, res) =>`
				// — has no `req.query` member read to seed taint from (COV-11).
				if destructured {
					fs.bindDestructuredParam("req", pat, a.Binding.Loc)
				}
			case fs.isComponent && destructured:
				// reqParam stays unset on purpose: it drives canonRoot's request-name
				// canonicalization, which would rewrite a component's own parameter
				// reads into request sources.
				fs.bindDestructuredParam("props", pat, a.Binding.Loc)
			}
		}
	}
}

// bindDestructuredParam binds each property of a destructured first parameter —
// `({ query, body: b }, res) => ...` — to a synthetic `js:<root>.<key>` read, so
// the local carries taint exactly as an in-body `req.query` member read would.
// Nested/computed patterns are skipped.
//
// The root is the CALLER's decision, not this function's: a route handler's
// parameter is the request object ("req"), a component's is its props ("props").
// They are separate roots because they are separate rule surfaces — a props read
// must not match a request-source glob.
func (fs *funcState) bindDestructuredParam(root string, pat *jsast.BObject, loc jsast.Loc) {
	for _, b := range objectPatternBindings(fs.src, pat) {
		if b.Key == "" || b.Local == "" {
			continue
		}
		fs.write(b.Local, fs.emitRootPropertyRead(root, b.Key, nil, loc))
	}
}

// isOpaqueBase reports whether v originates outside this function's own
// straight-line computation: a free/global identifier (Value_GlobalName) or one
// of this function's own parameters (a Value_RegName in fs.paramRegs, e.g. an
// Express handler's `req`). Both are treated alike — see the package doc's
// "opaque object source heuristic".
func (fs *funcState) isOpaqueBase(v *ir.Value) (name string, ok bool) {
	if v == nil {
		return "", false
	}
	if g := v.GetGlobalName(); g != "" {
		return g, true
	}
	if r := v.GetRegName(); r != "" && fs.paramRegs[r] {
		return fs.canonRoot(r), true
	}
	return "", false
}

// canonRoot canonicalizes a PARAMETER name used as an opaque member-read root:
// a route handler's request parameter (any name) becomes `req` so property reads
// off it (`rq.query` -> "js:req.query") match the request-source globs, which are
// keyed on the conventional names (COV-11). isOpaqueBase and opaqueRootFor's AST
// fallback must both route through this, or a request read inside a loop is named
// differently from the same read outside it and its taint is silently dropped.
func (fs *funcState) canonRoot(name string) string {
	if name == fs.reqParam && !reqConventionNames[name] {
		return "req"
	}
	return name
}

// opaqueRootFor classifies the base of a member read (`base.field` / `base[i]`)
// as an opaque source root. It first tries the value-based isOpaqueBase (which
// also handles an intra-block alias like `const r = req; r.query` and
// non-identifier bases such as `this`), then falls back to an AST-name check for
// a plain identifier base.
//
// The AST fallback is required inside loops: reading a parameter in a loop body
// returns an as-yet-unresolved header PHI whose register name is the PHI, not the
// parameter (it collapses back only when the header is sealed, after the body is
// lowered), so isOpaqueBase misses it and the member read wrongly becomes a plain
// FIELD instead of the synthetic source CALL, dropping loop-carried request taint.
// A free/global identifier is never tracked as a variable, so it is never
// PHI-wrapped; only a parameter needs this.
func (fs *funcState) opaqueRootFor(e jsast.Expr, base *ir.Value) (string, bool) {
	if root, ok := fs.isOpaqueBase(base); ok {
		return root, ok
	}
	name, ok := identName(fs.src, e)
	if !ok {
		return "", false
	}
	if fs.paramRegs[name] {
		return fs.canonRoot(name), true
	}
	if !fs.assigned[name] {
		return name, true // a free/global identifier
	}
	return "", false // an ordinary assigned local
}

// emitRootPropertyRead lowers the first property access off an opaque base
// (see isOpaqueBase) as an OP_CODE_CALL with a purely syntactic callee
// "js:<root>.<field>", so it can match a rule's source glob (e.g.
// "js:*req.query*") exactly like a real call would.
//
// When the base is a REGISTER it is also carried in Call.Value — where
// emitCallRecvInst puts a method call's receiver — and tagged
// builtin.member_read so the engine propagates the receiver's taint to the
// result. Both are needed because a parameter is an opaque base whether it holds
// a framework request object or ordinary data, and the two want opposite things:
// the former must INTRODUCE taint via the callee glob (it is not itself tainted —
// see internal/analysis doc.go on request sources), the latter must CARRY the
// taint it already has. Drop the receiver and `use(mk(req))` with
// `use(o){sink(o.field)}` reads clean, which is the shape most request data takes
// once it crosses a function boundary. A non-register base (a global, `this`, a
// closure-captured free name) keeps the plain FuncName form.
func (fs *funcState) emitRootPropertyRead(root, field string, base *ir.Value, loc jsast.Loc) *ir.Value {
	callee := "js:" + root + "." + field
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Comment = "property-read"
	inst.Call = calleeCommon(callee)
	if base != nil && base.GetRegName() != "" {
		inst.Call.Value = base
		inst.Intrinsic = "builtin.member_read"
	}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerBody lowers a statement list, building a REAL CFG (blocks + preds/succs +
// PHI) via the Builder for control-flow compounds and lowering straight-line
// statements into the current block, so a function with no branches still emits
// exactly ONE block (the engine's linear fast path).
func (fs *funcState) lowerBody(stmts []jsast.Stmt) {
	for _, s := range stmts {
		switch v := s.Data.(type) {
		case *jsast.SIf:
			fs.lowerIf(v)
		case *jsast.SFor:
			fs.lowerFor(v)
		case *jsast.SForIn:
			fs.lowerForRange(v.Init, v.Value, v.Body)
		case *jsast.SForOf:
			fs.lowerForRange(v.Init, v.Value, v.Body)
		case *jsast.SWhile:
			fs.lowerWhile(v)
		case *jsast.SDoWhile:
			fs.lowerDoWhile(v)
		case *jsast.SSwitch:
			fs.lowerSwitch(v)
		case *jsast.STry:
			fs.lowerTry(v)
		case *jsast.SBlock:
			fs.lowerBody(v.Stmts)
		case *jsast.SLabel:
			// A labelled loop/if is lowered as its underlying statement (the label
			// only matters for a precise break/continue, which we do not model).
			fs.lowerBody(stmtList(v.Stmt))
		case *jsast.SWith:
			// `with (obj) body`: lower the object (for any embedded source/sink) then
			// the body straight into the current block (no separate scope modeled).
			fs.lowerExpr(v.Value)
			fs.lowerBody(stmtList(v.Body))
		case *jsast.SExportDefault:
			// `export default <decl|expr>`: the export is a wrapper, so lower what it
			// wraps. Every other export form is a FLAG on the statement it exports and
			// needs no case at all.
			fs.lowerBody([]jsast.Stmt{v.Value})
		default:
			fs.lowerStmt(s)
		}
	}
}

// lowerIf lowers `if (test) consequent [else alternate]` into a REAL CFG
// diamond via the Builder's IfDiamond scaffold, so a variable rebound on either
// arm reconciles via an on-demand ReadVariable PHI — which is what keeps the
// pre-branch tainted value in the "default if empty" idiom `if (!x) x = "d"`.
// An `else if` is an SIf in the parent's NoOrNil, so a chain becomes nested
// diamonds via the recursive lowerBody.
func (fs *funcState) lowerIf(v *jsast.SIf) {
	cond := fs.lowerExpr(v.Test)
	fs.b.IfDiamond(&fs.cur, &fs.terminated, cond,
		func() { fs.lowerBody(stmtList(v.Yes)) },
		func() { fs.lowerBody(stmtList(v.NoOrNil)) })
}

// lowerWhile lowers `while (test) body` into a REAL loop CFG via the Builder's
// HeaderLoop scaffold (header/body/exit; the header PHI is what carries
// loop-carried taint — see the scaffold's doc).
func (fs *funcState) lowerWhile(v *jsast.SWhile) {
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return fs.lowerExpr(v.Test) }, // condition, lowered in the (unsealed) header
		func() { fs.lowerBody(stmtList(v.Body)) })
}

// lowerDoWhile lowers `do body while (test)` — the body runs BEFORE the test —
// via the Builder's BodyLoop scaffold (the body is the loop header; its
// back-edge comes from the test block). Loop-carried taint flows through the
// body-header PHI.
func (fs *funcState) lowerDoWhile(v *jsast.SDoWhile) {
	fs.b.BodyLoop(&fs.cur, &fs.terminated,
		func() { fs.lowerBody(stmtList(v.Body)) },
		func() *ir.Value { return fs.lowerExpr(v.Test) })
}

// lowerFor lowers a C-style `for (init; test; update) body` into the HeaderLoop
// CFG. A missing test is an opaque always-true, so both body and exit are
// traversed; the update runs at the END of the body block, before the back-edge.
// Reassignments in the body or update flow through the header PHI, modeling
// loop-carried taint.
func (fs *funcState) lowerFor(v *jsast.SFor) {
	fs.lowerForInit(v.InitOrNil) // evaluated once in the pre-loop block
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value {
			if v.TestOrNil.Data != nil {
				return fs.lowerExpr(v.TestOrNil) // lowered in the (unsealed) header
			}
			return ssabuild.Str("")
		},
		func() {
			fs.lowerBody(stmtList(v.Body))
			if v.UpdateOrNil.Data != nil {
				fs.lowerExpr(v.UpdateOrNil) // the `i++` step, at the body's END block
			}
		})
}

// lowerForRange lowers `for (into in|of source) body` into the same HeaderLoop
// CFG as lowerWhile. The loop variable is bound to the source's value at the top
// of the BODY block each iteration (element taint == container taint, so a
// tainted iterable taints the loop variable).
func (fs *funcState) lowerForRange(into jsast.Stmt, source jsast.Expr, body jsast.Stmt) {
	src := fs.lowerExpr(source) // evaluate the iterable in the pre-loop block
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return ssabuild.Str("") }, // opaque iteration condition
		func() {
			fs.bindForInto(into, src) // bind the loop variable each iteration
			fs.lowerBody(stmtList(body))
		})
}

// bindForInto binds a for-in/for-of loop variable (the `x` in `for (x of it)` /
// `for (const x in it)`) to val in the current block. A declared target writes a
// fresh local; a bare assignment target (`for (x of it)` reusing an outer `x`)
// rebinds through assignTo. Destructuring targets are dropped (a documented
// limitation).
func (fs *funcState) bindForInto(into jsast.Stmt, val *ir.Value) {
	switch t := into.Data.(type) {
	case *jsast.SLocal:
		if len(t.Decls) == 0 {
			return
		}
		if name := bindingName(fs.src, t.Decls[0].Binding); name != "" {
			fs.write(name, val)
		}
	case *jsast.SExpr:
		fs.assignTo(t.Value, val)
	}
}

// lowerSwitch lowers `switch (disc) { case ...: ... }` conservatively (a
// may-analysis; break is NOT modeled precisely). A cascade of two-way decision
// branches makes EVERY case block (and the exit, for the no-match path)
// reachable; each case's consequent lowers into its own block and FALLS THROUGH
// to the next (the last to exit), so taint written in any case — and carried by
// fall-through into a later case — is captured. `default` needs no special
// handling since every case is reachable.
func (fs *funcState) lowerSwitch(v *jsast.SSwitch) {
	disc := fs.lowerExpr(v.Test)
	n := len(v.Cases)
	if n == 0 {
		return // empty switch: discriminant already lowered for side effects
	}
	// Lower each case's test in the discriminant block for an embedded
	// source/sink; the boolean result is not otherwise needed.
	for _, cs := range v.Cases {
		if cs.ValueOrNil.Data != nil {
			fs.lowerExpr(cs.ValueOrNil)
		}
	}

	caseBlocks := make([]ssabuild.BlockID, n)
	for i := range caseBlocks {
		caseBlocks[i] = fs.b.NewBlock()
	}
	exit := fs.b.NewBlock()

	// Decision cascade: cur -?-> case0 else dec1 -?-> case1 else dec2 ... else exit.
	// Every case block gains its decision predecessor here; the no-match path
	// (all decisions false) reaches exit, so code after the switch stays reachable.
	dec := fs.cur
	for i := 0; i < n; i++ {
		falseTarget := exit
		if i < n-1 {
			falseTarget = fs.b.NewBlock()
		}
		fs.b.SetIf(dec, disc, caseBlocks[i], falseTarget)
		if i < n-1 {
			fs.b.Seal(falseTarget) // sole predecessor (dec) is known
			dec = falseTarget
		}
	}

	// A case block's predecessors — its decision edge and the prior case's
	// fall-through — are both wired before it is lowered, so it can be sealed here.
	for i := 0; i < n; i++ {
		fs.b.Seal(caseBlocks[i])
		fs.cur = caseBlocks[i]
		fs.terminated = false
		fs.lowerBody(v.Cases[i].Body)
		if fs.terminated {
			continue // a returning case has no fall-through edge
		}
		if i < n-1 {
			fs.b.SetJump(fs.cur, caseBlocks[i+1])
		} else {
			fs.b.SetJump(fs.cur, exit)
		}
	}

	fs.b.Seal(exit)
	fs.cur = exit
	fs.terminated = false
}

// lowerTry lowers `try { body } [catch (e) { handler }] [finally { fin }]`
// conservatively (a may-analysis; no exception typing). An EXCEPTION EDGE models
// that an exception may occur anywhere in the body: the body-end block branches
// to the catch block or to an after block, so a value assigned by a source in the
// try body reaches the handler via that predecessor edge (and, through the after
// block, code following the try). `finally` runs on both paths, so it lowers into
// the after block. A try/finally with no catch is a straight-line continuation.
// When the body always returns there is no exception edge (the handler's body-var
// reads are then undefined — a minor recall gap, never a false positive).
func (fs *funcState) lowerTry(v *jsast.STry) {
	fs.lowerBody(v.Block.Stmts)
	bodyEnd := fs.cur
	bodyTerm := fs.terminated

	if v.Catch == nil {
		if v.Finally != nil {
			fs.lowerBody(v.Finally.Block.Stmts)
		}
		return
	}

	handlerB := fs.b.NewBlock()
	after := fs.b.NewBlock()
	if !bodyTerm {
		fs.b.SetIf(bodyEnd, ssabuild.Str(""), handlerB, after) // opaque condition: both edges traversed
	}
	fs.b.Seal(handlerB) // sole predecessor (bodyEnd) known, if any

	fs.cur = handlerB
	fs.terminated = false
	// The catch parameter (the exception object) is not modeled as a taint source.
	fs.lowerBody(v.Catch.Block.Stmts)
	handlerTerm := fs.terminated
	if !handlerTerm {
		fs.b.SetJump(fs.cur, after)
	}

	fs.b.Seal(after)
	fs.cur = after
	fs.terminated = bodyTerm && handlerTerm
	if v.Finally != nil {
		fs.lowerBody(v.Finally.Block.Stmts)
	}
}

// lowerForInit lowers a `for(...)` loop's initializer clause, which is either a
// declaration or a bare expression statement.
func (fs *funcState) lowerForInit(init jsast.Stmt) {
	switch v := init.Data.(type) {
	case *jsast.SLocal:
		for _, d := range v.Decls {
			fs.lowerBinding(d)
		}
	case *jsast.SExpr:
		fs.lowerExpr(v.Value)
	}
}

// lowerStmt lowers one leaf statement (i.e. not a control-flow compound;
// those are flattened by lowerBody).
func (fs *funcState) lowerStmt(s jsast.Stmt) {
	switch v := s.Data.(type) {
	case *jsast.SLocal:
		for _, d := range v.Decls {
			fs.lowerBinding(d)
		}
	case *jsast.SExpr:
		fs.lowerExpr(v.Value)
	case *jsast.SReturn:
		inst := fs.newVoidInst(s.Loc)
		inst.Op = ir.OpCode_OP_CODE_RET
		if v.ValueOrNil.Data != nil {
			inst.Operands = []*ir.Value{fs.lowerExpr(v.ValueOrNil)}
		}
		fs.emit(inst)
		// A returning arm must not feed its values into a merge / loop header /
		// switch fall-through join.
		fs.terminated = true
	case *jsast.SThrow:
		// `throw x` deliberately does NOT terminate the block: leaving it
		// non-terminated preserves the exception edge into an enclosing try's catch
		// (see lowerTry), so taint assigned before a `throw` reaches the handler.
		fs.lowerExpr(v.Value)
	case *jsast.SFunction:
		// Converted separately (see collector); bind the name so later reads of it
		// as a plain VALUE resolve to a function reference rather than a GlobalName.
		// (Call callees are resolved syntactically instead — see lowerCall.)
		if v.Fn.Name != nil {
			if canonical, ok := fs.nameOf[fnID(v)]; ok {
				fs.write(fs.src.NameOf(v.Fn.Name.Ref), &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}})
			}
		}
	case *jsast.SExportEquals:
		fs.lowerExpr(v.Value)
	default:
		// SClass, SEmpty, SBreak, SContinue, SDebugger, SComment, SDirective,
		// SImport and the remaining export forms: dropped. collectClass already
		// queued each SClass method; the rest carry no dataflow.
	}
}

// lowerBinding lowers one `var`/`let`/`const` declarator, evaluating its
// initializer (if any) and binding the result to the target name.
func (fs *funcState) lowerBinding(d jsast.Decl) {
	switch t := d.Binding.Data.(type) {
	case *jsast.BObject:
		fs.lowerObjectPatternBinding(t, d.Binding.Loc, d.ValueOrNil)
		return
	case *jsast.BArray:
		fs.lowerArrayPatternBinding(t, d.ValueOrNil)
		return
	}
	name := bindingName(fs.src, d.Binding)
	if d.ValueOrNil.Data == nil {
		if name != "" {
			fs.write(name, ssabuild.Nil())
		}
		return
	}
	val := fs.lowerExpr(d.ValueOrNil)
	if name != "" {
		fs.write(name, val)
	}
}

// lowerObjectPatternBinding binds each name in an object-destructuring pattern
// (const { a, b: c, ...rest } = init) to a field read off the initializer, so
// taint carried by the initializer (typically req.query / req.body) reaches the
// destructured names — the common Express idiom.
func (fs *funcState) lowerObjectPatternBinding(op *jsast.BObject, loc jsast.Loc, init jsast.Expr) {
	if init.Data == nil {
		return
	}
	base := fs.lowerExpr(init)
	for _, b := range objectPatternBindings(fs.src, op) {
		if b.Local == "" {
			continue
		}
		fs.write(b.Local, fs.emitFieldRead(base, b.Key, loc))
	}
	// `const { ...rest } = init`: the rest object carries the initializer's taint.
	if name := objectPatternRest(fs.src, op); name != "" {
		fs.write(name, base)
	}
}

// lowerArrayPatternBinding binds each name in an array-destructuring pattern
// (const [a, b, ...rest] = init) to the initializer's value (element taint ==
// container taint). Elisions, per-element defaults and nested patterns are not
// modeled.
func (fs *funcState) lowerArrayPatternBinding(ap *jsast.BArray, init jsast.Expr) {
	if init.Data == nil {
		return
	}
	base := fs.lowerExpr(init)
	for _, it := range ap.Items {
		if name := bindingName(fs.src, it.Binding); name != "" {
			fs.write(name, base)
		}
	}
}

// patBinding is one name an object-destructuring pattern binds: the LOCAL name
// introduced, and the KEY (source field) it reads. Key is "" for a computed key
// propertyKeyName cannot resolve statically — each caller decides what to do
// with that, since they differ (bind nothing, vs. keep an empty field name).
type patBinding struct{ Local, Key string }

// objectPatternBindings returns the bindings an object pattern introduces, for
// the three places that walk one: a handler's destructured request parameter, a
// destructuring variable declaration, and `const {a, b} = require('m')`. Only a
// plain identifier target is modeled, so a nested pattern yields no entry. The
// rest element is deliberately NOT handled here — each caller binds it
// differently (see objectPatternRest).
func objectPatternBindings(f *jsast.File, op *jsast.BObject) []patBinding {
	var out []patBinding
	for _, p := range op.Properties {
		if p.IsSpread {
			continue
		}
		local := bindingName(f, p.Value)
		if local == "" {
			continue
		}
		out = append(out, patBinding{Local: local, Key: propertyKeyName(p.Key)})
	}
	return out
}

// objectPatternRest returns the name bound by a pattern's `...rest` element, or
// "" when there is none.
func objectPatternRest(f *jsast.File, op *jsast.BObject) string {
	for _, p := range op.Properties {
		if p.IsSpread {
			return bindingName(f, p.Value)
		}
	}
	return ""
}

// reactHTMLSink is the synthetic callee react-xss.yaml matches. Spelled with the
// `js:` prefix because emitCall writes the callee verbatim -- sfc.go's Vue
// equivalent gets the prefix for free by injecting source text that is then
// lowered as an ordinary call.
// isComponentName reports whether a function with this leaf name can be used as a
// React component, which is what makes its first parameter a props object.
//
// The capital initial is React's OWN dispatch rule, not a proxy for it: JSX
// compiles a lowercase tag to a host-element STRING, so a lowercase-named
// function cannot be rendered as a component at all. Why the broader "its first
// parameter is destructured" is wrong is pinned by test/js/react_props_xss_safe.
//
// A class METHOD leafs to its method name, so it is never a component -- correct,
// since a class component reads this.props rather than a parameter.
func isComponentName(leaf string) bool {
	return leaf != "" && leaf[0] >= 'A' && leaf[0] <= 'Z'
}

const reactHTMLSink = "js:__godzilla_react_html"

// emitReactHTMLSink gives React's dangerouslySetInnerHTML a callee to match.
// It is the framework's one documented escape from JSX auto-escaping, but unlike
// Vue's v-html it is spelled as DATA, not a directive: the JSX lowering turns the
// attribute into a `{__html: x}` object literal inside a createElement props
// argument, so nothing in the IR is a call and no sink glob can name it. Mirror
// it the way sfc.go mirrors v-html -- emit a call carrying the value.
//
// Keyed on the inner `__html`, not the attribute name. __html is React's own
// marker and the only reason to build such an object, and keying on it also
// catches the indirect form (`const h = {__html: x}` handed to the attribute by
// variable) that keying on the attribute would miss.
func (fs *funcState) emitReactHTMLSink(o *jsast.EObject) {
	for _, p := range o.Properties {
		if propertyKeyName(p.Key) != "__html" || p.ValueOrNil.Data == nil {
			continue
		}
		fs.emitCall(reactHTMLSink, []jsast.Expr{p.ValueOrNil}, p.ValueOrNil.Loc)
	}
}

// propertyKeyName extracts the static field name of a property key. esbuild
// spells an identifier key and a string-literal key alike, as an EString; any
// other key is computed and yields "".
func propertyKeyName(key jsast.Expr) string {
	if s, ok := unwrap(key).Data.(*jsast.EString); ok {
		return jsast.UTF16ToString(s.Value)
	}
	return ""
}

// lowerExpr lowers an expression to a gIR Value, emitting whatever instructions
// are needed to compute it into the current block. Names assigned as locals
// resolve through the Builder to their current SSA value; unbound names (free
// variables — builtins, another function's or the module's locals, since closures
// are not modeled) fall back to a GlobalName reference.
func (fs *funcState) lowerExpr(e jsast.Expr) *ir.Value {
	e = unwrap(e)
	if e.Data == nil {
		return nil
	}
	switch v := e.Data.(type) {
	case *jsast.EIdentifier:
		return fs.lowerIdent(fs.src.NameOf(v.Ref))

	case *jsast.EImportIdentifier:
		return fs.lowerIdent(fs.src.NameOf(v.Ref))

	case *jsast.EPrivateIdentifier:
		return fs.lowerIdent(fs.src.NameOf(v.Ref))

	case *jsast.ENameOfSymbol:
		return ssabuild.Str(fs.src.NameOf(v.Ref))

	case *jsast.EString:
		return ssabuild.Str(jsast.UTF16ToString(v.Value))

	case *jsast.ENumber:
		return numberValue(v.Value)

	case *jsast.EBigInt:
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: v.Value}}}}

	case *jsast.EBoolean:
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_BoolVal{BoolVal: v.Value}}}}

	case *jsast.ENull:
		return ssabuild.Nil()

	case *jsast.EUndefined, *jsast.EMissing:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "undefined"}}

	case *jsast.ERegExp:
		return ssabuild.Str(v.Value) // best-effort string representation

	case *jsast.ETemplate:
		return fs.lowerTemplateLiteral(e.Loc, v)

	case *jsast.EBinary:
		return fs.lowerBinaryExpr(e.Loc, v)

	case *jsast.EUnary:
		return fs.lowerUnary(e.Loc, v)

	case *jsast.EIf:
		// No branch blocks: evaluate the test for side effects/taint discovery,
		// then merge both arms with a PHI so taint from either reaches the result.
		fs.lowerExpr(v.Test)
		cv := fs.lowerExpr(v.Yes)
		av := fs.lowerExpr(v.No)
		inst := fs.newValueInst(e.Loc)
		inst.Op = ir.OpCode_OP_CODE_PHI
		inst.Operands = []*ir.Value{cv, av}
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)

	case *jsast.ECall:
		return fs.lowerCall(e.Loc, v)

	case *jsast.ENew:
		return fs.lowerNew(e.Loc, v)

	case *jsast.EDot:
		return fs.lowerDot(e.Loc, v)

	case *jsast.EIndex:
		return fs.lowerBracket(e.Loc, v)

	case *jsast.EArray:
		return fs.lowerAggregate(v.Items, e.Loc)

	case *jsast.EObject:
		vals := make([]jsast.Expr, 0, len(v.Properties))
		for _, p := range v.Properties {
			if p.ValueOrNil.Data != nil {
				vals = append(vals, p.ValueOrNil)
			} else if p.InitializerOrNil.Data != nil {
				vals = append(vals, p.InitializerOrNil)
			}
		}
		fs.emitReactHTMLSink(v)
		return fs.lowerAggregate(vals, e.Loc)

	case *jsast.ESpread:
		return fs.lowerExpr(v.Value)

	case *jsast.EThis:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "this"}}

	case *jsast.ESuper:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "super"}}

	case *jsast.EImportMeta:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "import.meta"}}

	case *jsast.ENewTarget:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "new.target"}}

	case *jsast.EYield:
		// Generators are not modeled: `yield x` lowers to `x`.
		if v.ValueOrNil.Data != nil {
			return fs.lowerExpr(v.ValueOrNil)
		}
		return ssabuild.Nil()

	case *jsast.EAwait:
		// `await x` lowers to `x` (see emitPromiseContinuation for `.then`).
		return fs.lowerExpr(v.Value)

	case *jsast.EImportCall:
		// `import(spec)` is a call whose argument is the only thing that carries
		// data; naming it keeps that argument visible to the engine.
		return fs.emitCall("js:import", []jsast.Expr{v.Expr}, e.Loc)

	case *jsast.EFunction, *jsast.EArrow:
		return fs.funcRefValue(e)

	default:
		return fs.emitUnsupported(e.Loc, fmt.Sprintf("unsupported javascript expression: %T", e.Data))
	}
}

// lowerIdent resolves a bare name: a local through the Builder, anything else
// (a builtin, an enclosing scope's local, an import) as a GlobalName.
func (fs *funcState) lowerIdent(name string) *ir.Value {
	if fs.assigned[name] {
		return fs.read(name)
	}
	return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: name}}
}

// funcRefValue resolves an inline function-literal/arrow expression (e.g. a
// callback argument) to a FuncName reference to the ir.Function the collector
// already created for it, rather than inlining its body again.
func (fs *funcState) funcRefValue(e jsast.Expr) *ir.Value {
	if canonical, ok := fs.nameOf[fnID(e.Data)]; ok {
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}}
	}
	// Unreachable: see "Collector coverage" in converter.go.
	return fs.emitUnsupported(e.Loc, "unresolved inline function literal")
}

// lowerDot lowers `a.b`. If the base is opaque (see isOpaqueBase), this hop
// is the root of the chain and becomes a synthetic property-read CALL;
// otherwise it is a normal FIELD read off the base's register.
func (fs *funcState) lowerDot(loc jsast.Loc, v *jsast.EDot) *ir.Value {
	base := fs.lowerExpr(v.Target)

	if root, ok := fs.opaqueRootFor(v.Target, base); ok {
		return fs.emitRootPropertyRead(root, v.Name, base, loc)
	}

	return fs.emitFieldRead(base, v.Name, loc)
}

func (fs *funcState) emitFieldRead(base *ir.Value, field string, loc jsast.Loc) *ir.Value {
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_FIELD
	inst.Operands = []*ir.Value{base}
	inst.Comment = "field:" + field
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerBracket lowers `a[i]`, the same way as lowerDot but for computed
// member access: a string-literal index contributes its literal value to a
// root property-read's synthetic callee (so `req.query['name']` matches the
// same source globs as `req.query.name`); any other index expression
// contributes "*".
func (fs *funcState) lowerBracket(loc jsast.Loc, v *jsast.EIndex) *ir.Value {
	base := fs.lowerExpr(v.Target)
	idx := fs.lowerExpr(v.Index)

	if root, ok := fs.opaqueRootFor(v.Target, base); ok {
		return fs.emitRootPropertyRead(root, bracketFieldName(v.Index), base, loc)
	}

	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{base, idx}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

func bracketFieldName(m jsast.Expr) string {
	if s, ok := unwrap(m).Data.(*jsast.EString); ok {
		return jsast.UTF16ToString(s.Value)
	}
	return "*"
}

// lowerAggregate lowers an array/object literal's element values, merging their
// taint into one register via OP_CODE_PHI (field-insensitive; see package doc).
func (fs *funcState) lowerAggregate(exprs []jsast.Expr, loc jsast.Loc) *ir.Value {
	var acc *ir.Value
	for _, e := range exprs {
		if e.Data == nil {
			continue
		}
		if _, hole := unwrap(e).Data.(*jsast.EMissing); hole {
			continue // sparse array elision
		}
		v := fs.lowerExpr(e)
		if acc == nil {
			acc = v
			continue
		}
		inst := fs.newValueInst(loc)
		inst.Op = ir.OpCode_OP_CODE_PHI
		inst.Operands = []*ir.Value{acc, v}
		fs.emit(inst)
		acc = ssabuild.Reg(inst.Name)
	}
	if acc == nil {
		acc = ssabuild.Nil()
	}
	return acc
}

// lowerTemplateLiteral folds a template literal's raw text chunks and
// substituted expressions left-to-right with BIN_OP_ADD, so taint carried by any
// ${expr} slot propagates to the final value.
//
// A TAGGED template is deliberately not lowered as a call to its tag: treating
// it as one would add findings the sink globs never meant to name.
func (fs *funcState) lowerTemplateLiteral(loc jsast.Loc, v *jsast.ETemplate) *ir.Value {
	acc := fs.concat(nil, ssabuild.Str(templateText(v.HeadRaw, v.HeadCooked)), loc)
	for _, p := range v.Parts {
		acc = fs.concat(acc, fs.lowerExpr(p.Value), loc)
		acc = fs.concat(acc, ssabuild.Str(templateText(p.TailRaw, p.TailCooked)), loc)
	}
	if acc == nil {
		acc = ssabuild.Str("")
	}
	return acc
}

// templateText picks the text of one template chunk: cooked for an untagged
// literal, raw for a tagged one (esbuild fills only the applicable field).
func templateText(raw string, cooked []uint16) string {
	if cooked != nil {
		return jsast.UTF16ToString(cooked)
	}
	return raw
}

func (fs *funcState) concat(acc, val *ir.Value, loc jsast.Loc) *ir.Value {
	if acc == nil {
		return val
	}
	if val == nil {
		return acc
	}
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = ir.BinOpKind_BIN_OP_ADD
	inst.Operands = []*ir.Value{acc, val}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerBinaryExpr fans an EBinary out to the three constructs esbuild packs into
// it: the comma operator, assignment (plain and compound), and a real binary
// operator.
func (fs *funcState) lowerBinaryExpr(loc jsast.Loc, v *jsast.EBinary) *ir.Value {
	switch {
	case v.Op == jsast.BinOpComma:
		fs.lowerExpr(v.Left)
		return fs.lowerExpr(v.Right)
	case isAssignOp(v.Op):
		return fs.lowerAssign(loc, v)
	default:
		return fs.lowerBinary(loc, v)
	}
}

// lowerBinary lowers a binary expression (arithmetic, bitwise, or — approximated,
// see package doc — logical) to a BIN_OP. A comparison instead lowers to the inert
// builtin.compare intrinsic: a bool carries influence rather than content.
func (fs *funcState) lowerBinary(loc jsast.Loc, v *jsast.EBinary) *ir.Value {
	left := fs.lowerExpr(v.Left)
	right := fs.lowerExpr(v.Right)
	inst := fs.newValueInst(loc)
	if isComparisonOp(v.Op) {
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "builtin.compare"
	} else {
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKind(v.Op)
	}
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerUnary lowers a unary expression. Prefix/postfix ++/-- on a plain
// identifier also rebinds it, approximating the mutation.
func (fs *funcState) lowerUnary(loc jsast.Loc, v *jsast.EUnary) *ir.Value {
	operand := fs.lowerExpr(v.Value)
	inst := fs.newValueInst(loc)
	inst.Op = ir.OpCode_OP_CODE_UN_OP
	inst.UnOp = unOpKind(v.Op)
	inst.Operands = []*ir.Value{operand}
	fs.emit(inst)
	result := ssabuild.Reg(inst.Name)

	if isIncDecOp(v.Op) {
		if name, ok := identName(fs.src, v.Value); ok {
			fs.write(name, result)
		}
	}
	return result
}

// lowerAssign lowers `target = value` (and compound assignments like `+=`),
// returning the assigned value so it can also be a sub-expression (`x = y = 5`).
func (fs *funcState) lowerAssign(loc jsast.Loc, a *jsast.EBinary) *ir.Value {
	var rhs *ir.Value
	if a.Op == jsast.BinOpAssign {
		rhs = fs.lowerExpr(a.Right)
	} else {
		cur := fs.lowerExpr(a.Left)
		right := fs.lowerExpr(a.Right)
		inst := fs.newValueInst(loc)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKindForCompoundAssign(a.Op)
		inst.Operands = []*ir.Value{cur, right}
		fs.emit(inst)
		rhs = ssabuild.Reg(inst.Name)
	}
	fs.assignTo(a.Left, rhs)
	return rhs
}

// assignTo binds a lowered value to an assignment target. A bare identifier
// rebinds the variable. An EDot/EIndex target (`obj.attr = v` / `arr[i] = v`)
// emits a STORE with the base object as the address operand, which is what lets
// a tainted value written into a container mark that container tainted (see
// visitStore in internal/analysis/taint.go). Destructuring targets are dropped.
func (fs *funcState) assignTo(target jsast.Expr, val *ir.Value) {
	target = unwrap(target)
	switch t := target.Data.(type) {
	case *jsast.EIdentifier:
		fs.write(fs.src.NameOf(t.Ref), val)
	case *jsast.EImportIdentifier:
		fs.write(fs.src.NameOf(t.Ref), val)
	case *jsast.EDot:
		fs.emitStore(t.Target, val, target.Loc)
	case *jsast.EIndex:
		fs.emitStore(t.Target, val, target.Loc)
	default:
		// Destructuring assignment or another unsupported target shape: dropped.
	}
}

// lowerCall lowers a call expression to OP_CODE_CALL. The callee is a purely
// syntactic dotted name (see syntacticCallee), never resolved through the
// environment, so `child_process.exec(cmd)` resolves to "js:child_process.exec"
// regardless of whether/how `child_process` is bound.
func (fs *funcState) lowerCall(loc jsast.Loc, v *jsast.ECall) *ir.Value {
	// For a method call, lower the receiver (the callee's base object) so its
	// register can be carried in Call.Value (see emitCallRecvInst): this both
	// evaluates the base -- which, off an opaque request object like `req.url`,
	// is itself the synthetic taint source -- and lets a taint-preserving method
	// like `.slice`/`.toLowerCase` propagate the receiver's taint to the result.
	// lowerExpr recurses through any nested call in the base chain, so it fully
	// subsumes lowerNestedCallees for these two callee shapes.
	target := unwrap(v.Target)
	var receiver *ir.Value
	var dot *jsast.EDot
	switch c := target.Data.(type) {
	case *jsast.EDot:
		dot = c
		receiver = fs.lowerExpr(c.Target)
	case *jsast.EIndex:
		receiver = fs.lowerExpr(c.Target)
	default:
		fs.lowerNestedCallees(v.Target)
	}
	callee := "js:" + fs.resolveRequire(syntacticCallee(fs.src, target))
	// A bare call to a top-level function (helper(x)) must carry the module name
	// so its callee matches the function's CanonicalName; otherwise byKey never
	// resolves it and taint does not flow through the local helper.
	if name, ok := identName(fs.src, target); ok {
		if canonical, found := fs.localFuncs[name]; found {
			callee = canonical
		} else if mod, found := fs.relativeDefaults[name]; found {
			// Bare call to a name default-imported from a relative module: emit a
			// resolvable marker naming the target module. Its default export is
			// filled in by resolveJSCrossModuleCalls once every file is lowered
			// (the callee function may live in a not-yet-seen file).
			callee = crossModuleMarker + mod
		}
	}
	// `this.method(x)` inside a class method: qualify to the sibling method's
	// canonical name so byKey resolves it. Optimistic — a non-method `this.x`
	// matches no function and stays unresolved (harmless). JS methods take no
	// explicit receiver param, so the arguments already align.
	if dot != nil && fs.methodClass != "" {
		if _, isThis := unwrap(dot.Target).Data.(*jsast.EThis); isThis {
			callee = "js:" + fs.moduleName + "." + fs.methodClass + dot.Name
		}
	}
	call := fs.emitCallRecvInst(callee, receiver, v.Args, loc)
	fs.emitPromiseContinuation(callee, receiver, call, loc)
	return ssabuild.Reg(call.Name)
}

// lowerNew lowers `new Foo(args)` the same way as a call (for taint purposes
// construction is indistinguishable from calling a function with the same
// arguments); the "new" prefix keeps the callee from colliding with a plain
// `Foo(args)` call.
func (fs *funcState) lowerNew(loc jsast.Loc, v *jsast.ENew) *ir.Value {
	fs.lowerNestedCallees(v.Target)
	callee := "js:new:" + syntacticCallee(fs.src, v.Target)
	inst := fs.emitCallRecvInst(callee, nil, v.Args, loc)
	// A URL's text is its argument's text, so mark it for ssrf.go's hostFixed():
	// without the marker the constructor hides the constant host inside it and
	// `fetch(new URL("https://fixed/x?q=" + tainted))` reads as a dynamic host.
	// Taint itself flows through the js:new:URL default propagator, not here.
	//
	// One argument only. The two-argument form resolves against a BASE
	// (`new URL(path, base)`) whose host wins, and Args[0] is the path, so
	// claiming identity there would let a tainted base look constant -- a false
	// negative. Unmarked it stays dynamic, which fires.
	if callee == "js:new:URL" && len(v.Args) == 1 {
		inst.Intrinsic = identityIntrinsic
	}
	return ssabuild.Reg(inst.Name)
}

// identityIntrinsic mirrors internal/analysis/ssrf.go: the cross-frontend marker
// for a value whose text is its Args[0]'s text.
const identityIntrinsic = "builtin.identity"

// lowerNestedCallees walks a call/new expression's callee along the same
// Dot/Index "Target" chain syntacticCallee walks and lowers any call it finds —
// e.g. the `require('./x')` inside `new (require('./x').Client)()` — inside-out
// via the ordinary lowerCall path.
//
// Without it the inner call is never visited at all: syntactic name building is
// a pure string walk with no side effects, so the inner call's instruction (and
// with it its args, its taint, and its chance to match a source/sink glob) would
// silently disappear. Its result register is deliberately discarded — the outer
// call is still named by syntacticCallee's "<dynamic>" fallback.
func (fs *funcState) lowerNestedCallees(e jsast.Expr) {
	e = unwrap(e)
	switch v := e.Data.(type) {
	case *jsast.ECall:
		fs.lowerCall(e.Loc, v)
	case *jsast.EDot:
		fs.lowerNestedCallees(v.Target)
	case *jsast.EIndex:
		fs.lowerNestedCallees(v.Target)
	}
}

// syntacticCallee builds a canonical, purely syntactic dotted callee name from a
// call's callee expression, e.g. `res.locals.get`. A callee rooted in anything
// other than a plain identifier / member / string-keyed-index chain (a nested
// call, a computed index, a function expression) resolves to "<dynamic>" for that
// sub-path, so `getHandler().process(x)` yields "<dynamic>.process" — glob
// patterns like "js:*.process" still match it. Any call along the chain has
// already been lowered by lowerNestedCallees, so collapsing it here costs only
// the outer call's name.
func syntacticCallee(f *jsast.File, e jsast.Expr) string {
	switch v := unwrap(e).Data.(type) {
	case *jsast.EIdentifier:
		return f.NameOf(v.Ref)
	case *jsast.EImportIdentifier:
		return f.NameOf(v.Ref)
	case *jsast.EDot:
		return syntacticCallee(f, v.Target) + "." + v.Name
	case *jsast.EIndex:
		if s, ok := unwrap(v.Index).Data.(*jsast.EString); ok {
			return syntacticCallee(f, v.Target) + "." + jsast.UTF16ToString(s.Value)
		}
		return syntacticCallee(f, v.Target) + ".<dynamic>"
	case *jsast.EBinary:
		// Every bundler emits a named import call as `(0, mod.fn)(x)`, whose callee
		// is a comma operator with the real name on the RIGHT. Recover it, or the
		// callee of most calls in bundled JS collapses to "<dynamic>".
		if v.Op == jsast.BinOpComma {
			return syntacticCallee(f, v.Right)
		}
		return "<dynamic>"
	default:
		return "<dynamic>"
	}
}

// numberValue converts a JS numeric literal to a gIR constant. esbuild stores
// every number as a float64; an integral one is emitted as an int so the IR
// spells `limit = 10` the way the source does.
func numberValue(f float64) *ir.Value {
	c := &ir.Constant{}
	if f == math.Trunc(f) && math.Abs(f) <= math.MaxInt64 {
		c.Value = &ir.Constant_IntVal{IntVal: int64(f)}
	} else {
		c.Value = &ir.Constant_FloatVal{FloatVal: f}
	}
	return &ir.Value{Kind: &ir.Value_Constant{Constant: c}}
}

// binOpKind maps a binary operator to a gIR BinOpKind. Logical &&/||/?? have no
// gIR counterpart and are approximated as their bitwise equivalents (safe for
// taint: either operand tainted still taints the result); the right-shift
// variants collapse into BIN_OP_SHR. Operators with no counterpart at all
// (`**`, `in`, `instanceof`) fall through to UNSPECIFIED, which still propagates.
func binOpKind(op jsast.OpCode) ir.BinOpKind {
	switch op {
	case jsast.BinOpAdd:
		return ir.BinOpKind_BIN_OP_ADD
	case jsast.BinOpSub:
		return ir.BinOpKind_BIN_OP_SUB
	case jsast.BinOpMul:
		return ir.BinOpKind_BIN_OP_MUL
	case jsast.BinOpDiv:
		return ir.BinOpKind_BIN_OP_QUO
	case jsast.BinOpRem:
		return ir.BinOpKind_BIN_OP_REM
	case jsast.BinOpBitwiseAnd, jsast.BinOpLogicalAnd:
		return ir.BinOpKind_BIN_OP_AND
	case jsast.BinOpBitwiseOr, jsast.BinOpLogicalOr, jsast.BinOpNullishCoalescing:
		return ir.BinOpKind_BIN_OP_OR
	case jsast.BinOpBitwiseXor:
		return ir.BinOpKind_BIN_OP_XOR
	case jsast.BinOpShl:
		return ir.BinOpKind_BIN_OP_SHL
	case jsast.BinOpShr, jsast.BinOpUShr:
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

// isComparisonOp reports whether op yields a bool. Those lower to the
// builtin.compare intrinsic, so they never reach binOpKind.
func isComparisonOp(op jsast.OpCode) bool {
	switch op {
	case jsast.BinOpLooseEq, jsast.BinOpStrictEq, jsast.BinOpLooseNe, jsast.BinOpStrictNe,
		jsast.BinOpLt, jsast.BinOpLe, jsast.BinOpGt, jsast.BinOpGe:
		return true
	}
	return false
}

// isAssignOp reports whether op writes to its left operand — esbuild spells
// assignment as a binary operator, so the lowering has to split it back out.
func isAssignOp(op jsast.OpCode) bool {
	switch op {
	case jsast.BinOpAssign,
		jsast.BinOpAddAssign, jsast.BinOpSubAssign, jsast.BinOpMulAssign,
		jsast.BinOpDivAssign, jsast.BinOpRemAssign, jsast.BinOpPowAssign,
		jsast.BinOpShlAssign, jsast.BinOpShrAssign, jsast.BinOpUShrAssign,
		jsast.BinOpBitwiseAndAssign, jsast.BinOpBitwiseOrAssign, jsast.BinOpBitwiseXorAssign,
		jsast.BinOpLogicalAndAssign, jsast.BinOpLogicalOrAssign, jsast.BinOpNullishCoalescingAssign:
		return true
	}
	return false
}

// binOpKindForCompoundAssign maps a compound-assignment operator (`+=`, `-=`,
// etc.) to the BinOpKind of its underlying operator.
func binOpKindForCompoundAssign(op jsast.OpCode) ir.BinOpKind {
	switch op {
	case jsast.BinOpAddAssign:
		return ir.BinOpKind_BIN_OP_ADD
	case jsast.BinOpSubAssign:
		return ir.BinOpKind_BIN_OP_SUB
	case jsast.BinOpMulAssign:
		return ir.BinOpKind_BIN_OP_MUL
	case jsast.BinOpDivAssign:
		return ir.BinOpKind_BIN_OP_QUO
	case jsast.BinOpRemAssign:
		return ir.BinOpKind_BIN_OP_REM
	case jsast.BinOpBitwiseAndAssign, jsast.BinOpLogicalAndAssign:
		return ir.BinOpKind_BIN_OP_AND
	case jsast.BinOpBitwiseOrAssign, jsast.BinOpLogicalOrAssign, jsast.BinOpNullishCoalescingAssign:
		return ir.BinOpKind_BIN_OP_OR
	case jsast.BinOpBitwiseXorAssign:
		return ir.BinOpKind_BIN_OP_XOR
	case jsast.BinOpShlAssign:
		return ir.BinOpKind_BIN_OP_SHL
	case jsast.BinOpShrAssign, jsast.BinOpUShrAssign:
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

// unOpKind maps a unary operator to a gIR UnOpKind. typeof/void/delete and
// ++/-- have no counterpart and fall back to UN_OP_UNSPECIFIED; lowerUnary
// still emits the UN_OP so taint propagates through it.
func unOpKind(op jsast.OpCode) ir.UnOpKind {
	switch op {
	case jsast.UnOpNot:
		return ir.UnOpKind_UN_OP_NOT
	case jsast.UnOpNeg:
		return ir.UnOpKind_UN_OP_NEG
	case jsast.UnOpPos:
		return ir.UnOpKind_UN_OP_POS
	case jsast.UnOpCpl:
		return ir.UnOpKind_UN_OP_BIT_NOT
	}
	return ir.UnOpKind_UN_OP_UNSPECIFIED
}

func isIncDecOp(op jsast.OpCode) bool {
	switch op {
	case jsast.UnOpPreInc, jsast.UnOpPreDec, jsast.UnOpPostInc, jsast.UnOpPostDec:
		return true
	}
	return false
}

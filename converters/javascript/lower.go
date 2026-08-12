package js_converter

import (
	"fmt"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/token"

	"godzilla/converters/ssabuild"
	ir "godzilla/pkg/ir/v1"
)

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
// ir.Function instead of being inlined again.
type funcState struct {
	filename   string
	fset       *file.FileSet
	nameOf     map[ast.Node]string
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

	// moduleAliases maps a require-bound name to its canonical module(.member)
	// path (FE-2): "cp" -> "child_process" for `const cp = require('child_process')`,
	// "exec" -> "child_process.exec" for a destructured require. resolveRequire
	// rewrites a callee's root through it so module-anchored sink rules match.
	moduleAliases map[string]string

	// relativeDefaults maps a name default-imported from a relative (project)
	// require -- `const f = require('./util')` -> f -> "util" (the scan-root-
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
}

// reqConventionNames are the request-object parameter names the source globs
// already match by name (req.*/request.*/ctx.*); a handler param already named
// one of these needs no canonicalization.
var reqConventionNames = map[string]bool{"req": true, "request": true, "ctx": true}

func newFuncState(filename string, fset *file.FileSet, nameOf map[ast.Node]string, localFuncs map[string]string) *funcState {
	b := ssabuild.NewBuilder()
	entry := b.NewBlock()
	b.Seal(entry) // the entry block has no predecessors, so it is sealed at once.
	return &funcState{
		filename:   filename,
		fset:       fset,
		nameOf:     nameOf,
		b:          b,
		cur:        entry,
		assigned:   map[string]bool{},
		paramRegs:  map[string]bool{},
		localFuncs: localFuncs,
	}
}

// resolveRequire rewrites the root component of a dotted callee name through the
// require-alias table, so `cp.exec` becomes `child_process.exec` and a
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

// posForIdx resolves a goja file.Idx to a gIR Position, returning nil when
// unavailable.
func posForIdx(fset *file.FileSet, filename string, idx file.Idx) *ir.Position {
	if fset == nil || idx == 0 {
		return nil
	}
	p := fset.Position(idx)
	if p.Line <= 0 {
		return nil
	}
	return &ir.Position{Filename: filename, Line: int32(p.Line), Column: int32(p.Column)}
}

// newValueInst allocates a fresh instruction with a result register (for
// value-producing ops: CALL, FIELD, INDEX, BIN_OP, UN_OP, PHI, INTRINSIC).
func (fs *funcState) newValueInst(idx file.Idx) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: posForIdx(fs.fset, fs.filename, idx)}
}

// newVoidInst allocates a fresh instruction with no result register (STORE/RET).
func (fs *funcState) newVoidInst(idx file.Idx) *ir.Instruction {
	return &ir.Instruction{Pos: posForIdx(fs.fset, fs.filename, idx)}
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

// calleeCommon builds a CallCommon naming callee both as its FuncName value and
// its Callee (the syntactic name the engine matches against rule globs).
func calleeCommon(callee string) *ir.CallCommon {
	return &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
	}
}

// emitCall emits an OP_CODE_CALL to callee with no receiver, lowering args in
// order, and returns its result register. Used by lowerNew; a method call goes
// through emitCallRecvInst directly so lowerCall can reach the instruction.
func (fs *funcState) emitCall(callee string, args []ast.Expression, idx file.Idx) *ir.Value {
	return ssabuild.Reg(fs.emitCallRecvInst(callee, nil, args, idx).Name)
}

// emitCallRecvInst is emitCallRecv returning the instruction, so a caller that
// needs the LOWERED argument values (rather than re-lowering the expressions,
// which would duplicate their side effects) can read them off Call.Args.
func (fs *funcState) emitCallRecvInst(callee string, receiver *ir.Value, args []ast.Expression, idx file.Idx) *ir.Instruction {
	cc := calleeCommon(callee)
	if receiver != nil {
		cc.Value = receiver
	}
	for _, a := range args {
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	inst := fs.newValueInst(idx)
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
func (fs *funcState) emitPromiseContinuation(callee string, receiver *ir.Value, call *ir.Instruction, idx file.Idx) {
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
	inst := fs.newValueInst(idx)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = cc
	fs.emit(inst)
}

// emitStore emits an OP_CODE_STORE of val into the address computed from
// baseExpr (`obj.attr = v` / `arr[i] = v`), so a tainted value written into a
// container marks that container tainted (see visitStore in the taint engine).
func (fs *funcState) emitStore(baseExpr ast.Expression, val *ir.Value, idx file.Idx) {
	base := fs.lowerExpr(baseExpr)
	inst := fs.newVoidInst(idx)
	inst.Op = ir.OpCode_OP_CODE_STORE
	inst.Operands = []*ir.Value{base, val}
	fs.emit(inst)
}

// emitUnsupported emits the generic "js.unsupported" intrinsic placeholder for
// an expression the converter does not model, returning its result register so
// the parent expression still has a value to consume.
func (fs *funcState) emitUnsupported(idx file.Idx, comment string) *ir.Value {
	inst := fs.newValueInst(idx)
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
	filename         string
	moduleName       string
	fset             *file.FileSet
	nameOf           map[ast.Node]string
	localFuncs       map[string]string
	moduleAliases    map[string]string
	relativeDefaults map[string]string
	handlers         map[ast.Node]bool
}

// newFuncState creates a funcState for a function in this module, priming the
// module-scoped fields. isHandler is NOT set here: it is per-function and the
// synthetic <module> function is never a handler.
func (m *moduleCtx) newFuncState() *funcState {
	fs := newFuncState(m.filename, m.fset, m.nameOf, m.localFuncs)
	fs.moduleName = m.moduleName
	fs.moduleAliases = m.moduleAliases
	fs.relativeDefaults = m.relativeDefaults
	return fs
}

// lowerFunction lowers one collected function (declaration, function expression,
// or arrow function) into an ir.Function whose body is a REAL CFG built by an
// ssabuild.Builder.
func lowerFunction(m *moduleCtx, pf pendingFunc) *ir.Function {
	filename, fset := m.filename, m.fset
	fn := &ir.Function{
		Name:          pf.qualname,
		ObjectName:    pf.objectName,
		PackageName:   m.moduleName,
		CanonicalName: "js:" + m.moduleName + "." + pf.qualname,
	}

	fs := m.newFuncState()
	fs.isHandler = m.handlers[pf.node]
	// A method's qualname is "<Class>.<method>" (or nested "<a>.<b>"); record the
	// prefix so `this.method(x)` resolves to the sibling method.
	if i := strings.LastIndexByte(pf.qualname, '.'); i >= 0 {
		fs.methodClass = pf.qualname[:i+1]
	}

	switch node := pf.node.(type) {
	case *ast.FunctionLiteral:
		fn.Pos = posForIdx(fset, filename, node.Function)
		if node.ParameterList != nil {
			bindParams(fs, fn, node.ParameterList)
		}
		if node.Body != nil {
			fs.lowerBody(node.Body.List)
		}
	case *ast.ArrowFunctionLiteral:
		fn.Pos = posForIdx(fset, filename, node.Start)
		if node.ParameterList != nil {
			bindParams(fs, fn, node.ParameterList)
		}
		fs.lowerConciseBody(node.Body)
	}

	fn.Blocks = fs.b.Finish()
	return fn
}

// bindParams binds each parameter (and the rest parameter, if any) to a
// register named after the parameter itself. Destructuring parameters
// (ObjectPattern/ArrayPattern) get a synthetic "_argN" name so the parameter
// list stays positionally aligned; the pattern's own bindings are not modeled.
func bindParams(fs *funcState, fn *ir.Function, params *ast.ParameterList) {
	bind := func(name string) {
		v := ssabuild.Reg(name)
		fn.Params = append(fn.Params, v)
		fs.write(name, v)
		fs.paramRegs[name] = true
	}
	for i, b := range params.List {
		name := bindingName(b.Target)
		if name == "" {
			name = fmt.Sprintf("_arg%d", i)
		}
		bind(name)
		// A route handler's first parameter is the framework request object;
		// remember it so property reads off it are canonicalized to `req` and match
		// the request-source globs regardless of the parameter's actual name.
		if i == 0 && fs.isHandler {
			fs.reqParam = name
			// A signature-destructured request object — `({ query, body }, res) =>`
			// — has no `req.query` member read to seed taint from (COV-11).
			if pat, ok := b.Target.(*ast.ObjectPattern); ok {
				fs.bindHandlerDestructure(pat)
			}
		}
	}
	if params.Rest != nil {
		if id, ok := params.Rest.(*ast.Identifier); ok {
			bind(string(id.Name))
		}
	}
}

// bindHandlerDestructure binds each property of a route handler's destructured
// request parameter — `({ query, body: b }, res) => ...` — to a synthetic
// `js:req.<key>` source read, so the local carries request taint exactly as an
// in-body `req.query` member read would. Nested/computed patterns are skipped.
func (fs *funcState) bindHandlerDestructure(pat *ast.ObjectPattern) {
	for _, b := range objectPatternBindings(pat) {
		if b.Key == "" || b.Local == "" {
			continue
		}
		fs.write(b.Local, fs.emitRootPropertyRead("req", b.Key, nil, pat.Idx0()))
	}
}

// lowerConciseBody lowers an arrow function's body, which is either a normal
// block or a "concise" bare-expression body (`(x) => x + 1`); the latter is
// treated as an implicit `return <expr>`.
func (fs *funcState) lowerConciseBody(body ast.ConciseBody) {
	switch b := body.(type) {
	case *ast.BlockStatement:
		fs.lowerBody(b.List)
	case *ast.ExpressionBody:
		inst := fs.newVoidInst(b.Expression.Idx0())
		inst.Op = ir.OpCode_OP_CODE_RET
		inst.Operands = []*ir.Value{fs.lowerExpr(b.Expression)}
		fs.emit(inst)
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
func (fs *funcState) opaqueRootFor(e ast.Expression, base *ir.Value) (string, bool) {
	if root, ok := fs.isOpaqueBase(base); ok {
		return root, ok
	}
	id, ok := e.(*ast.Identifier)
	if !ok {
		return "", false
	}
	name := string(id.Name)
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
func (fs *funcState) emitRootPropertyRead(root, field string, base *ir.Value, idx file.Idx) *ir.Value {
	callee := "js:" + root + "." + field
	inst := fs.newValueInst(idx)
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
func (fs *funcState) lowerBody(stmts []ast.Statement) {
	for _, s := range stmts {
		switch v := s.(type) {
		case *ast.IfStatement:
			fs.lowerIf(v)
		case *ast.ForStatement:
			fs.lowerFor(v)
		case *ast.ForInStatement:
			fs.lowerForRange(v.Into, v.Source, v.Body)
		case *ast.ForOfStatement:
			fs.lowerForRange(v.Into, v.Source, v.Body)
		case *ast.WhileStatement:
			fs.lowerWhile(v)
		case *ast.DoWhileStatement:
			fs.lowerDoWhile(v)
		case *ast.SwitchStatement:
			fs.lowerSwitch(v)
		case *ast.TryStatement:
			fs.lowerTry(v)
		case *ast.BlockStatement:
			fs.lowerBody(v.List)
		case *ast.LabelledStatement:
			// A labelled loop/if is lowered as its underlying statement (the label
			// only matters for a precise break/continue, which we do not model).
			fs.lowerBody(stmtList(v.Statement))
		case *ast.WithStatement:
			// `with (obj) body`: lower the object (for any embedded source/sink) then
			// the body straight into the current block (no separate scope modeled).
			fs.lowerExpr(v.Object)
			fs.lowerBody(stmtList(v.Body))
		default:
			fs.lowerStmt(s)
		}
	}
}

// lowerIf lowers `if (test) consequent [else alternate]` into a REAL CFG
// diamond via the Builder's IfDiamond scaffold, so a variable rebound on either
// arm reconciles via an on-demand ReadVariable PHI — which is what keeps the
// pre-branch tainted value in the "default if empty" idiom `if (!x) x = "d"`.
// An `else if` is an IfStatement in the parent's Alternate, so a chain becomes
// nested diamonds via the recursive lowerBody.
func (fs *funcState) lowerIf(v *ast.IfStatement) {
	cond := fs.lowerExpr(v.Test)
	fs.b.IfDiamond(&fs.cur, &fs.terminated, cond,
		func() { fs.lowerBody(stmtList(v.Consequent)) },
		func() {
			if v.Alternate != nil {
				fs.lowerBody(stmtList(v.Alternate))
			}
		})
}

// lowerWhile lowers `while (test) body` into a REAL loop CFG via the Builder's
// HeaderLoop scaffold (header/body/exit; the header PHI is what carries
// loop-carried taint — see the scaffold's doc).
func (fs *funcState) lowerWhile(v *ast.WhileStatement) {
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return fs.lowerExpr(v.Test) }, // condition, lowered in the (unsealed) header
		func() { fs.lowerBody(stmtList(v.Body)) })
}

// lowerDoWhile lowers `do body while (test)` — the body runs BEFORE the test —
// via the Builder's BodyLoop scaffold (the body is the loop header; its
// back-edge comes from the test block). Loop-carried taint flows through the
// body-header PHI.
func (fs *funcState) lowerDoWhile(v *ast.DoWhileStatement) {
	fs.b.BodyLoop(&fs.cur, &fs.terminated,
		func() { fs.lowerBody(stmtList(v.Body)) },
		func() *ir.Value { return fs.lowerExpr(v.Test) })
}

// lowerFor lowers a C-style `for (init; test; update) body` into the HeaderLoop
// CFG. A missing test is an opaque always-true, so both body and exit are
// traversed; the update runs at the END of the body block, before the back-edge.
// Reassignments in the body or update flow through the header PHI, modeling
// loop-carried taint.
func (fs *funcState) lowerFor(v *ast.ForStatement) {
	if v.Initializer != nil {
		fs.lowerForInit(v.Initializer) // evaluated once in the pre-loop block
	}
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value {
			if v.Test != nil {
				return fs.lowerExpr(v.Test) // lowered in the (unsealed) header
			}
			return ssabuild.Str("")
		},
		func() {
			fs.lowerBody(stmtList(v.Body))
			if v.Update != nil {
				fs.lowerExpr(v.Update) // the `i++` step, at the body's END block
			}
		})
}

// lowerForRange lowers `for (into in|of source) body` into the same HeaderLoop
// CFG as lowerWhile. The loop variable is bound to the source's value at the top
// of the BODY block each iteration (element taint == container taint, so a
// tainted iterable taints the loop variable).
func (fs *funcState) lowerForRange(into ast.ForInto, source ast.Expression, bodyStmt ast.Statement) {
	src := fs.lowerExpr(source) // evaluate the iterable in the pre-loop block
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return ssabuild.Str("") }, // opaque iteration condition
		func() {
			fs.bindForInto(into, src) // bind the loop variable each iteration
			fs.lowerBody(stmtList(bodyStmt))
		})
}

// bindForInto binds a for-in/for-of loop variable (the `x` in `for (x of it)` /
// `for (const x in it)`) to val in the current block. A declared target
// (ForIntoVar / ForDeclaration) writes a fresh local; a bare assignment target
// (ForIntoExpression, e.g. `for (x of it)` reusing an outer `x`) rebinds through
// assignTo. Destructuring targets are dropped (a documented limitation).
func (fs *funcState) bindForInto(into ast.ForInto, val *ir.Value) {
	switch t := into.(type) {
	case *ast.ForIntoVar:
		if name := bindingName(t.Binding.Target); name != "" {
			fs.write(name, val)
		}
	case *ast.ForDeclaration:
		if name := bindingName(t.Target); name != "" {
			fs.write(name, val)
		}
	case *ast.ForIntoExpression:
		fs.assignTo(t.Expression, val)
	}
}

// lowerSwitch lowers `switch (disc) { case ...: ... }` conservatively (a
// may-analysis; break is NOT modeled precisely). A cascade of two-way decision
// branches makes EVERY case block (and the exit, for the no-match path)
// reachable; each case's consequent lowers into its own block and FALLS THROUGH
// to the next (the last to exit), so taint written in any case — and carried by
// fall-through into a later case — is captured. `default` needs no special
// handling since every case is reachable.
func (fs *funcState) lowerSwitch(v *ast.SwitchStatement) {
	disc := fs.lowerExpr(v.Discriminant)
	n := len(v.Body)
	if n == 0 {
		return // empty switch: discriminant already lowered for side effects
	}
	// Lower each case's test in the discriminant block for an embedded
	// source/sink; the boolean result is not otherwise needed.
	for _, cs := range v.Body {
		if cs.Test != nil {
			fs.lowerExpr(cs.Test)
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
		fs.lowerBody(v.Body[i].Consequent)
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
func (fs *funcState) lowerTry(v *ast.TryStatement) {
	if v.Body != nil {
		fs.lowerBody(v.Body.List)
	}
	bodyEnd := fs.cur
	bodyTerm := fs.terminated

	if v.Catch == nil {
		if v.Finally != nil {
			fs.lowerBody(v.Finally.List)
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
	if v.Catch.Body != nil {
		fs.lowerBody(v.Catch.Body.List)
	}
	handlerTerm := fs.terminated
	if !handlerTerm {
		fs.b.SetJump(fs.cur, after)
	}

	fs.b.Seal(after)
	fs.cur = after
	fs.terminated = bodyTerm && handlerTerm
	if v.Finally != nil {
		fs.lowerBody(v.Finally.List)
	}
}

// lowerForInit lowers a `for(...)` loop's initializer clause, which may be a
// bare expression, a `var` declaration list, or a `let`/`const` declaration.
func (fs *funcState) lowerForInit(init ast.ForLoopInitializer) {
	switch v := init.(type) {
	case *ast.ForLoopInitializerExpression:
		fs.lowerExpr(v.Expression)
	case *ast.ForLoopInitializerVarDeclList:
		for _, b := range v.List {
			fs.lowerBinding(b)
		}
	case *ast.ForLoopInitializerLexicalDecl:
		for _, b := range v.LexicalDeclaration.List {
			fs.lowerBinding(b)
		}
	}
}

// lowerStmt lowers one leaf statement (i.e. not a control-flow compound;
// those are flattened by lowerBody).
func (fs *funcState) lowerStmt(s ast.Statement) {
	switch v := s.(type) {
	case *ast.VariableStatement:
		for _, b := range v.List {
			fs.lowerBinding(b)
		}
	case *ast.LexicalDeclaration:
		for _, b := range v.List {
			fs.lowerBinding(b)
		}
	case *ast.ExpressionStatement:
		fs.lowerExpr(v.Expression)
	case *ast.ReturnStatement:
		inst := fs.newVoidInst(s.Idx0())
		inst.Op = ir.OpCode_OP_CODE_RET
		if v.Argument != nil {
			inst.Operands = []*ir.Value{fs.lowerExpr(v.Argument)}
		}
		fs.emit(inst)
		// A returning arm must not feed its values into a merge / loop header /
		// switch fall-through join.
		fs.terminated = true
	case *ast.ThrowStatement:
		// `throw x` deliberately does NOT terminate the block: leaving it
		// non-terminated preserves the exception edge into an enclosing try's catch
		// (see lowerTry), so taint assigned before a `throw` reaches the handler.
		fs.lowerExpr(v.Argument)
	case *ast.FunctionDeclaration:
		// Converted separately (see collector); bind the name so later reads of it
		// as a plain VALUE resolve to a function reference rather than a GlobalName.
		// (Call callees are resolved syntactically instead — see lowerCall.)
		if v.Function.Name != nil {
			if canonical, ok := fs.nameOf[v.Function]; ok {
				fs.write(string(v.Function.Name.Name), &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}})
			}
		}
	default:
		// ClassDeclaration, EmptyStatement, BranchStatement,
		// DebuggerStatement, BadStatement: no-ops / unsupported, dropped
		// (documented limitation for classes; the rest carry no dataflow).
	}
}

// lowerBinding lowers one `var`/`let`/`const` binding, evaluating its
// initializer (if any) and binding the result to the target name.
func (fs *funcState) lowerBinding(b *ast.Binding) {
	if op, ok := b.Target.(*ast.ObjectPattern); ok {
		fs.lowerObjectPatternBinding(op, b.Initializer)
		return
	}
	if ap, ok := b.Target.(*ast.ArrayPattern); ok {
		fs.lowerArrayPatternBinding(ap, b.Initializer)
		return
	}
	name := bindingName(b.Target)
	if b.Initializer == nil {
		if name != "" {
			fs.write(name, ssabuild.Nil())
		}
		return
	}
	val := fs.lowerExpr(b.Initializer)
	if name != "" {
		fs.write(name, val)
	}
}

// lowerObjectPatternBinding binds each name in an object-destructuring pattern
// (const { a, b: c, ...rest } = init) to a field read off the initializer, so
// taint carried by the initializer (typically req.query / req.body) reaches the
// destructured names — the common Express idiom.
func (fs *funcState) lowerObjectPatternBinding(op *ast.ObjectPattern, init ast.Expression) {
	if init == nil {
		return
	}
	base := fs.lowerExpr(init)
	bindField := func(localName, field string) {
		if localName == "" {
			return
		}
		fs.write(localName, fs.emitFieldRead(base, field, op.LeftBrace))
	}
	for _, b := range objectPatternBindings(op) {
		bindField(b.Local, b.Key)
	}
	// `const { ...rest } = init`: the rest object carries the initializer's taint.
	if id, ok := op.Rest.(*ast.Identifier); ok {
		fs.write(string(id.Name), base)
	}
}

// lowerArrayPatternBinding binds each name in an array-destructuring pattern
// (const [a, b, ...rest] = init) to the initializer's value (element taint ==
// container taint). Elisions, per-element defaults and nested patterns are not
// modeled.
func (fs *funcState) lowerArrayPatternBinding(ap *ast.ArrayPattern, init ast.Expression) {
	if init == nil {
		return
	}
	base := fs.lowerExpr(init)
	for _, el := range ap.Elements {
		if id, ok := el.(*ast.Identifier); ok {
			fs.write(string(id.Name), base)
		}
	}
	if id, ok := ap.Rest.(*ast.Identifier); ok {
		fs.write(string(id.Name), base)
	}
}

// patBinding is one name an object-destructuring pattern binds: the LOCAL name
// introduced, and the KEY (source field) it reads. Key is "" for a computed key
// propertyKeyName cannot resolve statically — each caller decides what to do
// with that, since they differ (bind nothing, vs. keep an empty field name).
type patBinding struct{ Local, Key string }

// objectPatternBindings returns the bindings an object pattern introduces, for
// the three places that walk one: a handler's destructured request parameter, a
// destructuring variable declaration, and `const {a, b} = require('m')`. Only
// plain shorthand (`{query}`) and keyed-with-identifier-target (`{query: q}`)
// properties are modeled; a nested or otherwise non-identifier target yields no
// entry. op.Rest is deliberately NOT handled here — each caller binds it
// differently.
func objectPatternBindings(op *ast.ObjectPattern) []patBinding {
	var out []patBinding
	for _, p := range op.Properties {
		switch prop := p.(type) {
		case *ast.PropertyShort:
			out = append(out, patBinding{Local: string(prop.Name.Name), Key: string(prop.Name.Name)})
		case *ast.PropertyKeyed:
			// `{ query: q }` -> field `query`, local `q`.
			if id, ok := prop.Value.(*ast.Identifier); ok {
				out = append(out, patBinding{Local: string(id.Name), Key: propertyKeyName(prop.Key)})
			}
		}
	}
	return out
}

// reactHTMLSink is the synthetic callee react-xss.yaml matches. Spelled with the
// `js:` prefix because emitCall writes the callee verbatim -- sfc.go's Vue
// equivalent gets the prefix for free by injecting source text that is then
// lowered as an ordinary call.
const reactHTMLSink = "js:__godzilla_react_html"

// emitReactHTMLSink gives React's dangerouslySetInnerHTML a callee to match.
// It is the framework's one documented escape from JSX auto-escaping, but unlike
// Vue's v-html it is spelled as DATA, not a directive: esbuild lowers the JSX
// attribute to a `{__html: x}` object literal inside a createElement props
// argument, so nothing in the IR is a call and no sink glob can name it. Mirror
// it the way sfc.go mirrors v-html -- emit a call carrying the value.
//
// Keyed on the inner `__html`, not the attribute name. __html is React's own
// marker and the only reason to build such an object, and keying on it also
// catches the indirect form (`const h = {__html: x}` handed to the attribute by
// variable) that keying on the attribute would miss.
func (fs *funcState) emitReactHTMLSink(o *ast.ObjectLiteral) {
	for _, p := range o.Value {
		kp, ok := p.(*ast.PropertyKeyed)
		if !ok || propertyKeyName(kp.Key) != "__html" || kp.Value == nil {
			continue
		}
		fs.emitCall(reactHTMLSink, []ast.Expression{kp.Value}, kp.Value.Idx0())
	}
}

// propertyKeyName extracts the static field name of a destructuring property
// key (an identifier or string literal); other computed keys yield "".
func propertyKeyName(key ast.Expression) string {
	switch k := key.(type) {
	case *ast.Identifier:
		return string(k.Name)
	case *ast.StringLiteral:
		return string(k.Value)
	}
	return ""
}

// lowerExpr lowers an expression to a gIR Value, emitting whatever instructions
// are needed to compute it into the current block. Names assigned as locals
// resolve through the Builder to their current SSA value; unbound names (free
// variables — builtins, another function's or the module's locals, since closures
// are not modeled) fall back to a GlobalName reference.
func (fs *funcState) lowerExpr(e ast.Expression) *ir.Value {
	if e == nil {
		return nil
	}
	switch v := e.(type) {
	case *ast.Identifier:
		if fs.assigned[string(v.Name)] {
			return fs.read(string(v.Name))
		}
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: string(v.Name)}}

	case *ast.StringLiteral:
		return ssabuild.Str(string(v.Value))

	case *ast.NumberLiteral:
		return numberValue(v.Value)

	case *ast.BooleanLiteral:
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_BoolVal{BoolVal: v.Value}}}}

	case *ast.NullLiteral:
		return ssabuild.Nil()

	case *ast.RegExpLiteral:
		return ssabuild.Str(v.Literal) // best-effort string representation

	case *ast.TemplateLiteral:
		return fs.lowerTemplateLiteral(v)

	case *ast.BinaryExpression:
		return fs.lowerBinary(v)

	case *ast.UnaryExpression:
		return fs.lowerUnary(v)

	case *ast.AssignExpression:
		return fs.lowerAssign(v)

	case *ast.SequenceExpression:
		var last *ir.Value
		for _, x := range v.Sequence {
			last = fs.lowerExpr(x)
		}
		return last

	case *ast.ConditionalExpression:
		// No branch blocks: evaluate the test for side effects/taint discovery,
		// then merge both arms with a PHI so taint from either reaches the result.
		fs.lowerExpr(v.Test)
		cv := fs.lowerExpr(v.Consequent)
		av := fs.lowerExpr(v.Alternate)
		inst := fs.newValueInst(v.Idx0())
		inst.Op = ir.OpCode_OP_CODE_PHI
		inst.Operands = []*ir.Value{cv, av}
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)

	case *ast.CallExpression:
		return fs.lowerCall(v)

	case *ast.NewExpression:
		return fs.lowerNew(v)

	case *ast.DotExpression:
		return fs.lowerDot(v)

	case *ast.BracketExpression:
		return fs.lowerBracket(v)

	case *ast.ArrayLiteral:
		return fs.lowerAggregate(v.Value, v.Idx0())

	case *ast.ObjectLiteral:
		vals := make([]ast.Expression, 0, len(v.Value))
		for _, p := range v.Value {
			if pv := propertyValue(p); pv != nil {
				vals = append(vals, pv)
			}
		}
		fs.emitReactHTMLSink(v)
		return fs.lowerAggregate(vals, v.Idx0())

	case *ast.SpreadElement:
		return fs.lowerExpr(v.Expression)

	case *ast.ThisExpression:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "this"}}

	case *ast.SuperExpression:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "super"}}

	case *ast.YieldExpression:
		// Generators are not modeled: `yield x` lowers to `x`.
		if v.Argument != nil {
			return fs.lowerExpr(v.Argument)
		}
		return ssabuild.Nil()

	case *ast.AwaitExpression:
		// `await x` lowers to `x` (see emitPromiseContinuation for `.then`).
		return fs.lowerExpr(v.Argument)

	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		return fs.funcRefValue(e)

	case *ast.OptionalChain:
		// `a?.b` yields the same value as `a.b` when it does not short-circuit.
		return fs.lowerExpr(v.Expression)

	case *ast.Optional:
		return fs.lowerExpr(v.Expression)

	default:
		return fs.emitUnsupported(e.Idx0(), fmt.Sprintf("unsupported javascript expression: %T", e))
	}
}

// funcRefValue resolves an inline function-literal/arrow expression (e.g. a
// callback argument) to a FuncName reference to the ir.Function the collector
// already created for it, rather than inlining its body again.
func (fs *funcState) funcRefValue(e ast.Expression) *ir.Value {
	if canonical, ok := fs.nameOf[e]; ok {
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}}
	}
	// Unreachable — the collector visits every expression tree lowering does.
	return fs.emitUnsupported(e.Idx0(), "unresolved inline function literal")
}

// lowerDot lowers `a.b`. If the base is opaque (see isOpaqueBase), this hop
// is the root of the chain and becomes a synthetic property-read CALL;
// otherwise it is a normal FIELD read off the base's register.
func (fs *funcState) lowerDot(v *ast.DotExpression) *ir.Value {
	base := fs.lowerExpr(v.Left)
	field := string(v.Identifier.Name)

	if root, ok := fs.opaqueRootFor(v.Left, base); ok {
		return fs.emitRootPropertyRead(root, field, base, v.Idx0())
	}

	return fs.emitFieldRead(base, field, v.Idx0())
}

func (fs *funcState) emitFieldRead(base *ir.Value, field string, idx file.Idx) *ir.Value {
	inst := fs.newValueInst(idx)
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
func (fs *funcState) lowerBracket(v *ast.BracketExpression) *ir.Value {
	base := fs.lowerExpr(v.Left)
	idx := fs.lowerExpr(v.Member)

	if root, ok := fs.opaqueRootFor(v.Left, base); ok {
		return fs.emitRootPropertyRead(root, bracketFieldName(v.Member), base, v.Idx0())
	}

	inst := fs.newValueInst(v.Idx0())
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{base, idx}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

func bracketFieldName(m ast.Expression) string {
	if sl, ok := m.(*ast.StringLiteral); ok {
		return string(sl.Value)
	}
	return "*"
}

// lowerAggregate lowers an array/object literal's element values, merging their
// taint into one register via OP_CODE_PHI (field-insensitive; see package doc).
func (fs *funcState) lowerAggregate(exprs []ast.Expression, idx file.Idx) *ir.Value {
	var acc *ir.Value
	for _, e := range exprs {
		if e == nil {
			continue // sparse array elision
		}
		v := fs.lowerExpr(e)
		if acc == nil {
			acc = v
			continue
		}
		inst := fs.newValueInst(idx)
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
func (fs *funcState) lowerTemplateLiteral(v *ast.TemplateLiteral) *ir.Value {
	var acc *ir.Value
	for i, el := range v.Elements {
		if el != nil {
			acc = fs.concat(acc, ssabuild.Str(string(el.Parsed)), v.Idx0())
		}
		if i < len(v.Expressions) {
			acc = fs.concat(acc, fs.lowerExpr(v.Expressions[i]), v.Idx0())
		}
	}
	if acc == nil {
		acc = ssabuild.Str("")
	}
	return acc
}

func (fs *funcState) concat(acc, val *ir.Value, idx file.Idx) *ir.Value {
	if acc == nil {
		return val
	}
	if val == nil {
		return acc
	}
	inst := fs.newValueInst(idx)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = ir.BinOpKind_BIN_OP_ADD
	inst.Operands = []*ir.Value{acc, val}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerBinary lowers a binary expression (arithmetic, bitwise, or — approximated,
// see package doc — logical) to a BIN_OP. A comparison instead lowers to the inert
// builtin.compare intrinsic: a bool carries influence rather than content.
func (fs *funcState) lowerBinary(v *ast.BinaryExpression) *ir.Value {
	left := fs.lowerExpr(v.Left)
	right := fs.lowerExpr(v.Right)
	inst := fs.newValueInst(v.Idx0())
	if isComparisonToken(v.Operator) {
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "builtin.compare"
	} else {
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKind(v.Operator)
	}
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerUnary lowers a unary expression. Prefix/postfix ++/-- on a plain
// identifier also rebinds it, approximating the mutation.
func (fs *funcState) lowerUnary(v *ast.UnaryExpression) *ir.Value {
	operand := fs.lowerExpr(v.Operand)
	inst := fs.newValueInst(v.Idx0())
	inst.Op = ir.OpCode_OP_CODE_UN_OP
	inst.UnOp = unOpKind(v.Operator)
	inst.Operands = []*ir.Value{operand}
	fs.emit(inst)
	result := ssabuild.Reg(inst.Name)

	if v.Operator == token.INCREMENT || v.Operator == token.DECREMENT {
		if id, ok := v.Operand.(*ast.Identifier); ok {
			fs.write(string(id.Name), result)
		}
	}
	return result
}

// lowerAssign lowers `target = value` (and compound assignments like `+=`),
// returning the assigned value so it can also be a sub-expression (`x = y = 5`).
func (fs *funcState) lowerAssign(a *ast.AssignExpression) *ir.Value {
	var rhs *ir.Value
	if a.Operator == token.ASSIGN {
		rhs = fs.lowerExpr(a.Right)
	} else {
		cur := fs.lowerExpr(a.Left)
		right := fs.lowerExpr(a.Right)
		inst := fs.newValueInst(a.Idx0())
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKindForCompoundAssign(a.Operator)
		inst.Operands = []*ir.Value{cur, right}
		fs.emit(inst)
		rhs = ssabuild.Reg(inst.Name)
	}
	fs.assignTo(a.Left, rhs)
	return rhs
}

// assignTo binds a lowered value to an assignment target. A bare identifier
// rebinds the variable. A DotExpression/BracketExpression target (`obj.attr = v`
// / `arr[i] = v`) emits a STORE with the base object as the address operand,
// which is what lets a tainted value written into a container mark that container
// tainted (see visitStore in internal/analysis/taint.go). Destructuring targets
// are dropped.
func (fs *funcState) assignTo(target ast.Expression, val *ir.Value) {
	switch t := target.(type) {
	case *ast.Identifier:
		fs.write(string(t.Name), val)
	case *ast.DotExpression:
		fs.emitStore(t.Left, val, t.Idx0())
	case *ast.BracketExpression:
		fs.emitStore(t.Left, val, t.Idx0())
	default:
		// Destructuring assignment or another unsupported target shape: dropped.
	}
}

// lowerCall lowers a call expression to OP_CODE_CALL. The callee is a purely
// syntactic dotted name (see syntacticCallee), never resolved through the
// environment, so `child_process.exec(cmd)` resolves to "js:child_process.exec"
// regardless of whether/how `child_process` is bound.
func (fs *funcState) lowerCall(v *ast.CallExpression) *ir.Value {
	// For a method call, lower the receiver (the callee's base object) so its
	// register can be carried in Call.Value (see emitCallRecvInst): this both
	// evaluates the base -- which, off an opaque request object like `req.url`,
	// is itself the synthetic taint source -- and lets a taint-preserving method
	// like `.slice`/`.toLowerCase` propagate the receiver's taint to the result.
	// lowerExpr recurses through any nested call in the base chain, so it fully
	// subsumes lowerNestedCallees for these two callee shapes.
	var receiver *ir.Value
	switch c := v.Callee.(type) {
	case *ast.DotExpression:
		receiver = fs.lowerExpr(c.Left)
	case *ast.BracketExpression:
		receiver = fs.lowerExpr(c.Left)
	default:
		fs.lowerNestedCallees(v.Callee)
	}
	callee := "js:" + fs.resolveRequire(syntacticCallee(v.Callee))
	// A bare call to a top-level function (helper(x)) must carry the module name
	// so its callee matches the function's CanonicalName; otherwise byKey never
	// resolves it and taint does not flow through the local helper.
	if id, ok := v.Callee.(*ast.Identifier); ok {
		if canonical, found := fs.localFuncs[string(id.Name)]; found {
			callee = canonical
		} else if mod, found := fs.relativeDefaults[string(id.Name)]; found {
			// Bare call to a name default-imported from a relative require:
			// emit a resolvable marker naming the target module. Its default
			// export is filled in by resolveJSCrossModuleCalls once every file
			// is lowered (the callee function may live in a not-yet-seen file).
			callee = crossModuleMarker + mod
		}
	}
	// `this.method(x)` inside a class method: qualify to the sibling method's
	// canonical name so byKey resolves it. Optimistic — a non-method `this.x`
	// matches no function and stays unresolved (harmless). JS methods take no
	// explicit receiver param, so the arguments already align.
	if dot, ok := v.Callee.(*ast.DotExpression); ok && fs.methodClass != "" {
		if _, isThis := dot.Left.(*ast.ThisExpression); isThis {
			callee = "js:" + fs.moduleName + "." + fs.methodClass + string(dot.Identifier.Name)
		}
	}
	call := fs.emitCallRecvInst(callee, receiver, v.ArgumentList, v.Idx0())
	fs.emitPromiseContinuation(callee, receiver, call, v.Idx0())
	return ssabuild.Reg(call.Name)
}

// lowerNew lowers `new Foo(args)` the same way as a call (for taint purposes
// construction is indistinguishable from calling a function with the same
// arguments); the "new" prefix keeps the callee from colliding with a plain
// `Foo(args)` call.
func (fs *funcState) lowerNew(v *ast.NewExpression) *ir.Value {
	fs.lowerNestedCallees(v.Callee)
	return fs.emitCall("js:new:"+syntacticCallee(v.Callee), v.ArgumentList, v.Idx0())
}

// lowerNestedCallees walks a call/new expression's callee along the same
// Dot/Bracket "Left" chain syntacticCallee walks and lowers any CallExpression
// it finds — e.g. the `axios.get(url)` inside `axios.get(url).then(cb)` —
// inside-out via the ordinary lowerCall path.
//
// Without it the inner call is never visited at all: syntactic name building is
// a pure string walk with no side effects, so the inner call's instruction (and
// with it its args, its taint, and its chance to match a source/sink glob) would
// silently disappear. Its result register is deliberately discarded — the outer
// call is still named by syntacticCallee's "<dynamic>" fallback.
func (fs *funcState) lowerNestedCallees(e ast.Expression) {
	switch v := e.(type) {
	case *ast.CallExpression:
		fs.lowerCall(v)
	case *ast.DotExpression:
		fs.lowerNestedCallees(v.Left)
	case *ast.BracketExpression:
		fs.lowerNestedCallees(v.Left)
	}
}

// syntacticCallee builds a canonical, purely syntactic dotted callee name from a
// call's callee expression, e.g. `res.locals.get`. A callee rooted in anything
// other than a plain Identifier/Dot/string-keyed-Bracket chain (a nested call, a
// computed index, a function expression) resolves to "<dynamic>" for that
// sub-path, so `getHandler().process(x)` yields "<dynamic>.process" — glob
// patterns like "js:*.process" still match it. Any CallExpression along the chain
// has already been lowered by lowerNestedCallees, so collapsing it here costs
// only the outer call's name.
func syntacticCallee(e ast.Expression) string {
	switch v := e.(type) {
	case *ast.Identifier:
		return string(v.Name)
	case *ast.DotExpression:
		return syntacticCallee(v.Left) + "." + string(v.Identifier.Name)
	case *ast.BracketExpression:
		if sl, ok := v.Member.(*ast.StringLiteral); ok {
			return syntacticCallee(v.Left) + "." + string(sl.Value)
		}
		return syntacticCallee(v.Left) + ".<dynamic>"
	case *ast.SequenceExpression:
		// esbuild's ES-module interop lowers a named-import call `fn(x)` to
		// `(0, import_mod.fn)(x)` — the callee is a comma SequenceExpression whose
		// LAST element (import_mod.fn) carries the real name. Recover it so
		// import-based sources/sinks (e.g. `import {execSync} from ...`) still
		// match; without this the callee collapses to "<dynamic>".
		if n := len(v.Sequence); n > 0 {
			return syntacticCallee(v.Sequence[n-1])
		}
		return "<dynamic>"
	default:
		return "<dynamic>"
	}
}

// numberValue converts a goja NumberLiteral's parsed value (int64, float64,
// or -- for BigInt literals -- *big.Int) into a gIR constant Value.
func numberValue(raw interface{}) *ir.Value {
	c := &ir.Constant{}
	switch n := raw.(type) {
	case int64:
		c.Value = &ir.Constant_IntVal{IntVal: n}
	case float64:
		c.Value = &ir.Constant_FloatVal{FloatVal: n}
	default:
		c.Value = &ir.Constant_StringVal{StringVal: fmt.Sprintf("%v", n)}
	}
	return &ir.Value{Kind: &ir.Value_Constant{Constant: c}}
}

// binOpKind maps a goja binary-operator token to a gIR BinOpKind. Logical
// &&/||/?? have no gIR counterpart and are approximated as their bitwise
// equivalents (safe for taint: either operand tainted still taints the result);
// the right-shift variants collapse into BIN_OP_SHR.
func binOpKind(op token.Token) ir.BinOpKind {
	switch op {
	case token.PLUS:
		return ir.BinOpKind_BIN_OP_ADD
	case token.MINUS:
		return ir.BinOpKind_BIN_OP_SUB
	case token.MULTIPLY:
		return ir.BinOpKind_BIN_OP_MUL
	case token.SLASH:
		return ir.BinOpKind_BIN_OP_QUO
	case token.REMAINDER:
		return ir.BinOpKind_BIN_OP_REM
	case token.AND, token.LOGICAL_AND:
		return ir.BinOpKind_BIN_OP_AND
	case token.OR, token.LOGICAL_OR, token.COALESCE:
		return ir.BinOpKind_BIN_OP_OR
	case token.EXCLUSIVE_OR:
		return ir.BinOpKind_BIN_OP_XOR
	case token.SHIFT_LEFT:
		return ir.BinOpKind_BIN_OP_SHL
	case token.SHIFT_RIGHT, token.UNSIGNED_SHIFT_RIGHT:
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

// isComparisonToken reports whether op yields a bool. Those lower to the
// builtin.compare intrinsic, so they never reach binOpKind.
func isComparisonToken(op token.Token) bool {
	switch op {
	case token.EQUAL, token.STRICT_EQUAL, token.NOT_EQUAL, token.STRICT_NOT_EQUAL,
		token.LESS, token.LESS_OR_EQUAL, token.GREATER, token.GREATER_OR_EQUAL:
		return true
	}
	return false
}

// binOpKindForCompoundAssign maps a compound-assignment token (`+=`, `-=`,
// etc.) to the BinOpKind of its underlying operator.
func binOpKindForCompoundAssign(op token.Token) ir.BinOpKind {
	switch op {
	case token.ADD_ASSIGN:
		return ir.BinOpKind_BIN_OP_ADD
	case token.SUBTRACT_ASSIGN:
		return ir.BinOpKind_BIN_OP_SUB
	case token.MULTIPLY_ASSIGN:
		return ir.BinOpKind_BIN_OP_MUL
	case token.QUOTIENT_ASSIGN:
		return ir.BinOpKind_BIN_OP_QUO
	case token.REMAINDER_ASSIGN:
		return ir.BinOpKind_BIN_OP_REM
	case token.AND_ASSIGN, token.LOGICAL_AND_ASSIGN:
		return ir.BinOpKind_BIN_OP_AND
	case token.OR_ASSIGN, token.LOGICAL_OR_ASSIGN, token.COALESCE_ASSIGN:
		return ir.BinOpKind_BIN_OP_OR
	case token.EXCLUSIVE_OR_ASSIGN:
		return ir.BinOpKind_BIN_OP_XOR
	case token.SHIFT_LEFT_ASSIGN:
		return ir.BinOpKind_BIN_OP_SHL
	case token.SHIFT_RIGHT_ASSIGN, token.UNSIGNED_SHIFT_RIGHT_ASSIGN:
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

// unOpKind maps a goja unary-operator token to a gIR UnOpKind. ++/-- have no
// counterpart and fall back to UN_OP_UNSPECIFIED; lowerUnary still emits the
// UN_OP so taint propagates through it.
func unOpKind(op token.Token) ir.UnOpKind {
	switch op {
	case token.NOT:
		return ir.UnOpKind_UN_OP_NOT
	case token.MINUS:
		return ir.UnOpKind_UN_OP_NEG
	case token.PLUS:
		return ir.UnOpKind_UN_OP_POS
	case token.BITWISE_NOT:
		return ir.UnOpKind_UN_OP_BIT_NOT
	}
	return ir.UnOpKind_UN_OP_UNSPECIFIED
}

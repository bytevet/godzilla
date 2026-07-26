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
// lowered into (threaded through the AST walk instead of appending to one flat
// instruction list). `assigned` tracks which JS names have been written as a
// local SO FAR in the traversal — it replaces the old env's key-presence test
// (is this bare name a bound local, or a free identifier / global / import?)
// that the Builder's per-block value map cannot answer directly. `paramRegs`
// is the set of register names that are this function's own parameters (see
// isOpaqueBase); `terminated` reports whether the current block has already
// emitted a block-terminating RET (an explicit `return`), so a returning arm is
// not wired into a merge / loop header / switch fall-through as a predecessor.
// `nameOf` is the shared node->canonical-name map built by the collector (so an
// inline function expression/arrow used as a value resolves to a FuncName
// reference to its already-lowered ir.Function instead of being inlined again).
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

// posForIdx resolves a goja file.Idx to a gIR Position via the file's
// FileSet, returning nil when unavailable (matching converters/go's
// convertPos and converters/python's posFromNode, which both return nil for
// an invalid/unknown position).
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

// newVoidInst allocates a fresh instruction with no result register (for
// STORE/RET).
func (fs *funcState) newVoidInst(idx file.Idx) *ir.Instruction {
	return &ir.Instruction{Pos: posForIdx(fs.fset, fs.filename, idx)}
}

// emit appends an instruction to the block currently being lowered.
func (fs *funcState) emit(inst *ir.Instruction) { fs.b.AddInstr(fs.cur, inst) }

// read returns the SSA value current for a JS local in the current block,
// inserting PHIs on demand (branch joins / loop headers) via the Builder.
func (fs *funcState) read(name string) *ir.Value { return fs.b.ReadVariable(name, fs.cur) }

// write records val as the current value of a JS local name in the current
// block and marks the name as assigned (so a later bare read resolves it as a
// variable rather than a free identifier / global / import).
func (fs *funcState) write(name string, val *ir.Value) {
	fs.b.WriteVariable(name, fs.cur, val)
	fs.assigned[name] = true
}

func regValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func stringValue(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
}

func nilValue() *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{IsNil: true}}}
}

// calleeCommon builds a CallCommon naming callee both as its FuncName value and
// its Callee (the syntactic name the engine matches against rule globs).
func calleeCommon(callee string) *ir.CallCommon {
	return &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
	}
}

// emitCall emits an OP_CODE_CALL to callee, lowering args in order, and returns
// its result register. Shared by lowerNew and (via emitCallRecv) lowerCall,
// whose only difference is how they build the callee name.
func (fs *funcState) emitCall(callee string, args []ast.Expression, idx file.Idx) *ir.Value {
	return fs.emitCallRecv(callee, nil, args, idx)
}

// emitCallRecv emits an OP_CODE_CALL to callee. For a method call (`obj.m(x)`),
// receiver is the already-lowered base object; it is placed in Call.Value so the
// engine -- which reads a method call's receiver from Call.Value (see
// propagatorOperands in internal/analysis) -- carries taint from the receiver
// through a taint-preserving transform such as `tainted.slice(i)` or
// `tainted.toLowerCase()`. JS methods take no explicit receiver argument, so the
// receiver stays OUT of Args and the arg->param alignment the engine relies on
// for cross-function calls is unchanged. When receiver is nil (a free/identifier
// call or `new`), Call.Value falls back to the callee FuncName as before.
func (fs *funcState) emitCallRecv(callee string, receiver *ir.Value, args []ast.Expression, idx file.Idx) *ir.Value {
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
	return regValue(inst.Name)
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
	return regValue(inst.Name)
}

// moduleCtx bundles the file-scoped state every function lowered from one JS
// module needs. It exists so lowerFunction takes one context instead of nine
// positional parameters, and — more importantly — so the module-scoped funcState
// fields are primed in exactly ONE place (newFuncState below); the <module>
// function and each real function used to prime them separately, with nothing
// keeping the two lists in sync.
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

// lowerFunction lowers one collected function (declaration, function
// expression, or arrow function) into an ir.Function whose body is a REAL CFG
// (blocks + preds/succs + on-demand PHI) built by an ssabuild.Builder. A
// function with no branches still emits exactly ONE block (the engine's linear
// fast path).
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
// register named after the parameter itself, mirroring converters/python's
// convertFunction (which uses the Python parameter name directly as its gIR
// register name rather than allocating a fresh "tN" temp). Destructuring
// parameters (ObjectPattern/ArrayPattern) are a documented limitation: given
// a synthetic "_argN" name so the parameter list stays positionally aligned,
// but the pattern's own bindings are not modeled.
func bindParams(fs *funcState, fn *ir.Function, params *ast.ParameterList) {
	bind := func(name string) {
		v := regValue(name)
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
			// A handler that destructures its request object in the signature —
			// `(req, res) => ...` written as `({ query, body }, res) => ...` — has
			// no `req.query` member read to seed taint from. Bind each destructured
			// property to a synthetic `js:req.<key>` source read so it matches the
			// request-source globs exactly as an in-body `req.query` access would (COV-11).
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
// `js:req.<key>` source read, so the local (`query`, `b`) carries request taint
// exactly as an in-body `req.query` member read would. Only plain, non-computed
// shorthand/keyed properties are modeled (`{ query }`, `{ query: q }`); a nested
// or computed pattern is skipped (a documented limitation), mirroring how the
// positional-parameter path leaves unhandled patterns as opaque _argN slots.
func (fs *funcState) bindHandlerDestructure(pat *ast.ObjectPattern) {
	for _, b := range objectPatternBindings(pat) {
		if b.Key == "" || b.Local == "" {
			continue
		}
		fs.write(b.Local, fs.emitRootPropertyRead("req", b.Key, pat.Idx0()))
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

// isOpaqueBase reports whether v is a value whose origin is outside this
// function's own straight-line computation: either a free/global identifier
// (Value_GlobalName, e.g. an unrequired/undeclared name like `child_process`
// or `console`) or one of this function's own parameters (Value_RegName for
// a name in fs.paramRegs, e.g. an Express handler's `req`). See the package
// doc comment ("The opaque object source heuristic") for why both cases are
// treated the same way: property reads off either kind of value are the
// first opportunity to introduce taint, since the engine only ever seeds
// taint at a CALL matching a source glob.
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

// canonRoot canonicalizes a PARAMETER name used as an opaque member-read root.
// A route handler's request parameter (any name) canonicalizes to `req` so
// property reads off it (`rq.query` -> "js:req.query") match the request-source
// globs, which are keyed on the conventional names (COV-11). Shared by
// isOpaqueBase and opaqueRootFor's AST fallback: the two must agree, or a
// request read inside a loop is named differently from the same read outside it
// and its taint is silently dropped.
func (fs *funcState) canonRoot(name string) string {
	if name == fs.reqParam && !reqConventionNames[name] {
		return "req"
	}
	return name
}

// opaqueRootFor classifies the base of a member read (`base.field` / `base[i]`)
// as an opaque source root, given both the base AST expression and its lowered
// value. It first tries the value-based isOpaqueBase (which also handles an
// intra-block alias like `const r = req; r.query` and non-identifier bases such
// as `this`), then falls back to an AST-name check for a plain identifier base.
//
// The AST fallback is required inside loops: reading a parameter in a loop body
// returns an as-yet-unresolved header PHI value whose register name is the PHI,
// not the parameter, so isOpaqueBase would miss it (the PHI collapses back to the
// parameter only when the header is sealed, after the body is lowered) — and the
// member read would wrongly become a plain FIELD instead of the synthetic source
// CALL, dropping loop-carried request taint. A free/global identifier is never
// tracked as a variable, so it is never PHI-wrapped; only a parameter needs this.
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
func (fs *funcState) emitRootPropertyRead(root, field string, idx file.Idx) *ir.Value {
	callee := "js:" + root + "." + field
	inst := fs.newValueInst(idx)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Comment = "property-read"
	inst.Call = calleeCommon(callee)
	fs.emit(inst)
	return regValue(inst.Name)
}

// lowerBody lowers a statement list, building a REAL CFG (blocks + preds/succs +
// PHI) via the Builder for control-flow compounds (if/for/for-in/for-of/while/
// do-while/switch/try) and lowering straight-line statements (labelled/with and
// leaf statements) into the current block, so a function with no branches still
// emits exactly ONE block (the engine's linear fast path). Mirrors
// converters/python's lowerBody.
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

// lowerIf lowers `if (test) consequent [else alternate]` into a REAL CFG diamond
// via the Builder: the condition is lowered in the current block, which ends in
// an OP_CODE_IF to a fresh then-block and else-block; each arm is lowered in its
// own block and jumps to a fresh merge block; the merge is sealed once both
// arm-ends are its known predecessors, so any variable rebound on one or both
// arms reconciles automatically via an on-demand ReadVariable PHI (retiring the
// manual env-merge path — including the ubiquitous "default if empty" idiom
// `if (!x) x = "d"`, whose pre-branch tainted value is now kept by the merge
// PHI). An `else if` is an IfStatement in the parent's Alternate, so
// an arbitrarily long chain becomes nested diamonds via the recursive lowerBody.
func (fs *funcState) lowerIf(v *ast.IfStatement) {
	cond := fs.lowerExpr(v.Test) // condition (also lowers any embedded source/sink)
	thenB := fs.b.NewBlock()
	elseB := fs.b.NewBlock()
	merge := fs.b.NewBlock()
	fs.b.SetIf(fs.cur, cond, thenB, elseB)
	fs.b.Seal(thenB) // sole predecessor (the branch block) is known
	fs.b.Seal(elseB)

	fs.cur = thenB
	fs.terminated = false
	fs.lowerBody(stmtList(v.Consequent))
	thenTerm := fs.terminated
	if !thenTerm { // a returning arm has no fall-through edge to the merge
		fs.b.SetJump(fs.cur, merge)
	}

	fs.cur = elseB
	fs.terminated = false
	if v.Alternate != nil {
		fs.lowerBody(stmtList(v.Alternate))
	}
	elseTerm := fs.terminated
	if !elseTerm {
		fs.b.SetJump(fs.cur, merge)
	}

	fs.b.Seal(merge) // predecessors (only the non-returning arms) now wired
	fs.cur = merge
	// The merge is dead only if BOTH arms returned; otherwise it falls through.
	fs.terminated = thenTerm && elseTerm
}

// lowerWhile lowers `while (test) body` into a REAL loop CFG: header/body/exit
// blocks. The current block jumps to the header; the header lowers the condition
// and branches (body, exit); the body is lowered and jumps BACK to the header
// (the back-edge). The header is left UNSEALED while the body is built, so a
// loop variable read in the condition or body parks an incomplete PHI filled
// when the header is sealed after the back-edge is wired — this is what gives
// loop-carried taint: a value written in the body and read at the top of the
// next iteration flows through the header PHI (which the old single-block
// lowering could not model).
func (fs *funcState) lowerWhile(v *ast.WhileStatement) {
	header := fs.b.NewBlock()
	body := fs.b.NewBlock()
	exit := fs.b.NewBlock()

	fs.b.SetJump(fs.cur, header) // enter the loop
	fs.cur = header
	cond := fs.lowerExpr(v.Test) // condition, lowered in the (unsealed) header
	fs.b.SetIf(header, cond, body, exit)

	fs.b.Seal(body) // body's sole predecessor (header) is known
	fs.cur = body
	fs.terminated = false
	fs.lowerBody(stmtList(v.Body))
	if !fs.terminated { // a body that always returns has no back-edge
		fs.b.SetJump(fs.cur, header) // back-edge from the body's END block
	}

	fs.b.Seal(header) // predecessors (entry-jump [+ back-edge]) now known
	fs.b.Seal(exit)   // exit's sole predecessor is the header
	fs.cur = exit
	fs.terminated = false
}

// lowerDoWhile lowers `do body while (test)` — the body runs BEFORE the test —
// into a loop CFG: the current block jumps into the body block; the body is the
// loop header (its back-edge comes from the test block), so it is left UNSEALED
// until the back-edge is wired; the test block re-enters the body when true, or
// falls to exit. Loop-carried taint flows through the body-header PHI.
func (fs *funcState) lowerDoWhile(v *ast.DoWhileStatement) {
	body := fs.b.NewBlock()
	test := fs.b.NewBlock()
	exit := fs.b.NewBlock()

	fs.b.SetJump(fs.cur, body) // the body always runs at least once
	fs.cur = body              // body is the loop header (UNSEALED: has a back-edge)
	fs.terminated = false
	fs.lowerBody(stmtList(v.Body))
	if !fs.terminated {
		fs.b.SetJump(fs.cur, test) // body end -> test
	}

	fs.b.Seal(test) // test's sole predecessor (the body end) is known
	fs.cur = test
	cond := fs.lowerExpr(v.Test)
	fs.b.SetIf(test, cond, body, exit) // wire the back-edge test -> body

	fs.b.Seal(body) // predecessors (entry-jump + back-edge) now known
	fs.b.Seal(exit)
	fs.cur = exit
	fs.terminated = false
}

// lowerFor lowers a C-style `for (init; test; update) body` into a loop CFG. The
// initializer runs once in the pre-loop (current) block; the header evaluates
// the test (a missing test is an opaque always-true, so both body and exit are
// traversed) and branches to body or exit; the update runs at the END of the
// body block, before the back-edge to the header. Reassignments/accumulations in
// the body or update flow through the header PHI, modeling loop-carried taint.
func (fs *funcState) lowerFor(v *ast.ForStatement) {
	if v.Initializer != nil {
		fs.lowerForInit(v.Initializer) // evaluated once in the pre-loop block
	}
	header := fs.b.NewBlock()
	body := fs.b.NewBlock()
	exit := fs.b.NewBlock()

	fs.b.SetJump(fs.cur, header)
	fs.cur = header
	var cond *ir.Value
	if v.Test != nil {
		cond = fs.lowerExpr(v.Test) // lowered in the (unsealed) header
	} else {
		cond = stringValue("")
	}
	fs.b.SetIf(header, cond, body, exit)

	fs.b.Seal(body)
	fs.cur = body
	fs.terminated = false
	fs.lowerBody(stmtList(v.Body))
	if v.Update != nil {
		fs.lowerExpr(v.Update) // the `i++` step, at the body's END block
	}
	if !fs.terminated {
		fs.b.SetJump(fs.cur, header) // back-edge
	}

	fs.b.Seal(header)
	fs.b.Seal(exit)
	fs.cur = exit
	fs.terminated = false
}

// lowerForRange lowers `for (into in|of source) body` into the same
// header/body/exit loop CFG as lowerWhile. The source is lowered once in the
// pre-loop block; the loop variable (into) is bound to the source's value at the
// top of the BODY block each iteration (element taint == container taint, so a
// tainted iterable taints the loop variable, mirroring converters/python's
// for-loop target binding). Reassignments/accumulations in the body flow through
// the header PHI, modeling loop-carried taint.
func (fs *funcState) lowerForRange(into ast.ForInto, source ast.Expression, bodyStmt ast.Statement) {
	src := fs.lowerExpr(source) // evaluate the iterable in the pre-loop block
	header := fs.b.NewBlock()
	body := fs.b.NewBlock()
	exit := fs.b.NewBlock()

	fs.b.SetJump(fs.cur, header)
	fs.cur = header
	fs.b.SetIf(header, stringValue(""), body, exit) // opaque iteration condition

	fs.b.Seal(body)
	fs.cur = body
	fs.terminated = false
	fs.bindForInto(into, src) // bind the loop variable each iteration
	fs.lowerBody(stmtList(bodyStmt))
	if !fs.terminated {
		fs.b.SetJump(fs.cur, header) // back-edge
	}

	fs.b.Seal(header)
	fs.b.Seal(exit)
	fs.cur = exit
	fs.terminated = false
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
// may-analysis; break is NOT modeled precisely). The discriminant is lowered in
// the current block, which begins a cascade of two-way decision branches so
// EVERY case block (and the exit, for the no-match path) is reachable. Each
// case's consequent is lowered into its own block and FALLS THROUGH to the next
// case's block (the last case falls through to exit), so taint written in any
// case — and a value that fall-through carries into a later case — is captured.
// `default` is just one of the cases and needs no special handling (every case
// is reachable). See converters/python's conservative Try model for the same
// "opaque branch to reach every relevant block" idea.
func (fs *funcState) lowerSwitch(v *ast.SwitchStatement) {
	disc := fs.lowerExpr(v.Discriminant)
	n := len(v.Body)
	if n == 0 {
		return // empty switch: discriminant already lowered for side effects
	}
	// Lower each case's test expression (for an embedded source/sink) in the
	// discriminant block; the boolean result is not otherwise needed.
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

	// Lower each case body; add the conservative fall-through edge to the next
	// case (or exit for the last). A case block's predecessors — its decision
	// edge and the prior case's fall-through — are both wired before it is lowered.
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
// conservatively (a may-analysis; no exception typing), mirroring
// converters/python's lowerTry. The try body is lowered into the current block.
// An EXCEPTION EDGE then models that an exception may occur anywhere in the body:
// the body-end block branches to the catch block or to an after block, so a
// value a source in the try body assigned reaches the handler via that
// predecessor edge (and, through the after block, code following the try).
// `finally` runs on both paths, so it is lowered into the after block. A
// try/finally with no catch is a straight-line continuation. When the body
// always returns there is no exception edge (the handler's body-var reads are
// then undefined — a minor recall gap, never a false positive).
func (fs *funcState) lowerTry(v *ast.TryStatement) {
	if v.Body != nil {
		fs.lowerBody(v.Body.List)
	}
	bodyEnd := fs.cur
	bodyTerm := fs.terminated

	if v.Catch == nil {
		// try/finally with no catch clause: finally is a straight-line continuation.
		if v.Finally != nil {
			fs.lowerBody(v.Finally.List)
		}
		return
	}

	handlerB := fs.b.NewBlock()
	after := fs.b.NewBlock()
	if !bodyTerm {
		// Exception edge: the body may branch into the handler, else fall through to
		// the after block. The condition is opaque (both edges are traversed).
		fs.b.SetIf(bodyEnd, stringValue(""), handlerB, after)
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
		fs.lowerBody(v.Finally.List) // finally runs on both the normal and handler paths
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
		// The current block ends here: no fall-through edge to a merge / loop
		// header / switch fall-through (a returning arm must not feed its values
		// into the join).
		fs.terminated = true
	case *ast.ThrowStatement:
		// `throw x` does NOT terminate the block for CFG purposes: leaving the
		// block non-terminated preserves the exception edge into an enclosing
		// try's catch (see lowerTry), so taint assigned before a `throw` in a try
		// body still reaches the handler (mirrors converters/python's Raise).
		fs.lowerExpr(v.Argument)
	case *ast.FunctionDeclaration:
		// Converted separately (see collector); just bind the name in this
		// scope so later reads of it (as a plain value, not a call callee --
		// calls are resolved purely syntactically, see lowerCall) resolve to
		// a function reference instead of falling back to a GlobalName.
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
// initializer (if any) and binding the result to the target name in the
// current environment. Destructuring targets (ObjectPattern/ArrayPattern)
// are a documented limitation: the initializer is still lowered for its side
// effects / taint discovery, but no bindings are introduced.
func (fs *funcState) lowerBinding(b *ast.Binding) {
	// Object destructuring: `const { id } = req.query` / `const { user } =
	// req.body` is the common Express idiom, so bind each destructured name to a
	// field read off the initializer, propagating the initializer's taint.
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
			fs.write(name, nilValue())
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
// destructured names. Array destructuring remains a documented limitation.
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
// (const [a, b, ...rest] = init) to the initializer's value, so taint carried by
// the initializer reaches the destructured names (element taint == container
// taint, mirroring tuple unpacking). Elisions and per-element defaults / nested
// patterns are not modeled.
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
// properties are modeled — a nested or otherwise non-identifier binding target
// yields no entry, the documented limitation all three shared before this was
// factored out (and drifted on). op.Rest is deliberately NOT handled here: each
// caller binds it differently.
func objectPatternBindings(op *ast.ObjectPattern) []patBinding {
	var out []patBinding
	for _, p := range op.Properties {
		switch prop := p.(type) {
		case *ast.PropertyShort:
			out = append(out, patBinding{Local: string(prop.Name.Name), Key: string(prop.Name.Name)})
		case *ast.PropertyKeyed:
			// `{ query: q }` -> field `query`, local `q`; only a plain identifier
			// binding target is modeled (a nested/computed pattern is skipped).
			if id, ok := prop.Value.(*ast.Identifier); ok {
				out = append(out, patBinding{Local: string(id.Name), Key: propertyKeyName(prop.Key)})
			}
		}
	}
	return out
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

// lowerExpr lowers an expression to a gIR Value, emitting whatever
// instructions are needed to compute it (into the current block). Names
// assigned as locals resolve through the Builder to their current SSA value
// (constant, register, or an on-demand PHI); unbound names (free variables:
// builtins, other functions' or the module's locals, since closures are not
// modeled -- see package doc) fall back to a GlobalName reference.
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
		return stringValue(string(v.Value))

	case *ast.NumberLiteral:
		return numberValue(v.Value)

	case *ast.BooleanLiteral:
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_BoolVal{BoolVal: v.Value}}}}

	case *ast.NullLiteral:
		return nilValue()

	case *ast.RegExpLiteral:
		// Best-effort string representation, mirroring converters/python's
		// fallback for constants it does not model precisely.
		return stringValue(v.Literal)

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
		// No control-flow graph: evaluate the test for side effects/taint
		// discovery, then merge both branches' values with a PHI so taint
		// from either arm propagates to the result (see propagatingOps in
		// internal/analysis, which treats OP_CODE_PHI as a taint
		// propagator).
		fs.lowerExpr(v.Test)
		cv := fs.lowerExpr(v.Consequent)
		av := fs.lowerExpr(v.Alternate)
		inst := fs.newValueInst(v.Idx0())
		inst.Op = ir.OpCode_OP_CODE_PHI
		inst.Operands = []*ir.Value{cv, av}
		fs.emit(inst)
		return regValue(inst.Name)

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
		return fs.lowerAggregate(vals, v.Idx0())

	case *ast.SpreadElement:
		return fs.lowerExpr(v.Expression)

	case *ast.ThisExpression:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "this"}}

	case *ast.SuperExpression:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: "super"}}

	case *ast.YieldExpression:
		// Generators are not specially modeled: `yield x` lowers to `x`.
		if v.Argument != nil {
			return fs.lowerExpr(v.Argument)
		}
		return nilValue()

	case *ast.AwaitExpression:
		// Promises/async are not specially modeled: `await x` lowers to `x`.
		return fs.lowerExpr(v.Argument)

	case *ast.FunctionLiteral, *ast.ArrowFunctionLiteral:
		return fs.funcRefValue(e)

	case *ast.OptionalChain:
		// `a?.b` — optional chaining short-circuits on null/undefined but
		// otherwise yields the same value as `a.b`, so lower the wrapped
		// expression directly; taint flows identically.
		return fs.lowerExpr(v.Expression)

	case *ast.Optional:
		return fs.lowerExpr(v.Expression)

	default:
		return fs.emitUnsupported(e.Idx0(), fmt.Sprintf("unsupported javascript expression: %T", e))
	}
}

// funcRefValue resolves an inline function-literal/arrow expression (e.g. a
// callback argument) to a FuncName reference to the ir.Function the
// collector already created for it, rather than inlining its body again.
func (fs *funcState) funcRefValue(e ast.Expression) *ir.Value {
	if canonical, ok := fs.nameOf[e]; ok {
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}}
	}
	// Should not happen (the collector visits every expression tree lowering
	// does), but stay defensive rather than panicking.
	return fs.emitUnsupported(e.Idx0(), "unresolved inline function literal")
}

// lowerDot lowers `a.b`. If the base is opaque (see isOpaqueBase), this hop
// is the root of the chain and becomes a synthetic property-read CALL;
// otherwise it is a normal FIELD read off the base's register.
func (fs *funcState) lowerDot(v *ast.DotExpression) *ir.Value {
	base := fs.lowerExpr(v.Left)
	field := string(v.Identifier.Name)

	if root, ok := fs.opaqueRootFor(v.Left, base); ok {
		return fs.emitRootPropertyRead(root, field, v.Idx0())
	}

	return fs.emitFieldRead(base, field, v.Idx0())
}

// emitFieldRead emits a FIELD read of field off base at idx and returns the
// resulting register value.
func (fs *funcState) emitFieldRead(base *ir.Value, field string, idx file.Idx) *ir.Value {
	inst := fs.newValueInst(idx)
	inst.Op = ir.OpCode_OP_CODE_FIELD
	inst.Operands = []*ir.Value{base}
	inst.Comment = "field:" + field
	fs.emit(inst)
	return regValue(inst.Name)
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
		return fs.emitRootPropertyRead(root, bracketFieldName(v.Member), v.Idx0())
	}

	inst := fs.newValueInst(v.Idx0())
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{base, idx}
	fs.emit(inst)
	return regValue(inst.Name)
}

func bracketFieldName(m ast.Expression) string {
	if sl, ok := m.(*ast.StringLiteral); ok {
		return string(sl.Value)
	}
	return "*"
}

// lowerAggregate lowers an array/object literal's element values, merging
// their taint into one register via OP_CODE_PHI (a documented
// field-insensitive approximation: see the package doc comment).
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
		acc = regValue(inst.Name)
	}
	if acc == nil {
		acc = nilValue()
	}
	return acc
}

// lowerTemplateLiteral folds a template literal's raw text chunks and
// substituted expressions left-to-right with BIN_OP_ADD (string
// concatenation), mirroring converters/python's JoinedStr (f-string)
// handling, so taint carried by any ${expr} slot propagates to the final
// value.
func (fs *funcState) lowerTemplateLiteral(v *ast.TemplateLiteral) *ir.Value {
	var acc *ir.Value
	for i, el := range v.Elements {
		if el != nil {
			acc = fs.concat(acc, stringValue(string(el.Parsed)), v.Idx0())
		}
		if i < len(v.Expressions) {
			acc = fs.concat(acc, fs.lowerExpr(v.Expressions[i]), v.Idx0())
		}
	}
	if acc == nil {
		acc = stringValue("")
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
	return regValue(inst.Name)
}

// lowerBinary lowers a binary expression (arithmetic, bitwise, comparison,
// or -- approximated, see package doc -- logical) to a BIN_OP instruction.
func (fs *funcState) lowerBinary(v *ast.BinaryExpression) *ir.Value {
	left := fs.lowerExpr(v.Left)
	right := fs.lowerExpr(v.Right)
	inst := fs.newValueInst(v.Idx0())
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = binOpKind(v.Operator)
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return regValue(inst.Name)
}

// lowerUnary lowers a unary expression, including prefix/postfix ++/--,
// which also rebinds the operand's environment entry (approximating the
// mutation) when the operand is a plain identifier.
func (fs *funcState) lowerUnary(v *ast.UnaryExpression) *ir.Value {
	operand := fs.lowerExpr(v.Operand)
	inst := fs.newValueInst(v.Idx0())
	inst.Op = ir.OpCode_OP_CODE_UN_OP
	inst.UnOp = unOpKind(v.Operator)
	inst.Operands = []*ir.Value{operand}
	fs.emit(inst)
	result := regValue(inst.Name)

	if v.Operator == token.INCREMENT || v.Operator == token.DECREMENT {
		if id, ok := v.Operand.(*ast.Identifier); ok {
			fs.write(string(id.Name), result)
		}
	}
	return result
}

// lowerAssign lowers `target = value` (and compound assignments like `+=`),
// returning the assigned value so AssignExpression can also be used as a
// sub-expression (e.g. `x = y = 5`).
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
		rhs = regValue(inst.Name)
	}
	fs.assignTo(a.Left, rhs)
	return rhs
}

// assignTo binds a lowered value to an assignment target. A bare identifier
// target rebinds the environment. A DotExpression/BracketExpression target
// (`obj.attr = v` / `arr[i] = v`) emits a STORE with the base object as the
// address operand, matching how converters/python's `assign` lowers
// Attribute/Subscript targets: this is what lets a tainted value written
// into a container mark that container tainted (see visitStore in
// internal/analysis/taint.go). Destructuring targets are a documented
// limitation: dropped.
func (fs *funcState) assignTo(target ast.Expression, val *ir.Value) {
	switch t := target.(type) {
	case *ast.Identifier:
		fs.write(string(t.Name), val)
	case *ast.DotExpression:
		fs.emitStore(t.Left, val, t.Idx0())
	case *ast.BracketExpression:
		fs.emitStore(t.Left, val, t.Idx0())
	default:
		// ArrayPattern/ObjectPattern (destructuring assignment) or other
		// unsupported target shape: dropped.
	}
}

// lowerCall lowers a call expression to OP_CODE_CALL. The callee is a purely
// syntactic dotted name built from the call's callee expression (see
// syntacticCallee), never resolved through the environment -- mirroring
// converters/python's dottedName -- so e.g. `child_process.exec(cmd)`
// resolves to "js:child_process.exec" regardless of whether/how
// `child_process` is bound.
//
// Before that syntactic name is built, lowerNestedCallees walks the same
// Dot/Bracket "Left" chain looking for an embedded CallExpression -- e.g. the
// `axios.get(url)` inside `axios.get(url).then(cb)` -- and lowers it first.
// Without this step the inner call would never be visited at all: syntactic
// name building is a pure string walk with no side effects, so the inner
// call's own instruction (and therefore its args, its taint, and its chance
// to match a source/sink glob) would silently disappear. See the package doc
// note on the js-ssrf sample's chained axios.get(...).then(...) handler.
func (fs *funcState) lowerCall(v *ast.CallExpression) *ir.Value {
	// For a method call, lower the receiver (the callee's base object) so its
	// register can be carried in Call.Value (see emitCallRecv): this both
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
	// A bare call to a top-level function (helper(x)) must carry the module
	// name so its callee matches the function's CanonicalName; otherwise byKey
	// never resolves it and taint does not flow through the local helper.
	// Member calls (obj.method) and unknown/global names are left unqualified.
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
	return fs.emitCallRecv(callee, receiver, v.ArgumentList, v.Idx0())
}

// lowerNew lowers `new Foo(args)` the same way as a call (constructing an
// object is, for taint-propagation purposes, indistinguishable from calling
// a function with the same arguments); the "new" prefix is preserved in the
// callee so it does not collide with a plain `Foo(args)` call. Like lowerCall,
// it lowers any call nested in its callee chain first (see lowerNestedCallees)
// so e.g. `new (getCtor()).Client(url)` still lowers `getCtor()`.
func (fs *funcState) lowerNew(v *ast.NewExpression) *ir.Value {
	fs.lowerNestedCallees(v.Callee)
	return fs.emitCall("js:new:"+syntacticCallee(v.Callee), v.ArgumentList, v.Idx0())
}

// lowerNestedCallees walks a call/new expression's callee along its
// DotExpression/BracketExpression "Left" links -- the exact chain shape
// syntacticCallee walks -- and lowers any CallExpression it finds along the
// way via the ordinary fs.lowerCall path. It recurses into that inner call's
// own callee too, so a multiply-chained expression like
// `foo(x).bar(y).baz(z)` lowers inside-out: `foo(x)` first, then `bar(y)`
// (called on foo's result), then the outer `baz(z)` is built by lowerCall's
// caller. The inner call's result register is intentionally discarded here --
// syntacticCallee's existing "<dynamic>" fallback for a non-Identifier/Dot
// root (already relied on for e.g. `getHandler().process(x)` ->
// "<dynamic>.process") still names the outer call; this function's only job
// is to make sure the inner call is not silently skipped, so its own
// callee/args/taint remain visible to the analysis engine.
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

// syntacticCallee builds a canonical, purely syntactic dotted callee name
// from a call's callee expression, e.g. DotExpression(DotExpression(
// Identifier("res"), "locals"), "get") -> "res.locals.get". A callee rooted
// in something other than a plain Identifier/DotExpression/string-keyed
// BracketExpression chain (e.g. a nested call, a computed bracket index, or
// a function expression) resolves to "<dynamic>" for that sub-path, so e.g.
// `getHandler().process(x)` yields "<dynamic>.process" -- glob patterns like
// "js:*.process" still match it. Mirrors converters/python's dottedName. Any
// CallExpression along this same chain has already been lowered to its own
// instruction by lowerCall/lowerNew's call to lowerNestedCallees before this
// runs, so collapsing it to "<dynamic>" here only affects the outer call's
// name, not whether the inner call itself was seen.
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
// &&/||/?? have no logical-op counterpart in gIR's BinOpKind and are
// approximated as their bitwise equivalents (safe for taint propagation:
// either operand tainted still taints the result), and the three
// right-shift variants are collapsed into BIN_OP_SHR -- both documented in
// the package doc comment.
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
	case token.EQUAL, token.STRICT_EQUAL:
		return ir.BinOpKind_BIN_OP_EQL
	case token.NOT_EQUAL, token.STRICT_NOT_EQUAL:
		return ir.BinOpKind_BIN_OP_NEQ
	case token.LESS:
		return ir.BinOpKind_BIN_OP_LSS
	case token.LESS_OR_EQUAL:
		return ir.BinOpKind_BIN_OP_LEQ
	case token.GREATER:
		return ir.BinOpKind_BIN_OP_GTR
	case token.GREATER_OR_EQUAL:
		return ir.BinOpKind_BIN_OP_GEQ
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
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
// dedicated UnOpKind counterpart and fall back to UN_OP_UNSPECIFIED; the
// UN_OP instruction is still emitted (see lowerUnary) so taint still
// propagates through it.
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

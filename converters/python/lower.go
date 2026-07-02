package py_converter

import (
	"encoding/json"
	"fmt"

	ir "godzilla/pkg/ir/v1"
)

// convertModule turns one parsed Python file (root = the {"kind":"Module", ...}
// node from pyast.py) into a gIR Module. Every `def` (including nested defs
// and methods) becomes its own ir.Function; module-level statements that are
// not defs/classes are collected into one synthetic "<module>" function, the
// Python analogue of Go's package-init/main flattening in converters/go.
func convertModule(root astNode, filename, moduleName string) *ir.Module {
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

	var collect func(stmts []astNode, qualPrefix string)
	collect = func(stmts []astNode, qualPrefix string) {
		for _, s := range stmts {
			switch s.kind() {
			case "FunctionDef":
				fn := convertFunction(s, filename, moduleName, qualPrefix, localFuncs)
				functions = append(functions, fn)
				collect(s.list("body"), qualPrefix+s.str("name")+".")
			case "ClassDef":
				// Only methods (nested FunctionDefs) are modeled; other
				// class-body statements are a documented limitation.
				collect(s.list("body"), qualPrefix+s.str("name")+".")
			}
		}
	}
	collect(root.list("body"), "")

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

	moduleFn := convertModuleInit(root, filename, moduleName, localFuncs)
	mod.Functions = append([]*ir.Function{moduleFn}, functions...)

	return mod
}

// convertModuleInit lowers a file's top-level straight-line statements
// (skipping nested def/class bodies, which become their own functions) into a
// synthetic entry-point function, analogous to converters/go treating
// package-level init code as part of the SSA program.
func convertModuleInit(root astNode, filename, moduleName string, localFuncs map[string]bool) *ir.Function {
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
	fs.lowerBody(root.list("body"))
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
	return fn
}

// convertFunction lowers a single `def` (module-level, nested, or method)
// into an ir.Function containing one straight-line basic block.
func convertFunction(node astNode, filename, moduleName, qualPrefix string, localFuncs map[string]bool) *ir.Function {
	name := node.str("name")
	qualname := qualPrefix + name

	fn := &ir.Function{
		Name:          qualname,
		ObjectName:    name,
		PackageName:   moduleName,
		CanonicalName: "py:" + moduleName + "." + qualname,
		Pos:           posFromNode(filename, node),
	}

	fs := newFuncState(filename)
	fs.moduleName = moduleName
	fs.localFuncs = localFuncs
	for _, p := range node.strList("params") {
		v := &ir.Value{Kind: &ir.Value_RegName{RegName: p}}
		fn.Params = append(fn.Params, v)
		fs.env[p] = v
		fs.paramRegs[p] = true
	}

	fs.lowerBody(node.list("body"))
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
	return fn
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
}

func newFuncState(filename string) *funcState {
	return &funcState{filename: filename, env: map[string]*ir.Value{}, paramRegs: map[string]bool{}}
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
			fs.lowerBody(s.list("body"))
			fs.lowerBody(s.list("orelse"))
		case "While":
			if t := s.node("test"); t != nil {
				fs.lowerExpr(t)
			}
			fs.lowerBody(s.list("body"))
			fs.lowerBody(s.list("orelse"))
		case "For":
			// `for x in iter:` — lower the iterable and bind the loop target to
			// it, so taint in the iterable reaches the loop variable
			// (conservative: element taint == container taint), and a source in
			// the iterable is not dropped.
			if it := s.node("iter"); it != nil {
				iterVal := fs.lowerExpr(it)
				if tgt := s.node("target"); tgt != nil {
					fs.assign(tgt, iterVal)
				}
			}
			fs.lowerBody(s.list("body"))
			fs.lowerBody(s.list("orelse"))
		case "With":
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

// lowerStmt lowers one leaf statement (i.e. not a control-flow compound;
// those are flattened by lowerBody).
func (fs *funcState) lowerStmt(s astNode) {
	switch s.kind() {
	case "Assign":
		val := fs.lowerExpr(s.node("value"))
		for _, target := range s.list("targets") {
			fs.assign(target, val)
		}
	case "AugAssign":
		target := s.node("target")
		cur := fs.lowerExpr(target)
		rhs := fs.lowerExpr(s.node("value"))
		inst := fs.newValueInst(s)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKind(s.str("op"))
		inst.Operands = []*ir.Value{cur, rhs}
		fs.emit(inst)
		fs.assign(target, regValue(inst.Name))
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
	default:
		// Unpacking assignment (Tuple/List target) or other unsupported
		// target shape: dropped.
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
		base := fs.lowerExpr(n.node("value"))
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_FIELD
		inst.Operands = []*ir.Value{base}
		inst.Comment = "attr:" + n.str("attr")
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
			idx = &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{IsNil: true}}}
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
				return regValue(inst.Name)
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
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = binOpKind(n.str("op"))
		inst.Operands = []*ir.Value{left, right}
		fs.emit(inst)
		return regValue(inst.Name)

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
			cur := fs.lowerExpr(v)
			if acc == nil {
				acc = cur
				continue
			}
			inst := fs.newValueInst(n)
			inst.Op = ir.OpCode_OP_CODE_BIN_OP
			inst.BinOp = ir.BinOpKind_BIN_OP_OR
			inst.Operands = []*ir.Value{acc, cur}
			fs.emit(inst)
			acc = regValue(inst.Name)
		}
		if acc == nil {
			return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: ""}}}}
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
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = ir.BinOpKind_BIN_OP_OR
		inst.Operands = []*ir.Value{body, orelse}
		fs.emit(inst)
		return regValue(inst.Name)

	case "NamedExpr":
		// walrus `target := value`: the expression evaluates to `value` and also
		// binds `target`, so both the result and the bound name carry taint.
		val := fs.lowerExpr(n.node("value"))
		fs.assign(n.node("target"), val)
		return val

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
			if it := g.node("iter"); it != nil {
				iterVal := fs.lowerExpr(it)
				if tgt := g.node("target"); tgt != nil {
					fs.assign(tgt, iterVal)
				}
			}
			for _, cond := range g.list("ifs") {
				fs.lowerExpr(cond)
			}
		}
		for _, key := range []string{"elt", "key", "value"} {
			if e := n.node(key); e != nil {
				fs.lowerExpr(e)
			}
		}
		return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: ""}}}}

	case "JoinedStr":
		// f-string: fold parts left-to-right with BIN_OP_ADD (string
		// concatenation) so taint carried by any {expr} slot propagates to
		// the final value, same as Python's runtime semantics.
		var acc *ir.Value
		for _, part := range n.list("values") {
			v := fs.lowerExpr(part)
			if acc == nil {
				acc = v
				continue
			}
			inst := fs.newValueInst(n)
			inst.Op = ir.OpCode_OP_CODE_BIN_OP
			inst.BinOp = ir.BinOpKind_BIN_OP_ADD
			inst.Operands = []*ir.Value{acc, v}
			fs.emit(inst)
			acc = regValue(inst.Name)
		}
		if acc == nil {
			acc = &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: ""}}}}
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
func (fs *funcState) lowerCall(n astNode) *ir.Value {
	funcNode := n.node("func")
	if funcNode != nil && funcNode.kind() == "Attribute" && funcNode.str("attr") == "format" {
		return fs.lowerFormatCall(n, funcNode)
	}

	// Lower any call embedded in the callee chain first, so a chained call like
	// requests.get(url).json() still emits the inner requests.get call (an SSRF
	// sink) even though the outer call is `.json()`. Mirrors JS's
	// lowerNestedCallees.
	fs.lowerNestedCallees(funcNode)

	callee := "py:" + dottedName(funcNode)
	// A bare call to a module-level function (helper(x)) must carry the module
	// name so its callee matches the function's CanonicalName
	// ("py:<module>.helper"); otherwise byKey never resolves it and taint does
	// not flow through the local helper. Builtins (open, print) and imported
	// names are not in localFuncs, so they are left unqualified.
	if funcNode != nil && funcNode.kind() == "Name" && fs.localFuncs[funcNode.str("id")] {
		callee = "py:" + fs.moduleName + "." + funcNode.str("id")
	}
	cc := &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
	}
	for _, a := range n.list("args") {
		cc.Args = append(cc.Args, fs.lowerExpr(a))
	}
	for _, kw := range n.list("keywords") {
		cc.Args = append(cc.Args, fs.lowerExpr(kw.node("value")))
	}

	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
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
	acc := fs.lowerExpr(funcNode.node("value"))
	args := n.list("args")
	kwArgs := n.list("keywords")
	for _, a := range args {
		v := fs.lowerExpr(a)
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = ir.BinOpKind_BIN_OP_ADD
		inst.Operands = []*ir.Value{acc, v}
		fs.emit(inst)
		acc = regValue(inst.Name)
	}
	for _, kw := range kwArgs {
		v := fs.lowerExpr(kw.node("value"))
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_BIN_OP
		inst.BinOp = ir.BinOpKind_BIN_OP_ADD
		inst.Operands = []*ir.Value{acc, v}
		fs.emit(inst)
		acc = regValue(inst.Name)
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

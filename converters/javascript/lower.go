package js_converter

import (
	"fmt"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/token"

	ir "godzilla/pkg/ir/v1"
)

// funcState holds the per-function lowering state: a monotonically
// increasing temp-register counter, an environment mapping the current JS
// variable name to its most recent gIR value (constant, register, global, or
// function reference), the set of register names that are this function's
// own parameters (see isOpaqueBase), the flat instruction list for the
// function's single basic block, and the shared node->canonical-name map
// built by the collector (so an inline function expression/arrow used as a
// value resolves to a FuncName reference to its already-lowered
// ir.Function instead of being inlined again).
type funcState struct {
	filename  string
	fset      *file.FileSet
	nameOf    map[ast.Node]string
	counter   int
	env       map[string]*ir.Value
	paramRegs map[string]bool
	instrs    []*ir.Instruction

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
}

func newFuncState(filename string, fset *file.FileSet, nameOf map[ast.Node]string, localFuncs map[string]string) *funcState {
	return &funcState{
		filename:   filename,
		fset:       fset,
		nameOf:     nameOf,
		env:        map[string]*ir.Value{},
		paramRegs:  map[string]bool{},
		localFuncs: localFuncs,
	}
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

func (fs *funcState) emit(inst *ir.Instruction) {
	fs.instrs = append(fs.instrs, inst)
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

// emitCall emits an OP_CODE_CALL to callee, lowering args in order, and returns
// its result register. Shared by lowerCall and lowerNew, whose only difference
// is how they build the callee name.
func (fs *funcState) emitCall(callee string, args []ast.Expression, idx file.Idx) *ir.Value {
	cc := &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
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

// lowerFunction lowers one collected function (declaration, function
// expression, or arrow function) into an ir.Function with a single
// straight-line basic block.
func lowerFunction(pf pendingFunc, filename, moduleName string, fset *file.FileSet, nameOf map[ast.Node]string, localFuncs map[string]string) *ir.Function {
	fn := &ir.Function{
		Name:          pf.qualname,
		ObjectName:    pf.objectName,
		PackageName:   moduleName,
		CanonicalName: "js:" + moduleName + "." + pf.qualname,
	}

	fs := newFuncState(filename, fset, nameOf, localFuncs)
	fs.moduleName = moduleName
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

	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
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
		fs.env[name] = v
		fs.paramRegs[name] = true
	}
	for i, b := range params.List {
		name := bindingName(b.Target)
		if name == "" {
			name = fmt.Sprintf("_arg%d", i)
		}
		bind(name)
	}
	if params.Rest != nil {
		if id, ok := params.Rest.(*ast.Identifier); ok {
			bind(string(id.Name))
		}
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
		return r, true
	}
	return "", false
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
	inst.Call = &ir.CallCommon{
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Callee: callee,
	}
	fs.emit(inst)
	return regValue(inst.Name)
}

// lowerBody lowers a statement list, flattening control-flow compounds
// (if/for/while/do-while/try/switch/labelled/with) into the enclosing
// straight-line block, mirroring converters/python's lowerBody. See the
// package doc comment for the rationale and tradeoffs of this approximation.
func (fs *funcState) lowerBody(stmts []ast.Statement) {
	for _, s := range stmts {
		fs.lowerBodyStmt(s)
	}
}

func (fs *funcState) lowerBodyStmt(s ast.Statement) {
	switch v := s.(type) {
	case *ast.IfStatement:
		fs.lowerExpr(v.Test)
		fs.lowerBody(stmtList(v.Consequent))
		if v.Alternate != nil {
			fs.lowerBody(stmtList(v.Alternate))
		}
	case *ast.ForStatement:
		if v.Initializer != nil {
			fs.lowerForInit(v.Initializer)
		}
		if v.Test != nil {
			fs.lowerExpr(v.Test)
		}
		fs.lowerBody(stmtList(v.Body))
		if v.Update != nil {
			fs.lowerExpr(v.Update)
		}
	case *ast.ForInStatement:
		fs.lowerExpr(v.Source)
		fs.lowerBody(stmtList(v.Body))
	case *ast.ForOfStatement:
		fs.lowerExpr(v.Source)
		fs.lowerBody(stmtList(v.Body))
	case *ast.WhileStatement:
		fs.lowerExpr(v.Test)
		fs.lowerBody(stmtList(v.Body))
	case *ast.DoWhileStatement:
		fs.lowerBody(stmtList(v.Body))
		fs.lowerExpr(v.Test)
	case *ast.BlockStatement:
		fs.lowerBody(v.List)
	case *ast.TryStatement:
		if v.Body != nil {
			fs.lowerBody(v.Body.List)
		}
		if v.Catch != nil && v.Catch.Body != nil {
			fs.lowerBody(v.Catch.Body.List)
		}
		if v.Finally != nil {
			fs.lowerBody(v.Finally.List)
		}
	case *ast.SwitchStatement:
		fs.lowerExpr(v.Discriminant)
		for _, cs := range v.Body {
			fs.lowerBody(cs.Consequent)
		}
	case *ast.LabelledStatement:
		fs.lowerBody(stmtList(v.Statement))
	case *ast.WithStatement:
		fs.lowerExpr(v.Object)
		fs.lowerBody(stmtList(v.Body))
	default:
		fs.lowerStmt(s)
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
	case *ast.ThrowStatement:
		fs.lowerExpr(v.Argument)
	case *ast.FunctionDeclaration:
		// Converted separately (see collector); just bind the name in this
		// scope so later reads of it (as a plain value, not a call callee --
		// calls are resolved purely syntactically, see lowerCall) resolve to
		// a function reference instead of falling back to a GlobalName.
		if v.Function.Name != nil {
			if canonical, ok := fs.nameOf[v.Function]; ok {
				fs.env[string(v.Function.Name.Name)] = &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}}
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
			fs.env[name] = nilValue()
		}
		return
	}
	val := fs.lowerExpr(b.Initializer)
	if name != "" {
		fs.env[name] = val
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
		inst := fs.newValueInst(op.LeftBrace)
		inst.Op = ir.OpCode_OP_CODE_FIELD
		inst.Operands = []*ir.Value{base}
		inst.Comment = "field:" + field
		fs.emit(inst)
		fs.env[localName] = regValue(inst.Name)
	}
	for _, p := range op.Properties {
		switch prop := p.(type) {
		case *ast.PropertyShort:
			bindField(string(prop.Name.Name), string(prop.Name.Name))
		case *ast.PropertyKeyed:
			if id, ok := prop.Value.(*ast.Identifier); ok {
				bindField(string(id.Name), propertyKeyName(prop.Key))
			}
		}
	}
	// `const { ...rest } = init`: the rest object carries the initializer's taint.
	if id, ok := op.Rest.(*ast.Identifier); ok {
		fs.env[string(id.Name)] = base
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
			fs.env[string(id.Name)] = base
		}
	}
	if id, ok := ap.Rest.(*ast.Identifier); ok {
		fs.env[string(id.Name)] = base
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

// lowerExpr lowers an expression to a gIR Value, emitting whatever
// instructions are needed to compute it (appended to fs.instrs). Names bound
// in fs.env resolve to their current value directly; unbound names (free
// variables: builtins, other functions' or the module's locals, since
// closures are not modeled -- see package doc) fall back to a GlobalName
// reference.
func (fs *funcState) lowerExpr(e ast.Expression) *ir.Value {
	if e == nil {
		return nil
	}
	switch v := e.(type) {
	case *ast.Identifier:
		if val, ok := fs.env[string(v.Name)]; ok {
			return val
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

	if root, ok := fs.isOpaqueBase(base); ok {
		return fs.emitRootPropertyRead(root, field, v.Idx0())
	}

	inst := fs.newValueInst(v.Idx0())
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

	if root, ok := fs.isOpaqueBase(base); ok {
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
			fs.env[string(id.Name)] = result
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
		fs.env[string(t.Name)] = val
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
	fs.lowerNestedCallees(v.Callee)
	callee := "js:" + syntacticCallee(v.Callee)
	// A bare call to a top-level function (helper(x)) must carry the module
	// name so its callee matches the function's CanonicalName; otherwise byKey
	// never resolves it and taint does not flow through the local helper.
	// Member calls (obj.method) and unknown/global names are left unqualified.
	if id, ok := v.Callee.(*ast.Identifier); ok {
		if canonical, found := fs.localFuncs[string(id.Name)]; found {
			callee = canonical
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
	return fs.emitCall(callee, v.ArgumentList, v.Idx0())
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

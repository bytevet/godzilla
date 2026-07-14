package ruby_converter

import (
	"encoding/json"
	"fmt"

	ir "godzilla/pkg/ir/v1"
)

// A Ripper sexp node is a JSON value: a list (`[]interface{}` whose head is a
// string tag) or a scalar (string / json.Number / nil). These helpers navigate
// it without panicking on unexpected shapes.

func asList(n interface{}) ([]interface{}, bool) {
	l, ok := n.([]interface{})
	return l, ok
}

// tag returns a node's head tag ("def", "call", "@ident", …), or "" if the node
// is not a tagged list.
func tag(n interface{}) string {
	if l, ok := asList(n); ok && len(l) > 0 {
		if s, ok := l[0].(string); ok {
			return s
		}
	}
	return ""
}

// at returns the i-th element of a list node, or nil.
func at(n interface{}, i int) interface{} {
	if l, ok := asList(n); ok && i >= 0 && i < len(l) {
		return l[i]
	}
	return nil
}

// identName returns the token text of an `@ident`/`@const`/`@kw`/`@label`
// leaf (`["@ident","name",[line,col]]`), or "".
func identName(n interface{}) string {
	if l, ok := asList(n); ok && len(l) >= 2 {
		if s, ok := l[1].(string); ok {
			return s
		}
	}
	return ""
}

// firstPos finds the first `[line,col]` position pair in n (depth-first), which
// tokens carry as their trailing element.
func firstPos(n interface{}) (line, col int, ok bool) {
	l, isList := asList(n)
	if !isList {
		return 0, 0, false
	}
	// A position pair is a 2-element list of numbers.
	if len(l) == 2 {
		if ln, okl := l[0].(json.Number); okl {
			if cl, okc := l[1].(json.Number); okc {
				li, _ := ln.Int64()
				ci, _ := cl.Int64()
				return int(li), int(ci), true
			}
		}
	}
	for _, e := range l {
		if li, ci, found := firstPos(e); found {
			return li, ci, true
		}
	}
	return 0, 0, false
}

// convertModule lowers one Ruby file's Ripper sexp into a gIR module: every
// `def` (top level or inside a class/module) becomes a function, and remaining
// top-level statements are collected into a synthetic "<module>" function so
// script-style and Sinatra-style handler code is still analyzed.
func convertModule(root interface{}, filename, moduleName string) *ir.Module {
	mod := &ir.Module{Name: moduleName, Language: "ruby"}

	stmts := programStmts(root)

	// Local (top-level) def names: a bare call to one is qualified with the module
	// so it resolves to the function's canonical name for cross-function taint.
	localFuncs := map[string]bool{}
	var collectNames func(ss []interface{})
	collectNames = func(ss []interface{}) {
		for _, s := range ss {
			switch tag(s) {
			case "def":
				localFuncs[identName(at(s, 1))] = true
			case "class", "module":
				collectNames(bodyStmts(at(s, 3)))
			}
		}
	}
	collectNames(stmts)

	var functions []*ir.Function
	var collect func(ss []interface{}, qualPrefix string)
	collect = func(ss []interface{}, qualPrefix string) {
		for _, s := range ss {
			switch tag(s) {
			case "def":
				functions = append(functions, lowerDef(s, filename, moduleName, qualPrefix, localFuncs))
			case "class", "module":
				// class C ... end → constant name at at(s,1) = ["const_ref",["@const","C",pos]]
				name := identName(at(at(s, 1), 1))
				collect(bodyStmts(at(s, 3)), qualPrefix+name+".")
			}
		}
	}
	collect(stmts, "")

	// The module entry point: top-level statements that are not a def/class.
	if init := lowerModuleInit(stmts, filename, moduleName, localFuncs); init != nil {
		functions = append([]*ir.Function{init}, functions...)
	}

	mod.Functions = functions
	return mod
}

// programStmts returns the top-level statement list of a `["program",[stmts]]`.
func programStmts(root interface{}) []interface{} {
	if tag(root) != "program" {
		return nil
	}
	l, _ := asList(at(root, 1))
	return l
}

// bodyStmts returns the statement list inside a `["bodystmt",[stmts],…]`.
func bodyStmts(n interface{}) []interface{} {
	if tag(n) != "bodystmt" {
		return nil
	}
	l, _ := asList(at(n, 1))
	return l
}

// lowerModuleInit lowers the top-level non-def/class statements into a
// synthetic "<module>" function, or returns nil if there are none.
func lowerModuleInit(stmts []interface{}, filename, moduleName string, localFuncs map[string]bool) *ir.Function {
	var top []interface{}
	for _, s := range stmts {
		switch tag(s) {
		case "def", "class", "module", "void_stmt":
			// skip
		default:
			top = append(top, s)
		}
	}
	if len(top) == 0 {
		return nil
	}
	fs := newFuncState(filename, moduleName, localFuncs)
	fs.lowerBody(top)
	if len(fs.instrs) == 0 {
		return nil
	}
	return &ir.Function{
		Name:          "<module>",
		ObjectName:    "<module>",
		PackageName:   moduleName,
		CanonicalName: "ruby:" + moduleName + ".<module>",
		Synthetic:     true,
		Blocks:        []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}},
	}
}

// lowerDef lowers one `def` into a function.
func lowerDef(defNode interface{}, filename, moduleName, qualPrefix string, localFuncs map[string]bool) *ir.Function {
	name := identName(at(defNode, 1))
	qualname := qualPrefix + name
	fn := &ir.Function{
		Name:          qualname,
		ObjectName:    name,
		PackageName:   moduleName,
		CanonicalName: "ruby:" + moduleName + "." + qualname,
		Pos:           posFrom(filename, defNode),
	}
	fs := newFuncState(filename, moduleName, localFuncs)
	for _, p := range paramNames(at(defNode, 2)) {
		v := regValue(p)
		fn.Params = append(fn.Params, v)
		fs.env[p] = v
		fs.paramNames[p] = true
	}
	// def name params bodystmt → the body is the bodystmt at index 3.
	fs.lowerBody(bodyStmts(at(defNode, 3)))
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: fs.instrs}}
	return fn
}

// paramNames extracts the required positional parameter names from a `params`
// node (`["params", [reqs], opts, rest, …]`). Optional/keyword/splat params are
// out of scope for the taint-focused MVP.
func paramNames(n interface{}) []string {
	// def may wrap params in `paren`: ["paren", ["params", …]].
	if tag(n) == "paren" {
		n = at(n, 1)
	}
	if tag(n) != "params" {
		return nil
	}
	reqs, _ := asList(at(n, 1))
	var out []string
	for _, r := range reqs {
		if name := identName(r); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// funcState holds the per-function lowering state: a temp-register counter, the
// env mapping a Ruby local name to its current gIR value, and the flat
// instruction list for the function's single basic block.
type funcState struct {
	filename   string
	moduleName string
	localFuncs map[string]bool
	counter    int
	env        map[string]*ir.Value
	// paramNames is the set of this function's own parameter names. A member
	// read / `[]` off a parameter (or off a free/unbound identifier) is an
	// "opaque base" — see isOpaqueBase — and the first opportunity to introduce
	// taint, mirroring the JS/Python frontends' opaque-base source heuristic.
	paramNames map[string]bool
	instrs     []*ir.Instruction
}

func newFuncState(filename, moduleName string, localFuncs map[string]bool) *funcState {
	return &funcState{
		filename:   filename,
		moduleName: moduleName,
		localFuncs: localFuncs,
		env:        map[string]*ir.Value{},
		paramNames: map[string]bool{},
	}
}

func (fs *funcState) newReg() string {
	r := fmt.Sprintf("r%d", fs.counter)
	fs.counter++
	return r
}

func (fs *funcState) emit(inst *ir.Instruction) { fs.instrs = append(fs.instrs, inst) }

func (fs *funcState) newValueInst(n interface{}) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: posFrom(fs.filename, n)}
}

func regValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func constString(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}}}}
}

func posFrom(filename string, n interface{}) *ir.Position {
	if line, col, ok := firstPos(n); ok {
		return &ir.Position{Filename: filename, Line: int32(line), Column: int32(col)}
	}
	return &ir.Position{Filename: filename}
}

func (fs *funcState) lowerBody(stmts []interface{}) {
	for _, s := range stmts {
		fs.lowerStmt(s)
	}
}

func (fs *funcState) lowerStmt(s interface{}) {
	switch tag(s) {
	case "void_stmt", "":
		return
	case "assign", "opassign":
		// ["assign", target, rhs]; target is ["var_field",["@ident","x",pos]].
		val := fs.lowerExpr(at(s, 2))
		if name := identName(at(at(s, 1), 1)); name != "" {
			fs.env[name] = val
		}
		return
	case "def", "class", "module":
		return // lowered separately by convertModule.collect
	default:
		fs.lowerExpr(s)
	}
}

// lowerExpr lowers one Ruby expression to a gIR value, emitting instructions as
// a side effect. Unhandled nodes become a ruby.unsupported intrinsic so an
// unmodeled construct never silently claims to carry no taint AND is visible to
// the converter's coverage check.
func (fs *funcState) lowerExpr(n interface{}) *ir.Value {
	switch tag(n) {
	case "":
		return constString("")
	case "string_literal":
		return fs.lowerStringLiteral(n)
	case "string_content":
		return fs.lowerStringContent(n)
	case "xstring_literal":
		return fs.lowerBacktick(n)
	case "@tstring_content", "@int", "@float", "@CHAR":
		return constString(scalarText(n))
	case "string_embexpr":
		// `#{ stmts }` — lower the inner statements, return the last value.
		inner, _ := asList(at(n, 1))
		var last *ir.Value
		for _, e := range inner {
			last = fs.lowerExpr(e)
		}
		if last == nil {
			return constString("")
		}
		return last
	case "const_path_ref", "top_const_ref":
		// A namespaced constant (`Net::HTTP`, `ERB::Util`). It carries no taint;
		// return its flattened name so lowering the receiver of `Net::HTTP.get`
		// does not fall through to a `ruby.unsupported` intrinsic.
		return constString(constPathName(n))
	case "symbol_literal":
		return constString(identName(at(at(n, 1), 1)))
	case "dyna_symbol":
		return constString("")
	case "var_ref":
		inner := at(n, 1)
		if tag(inner) == "@ident" {
			return fs.lookup(identName(inner))
		}
		return constString(scalarText(inner)) // @const / @kw / @gvar
	case "vcall":
		// A bare name: a local variable read if bound, else a 0-arg call/const.
		name := identName(at(n, 1))
		if v, ok := fs.env[name]; ok {
			return v
		}
		return constString(name)
	case "paren":
		inner := at(n, 1)
		if l, ok := asList(inner); ok && len(l) > 0 {
			if _, isStmtList := l[0].([]interface{}); isStmtList {
				var last *ir.Value
				for _, e := range l {
					last = fs.lowerExpr(e)
				}
				if last != nil {
					return last
				}
				return constString("")
			}
		}
		return fs.lowerExpr(inner)
	case "aref":
		return fs.lowerAref(n)
	case "binary":
		return fs.lowerBinary(n)
	case "call":
		return fs.lowerDotCall(n, nil) // receiver.method with no args
	case "method_add_arg":
		return fs.lowerMethodAddArg(n)
	case "command":
		return fs.lowerCommand(n)
	case "command_call":
		return fs.lowerCommandCall(n)
	case "method_add_block":
		return fs.lowerMethodAddBlock(n)
	case "fcall":
		return fs.lowerCallExpr("ruby:"+identName(at(n, 1)), nil, n)
	case "array":
		// Lower elements (so a source/sink inside fires); the container itself is
		// left untainted, matching the other frontends' list handling.
		if elts, ok := asList(at(n, 1)); ok {
			for _, e := range elts {
				fs.lowerExpr(e)
			}
		}
		return constString("")
	}
	// Unhandled: emit a visible intrinsic placeholder.
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = "ruby.unsupported"
	fs.emit(inst)
	return regValue(inst.Name)
}

// lowerStringLiteral lowers `"...#{x}..."`. Interpolation parts are folded with
// BIN_OP_ADD so taint from an embedded expression flows to the string (mirroring
// the Python f-string / JS template-literal lowering).
func (fs *funcState) lowerStringLiteral(n interface{}) *ir.Value {
	return fs.lowerStringContent(at(n, 1))
}

func (fs *funcState) lowerStringContent(content interface{}) *ir.Value {
	l, ok := asList(content)
	if !ok || len(l) < 2 {
		return constString("")
	}
	var acc *ir.Value
	for _, part := range l[1:] { // l[0] == "string_content"
		v := fs.lowerExpr(part)
		if acc == nil {
			acc = v
			continue
		}
		acc = fs.emitBinOp(acc, v, part)
	}
	if acc == nil {
		return constString("")
	}
	return acc
}

// lowerBacktick lowers a backtick command literal “ `cmd #{x}` “ (and %x{}) —
// which executes a shell command — to a synthetic CALL "ruby:%x" whose args are
// the literal's parts, so a tainted interpolation reaches the sink.
func (fs *funcState) lowerBacktick(n interface{}) *ir.Value {
	parts, _ := asList(at(n, 1))
	var args []*ir.Value
	for _, p := range parts {
		args = append(args, fs.lowerExpr(p))
	}
	return fs.lowerCallExprVals("ruby:%x", args, n)
}

func (fs *funcState) lowerBinary(n interface{}) *ir.Value {
	left := fs.lowerExpr(at(n, 1))
	right := fs.lowerExpr(at(n, 3))
	return fs.emitBinOp(left, right, n)
}

func (fs *funcState) emitBinOp(left, right *ir.Value, n interface{}) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = ir.BinOpKind_BIN_OP_ADD
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return regValue(inst.Name)
}

// isOpaqueBase reports whether a receiver/base node refers to a value whose
// origin is outside this function's own straight-line computation — either a
// free/unbound identifier (a `vcall`, e.g. a framework accessor such as
// Sinatra's `params`/`request` that Ripper cannot resolve to a local) or one of
// this function's own parameters (a `var_ref` to a name in paramNames, e.g. a
// Rails/Rack handler's `request`/`req` object). A member read / `[]` off such a
// base is the first opportunity to introduce taint, mirroring the JS/Python
// frontends' opaque-base heuristic (see converters/javascript/lower.go
// isOpaqueBase). It deliberately does NOT treat an ordinary assigned local (a
// `var_ref` not in paramNames) or a constant (`@const`) as opaque, so a local
// happening to be named `params`, or a class like `User`, is not mistaken for
// a request. Which opaque-base accessors actually seed taint is decided by the
// rulepack source globs, not here.
func (fs *funcState) isOpaqueBase(recv interface{}) (name string, ok bool) {
	switch tag(recv) {
	case "vcall":
		if inner := at(recv, 1); tag(inner) == "@ident" {
			return identName(inner), true
		}
	case "var_ref":
		if inner := at(recv, 1); tag(inner) == "@ident" {
			if n := identName(inner); fs.paramNames[n] {
				return n, true
			}
		}
	}
	return "", false
}

// requestDotBases are the conventional names of a web request object across Ruby
// frameworks. A member read off an opaque base with one of these names is
// synthesized as a source CALL `ruby:<base>.<method>` (receiver-/base-scoped, so
// the rulepack globs `ruby:request.*` / `ruby:req.*` filter by framework). Any
// accessor is covered — the frontend no longer enumerates a fixed member list,
// so Rack/Sinatra/Hanami accessors beyond the classic params/query/… set fire.
var requestDotBases = map[string]bool{"request": true, "req": true, "params": true}

// requestIndexBases are the conventional names of a request-controlled hash
// indexed as `base[:x]` (Rails/Sinatra `params[...]`, `cookies[...]`).
var requestIndexBases = map[string]bool{"params": true, "cookies": true}

// lowerAref lowers `base[index]`. When the base is an opaque request hash
// (`params[:x]`, `cookies['x']`), it becomes a synthetic source CALL so the
// engine seeds taint; otherwise it is an INDEX whose taint flows from the base.
func (fs *funcState) lowerAref(n interface{}) *ir.Value {
	base := at(n, 1)
	if name, ok := fs.isOpaqueBase(base); ok && requestIndexBases[name] {
		return fs.lowerCallExprVals("ruby:"+name, nil, n)
	}
	baseVal := fs.lowerExpr(base)
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{baseVal}
	fs.emit(inst)
	return regValue(inst.Name)
}

// lowerDotCall lowers `recv.method(args?)`. args is nil for the no-arg `call`
// form. Any accessor off an opaque request base (`request.query_string`,
// `req.params`) becomes a base-scoped source CALL `ruby:<base>.<method>`.
func (fs *funcState) lowerDotCall(n interface{}, args []interface{}) *ir.Value {
	recv := at(n, 1)
	method := identName(at(n, 3))
	if name, ok := fs.isOpaqueBase(recv); ok && requestDotBases[name] {
		return fs.lowerCallExprVals("ruby:"+name+"."+method, nil, n)
	}
	// Lower the receiver first so a chained inner call (a.b(x).c) still emits.
	recvVal := fs.lowerExpr(recv)
	callee := fs.calleeFor(recv, method)
	argVals := []*ir.Value{recvVal} // receiver as operand 0 (rules pin the tainted arg with #1)
	for _, a := range args {
		argVals = append(argVals, fs.lowerExpr(a))
	}
	return fs.lowerCallExprVals(callee, argVals, n)
}

// calleeFor builds a call's canonical callee: `ruby:<Const>.<method>` when the
// receiver is a constant (a class/module: User.where, Open3.capture3), else the
// bare `ruby:<method>` (Ruby is dynamically dispatched, so method-name rules are
// the pragmatic join).
func (fs *funcState) calleeFor(recv interface{}, method string) string {
	if tag(recv) == "var_ref" && tag(at(recv, 1)) == "@const" {
		return "ruby:" + identName(at(recv, 1)) + "." + method
	}
	if tag(recv) == "vcall" && tag(at(recv, 1)) == "@const" {
		return "ruby:" + identName(at(recv, 1)) + "." + method
	}
	// A namespaced constant receiver (`Net::HTTP.get`, `Open3::Foo.bar`) — scope
	// the callee by the full constant path so a sink glob (`ruby:Net::HTTP.get`)
	// does not collapse to the bare, collision-prone method name (`ruby:get`).
	if tag(recv) == "const_path_ref" || tag(recv) == "top_const_ref" {
		return "ruby:" + constPathName(recv) + "." + method
	}
	return "ruby:" + method
}

// constPathName flattens a namespaced-constant node (`Net::HTTP`, `A::B::C`,
// `::Foo`) into its `::`-joined source text (`Net::HTTP`).
func constPathName(n interface{}) string {
	switch tag(n) {
	case "const_path_ref":
		return constPathName(at(n, 1)) + "::" + identName(at(n, 2))
	case "top_const_ref":
		return identName(at(n, 1))
	case "var_ref", "vcall":
		return identName(at(n, 1))
	}
	return identName(n)
}

// localCallee builds the canonical callee for a bare function call `name(...)`,
// qualifying a local (top-level) def with the module name so cross-function
// taint resolves to the function's canonical name; other names stay bare.
func (fs *funcState) localCallee(name string) string {
	if fs.localFuncs[name] {
		return "ruby:" + fs.moduleName + "." + name
	}
	return "ruby:" + name
}

func (fs *funcState) lowerMethodAddArg(n interface{}) *ir.Value {
	head := at(n, 1)
	args := extractArgs(at(n, 2))
	switch tag(head) {
	case "fcall":
		callee := fs.localCallee(identName(at(head, 1)))
		var argVals []*ir.Value
		for _, a := range args {
			argVals = append(argVals, fs.lowerExpr(a))
		}
		return fs.lowerCallExprVals(callee, argVals, n)
	case "call":
		return fs.lowerDotCall(head, args)
	}
	return constString("")
}

func (fs *funcState) lowerCommand(n interface{}) *ir.Value {
	callee := fs.localCallee(identName(at(n, 1)))
	var argVals []*ir.Value
	for _, a := range extractArgs(at(n, 2)) {
		argVals = append(argVals, fs.lowerExpr(a))
	}
	return fs.lowerCallExprVals(callee, argVals, n)
}

func (fs *funcState) lowerCommandCall(n interface{}) *ir.Value {
	// ["command_call", recv, ".", methodIdent, args] — same recv/method layout
	// as a `call` node, so lowerDotCall handles it once the args are unwrapped.
	return fs.lowerDotCall(n, extractArgs(at(n, 4)))
}

// lowerMethodAddBlock lowers `call do |x| … end` / `call { … }` (Sinatra routes,
// blocks): the call is lowered and the block body is lowered inline in the
// current function so handler code inside the block is analyzed.
func (fs *funcState) lowerMethodAddBlock(n interface{}) *ir.Value {
	v := fs.lowerExpr(at(n, 1))
	block := at(n, 2)
	switch tag(block) {
	case "do_block":
		fs.lowerBody(bodyStmts(at(block, 2)))
	case "brace_block":
		if stmts, ok := asList(at(block, 2)); ok {
			fs.lowerBody(stmts)
		}
	}
	return v
}

// extractArgs unwraps an argument node (`arg_paren` / `args_add_block`) into the
// list of argument expressions, dropping any trailing block argument.
func extractArgs(n interface{}) []interface{} {
	switch tag(n) {
	case "arg_paren":
		return extractArgs(at(n, 1))
	case "args_add_block":
		l, _ := asList(at(n, 1))
		return l
	}
	return nil
}

func (fs *funcState) lowerCallExpr(callee string, args []interface{}, n interface{}) *ir.Value {
	var argVals []*ir.Value
	for _, a := range args {
		argVals = append(argVals, fs.lowerExpr(a))
	}
	return fs.lowerCallExprVals(callee, argVals, n)
}

func (fs *funcState) lowerCallExprVals(callee string, args []*ir.Value, n interface{}) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_CALL
	inst.Call = &ir.CallCommon{
		Callee: callee,
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Args:   args,
	}
	fs.emit(inst)
	return regValue(inst.Name)
}

func (fs *funcState) lookup(name string) *ir.Value {
	if v, ok := fs.env[name]; ok {
		return v
	}
	return constString(name)
}

// scalarText returns a token/scalar node's text for a constant value.
func scalarText(n interface{}) string {
	switch v := n.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	if s := identName(n); s != "" {
		return s
	}
	return ""
}

package ruby_converter

import (
	"encoding/json"
	"fmt"

	"github.com/bytevet/godzilla/converters/ssabuild"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
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

// convertModule lowers one Ruby file's Ripper sexp into a gIR module: every `def`
// becomes a function, and the remaining top-level statements are collected into a
// synthetic "<module>" function so script- and Sinatra-style handler code is
// still analyzed.
func convertModule(root interface{}, filename, moduleName string) *ir.Module {
	mod := &ir.Module{Name: moduleName, Language: "ruby"}

	stmts := programStmts(root)

	// localFuncs holds top-level def names; qualifiedFuncs additionally records
	// every def's CLASS-qualified name (the `<Class>.method` part after
	// `ruby:<module>.`). See localCallee for what each resolves.
	localFuncs := map[string]bool{}
	qualifiedFuncs := map[string]bool{}
	walkDefs(root, defScope{}, func(d interface{}, sc defScope) {
		// A singleton def is NOT recorded: its function is named `ruby:<Class>.m`,
		// so resolving a bare self-call to `ruby:<module>.<prefix>m` here would
		// point the callee at a function that does not exist.
		if tag(d) == "def" && !sc.singleton {
			name := identName(at(d, 1))
			localFuncs[name] = true
			qualifiedFuncs[sc.qualPrefix+name] = true
		}
	})

	var functions []*ir.Function
	walkDefs(root, defScope{}, func(d interface{}, sc defScope) {
		switch {
		case tag(d) == "defs":
			functions = append(functions, lowerDefs(d, filename, moduleName, sc.className, sc.qualPrefix, localFuncs, qualifiedFuncs))
		case sc.singleton:
			functions = append(functions, lowerSingletonDef(d, filename, moduleName, sc.className, sc.qualPrefix, localFuncs, qualifiedFuncs))
		default:
			functions = append(functions, lowerDef(d, filename, moduleName, sc.qualPrefix, localFuncs, qualifiedFuncs))
		}
	})

	// The module entry point: top-level statements that are not a def/class.
	if init := lowerModuleInit(stmts, filename, moduleName, localFuncs, qualifiedFuncs); init != nil {
		functions = append([]*ir.Function{init}, functions...)
	}

	mod.Functions = functions
	return mod
}

// defScope is the naming context a def inherits from the nodes enclosing it.
type defScope struct {
	qualPrefix string // dotted class prefix after `ruby:<module>.`, e.g. "Admin.User."
	className  string // innermost enclosing class, the namespace a class method takes
	singleton  bool   // inside a `class << self` body: a plain def is a CLASS method
}

// walkDefs visits every `def`/`defs` in a Ripper tree with its enclosing scope.
//
// Only class/module/sclass open a scope; every other node is descended through
// unchanged, so a def under `if`, `unless`, a `rescue` clause or a `do` block is
// reached. That generality is the point: lowerStmt recurses into all of those,
// and a def the collectors miss is lowered by NOBODY — it leaves no intrinsic
// and fails no test, it simply is not analyzed.
func walkDefs(n interface{}, sc defScope, visit func(def interface{}, sc defScope)) {
	switch tag(n) {
	case "def", "defs":
		visit(n, sc)
	case "class", "module":
		// class C ... end → constant name at at(n,1) = ["const_ref",["@const","C",pos]]
		name := identName(at(at(n, 1), 1))
		walkDefs(classModuleBody(n), defScope{qualPrefix: sc.qualPrefix + name + ".", className: name}, visit)
	case "sclass":
		// `class << self; def m; end; end` — ["sclass", target, bodystmt].
		walkDefs(at(n, 2), defScope{qualPrefix: sc.qualPrefix, className: sc.className, singleton: true}, visit)
	default:
		l, ok := asList(n)
		if !ok {
			return
		}
		for _, c := range l {
			walkDefs(c, sc, visit)
		}
	}
}

// lowerSingletonDef lowers a plain `def` inside a `class << self` body. Ruby
// makes it a class method, so it is named and shaped like `def self.m`: a
// class-qualified canonical name a call on the class resolves to from another
// file, and a receiver in parameter slot 0 to line the arguments up.
func lowerSingletonDef(defNode interface{}, filename, moduleName, className, qualPrefix string, localFuncs, qualifiedFuncs map[string]bool) *ir.Function {
	fn := lowerDef(defNode, filename, moduleName, qualPrefix, localFuncs, qualifiedFuncs)
	fn.Name = fn.ObjectName
	if className != "" {
		fn.CanonicalName = "ruby:" + className + "." + fn.ObjectName
	}
	fn.Params = append([]*ir.Value{ssabuild.Reg("self")}, fn.Params...)
	return fn
}

// programStmts returns the top-level statement list of a `["program",[stmts]]`.
func programStmts(root interface{}) []interface{} {
	if tag(root) != "program" {
		return nil
	}
	l, _ := asList(at(root, 1))
	return l
}

// classModuleBody returns the bodystmt node of a `class`/`module` node. Ripper
// lays these out differently: `["class", const, superclass_or_null, bodystmt]`
// (body at index 3) but `["module", const, bodystmt]` (body at index 2). A fixed
// index 3 for both silently drops every nested module's contents.
func classModuleBody(s interface{}) interface{} {
	if tag(s) == "module" {
		return at(s, 2)
	}
	return at(s, 3)
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
func lowerModuleInit(stmts []interface{}, filename, moduleName string, localFuncs, qualifiedFuncs map[string]bool) *ir.Function {
	var top []interface{}
	for _, s := range stmts {
		switch tag(s) {
		case "def", "defs", "class", "module", "void_stmt":
			// skip
		default:
			top = append(top, s)
		}
	}
	if len(top) == 0 {
		return nil
	}
	fs := newFuncState(filename, moduleName, localFuncs, qualifiedFuncs, "")
	fs.lowerBody(top)
	blocks := fs.b.Finish()
	if instrCount(blocks) == 0 {
		return nil
	}
	return &ir.Function{
		Name:          "<module>",
		ObjectName:    "<module>",
		PackageName:   moduleName,
		CanonicalName: "ruby:" + moduleName + ".<module>",
		Synthetic:     true,
		Blocks:        blocks,
	}
}

func instrCount(blocks []*ir.BasicBlock) int {
	n := 0
	for _, b := range blocks {
		n += len(b.Instrs)
	}
	return n
}

// lowerDef lowers one `def` into a function.
func lowerDef(defNode interface{}, filename, moduleName, qualPrefix string, localFuncs, qualifiedFuncs map[string]bool) *ir.Function {
	name := identName(at(defNode, 1))
	qualname := qualPrefix + name
	fn := &ir.Function{
		Name:          qualname,
		ObjectName:    name,
		PackageName:   moduleName,
		CanonicalName: "ruby:" + moduleName + "." + qualname,
		Pos:           posFrom(filename, defNode),
	}
	fs := newFuncState(filename, moduleName, localFuncs, qualifiedFuncs, qualPrefix)
	for _, p := range paramNames(at(defNode, 2)) {
		v := ssabuild.Reg(p)
		fn.Params = append(fn.Params, v)
		fs.write(p, v)
		fs.paramNames[p] = true
	}
	// def name params bodystmt → the body is the bodystmt at index 3.
	fs.lowerDefBody(bodyStmts(at(defNode, 3)))
	fn.Blocks = fs.b.Finish()
	return fn
}

// lowerDefs lowers a singleton/class method `def self.m(...)` into a function.
// Its layout is ["defs", recv, ".", methodIdent, params, bodystmt].
//
// The canonical name is class-qualified but FILE-PATH-INDEPENDENT
// (`ruby:<Class>.<method>`), because the engine matches a callee to a function by
// exact canonical name: that is what lets a call on the class — or on an
// ActiveRecord relation of it, `Model.scope(...).class_method(arg)` — resolve
// here from ANOTHER file. A synthetic receiver parameter occupies slot 0,
// mirroring the receiver a `recv.m(args)` call site prepends, so the arg->param
// mapping lines the first real argument up with the first declared parameter.
func lowerDefs(defNode interface{}, filename, moduleName, className, qualPrefix string, localFuncs, qualifiedFuncs map[string]bool) *ir.Function {
	name := identName(at(defNode, 3))
	canonical := "ruby:" + className + "." + name
	if className == "" {
		// A top-level `def self.m` with no enclosing class: fall back to the
		// file-scoped naming so it is at least uniquely identified.
		canonical = "ruby:" + moduleName + "." + name
	}
	fn := &ir.Function{
		Name:          name,
		ObjectName:    name,
		PackageName:   moduleName,
		CanonicalName: canonical,
		Pos:           posFrom(filename, defNode),
	}
	fs := newFuncState(filename, moduleName, localFuncs, qualifiedFuncs, qualPrefix)
	// Synthetic receiver at slot 0 (the class / relation); never referenced.
	fn.Params = append(fn.Params, ssabuild.Reg("self"))
	for _, p := range paramNames(at(defNode, 4)) {
		v := ssabuild.Reg(p)
		fn.Params = append(fn.Params, v)
		fs.write(p, v)
		fs.paramNames[p] = true
	}
	fs.lowerDefBody(bodyStmts(at(defNode, 5)))
	fn.Blocks = fs.b.Finish()
	return fn
}

// paramNames extracts the positional parameter names from a `params` node
// (`["params", [reqs], [opts], rest, …]`) in source order: required first, then
// optional (defaulted). The optionals matter for taint — a classic vulnerable
// signature is `def m(filter = nil)`, and unbound its tainted argument maps to no
// parameter and drops. Keyword/splat/block params are out of scope.
func paramNames(n interface{}) []string {
	// def may wrap params in `paren`: ["paren", ["params", …]].
	if tag(n) == "paren" {
		n = at(n, 1)
	}
	if tag(n) != "params" {
		return nil
	}
	var out []string
	reqs, _ := asList(at(n, 1))
	for _, r := range reqs {
		if name := identName(r); name != "" {
			out = append(out, name)
		}
	}
	// Optionals: index 2 is a list of [identNode, defaultExpr] pairs.
	opts, _ := asList(at(n, 2))
	for _, o := range opts {
		pair, ok := asList(o)
		if !ok || len(pair) == 0 {
			continue
		}
		if name := identName(pair[0]); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// funcState holds the per-function lowering state. Variable values and the
// per-block instruction stream are owned by an ssabuild.Builder (real CFG +
// on-demand PHI insertion, Braun et al.); `cur` is the block currently being
// lowered into. `assigned` answers what the Builder's per-block value map cannot
// — is this bare name a bound local/ivar, or a free identifier / method?
type funcState struct {
	filename   string
	moduleName string
	localFuncs map[string]bool
	// qualifiedFuncs is the module-wide set of class-qualified def names
	// ("<Class>.method"); classQual is this function's own class prefix
	// ("<Class>." or "" at top level). Together they let a bare call resolve to
	// a same-class method for implicit-self inter-procedural taint.
	qualifiedFuncs map[string]bool
	classQual      string
	counter        int
	b              *ssabuild.Builder
	cur            ssabuild.BlockID
	assigned       map[string]bool
	// terminated reports whether the current block has already emitted a
	// block-terminating RET. Such a block must NOT receive a fall-through JUMP and
	// must NOT become a predecessor of a merge / loop header — a returning arm
	// feeding its possibly-tainted values into the join is a false positive. Reset
	// to false whenever lowering begins in a fresh block.
	terminated bool
	// paramNames is the set of this function's own parameter names; see
	// isOpaqueBase.
	paramNames map[string]bool
}

func newFuncState(filename, moduleName string, localFuncs, qualifiedFuncs map[string]bool, classQual string) *funcState {
	b := ssabuild.NewBuilder()
	entry := b.NewBlock()
	b.Seal(entry) // the entry block has no predecessors, so it is sealed at once.
	return &funcState{
		filename:       filename,
		moduleName:     moduleName,
		localFuncs:     localFuncs,
		qualifiedFuncs: qualifiedFuncs,
		classQual:      classQual,
		b:              b,
		cur:            entry,
		assigned:       map[string]bool{},
		paramNames:     map[string]bool{},
	}
}

func (fs *funcState) newReg() string {
	r := fmt.Sprintf("r%d", fs.counter)
	fs.counter++
	return r
}

func (fs *funcState) emit(inst *ir.Instruction) { fs.b.AddInstr(fs.cur, inst) }

// write records val as the current value of a Ruby local/ivar name in the
// current block and marks the name as assigned (so a later bare read resolves
// it as a variable rather than a free identifier / method call).
func (fs *funcState) write(name string, val *ir.Value) {
	fs.b.WriteVariable(name, fs.cur, val)
	fs.assigned[name] = true
}

// read returns the SSA value current for a Ruby local in the current block,
// inserting PHIs on demand (branch joins / loop headers) via the Builder.
func (fs *funcState) read(name string) *ir.Value {
	return fs.b.ReadVariable(name, fs.cur)
}

func (fs *funcState) newValueInst(n interface{}) *ir.Instruction {
	return &ir.Instruction{Name: fs.newReg(), Pos: posFrom(fs.filename, n)}
}

// ivarGlobal returns the synthetic global key for an instance variable `@f`
// inside a class method, or "" outside a class. It is the cross-method channel
// for instance-variable taint: the store/read carry this key as a GlobalName
// operand, which the engine's recordGlobalStore / readGlobalTaint already handle,
// so `@f = tainted` in one method reaches a sibling's read with NO engine change.
// Object-insensitive (all instances share the key) but scoped to the method's own
// class+module, so a same-named ivar on an unrelated class cannot alias.
func (fs *funcState) ivarGlobal(ivarName string) string {
	if fs.classQual == "" || ivarName == "" {
		return ""
	}
	return "rubyfield:" + fs.moduleName + "." + fs.classQual + ivarName
}

// assocPairs returns the `assoc_new` pairs of a hash node. Ripper spells the two
// hash forms differently -- `bare_assoc_hash` holds the pair list directly, while
// a braced `hash` wraps it in `assoclist_from_args` (and is nil when empty).
func assocPairs(n interface{}) []interface{} {
	list := at(n, 1)
	if tag(list) == "assoclist_from_args" {
		list = at(list, 1)
	}
	pairs, ok := asList(list)
	if !ok {
		return nil
	}
	var out []interface{}
	for _, p := range pairs {
		if tag(p) == "assoc_new" {
			out = append(out, p)
		}
	}
	return out
}

// posFrom converts a Ripper node's position to a gIR one. Ripper counts columns
// from 0 and every other frontend — and every editor a reported column is read
// in — counts from 1, so the column is shifted here. A node with no position at
// all keeps Line 0, which the report layer already reads as "unknown"; a
// Column 1 alongside it would claim a precision that does not exist.
func posFrom(filename string, n interface{}) *ir.Position {
	if line, col, ok := firstPos(n); ok {
		return &ir.Position{Filename: filename, Line: int32(line), Column: int32(col + 1)}
	}
	return &ir.Position{Filename: filename}
}

func (fs *funcState) lowerBody(stmts []interface{}) {
	for _, s := range stmts {
		fs.lowerStmt(s)
	}
}

// lowerDefBody lowers a method body and emits an implicit RET of the last
// expression's value — Ruby's implicit return — so the engine can summarize a
// helper that returns request data as taint-returning. An explicit `return x`
// emits its own RET (see lowerStmt); this covers the fall-through value.
func (fs *funcState) lowerDefBody(stmts []interface{}) {
	var last *ir.Value
	for _, s := range stmts {
		last = fs.lowerStmt(s)
	}
	if last != nil {
		fs.emit(&ir.Instruction{Op: ir.OpCode_OP_CODE_RET, Operands: []*ir.Value{last}})
	}
}

// lowerSeqLast lowers a sequence of expressions and returns the last value (or
// the empty string for an empty sequence) — the value of a `(...)` or `#{...}`.
func (fs *funcState) lowerSeqLast(exprs []interface{}) *ir.Value {
	var last *ir.Value
	for _, e := range exprs {
		last = fs.lowerExpr(e)
	}
	if last == nil {
		return ssabuild.Str("")
	}
	return last
}

// assignTarget binds val to an assignment target. An instance variable rebinds
// the local value (intra-method precision) AND stores into the per-(class,
// @ivar) synthetic global for cross-method flow (see ivarGlobal).
func (fs *funcState) assignTarget(target interface{}, val *ir.Value) {
	leaf := at(target, 1)
	name := identName(leaf)
	if name != "" {
		fs.write(name, val)
	}
	if tag(leaf) == "@ivar" {
		if g := fs.ivarGlobal(name); g != "" {
			fs.emit(&ir.Instruction{
				Op:       ir.OpCode_OP_CODE_STORE,
				Operands: []*ir.Value{ssabuild.Global(g), val},
				Pos:      posFrom(fs.filename, target),
			})
		}
	}
}

// lowerStmt lowers one statement and returns its Ruby value (the value an
// implicit return would yield); callers that don't need the value discard it.
func (fs *funcState) lowerStmt(s interface{}) *ir.Value {
	switch tag(s) {
	case "void_stmt", "":
		return nil
	case "assign":
		// ["assign", target, rhs]; target is ["var_field",["@ident"/"@ivar","x",pos]].
		val := fs.lowerExpr(at(s, 2))
		fs.assignTarget(at(s, 1), val)
		return val // Ruby assignment evaluates to the assigned value.
	case "opassign":
		// ["opassign", target, ["@op","||="/"+="/…], rhs] — index 2 is the OPERATOR
		// token, so the rhs must be read from index 3; index 2 would drop the
		// expression and any source/sink inside it.
		val := fs.lowerExpr(at(s, 3))
		fs.assignTarget(at(s, 1), val)
		return val
	case "return":
		// ["return", args] — RET of the returned value, so the engine's
		// taint-return summary sees it.
		v := fs.lowerSeqLast(extractArgs(at(s, 1)))
		fs.emit(&ir.Instruction{Op: ir.OpCode_OP_CODE_RET, Operands: []*ir.Value{v}})
		fs.terminated = true // the current block ends here; no fall-through edge.
		return v
	case "return0":
		// Ripper's tag for an argument-less `return`. The RET terminates the block;
		// without this case it would fall through to a ruby.unsupported intrinsic.
		v := ssabuild.Str("")
		fs.emit(&ir.Instruction{Op: ir.OpCode_OP_CODE_RET, Operands: []*ir.Value{v}})
		fs.terminated = true
		return v
	case "def", "defs", "class", "module", "sclass":
		return nil // lowered separately by walkDefs
	default:
		return fs.lowerExpr(s)
	}
}

// lowerExpr lowers one Ruby expression to a gIR value, emitting instructions as
// a side effect. Unhandled nodes become a ruby.unsupported intrinsic so an
// unmodeled construct never silently claims to carry no taint AND is visible to
// the converter's coverage check.
func (fs *funcState) lowerExpr(n interface{}) *ir.Value {
	switch tag(n) {
	case "":
		return ssabuild.Str("")
	case "string_literal":
		return fs.lowerStringLiteral(n)
	case "string_content":
		return fs.lowerStringContent(n)
	case "xstring_literal":
		return fs.lowerBacktick(n)
	// @label is a keyword-argument key (`name:`) -- a symbol literal, like the rest.
	case "@tstring_content", "@int", "@float", "@CHAR", "@label":
		return ssabuild.Str(scalarText(n))
	case "string_embexpr":
		// `#{ stmts }` — lower the inner statements, return the last value.
		inner, _ := asList(at(n, 1))
		return fs.lowerSeqLast(inner)
	case "const_path_ref", "top_const_ref":
		// A namespaced constant carries no taint; its flattened name keeps the
		// receiver of `Net::HTTP.get` off the ruby.unsupported path.
		return ssabuild.Str(constPathName(n))
	case "symbol_literal":
		return ssabuild.Str(identName(at(at(n, 1), 1)))
	case "dyna_symbol":
		return ssabuild.Str("")
	case "var_ref":
		inner := at(n, 1)
		switch tag(inner) {
		case "@ident":
			return fs.lookup(identName(inner))
		case "@ivar":
			// Prefer this method's own binding; otherwise read the per-(class,
			// @ivar) global so a sibling method's stashed taint is observed.
			name := identName(inner)
			if fs.assigned[name] {
				return fs.read(name)
			}
			if g := fs.ivarGlobal(name); g != "" {
				ld := fs.newValueInst(n)
				ld.Op = ir.OpCode_OP_CODE_LOAD
				ld.Operands = []*ir.Value{ssabuild.Global(g)}
				fs.emit(ld)
				return ssabuild.Reg(ld.Name)
			}
			return ssabuild.Str(scalarText(inner))
		}
		return ssabuild.Str(scalarText(inner)) // @const / @kw / @gvar
	case "vcall":
		// A bare name: a local read if bound; else, if it names a known method, a
		// 0-arg CALL so `p = fetch_path` links up for inter-procedural taint;
		// otherwise a free identifier / constant.
		name := identName(at(n, 1))
		if fs.assigned[name] {
			return fs.read(name)
		}
		if fs.isKnownMethod(name) {
			return fs.lowerCallExpr(fs.localCallee(name), nil, n)
		}
		return fs.lookup(name)
	case "paren":
		inner := at(n, 1)
		if l, ok := asList(inner); ok && len(l) > 0 {
			if _, isStmtList := l[0].([]interface{}); isStmtList {
				return fs.lowerSeqLast(l)
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
	case "case":
		return fs.lowerCase(n)
	case "if", "elsif", "unless":
		return fs.lowerIf(n)
	case "while", "until":
		return fs.lowerWhile(n)
	case "if_mod", "unless_mod":
		return fs.lowerCondMod(n)
	case "while_mod", "until_mod":
		return fs.lowerLoopMod(n)
	case "bare_assoc_hash", "hash":
		// A keyword-argument or brace hash. Lower each key and value so a source or
		// sink inside still fires, and leave the hash itself untainted like `array`.
		//
		// Untainted is not a shortcut here, it is the point: ActiveRecord's hash
		// form (`where(name: params[:q])`) is parameterized by construction, so a
		// hash that carried its values' taint would make every one of them a false
		// positive.
		for _, pair := range assocPairs(n) {
			fs.lowerExpr(at(pair, 1))
			fs.lowerExpr(at(pair, 2))
		}
		return ssabuild.Str("")
	case "array":
		// Lower elements (so a source/sink inside fires); the container itself is
		// left untainted, matching the other frontends' list handling.
		if elts, ok := asList(at(n, 1)); ok {
			for _, e := range elts {
				fs.lowerExpr(e)
			}
		}
		return ssabuild.Str("")
	}
	// Unhandled: emit a visible intrinsic placeholder.
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INTRINSIC
	inst.Intrinsic = "ruby.unsupported"
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerStringLiteral lowers `"...#{x}..."`, folding the parts with BIN_OP_ADD so
// taint from an embedded expression flows to the string.
func (fs *funcState) lowerStringLiteral(n interface{}) *ir.Value {
	return fs.lowerStringContent(at(n, 1))
}

func (fs *funcState) lowerStringContent(content interface{}) *ir.Value {
	l, ok := asList(content)
	if !ok || len(l) < 2 {
		return ssabuild.Str("")
	}
	var acc *ir.Value
	for _, part := range l[1:] { // l[0] == "string_content"
		v := fs.lowerExpr(part)
		if acc == nil {
			acc = v
			continue
		}
		acc = fs.emitBinOp(ir.BinOpKind_BIN_OP_ADD, acc, v, part)
	}
	return acc
}

// lowerCase lowers `case cond; when …; else …; end`. The condition and EVERY
// branch body are lowered inline into the current block, so taint reaching any
// branch — a raw SQL string built only in the `else` arm — is still analyzed.
func (fs *funcState) lowerCase(n interface{}) *ir.Value {
	fs.lowerExpr(at(n, 1)) // subject expression (for any embedded source/sink)
	var last *ir.Value
	node := at(n, 2)
	for node != nil {
		switch tag(node) {
		case "when":
			// ["when", conditions, body, next] — next is a `when`, `else`, or nil.
			if conds, ok := asList(at(node, 1)); ok {
				for _, c := range conds {
					fs.lowerExpr(c)
				}
			}
			if body, ok := asList(at(node, 2)); ok {
				last = fs.lowerSeqLast(body)
			}
			node = at(node, 3)
		case "else":
			if body, ok := asList(at(node, 1)); ok {
				last = fs.lowerSeqLast(body)
			}
			node = nil
		default:
			node = nil
		}
	}
	if last == nil {
		return ssabuild.Str("")
	}
	return last
}

// lowerStmtSeqLast lowers a statement list inline and returns the last
// statement's value. Unlike lowerSeqLast (expressions), it dispatches through
// lowerStmt, so an `assign`/`opassign`/`return` inside a branch or loop body
// rebinds instead of falling through to a `ruby.unsupported` intrinsic.
func (fs *funcState) lowerStmtSeqLast(stmts []interface{}) *ir.Value {
	var last *ir.Value
	for _, s := range stmts {
		last = fs.lowerStmt(s)
	}
	return last
}

// lowerIf lowers `if`/`unless`/`elsif cond; body; [elsif…|else…] end` into a REAL
// CFG diamond via the Builder's IfDiamond scaffold, so a variable rebound on
// either arm reconciles via an on-demand ReadVariable PHI. All three share the
// layout (`[tag, cond, [body], tail]`, tail = elsif/else/nil); `unless`'s
// polarity is immaterial to taint since both arms are reachable. A nested `elsif`
// recurses into the else-block, so a chain becomes nested diamonds.
func (fs *funcState) lowerIf(n interface{}) *ir.Value {
	cond := fs.lowerExpr(at(n, 1)) // condition (also lowers any embedded source/sink)
	var lastBody, lastElse *ir.Value
	thenEnd, elseEnd, merge := fs.b.IfDiamond(&fs.cur, &fs.terminated, cond,
		func() {
			if body, ok := asList(at(n, 2)); ok {
				lastBody = fs.lowerStmtSeqLast(body)
			}
		},
		func() { lastElse = fs.lowerElseTail(at(n, 3)) })
	return fs.branchResult(lastBody, lastElse, thenEnd, elseEnd, merge)
}

// branchResult reconciles the two arms' RESULT values of an if/unless used as an
// expression (`x = if c; a; else; b; end`). Two distinct values are stashed into
// a synthetic variable at each arm-end and read back in the merge block, so the
// Builder emits a proper PHI (with correct predecessor labels) that keeps taint
// from either arm; otherwise whichever arm produced a value is forwarded.
func (fs *funcState) branchResult(a, b *ir.Value, thenEnd, elseEnd, merge ssabuild.BlockID) *ir.Value {
	switch {
	case a != nil && b != nil && a != b:
		key := "__br." + fs.newReg()
		fs.b.WriteVariable(key, thenEnd, a)
		fs.b.WriteVariable(key, elseEnd, b)
		return fs.b.ReadVariable(key, merge)
	case a != nil:
		return a
	case b != nil:
		return b
	}
	return ssabuild.Str("")
}

// lowerElseTail lowers the tail of an if/unless chain in the current (else)
// block: an `elsif` (recursively — its own diamond), an `else` body, or nil.
func (fs *funcState) lowerElseTail(node interface{}) *ir.Value {
	switch tag(node) {
	case "elsif":
		return fs.lowerIf(node)
	case "else":
		if body, ok := asList(at(node, 1)); ok {
			return fs.lowerStmtSeqLast(body)
		}
	}
	return nil
}

// lowerLoopCFG builds the REAL loop CFG shared by `while`/`until` and their
// statement-modifier forms via the Builder's HeaderLoop scaffold, which owns
// the header/body/exit blocks and the seal order (the header PHI over
// [pre-loop, back-edge] is what carries loop-carried taint — see the
// scaffold's doc). cond is a Ruby AST node, lowered in the (unsealed) header.
func (fs *funcState) lowerLoopCFG(cond interface{}, lowerBody func()) *ir.Value {
	fs.b.HeaderLoop(&fs.cur, &fs.terminated,
		func() *ir.Value { return fs.lowerExpr(cond) },
		lowerBody)
	return ssabuild.Str("")
}

// lowerWhile lowers `while`/`until cond; body; end` into the shared loop CFG.
// `until` differs only in condition polarity, immaterial to taint.
func (fs *funcState) lowerWhile(n interface{}) *ir.Value {
	return fs.lowerLoopCFG(at(n, 1), func() {
		if bstmts, ok := asList(at(n, 2)); ok {
			fs.lowerStmtSeqLast(bstmts)
		}
	})
}

// lowerCondMod lowers the statement-modifier conditionals `stmt if cond` and
// `stmt unless cond` (`[tag, cond, stmt]`) as a one-armed diamond: the current
// block branches to a then-block or straight to the merge. The false edge carries
// the pre-modifier value, so a binding rebound in the guarded statement
// reconciles against it via the merge PHI and `x = safe unless c` keeps the
// original value live on the not-taken path.
func (fs *funcState) lowerCondMod(n interface{}) *ir.Value {
	cond := fs.lowerExpr(at(n, 1)) // condition (also lowers any embedded source/sink)
	thenB := fs.b.NewBlock()
	merge := fs.b.NewBlock()
	fs.b.SetIf(fs.cur, cond, thenB, merge) // false edge goes straight to merge
	fs.b.Seal(thenB)

	fs.cur = thenB
	fs.terminated = false
	last := fs.lowerStmt(at(n, 2)) // guarded statement (the taken arm)
	if !fs.terminated {            // a `return x if c` arm has no edge to the merge
		fs.b.SetJump(fs.cur, merge)
	}

	fs.b.Seal(merge) // predecessors: the branch block (false) [+ the then-end]
	fs.cur = merge
	fs.terminated = false // the merge is always reachable via the false edge
	return last
}

// lowerLoopMod lowers the statement-modifier loops `stmt while cond` and
// `stmt until cond` (`[tag, cond, stmt]`) into the same header/body/exit loop
// CFG as lowerWhile, so loop-carried taint through the guarded statement is
// modeled (a pre-test loop; `stmt until cond` on a non-begin statement is
// pre-test in Ruby, and treating it so is conservative for taint).
func (fs *funcState) lowerLoopMod(n interface{}) *ir.Value {
	return fs.lowerLoopCFG(at(n, 1), func() {
		fs.lowerStmt(at(n, 2)) // loop body statement
	})
}

// lowerBacktick lowers a backtick command literal (and %x{}) — which executes a
// shell command — to a synthetic CALL "ruby:%x" whose args are the literal's
// parts, so a tainted interpolation reaches the sink.
func (fs *funcState) lowerBacktick(n interface{}) *ir.Value {
	parts, _ := asList(at(n, 1))
	var args []*ir.Value
	for _, p := range parts {
		args = append(args, fs.lowerExpr(p))
	}
	return fs.lowerCallExprVals("ruby:%x", args, n)
}

// lowerBinary lowers `a <op> b`. Ripper shapes this as
// ["binary", left, "<op>", right] -- the operator is a PLAIN STRING at index 2,
// which is why scalarText reads it rather than identName.
//
// The operator must not be discarded: BIN_OP_ADD is the engine's universal
// propagator AND the kind ssrf.go's constant-prefix reconstruction walks, so a
// comparison lowered as one would make `user == "admin"` carry taint and read as
// string building.
func (fs *funcState) lowerBinary(n interface{}) *ir.Value {
	left := fs.lowerExpr(at(n, 1))
	right := fs.lowerExpr(at(n, 3))
	op := scalarText(at(n, 2))
	if isComparisonOp(op) {
		// A comparison result is influence, not content. The inert intrinsic still
		// gives the engine a def-use edge for guard analysis.
		inst := fs.newValueInst(n)
		inst.Op = ir.OpCode_OP_CODE_INTRINSIC
		inst.Intrinsic = "builtin.compare"
		inst.Operands = []*ir.Value{left, right}
		fs.emit(inst)
		return ssabuild.Reg(inst.Name)
	}
	return fs.emitBinOp(binOpKind(op), left, right, n)
}

// isComparisonOp reports whether a Ruby binary operator yields a comparison
// result rather than a value built from its operands' text.
func isComparisonOp(op string) bool {
	switch op {
	case "==", "!=", "<", ">", "<=", ">=", "<=>", "===", "=~", "!~":
		return true
	}
	return false
}

// binOpKind maps a Ruby binary operator to its gIR kind. Every BIN_OP propagates
// taint regardless of kind (propagatingOps in internal/analysis/taint.go), so
// only two are load-bearing and the rest are descriptive:
//
//   - BIN_OP_ADD is the one kind ssrf.go's constSkeleton walks to rebuild a URL's
//     constant prefix. `<<` maps to it because Ruby's shovel on a String or Array
//     IS an append -- calling it SHL would still propagate taint but would make
//     `url << part` opaque to the host check.
//   - BIN_OP_REM is read by the same function as a printf-style template with the
//     format at operand 0, which is exactly the shape of Ruby's `"...%s" % v`.
func binOpKind(op string) ir.BinOpKind {
	switch op {
	case "+", "<<":
		return ir.BinOpKind_BIN_OP_ADD
	case "%":
		return ir.BinOpKind_BIN_OP_REM
	case "-":
		return ir.BinOpKind_BIN_OP_SUB
	case "*", "**":
		return ir.BinOpKind_BIN_OP_MUL
	case "/":
		return ir.BinOpKind_BIN_OP_QUO
	// `&&`/`||`/`and`/`or` must keep propagating: `params[:a] || "default"`
	// evaluates to one of its operands, so the result carries their taint.
	case "&", "&&", "and":
		return ir.BinOpKind_BIN_OP_AND
	case "|", "||", "or":
		return ir.BinOpKind_BIN_OP_OR
	case "^":
		return ir.BinOpKind_BIN_OP_XOR
	case ">>":
		return ir.BinOpKind_BIN_OP_SHR
	}
	return ir.BinOpKind_BIN_OP_ADD // unknown operator: propagate conservatively
}

func (fs *funcState) emitBinOp(kind ir.BinOpKind, left, right *ir.Value, n interface{}) *ir.Value {
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_BIN_OP
	inst.BinOp = kind
	inst.Operands = []*ir.Value{left, right}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// isOpaqueBase reports whether a receiver/base node refers to a value whose
// origin is outside this function's own straight-line computation — a
// free/unbound identifier (a `vcall`, e.g. Sinatra's `params`) or one of this
// function's own parameters (a `var_ref` in paramNames, e.g. a Rails/Rack
// handler's `request`). A member read / `[]` off such a base is the first
// opportunity to introduce taint, mirroring converters/javascript's
// isOpaqueBase. It deliberately does NOT treat an ordinary assigned local or a
// constant as opaque, so a local happening to be named `params`, or a class like
// `User`, is not mistaken for a request. Which opaque-base accessors actually
// seed taint is decided by the rulepack source globs, not here.
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
// frameworks. A member read off an opaque base with one of these names becomes a
// source CALL `ruby:<base>.<method>` — base-scoped, so the rulepack globs
// (`ruby:request.*`) filter by framework. ANY accessor is covered rather than a
// fixed member list, so Rack/Sinatra/Hanami accessors beyond params/query fire.
var requestDotBases = map[string]bool{"request": true, "req": true, "params": true}

// requestIndexBases are the conventional names of a request-controlled hash
// indexed as `base[:x]` (Rails/Sinatra `params[...]`, `cookies[...]`).
var requestIndexBases = map[string]bool{"params": true, "cookies": true}

// cellOptionSource names a read of a cell's `options[...]` -- the arguments its
// CALLER passed. Unlike params it is not request input by construction: a cell is
// invoked from a controller or another view, and the value may be a request
// parameter or an internal object. That is the whole reason the rule sourcing it
// ships at `severity: low`, advisory under the default gate, rather than joining
// ruby-xss.
//
// Synthetic and `@`-marked so it can never collide with a real method named
// `options`, and emitted only inside a cell (isCellsPath), where `options` has
// this one meaning.
const cellOptionSource = "ruby:@cell.options"

// lowerAref lowers `base[index]`. When the base is an opaque request hash
// (`params[:x]`, `cookies['x']`), it becomes a synthetic source CALL so the
// engine seeds taint; otherwise it is an INDEX whose taint flows from the base.
func (fs *funcState) lowerAref(n interface{}) *ir.Value {
	base := at(n, 1)
	if name, ok := fs.isOpaqueBase(base); ok {
		if requestIndexBases[name] {
			return fs.lowerCallExprVals("ruby:"+name, nil, n)
		}
		if name == "options" && isCellsPath(fs.filename) {
			return fs.lowerCallExprVals(cellOptionSource, nil, n)
		}
	}
	baseVal := fs.lowerExpr(base)
	inst := fs.newValueInst(n)
	inst.Op = ir.OpCode_OP_CODE_INDEX
	inst.Operands = []*ir.Value{baseVal}
	fs.emit(inst)
	return ssabuild.Reg(inst.Name)
}

// lowerDotCall lowers `recv.method(args?)`; args is nil for the no-arg `call`
// form. An accessor off an opaque request base becomes a source CALL (see
// requestDotBases).
func (fs *funcState) lowerDotCall(n interface{}, args []interface{}) *ir.Value {
	recv := at(n, 1)
	method := identName(at(n, 3))
	if name, ok := fs.isOpaqueBase(recv); ok && requestDotBases[name] {
		return fs.lowerCallExprVals("ruby:"+name+"."+method, nil, n)
	}
	// Lower the receiver first so a chained inner call (a.b(x).c) still emits.
	recvVal := fs.lowerExpr(recv)
	callee := fs.calleeFor(recv, method)
	// A chain rooted at a constant — `Model.scope(a).class_method(x)` — dispatches
	// (via the ActiveRecord relation) to the class's method, so a class-qualified
	// callee resolves it to that `def self.method` across files instead of leaving
	// the bare, unresolvable `ruby:method`.
	if callee == "ruby:"+method {
		if base := chainRootConstBase(recv); base != "" {
			callee = "ruby:" + base + "." + method
		}
	}
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
	if (tag(recv) == "var_ref" || tag(recv) == "vcall") && tag(at(recv, 1)) == "@const" {
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

// chainRootConstBase returns the base (last-segment) name of the constant a
// receiver method chain is rooted at, or "" if it does not root at a constant.
// It unwraps call / method_add_arg / method_add_block nodes down to the chain's
// head receiver: `Foo::Bar.a(x).b` roots at `Foo::Bar`, base `Bar`.
func chainRootConstBase(n interface{}) string {
	for i := 0; i < 64; i++ {
		switch tag(n) {
		case "var_ref", "vcall":
			if tag(at(n, 1)) == "@const" {
				return identName(at(n, 1))
			}
			return ""
		case "const_path_ref":
			return identName(at(n, 2)) // last segment of A::B::C
		case "top_const_ref":
			return identName(at(n, 1))
		case "call", "command_call":
			n = at(n, 1) // unwrap to the receiver
		case "method_add_arg", "method_add_block":
			n = at(n, 1) // unwrap to the inner call
		default:
			return ""
		}
	}
	return ""
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

// isKnownMethod reports whether name is a def in this module — a same-class
// instance method (implicit-self) or a top-level function — as opposed to a
// local variable or an external/framework name.
func (fs *funcState) isKnownMethod(name string) bool {
	if fs.classQual != "" && fs.qualifiedFuncs[fs.classQual+name] {
		return true
	}
	return fs.localFuncs[name]
}

// localCallee builds the canonical callee for a bare call `name(...)`. A
// same-class instance method wins over a top-level def: implicit-self dispatch
// calls the former, whose canonical name carries the class prefix, and only that
// name links caller to callee for inter-procedural taint. Unknown names stay bare.
func (fs *funcState) localCallee(name string) string {
	if fs.classQual != "" && fs.qualifiedFuncs[fs.classQual+name] {
		return "ruby:" + fs.moduleName + "." + fs.classQual + name
	}
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
		return fs.lowerCallExpr(fs.localCallee(identName(at(head, 1))), args, n)
	case "call":
		return fs.lowerDotCall(head, args)
	}
	return ssabuild.Str("")
}

func (fs *funcState) lowerCommand(n interface{}) *ir.Value {
	return fs.lowerCallExpr(fs.localCallee(identName(at(n, 1))), extractArgs(at(n, 2)), n)
}

func (fs *funcState) lowerCommandCall(n interface{}) *ir.Value {
	// ["command_call", recv, ".", methodIdent, args] — same recv/method layout
	// as a `call` node, so lowerDotCall handles it once the args are unwrapped.
	return fs.lowerDotCall(n, extractArgs(at(n, 4)))
}

// lowerMethodAddBlock lowers `call do |x| … end` / `call { … }` (Sinatra routes,
// blocks). The block body is lowered inline in the current function, so handler
// code inside the block is analyzed.
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
	return ssabuild.Reg(inst.Name)
}

func (fs *funcState) lookup(name string) *ir.Value {
	if fs.assigned[name] {
		return fs.read(name)
	}
	return ssabuild.Str(name)
}

func scalarText(n interface{}) string {
	switch v := n.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return identName(n)
}

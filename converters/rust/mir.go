package rust_converter

import (
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	ir "godzilla/pkg/ir/v1"
)

// This file lowers rustc's textual MIR (Mid-level IR) to gIR. MIR is the right
// substrate for Rust taint analysis — unlike LLVM IR it names the source-level
// public API (`std::env::var`, `Command::arg`, not the internal monomorphized
// `std::env::__var`) and assigns call results directly to locals (no `sret`
// out-pointer indirection), so a straight-line value-forwarding pass recovers
// clean SSA. See converter.go for how the MIR text is produced.
//
// The lowering flattens control flow into one block (like the Python/JS
// frontends): it walks a function's basic blocks in order and forwards each
// MIR local to its current gIR value. That is exact for the straight-line
// source→sink handler shape that matters for taint.

// lowerMIR parses the MIR dump `text` for source file `filename` into a module.
func lowerMIR(text, filename string) *ir.Module {
	mod := &ir.Module{Name: filename, Language: "rust"}
	for _, body := range splitFns(text) {
		if fn := lowerFn(body, filename); fn != nil {
			mod.Functions = append(mod.Functions, fn)
		}
	}
	return mod
}

// splitFns returns the line groups of every top-level `fn` item in a MIR dump.
// A fn item starts with a line beginning `fn ` (column 0) and runs until the
// matching closing brace at column 0. Brace counting ignores `//` comments,
// whose braces (e.g. in the `// + const_: Const { ty: fn() {...} }` annotation
// lines) would otherwise unbalance it.
func splitFns(text string) [][]string {
	var out [][]string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "fn ") {
			continue
		}
		var body []string
		depth := 0
		for ; i < len(lines); i++ {
			code, _ := splitCodeComment(lines[i])
			depth += strings.Count(code, "{") - strings.Count(code, "}")
			body = append(body, lines[i])
			if depth <= 0 && len(body) > 1 {
				break
			}
		}
		out = append(out, body)
	}
	return out
}

// lowerState carries the per-function value-forwarding environment.
type lowerState struct {
	filename string
	counter  int
	env      map[string]*ir.Value   // MIR local ("_5") -> current gIR value
	agg      map[string][]*ir.Value // MIR local -> aggregate element values (for field folding)
	instrs   []*ir.Instruction
	firstPos *ir.Position
}

var (
	localRe = regexp.MustCompile(`^_\d+$`)
	fieldRe = regexp.MustCompile(`^\(\*?_(\d+)\.(\d+):`) // (_6.0: T) or (*_6.0: T)
	indexRe = regexp.MustCompile(`^\(?\*?_(\d+)\[`)      // _3[_4] or (_3[_4])
	derefRe = regexp.MustCompile(`^\(\*_(\d+)\)`)        // (*_9)
	spanRe  = regexp.MustCompile(`at ([^ ]+\.rs):(\d+):(\d+)`)
	blockRe = regexp.MustCompile(`^\s*(bb\d+)(\s*\(cleanup\))?\s*:\s*\{`) // block header
	bbRefRe = regexp.MustCompile(`bb\d+`)                                 // a basic-block target
	retEdge = regexp.MustCompile(`return:\s*(bb\d+)`)                     // call/drop normal edge
	colonRe = regexp.MustCompile(`:{3,}`)                                 // ::: runs left by generic-stripping
	// binOps are MIR BinaryOp/UnaryOp names; matched to distinguish an operator
	// rvalue like `Add(copy _a, copy _b)` from an enum-variant constructor.
	binOps = map[string]bool{
		"Add": true, "Sub": true, "Mul": true, "Div": true, "Rem": true,
		"BitXor": true, "BitAnd": true, "BitOr": true, "Shl": true, "Shr": true,
		"Eq": true, "Lt": true, "Le": true, "Ne": true, "Ge": true, "Gt": true,
		"Cmp": true, "Offset": true,
		"AddWithOverflow": true, "SubWithOverflow": true, "MulWithOverflow": true,
		"AddUnchecked": true, "SubUnchecked": true, "MulUnchecked": true,
	}
	unOps = map[string]bool{"Neg": true, "Not": true, "PtrMetadata": true}
)

func lowerFn(body []string, filename string) *ir.Function {
	name, params := parseHeader(body[0])
	if name == "" {
		return nil
	}
	st := &lowerState{filename: filename, env: map[string]*ir.Value{}, agg: map[string][]*ir.Value{}}
	fn := &ir.Function{
		Name:          name,
		ObjectName:    name,
		CanonicalName: "rust:" + name,
	}
	// synthSources are the synthetic axum-extractor source CALLs; their position
	// is patched to the function's after the body is lowered (a header line has
	// no span, so firstPos is only known then).
	var synthSources []*ir.Instruction
	for i, p := range params {
		v := regValue(fmt.Sprintf("p%d", i))
		fn.Params = append(fn.Params, v) // preserve arity for interproc arg->param mapping
		if src, ok := axumExtractorSource(p.typ); ok {
			// An axum handler receives already-extracted, attacker-controlled data
			// as a typed parameter (Query<T>/Path<T>/Json<T>/Form<T>); synthesize a
			// source CALL whose result IS the parameter's value, so the taint engine
			// seeds it (the same trick the Java @RequestParam frontend uses). COV-7.
			reg := st.reg()
			inst := &ir.Instruction{
				Name: reg, Op: ir.OpCode_OP_CODE_CALL,
				Call: &ir.CallCommon{Callee: src, Value: &ir.Value{Kind: &ir.Value_FuncName{FuncName: src}}},
			}
			st.instrs = append(st.instrs, inst)
			synthSources = append(synthSources, inst)
			st.env[p.local] = regValue(reg)
			continue
		}
		st.env[p.local] = v
	}
	st.lowerBlocks(body[1:])
	fn.Pos = st.firstPos
	for _, s := range synthSources {
		s.Pos = fn.Pos // best-effort: attribute the source to the handler's position
	}
	fn.Blocks = []*ir.BasicBlock{{Index: 0, Instrs: st.instrs}}
	return fn
}

// mirBlock is one MIR basic block: its label, its statement/terminator lines,
// and the normal-control-flow successors parsed from its terminator (unwind /
// cleanup edges are excluded — see parseSuccs).
type mirBlock struct {
	label string
	lines []string
	succs []string
}

// lowerBlocks lowers a function body block-by-block, threading the value
// environment along the control-flow graph so a local reassigned on only some
// paths is PHI-merged at the join instead of last-write-wins overwritten (FE-5).
// The prior linear flattener dropped taint through the ubiquitous "default if
// empty" shape (`if x.is_empty() { x = "default" }`): the else-arm's constant
// reassignment clobbered the tainted binding, and the post-join sink read the
// constant. Now each join block (≥2 predecessors) emits an OP_CODE_PHI of the
// incoming values, keeping the tainted path live.
//
// Straight-line code — including the call chains that MIR splits across blocks
// via return edges — has one predecessor per block, so its env is copied
// through unchanged and lowering is identical to before. A block whose only
// predecessors are unwind/cleanup edges (not in the normal CFG) falls back to
// the textually-previous block's exit env, never doing worse than the old
// linear walk. Aggregates (st.agg) stay global (last-write-wins); merging them
// across branches is a rarer case left as-is.
func (st *lowerState) lowerBlocks(lines []string) {
	preamble, blocks := splitMIRBlocks(lines)
	for _, ln := range preamble {
		st.line(ln) // decls/debug/scope — no env effect, but keep span discovery
	}
	preds := map[string][]string{}
	for _, b := range blocks {
		for _, s := range b.succs {
			preds[s] = append(preds[s], b.label)
		}
	}
	exitEnvs := map[string]map[string]*ir.Value{}
	prevExit := st.env // linear fallback / bb0 seed (params + synthetic sources)
	for _, blk := range blocks {
		var known []string
		for _, p := range preds[blk.label] {
			if _, ok := exitEnvs[p]; ok {
				known = append(known, p)
			}
		}
		switch len(known) {
		case 0:
			st.env = maps.Clone(prevExit)
		case 1:
			st.env = maps.Clone(exitEnvs[known[0]])
		default:
			st.env = st.mergeBlockEnvs(known, exitEnvs)
		}
		for _, ln := range blk.lines {
			st.line(ln)
		}
		exitEnvs[blk.label] = st.env
		prevExit = st.env
	}
}

// splitMIRBlocks partitions a function body into the preamble (local
// declarations before the first block) and the list of basic blocks.
func splitMIRBlocks(lines []string) (preamble []string, blocks []mirBlock) {
	cur := -1
	for _, ln := range lines {
		if m := blockRe.FindStringSubmatch(ln); m != nil {
			blocks = append(blocks, mirBlock{label: m[1]})
			cur = len(blocks) - 1
			continue
		}
		if cur < 0 {
			preamble = append(preamble, ln)
			continue
		}
		blocks[cur].lines = append(blocks[cur].lines, ln)
		blocks[cur].succs = append(blocks[cur].succs, parseSuccs(ln)...)
	}
	return preamble, blocks
}

// parseSuccs extracts a terminator line's normal-control-flow successors. A call
// or drop names its edges (`-> [return: bbR, unwind: bbU]`); only the return
// edge is a normal successor (the unwind edge leads to cleanup blocks that never
// reach a sink). A `goto`/`switchInt` (`-> bbN` / `-> [0: bbA, otherwise: bbZ]`)
// has no `return:` label, so every listed block is a real successor. Non-
// terminator lines have no `->` and yield nothing.
func parseSuccs(line string) []string {
	i := strings.Index(line, "->")
	if i < 0 {
		return nil
	}
	rest := line[i+2:]
	if c := strings.Index(rest, "//"); c >= 0 {
		rest = rest[:c]
	}
	if strings.Contains(rest, "return:") {
		if m := retEdge.FindStringSubmatch(rest); m != nil {
			return []string{m[1]}
		}
		return nil
	}
	return bbRefRe.FindAllString(rest, -1)
}

// mergeBlockEnvs computes a join block's entry environment from its already-
// lowered predecessors, emitting an OP_CODE_PHI for every local that carries
// divergent values across the incoming edges (identical bindings pass through).
func (st *lowerState) mergeBlockEnvs(preds []string, exitEnvs map[string]map[string]*ir.Value) map[string]*ir.Value {
	names := map[string]bool{}
	for _, p := range preds {
		for k := range exitEnvs[p] {
			names[k] = true
		}
	}
	out := make(map[string]*ir.Value, len(names))
	for name := range names {
		var distinct []*ir.Value
		seen := map[*ir.Value]bool{}
		for _, p := range preds {
			v := exitEnvs[p][name]
			if v == nil || seen[v] {
				continue
			}
			seen[v] = true
			distinct = append(distinct, v)
		}
		switch len(distinct) {
		case 0:
			// local bound in no predecessor's exit env — leave unset
		case 1:
			out[name] = distinct[0]
		default:
			out[name] = st.emit(st.reg(), ir.OpCode_OP_CODE_PHI, distinct, nil)
		}
	}
	return out
}

// mirParam is a lowered function parameter: its MIR local and its type text.
type mirParam struct {
	local string
	typ   string
}

// parseHeader extracts a function's normalized name and its parameters (local +
// type) from a MIR header line, e.g. `fn build_cmd(_1: &str, _2: i32) -> String {`.
func parseHeader(h string) (name string, params []mirParam) {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "fn ")
	open := indexAtDepth0(h, '(')
	if open < 0 {
		return normalizeName(strings.TrimSuffix(strings.TrimSpace(h), "{")), nil
	}
	name = normalizeName(h[:open])
	closeIdx := matchParen(h, open)
	if closeIdx < 0 {
		return name, nil
	}
	for _, part := range splitTop(h[open+1:closeIdx], ',') {
		if id, typ, ok := strings.Cut(strings.TrimSpace(part), ":"); ok {
			if id = strings.TrimSpace(id); localRe.MatchString(id) {
				params = append(params, mirParam{local: id, typ: strings.TrimSpace(typ)})
			}
		}
	}
	return name, params
}

// axumExtractorSource maps an axum extractor parameter type to the canonical
// source name Godzilla synthesizes for it. axum handlers take request data as
// typed extractor parameters, so each is a taint source. Two shapes are matched:
//
//   - Generic extractors — Query<T>, Path<T>, Json<T>, Form<T> — keyed on the
//     extractor identifier immediately before the generic `<`, so both a bare
//     `Query<..>` and a fully-qualified `axum::extract::Query<..>` match.
//   - Non-generic body/query extractors — RawQuery (the raw query string) and
//     RawForm (the raw form body) — matched by their bare type name. These names
//     are axum-specific, so matching them does not risk the false positives a
//     bare `String`/`Bytes` request-body param would (those common types are
//     deliberately NOT treated as sources).
//
// Returns ok=false for any non-extractor type.
func axumExtractorSource(typ string) (string, bool) {
	typ = strings.TrimSpace(typ)
	if lt := strings.IndexByte(typ, '<'); lt >= 0 { // the extractor's own generic opener
		head := strings.TrimSpace(typ[:lt])
		if i := strings.LastIndex(head, "::"); i >= 0 {
			head = head[i+2:]
		}
		switch head {
		case "Query", "Path", "Json", "Form":
			return "rust:axum::extract::" + head, true
		}
		return "", false
	}
	// Non-generic extractor: match the bare type name (RawQuery / RawForm only).
	head := typ
	if i := strings.LastIndex(head, "::"); i >= 0 {
		head = head[i+2:]
	}
	switch head {
	case "RawQuery", "RawForm":
		return "rust:axum::extract::" + head, true
	}
	return "", false
}

func (st *lowerState) line(raw string) {
	code, comment := splitCodeComment(raw)
	code = strings.TrimSpace(code)
	if code == "" {
		return
	}
	pos := st.span(comment)

	// Terminators & non-assignment statements we flatten away or ignore.
	switch {
	case code == "return;":
		st.emit("", ir.OpCode_OP_CODE_RET, valueSlice(st.env["_0"]), pos)
		return
	case strings.HasPrefix(code, "bb"), strings.HasPrefix(code, "let "),
		strings.HasPrefix(code, "debug "), strings.HasPrefix(code, "scope "),
		strings.HasPrefix(code, "StorageLive"), strings.HasPrefix(code, "StorageDead"),
		strings.HasPrefix(code, "drop("), strings.HasPrefix(code, "goto"),
		strings.HasPrefix(code, "switchInt"), strings.HasPrefix(code, "assert"),
		strings.HasPrefix(code, "_0 = const"), code == "unreachable;",
		code == "resume;", code == "{", code == "}":
		return
	}

	code = strings.TrimSuffix(code, ";")
	// A call is a terminator of the form `_dst = callee(args) -> [return: ..]`.
	isCall := false
	if idx := strings.Index(code, " -> ["); idx >= 0 {
		code = strings.TrimSpace(code[:idx])
		isCall = true
	}

	dst, expr, ok := strings.Cut(code, " = ")
	if !ok {
		return
	}
	dst = strings.TrimSpace(dst)
	if !localRe.MatchString(dst) { // e.g. `discriminant(_x) = ..`, `(*_p) = ..`
		return
	}
	st.assign(dst, strings.TrimSpace(expr), pos, isCall)
}

// assign lowers a single MIR assignment `_dst = <rvalue>` (or a call
// terminator) into gIR, updating the value-forwarding environment.
func (st *lowerState) assign(dst, expr string, pos *ir.Position, isCall bool) {
	// rustc 1.97+ prefixes some Use rvalues with a `no_retag` qualifier (a
	// Tree-Borrows retag annotation, e.g. `_10 = no_retag copy (_4.0: T)`). It
	// carries no dataflow meaning; strip it so the operand parses exactly as on
	// older rustc — without this, the case below misses and taint silently drops
	// (notably through format!, which lowers its args via such a copy).
	expr = strings.TrimPrefix(expr, "no_retag ")
	if isCall {
		st.emitCall(dst, expr, pos)
		return
	}
	switch {
	case strings.HasPrefix(expr, "&"): // reference rvalue: & / &mut / &raw <place>
		st.env[dst] = st.place(refPlace(expr), pos)
	case fieldRe.MatchString(expr), derefRe.MatchString(expr), indexRe.MatchString(expr):
		st.env[dst] = st.place(expr, pos)
	case strings.HasPrefix(expr, "("): // tuple aggregate: (a, b,) — unit () is empty
		st.setAgg(dst, splitTop(insideDelims(expr, '(', ')'), ','), "builtin.aggregate", pos)
	case strings.HasPrefix(expr, "["): // array aggregate: [a, b] or [a; N]
		body := insideDelims(expr, '[', ']')
		if semi := indexAtDepth0(body, ';'); semi >= 0 {
			body = body[:semi]
		}
		st.setAgg(dst, splitTop(body, ','), "builtin.aggregate", pos)
	case strings.HasPrefix(expr, "move "), strings.HasPrefix(expr, "copy "), localRe.MatchString(expr):
		st.env[dst] = st.place(placeOf(expr), pos)
	case strings.HasPrefix(expr, "const "):
		st.env[dst] = constFromLiteral(strings.TrimPrefix(expr, "const "))
	default:
		st.assignOperator(dst, expr, pos)
	}
}

// assignOperator handles the remaining rvalue forms: binary/unary operators,
// casts, and constructor-shaped rvalues (`Name(args)` / `Name { .. }`), which
// are modeled as aggregates so taint flows through any operand.
func (st *lowerState) assignOperator(dst, expr string, pos *ir.Position) {
	if op, argStr, ok := callShape(expr); ok {
		args := splitTop(argStr, ',')
		switch {
		case binOps[op]:
			st.env[dst] = st.emit(st.reg(), ir.OpCode_OP_CODE_BIN_OP, st.operands(args), pos)
			return
		case unOps[op]:
			st.env[dst] = st.emit(st.reg(), ir.OpCode_OP_CODE_UN_OP, st.operands(args), pos)
			return
		case op == "Len" || op == "discriminant" || op == "NullaryOp":
			st.env[dst] = constString("")
			return
		default: // enum-variant / tuple-struct constructor: taint if any field is
			st.setAgg(dst, args, "builtin.aggregate", pos)
			return
		}
	}
	if before, ok := cutCast(expr); ok { // `<operand> as T (Kind)`
		st.env[dst] = st.emit(st.reg(), ir.OpCode_OP_CODE_CONVERT, st.operands([]string{before}), pos)
		return
	}
	if brace := strings.IndexByte(expr, '{'); brace >= 0 { // struct literal Name { f: op, .. }
		st.setAgg(dst, structFields(expr[brace:]), "builtin.aggregate", pos)
		return
	}
	st.env[dst] = constString("")
}

// emitCall lowers a MIR call terminator. Method and free-function calls alike
// become OP_CODE_CALL with every operand (receiver first, for a method) in Args,
// so a sink's `#idx` injection point counts from operand 0 — the convention the
// Rust rule pack is written against.
func (st *lowerState) emitCall(dst, expr string, pos *ir.Position) {
	callee, argStr, ok := callShape(expr)
	name := st.reg()
	if !ok { // indirect call through a fn-pointer local: `(move _f)(args)`
		st.env[dst] = regValue(name)
		st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: &ir.CallCommon{}, Pos: pos})
		return
	}
	norm := normalizeName(callee)
	// `String + &str` overloads Add::add, which rustc lowers to a CALL rather than
	// the native numeric-add rvalue. It is a string concatenation, so model it as
	// the universal BIN_OP_ADD the engine already interprets for `+` in every
	// language (taint propagation and SSRF fixed-host prefix reconstruction), so
	// the engine needs no Rust-callee special case.
	if norm == "add" {
		operands := st.operands(splitTop(argStr, ','))
		st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD, Operands: operands, Pos: pos})
		st.env[dst] = regValue(name)
		return
	}
	canonical := "rust:" + norm
	cc := &ir.CallCommon{
		Callee: canonical,
		Args:   st.operands(splitTop(argStr, ',')),
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}},
	}
	inst := &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: cc, Pos: pos}
	// Tag two shapes with a language-neutral marker so the engine's SSRF host
	// reconstruction reads the marker, not a Rust callee-name shape (both markers
	// are inert to taint propagation — only OP_CODE_INTRINSIC consults the
	// intrinsic-propagator table — so taint still flows via the existing rules):
	//   - format!  -> fmt::Arguments::new(<decoded template>, args): builtin.format
	//   - identity string conversions that forward their operand's text unchanged
	//     (to_string/as_str/into/clone/deref/format-result wrappers): builtin.identity
	switch {
	case strings.Contains(canonical, "Arguments::new"):
		inst.Intrinsic = "builtin.format"
	case rustIdentityConv(canonical):
		inst.Intrinsic = "builtin.identity"
	}
	st.instrs = append(st.instrs, inst)
	st.env[dst] = regValue(name)
}

// rustIdentityConv reports whether a Rust callee is a string-valued conversion
// that forwards its operand's text unchanged, so the SSRF prefix reconstruction
// can look one hop deeper. Covers the `format!` result wrappers (format ->
// must_use -> deref) and the common owned/borrowed conversions. The suffix set
// mirrors the engine's former isPassthroughCallee so behavior is unchanged.
func rustIdentityConv(callee string) bool {
	for _, suffix := range []string{
		"to_string", "to_owned", "as_str", "as_ref", "into", "clone", "deref",
		"String::from", "borrow", "must_use", "format",
	} {
		if strings.HasSuffix(callee, suffix) {
			return true
		}
	}
	return false
}

// setAgg records an aggregate construction: it both emits a builtin.aggregate
// intrinsic (so a whole-aggregate use propagates taint from any element) and
// remembers the element values so a later field read `(_dst.i)` folds directly
// to element i (precise field-sensitive flow through tuples/arrays/structs).
func (st *lowerState) setAgg(dst string, operandToks []string, intrinsic string, pos *ir.Position) {
	vals := st.operands(operandToks)
	name := st.reg()
	st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_INTRINSIC, Intrinsic: intrinsic, Operands: vals, Pos: pos})
	st.env[dst] = regValue(name)
	st.agg[dst] = vals
}

// place resolves a MIR place expression to a gIR value, folding tuple/array
// field reads to the stored element when the aggregate is known.
func (st *lowerState) place(p string, pos *ir.Position) *ir.Value {
	p = strings.TrimSpace(p)
	if m := fieldRe.FindStringSubmatch(p); m != nil {
		base, field := "_"+m[1], atoi(m[2])
		if elts, ok := st.agg[base]; ok && field < len(elts) {
			return elts[field]
		}
		return st.emit(st.reg(), ir.OpCode_OP_CODE_FIELD, valueSlice(st.local(base)), pos)
	}
	if m := derefRe.FindStringSubmatch(p); m != nil {
		return st.local("_" + m[1]) // deref forwards the referent's taint
	}
	if m := indexRe.FindStringSubmatch(p); m != nil {
		return st.emit(st.reg(), ir.OpCode_OP_CODE_INDEX, valueSlice(st.local("_"+m[1])), pos)
	}
	if localRe.MatchString(p) {
		return st.local(p)
	}
	return constString("")
}

// local returns the current gIR value bound to a MIR local, or an untainted
// placeholder for one not yet seen (e.g. defined in an unvisited block).
func (st *lowerState) local(name string) *ir.Value {
	if v, ok := st.env[name]; ok {
		return v
	}
	return constString("")
}

func (st *lowerState) operands(toks []string) []*ir.Value {
	out := make([]*ir.Value, 0, len(toks))
	for _, t := range toks {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		out = append(out, st.operand(t))
	}
	return out
}

// operand resolves a single MIR operand token (`move _x` / `copy _x` /
// `const ..` / `_x`) to a gIR value.
func (st *lowerState) operand(tok string) *ir.Value {
	tok = strings.TrimSpace(tok)
	if strings.HasPrefix(tok, "const ") {
		return constFromLiteral(strings.TrimPrefix(tok, "const "))
	}
	return st.place(placeOf(tok), nil)
}

func (st *lowerState) emit(name string, op ir.OpCode, operands []*ir.Value, pos *ir.Position) *ir.Value {
	st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: op, Operands: operands, Pos: pos})
	if name == "" {
		return nil
	}
	return regValue(name)
}

func (st *lowerState) reg() string {
	st.counter++
	return fmt.Sprintf("%%%d", st.counter)
}

func (st *lowerState) span(comment string) *ir.Position {
	m := spanRe.FindStringSubmatch(comment)
	if m == nil {
		return nil
	}
	// Prefer the file the MIR span names (correct per-instruction for a
	// multi-file Cargo crate); fall back to the frontend's filename.
	file := m[1]
	if file == "" {
		file = st.filename
	}
	pos := &ir.Position{Filename: file, Line: int32(atoi(m[2])), Column: int32(atoi(m[3]))}
	if st.firstPos == nil {
		st.firstPos = pos
	}
	return pos
}

// --- text helpers ---

// splitCodeComment splits a MIR line into its code and trailing `//` comment,
// honoring double-quoted string/byte-string literals so a `//` inside a literal
// is not mistaken for a comment.
func splitCodeComment(line string) (code, comment string) {
	inStr := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' && (i == 0 || line[i-1] != '\\') {
			inStr = !inStr
		}
		if !inStr && c == '/' && i+1 < len(line) && line[i+1] == '/' {
			return line[:i], line[i+2:]
		}
	}
	return line, ""
}

// normalizeName strips generic/type/lifetime groups (`<...>`, including
// turbofish `::<...>`) from a MIR path and collapses the resulting `::` runs,
// e.g. `Result::<String, VarError>::unwrap` → `Result::unwrap`,
// `Command::arg::<&str>` → `Command::arg`.
func normalizeName(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	out := colonRe.ReplaceAllString(b.String(), "::")
	return strings.Trim(strings.TrimSpace(out), ":")
}

// callShape splits `callee(args)` into the callee text and the raw argument
// string, where the arg list opens at the first `(` outside any `<...>` group
// (so a generic like `arg::<&str>(..)` is handled). It reports ok=false when
// there is no callee before the parens (a tuple/indirect form).
func callShape(expr string) (callee, args string, ok bool) {
	open := indexAtDepth0(expr, '(')
	if open <= 0 {
		return "", "", false
	}
	closeIdx := matchParen(expr, open)
	if closeIdx < 0 {
		return "", "", false
	}
	callee = strings.TrimSpace(expr[:open])
	// An indirect call through a fn value prints the callee as an operand
	// (`move _f(..)`, `copy _f(..)`, `(_f)(..)`) or a bare local; a direct call
	// names a path, which may carry generics with spaces (`Result::<A, B>::x`).
	if strings.HasPrefix(callee, "move ") || strings.HasPrefix(callee, "copy ") ||
		strings.HasPrefix(callee, "(") || localRe.MatchString(callee) {
		return "", "", false
	}
	return callee, expr[open+1 : closeIdx], true
}

// placeOf strips a leading move/copy qualifier from an operand, yielding the
// bare place.
func placeOf(tok string) string {
	tok = strings.TrimSpace(tok)
	tok = strings.TrimPrefix(tok, "no_retag ") // rustc 1.97+ retag qualifier (see assign)
	tok = strings.TrimPrefix(tok, "move ")
	tok = strings.TrimPrefix(tok, "copy ")
	return strings.TrimSpace(tok)
}

// refPlace strips a reference rvalue's borrow prefix to the borrowed place:
// `&_1`, `&mut _1`, `&raw const _1`, `&raw mut _1` → `_1`.
func refPlace(expr string) string {
	p := strings.TrimPrefix(expr, "&")
	p = strings.TrimPrefix(p, "raw ")
	p = strings.TrimPrefix(p, "mut ")
	p = strings.TrimPrefix(p, "const ")
	return strings.TrimSpace(p)
}

// cutCast returns the operand of a MIR cast rvalue `<operand> as <type> (<kind>)`,
// dropping the type and parenthesized cast-kind suffix.
func cutCast(expr string) (before string, ok bool) {
	i := strings.LastIndex(expr, " as ")
	if i < 0 {
		return "", false
	}
	return strings.TrimSpace(expr[:i]), true
}

// structFields extracts the field operand tokens from a struct-literal tail
// `{ f0: op0, f1: op1 }`, returning [op0, op1].
func structFields(brace string) []string {
	inner := insideDelims(brace, '{', '}')
	var out []string
	for _, f := range splitTop(inner, ',') {
		if _, v, ok := strings.Cut(f, ":"); ok {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// insideDelims returns the content between the first `open` and its matching
// `close`, respecting nesting of ()/[]/<>/{} and quotes.
func insideDelims(s string, open, close byte) string {
	i := strings.IndexByte(s, open)
	if i < 0 {
		return ""
	}
	j := matchDelim(s, i, open, close)
	if j < 0 {
		return ""
	}
	return s[i+1 : j]
}

// splitTop splits s on the separator byte at bracket/quote depth 0.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, start, inStr := 0, 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inStr = !inStr
		case inStr:
		case c == '(' || c == '[' || c == '<' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '>' || c == '}':
			if depth > 0 {
				depth--
			}
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}

// indexAtDepth0 finds the first `target` byte outside any <...> group and
// outside string literals (used to locate a call's arg-list `(`).
func indexAtDepth0(s string, target byte) int {
	angle, inStr := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inStr = !inStr
		case inStr:
		case c == '<':
			angle++
		case c == '>':
			if angle > 0 {
				angle--
			}
		case c == target && angle == 0:
			return i
		}
	}
	return -1
}

func matchParen(s string, open int) int { return matchDelim(s, open, '(', ')') }

// matchDelim returns the index of the delimiter matching the opener at index
// `open`, honoring nesting and string literals.
func matchDelim(s string, open int, oc, cc byte) int {
	depth, inStr := 0, false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inStr = !inStr
		case inStr:
		case c == oc:
			depth++
		case c == cc:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func valueSlice(v *ir.Value) []*ir.Value {
	if v == nil {
		return nil
	}
	return []*ir.Value{v}
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

func regValue(name string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_RegName{RegName: name}}
}

func constString(v string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: v}}}}
}

// constFromLiteral models a MIR constant. String literals are preserved (so the
// secrets scanner can see them and taint stays constant-free); every other
// constant becomes an empty string constant — untainted, which is correct since
// compile-time constants are never attacker-controlled.
func constFromLiteral(lit string) *ir.Value {
	lit = strings.TrimSpace(lit)
	if strings.HasPrefix(lit, `"`) {
		if end := strings.LastIndexByte(lit, '"'); end > 0 {
			return constString(lit[1:end])
		}
	}
	// A byte-string literal `b"..."` is how MIR renders the packed template that
	// `format!` hands to fmt::Arguments::new (assigned to a temp, then passed in).
	// Decode a well-formed template into a readable `{}`-placeholder string so the
	// SSRF URL-host reconstruction can see its constant pieces; anything that is
	// not a clean template stays an empty constant (unchanged behavior).
	if strings.HasPrefix(lit, `b"`) {
		if tmpl, ok := decodeFmtTemplate(lit); ok {
			return constString(tmpl)
		}
	}
	return constString("")
}

// decodeFmtTemplate decodes the packed byte-string template that `format!` passes
// to `fmt::Arguments::new` into a readable format string with `{}` at each
// argument position. The template (rustc's `fmt::rt` encoding) is a sequence of
// tokens: the byte 0xC0 marks an argument insertion, and a byte < 0x80 is the
// length of a literal run that immediately follows. tok is the raw MIR operand,
// e.g. `const b"\x14https://h/v1/\xc0\x00"`. Returns ok=false for anything that
// is not a well-formed, UTF-8-clean byte-string template (the caller then leaves
// the original empty constant, so a decode miss can never invent a fixed host).
func decodeFmtTemplate(tok string) (string, bool) {
	tok = strings.TrimSpace(tok)
	tok = strings.TrimSpace(strings.TrimPrefix(tok, "const "))
	if !strings.HasPrefix(tok, `b"`) {
		return "", false
	}
	end := strings.LastIndexByte(tok, '"')
	if end <= 1 {
		return "", false
	}
	raw, ok := decodeByteString(tok[2:end])
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < len(raw); {
		b := raw[i]
		i++
		switch {
		case b == 0xC0: // argument insertion
			sb.WriteString("{}")
		case int(b) < 0x80: // literal run of length b
			if i+int(b) > len(raw) {
				return "", false
			}
			sb.Write(raw[i : i+int(b)])
			i += int(b)
		default: // unrecognized control byte (e.g. an explicit-index/spec arg)
			return "", false
		}
	}
	if !utf8.ValidString(sb.String()) {
		return "", false
	}
	return sb.String(), true
}

// decodeByteString decodes the escapes rustc uses when printing a byte-string
// literal's contents (the bytes between `b"` and the closing quote): `\xHH` for
// arbitrary bytes plus the usual `\n`/`\t`/`\r`/`\0`/`\\`/`\"`/`\'`.
func decodeByteString(s string) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, false
		}
		switch s[i+1] {
		case 'x':
			if i+3 >= len(s) {
				return nil, false
			}
			v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
			if err != nil {
				return nil, false
			}
			out = append(out, byte(v))
			i += 4
		case 'n':
			out = append(out, '\n')
			i += 2
		case 't':
			out = append(out, '\t')
			i += 2
		case 'r':
			out = append(out, '\r')
			i += 2
		case '0':
			out = append(out, 0)
			i += 2
		case '\\', '"', '\'':
			out = append(out, s[i+1])
			i += 2
		default:
			return nil, false
		}
	}
	return out, true
}

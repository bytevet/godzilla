package rust_converter

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bytevet/godzilla/converters/ssabuild"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// This file lowers rustc's textual MIR (Mid-level IR) to gIR. MIR is the right
// substrate for Rust taint analysis — unlike LLVM IR it names the source-level
// public API (`std::env::var`, `Command::arg`, not the internal monomorphized
// `std::env::__var`) and assigns call results directly to locals (no `sret`
// out-pointer indirection), so a straight-line value-forwarding pass recovers
// clean SSA. See converter.go for how the MIR text is produced.
//
// The emitted gIR is ONE block (unlike the Python/JS/Ruby frontends, which build
// a real CFG): MIR's blocks are walked in order, forwarding each MIR local to its
// current gIR value, with explicit PHIs at joins (see lowerBlocks). That is exact
// for the straight-line source→sink handler shape that matters for taint.

// lowerMIR parses the MIR dump `text` for source file `filename` into a module.
// `root` is the tree being scanned; spans outside it are rustc's own and are not
// reported (see lowerState.span). An empty root disables that filter.
func lowerMIR(text, filename, root string) *ir.Module {
	mod := &ir.Module{Name: filename, Language: "rust"}
	if abs, err := filepath.Abs(root); root != "" && err == nil {
		root = abs
	}
	// Promoted consts (the format! literal-pieces arrays an older rustc emits;
	// see promotedPieces) are separate top-level MIR items, not inside any `fn`
	// body, so they are collected once over the whole dump and threaded into
	// every function that references one.
	promoted := promotedPieces(text)
	for _, body := range splitFns(text) {
		if fn := lowerFn(body, filename, root, promoted); fn != nil {
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

type lowerState struct {
	filename string
	root     string // absolute scan root; a span outside it is rustc's own
	counter  int
	env      map[string]*ir.Value   // MIR local ("_5") -> current gIR value
	agg      map[string][]*ir.Value // MIR local -> aggregate element values (for field folding)
	intr     map[string]string      // gIR reg name -> builtin.* marker its defining call carries
	instrs   []*ir.Instruction
	firstPos *ir.Position
	lastPos  *ir.Position // last span accepted as user code

	// promoted is this module's promoted-const literal-piece arrays (see
	// promotedPieces), keyed by the path a `const` operand names it with (e.g.
	// "f::promoted[0]"). piecesByLocal is the per-function projection of that:
	// which MIR local currently holds which promoted const's pieces, recorded
	// when `assign` lowers `_N = const <path>;` — see reconstructFormatTemplate.
	promoted      map[string][]string
	piecesByLocal map[string][]string
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

func lowerFn(body []string, filename, root string, promoted map[string][]string) *ir.Function {
	name, params := parseHeader(body[0])
	if name == "" {
		return nil
	}
	st := &lowerState{
		filename: filename, root: root,
		env: map[string]*ir.Value{}, agg: map[string][]*ir.Value{}, intr: map[string]string{},
		promoted: promoted, piecesByLocal: map[string][]string{},
	}
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
		v := ssabuild.Reg(fmt.Sprintf("p%d", i))
		fn.Params = append(fn.Params, v) // preserve arity for interproc arg->param mapping
		if src, ok := axumExtractorSource(p.typ); ok {
			// An axum handler receives already-extracted, attacker-controlled data
			// as a typed parameter; synthesize a source CALL whose result IS the
			// parameter's value, so the taint engine seeds it (COV-7).
			reg := st.reg()
			inst := &ir.Instruction{
				Name: reg, Op: ir.OpCode_OP_CODE_CALL,
				Call: &ir.CallCommon{Callee: src, Value: &ir.Value{Kind: &ir.Value_FuncName{FuncName: src}}},
			}
			st.instrs = append(st.instrs, inst)
			synthSources = append(synthSources, inst)
			st.env[p.local] = ssabuild.Reg(reg)
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
// paths is PHI-merged at the join (≥2 predecessors) rather than overwritten
// last-write-wins (FE-5). Without the merge the ubiquitous "default if empty"
// shape (`if x.is_empty() { x = "default" }`) drops taint: the else-arm's
// constant clobbers the tainted binding and the post-join sink reads the constant.
//
// Straight-line code — including the call chains MIR splits across blocks via
// return edges — has one predecessor per block, so its env is copied through
// unchanged. A block whose only predecessors are unwind/cleanup edges (not in the
// normal CFG) falls back to the textually-previous block's exit env. Aggregates
// (st.agg) stay global (last-write-wins); merging them across branches is a rarer
// case left as-is.
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
//   - Non-generic body/query extractors — RawQuery and RawForm — matched by bare
//     type name. Those names are axum-specific; a bare `String`/`Bytes`
//     request-body param is deliberately NOT a source, being far too common.
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
	// Tree-Borrows annotation, e.g. `_10 = no_retag copy (_4.0: T)`). It carries no
	// dataflow meaning, and leaving it on makes every case below miss, silently
	// dropping taint — notably through format!, whose args lower via such a copy.
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
		if before, ok := cutCast(expr); ok {
			// `copy X as T (Kind)` / `move X as T (Kind)`: an operand-PREFIXED
			// cast (e.g. the unsizing coercion `copy _8 as &[&str] (PointerCoercion
			// (Unsize, Implicit))` new_v1_formatted's slice params go through),
			// not a bare place. Caught here, ahead of the plain st.place below,
			// because it also starts with "copy "/"move " — left to st.place it
			// hits the "not a recognized place" fallback (an untainted empty
			// constant), silently dropping any taint flowing through the cast.
			st.env[dst] = st.emit(st.reg(), ir.OpCode_OP_CODE_CONVERT, st.operands([]string{before}), pos)
			if pcs, ok := st.piecesByLocal[placeOf(before)]; ok {
				st.piecesByLocal[dst] = pcs
			}
			return
		}
		st.env[dst] = st.place(placeOf(expr), pos)
	case strings.HasPrefix(expr, "const "):
		lit := strings.TrimPrefix(expr, "const ")
		st.env[dst] = constFromLiteral(lit)
		// A promoted const's operand is a bare path (`f::promoted[0]`), never a
		// quoted literal, so it always falls through constFromLiteral to an empty
		// placeholder above; this side channel is what lets emitCall recover its
		// actual literal pieces for the ONE place that needs them (see
		// reconstructFormatTemplate). Everywhere else the empty/untainted value
		// above is correct as-is: a promoted const is compile-time data.
		if pcs, ok := st.promoted[strings.TrimSpace(lit)]; ok {
			st.piecesByLocal[dst] = pcs
		}
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
			st.env[dst] = ssabuild.Str("")
			return
		default: // enum-variant / tuple-struct constructor: taint if any field is
			st.setAgg(dst, args, "builtin.aggregate", pos)
			return
		}
	}
	if before, ok := cutCast(expr); ok { // `<operand> as T (Kind)`
		st.env[dst] = st.emit(st.reg(), ir.OpCode_OP_CODE_CONVERT, st.operands([]string{before}), pos)
		// An unsizing coercion (`&[T; N] as &[T]`) is exactly how MIR hands
		// new_v1_formatted's pieces array to its slice-typed parameter (its
		// signature takes unsized slices, unlike new_v1/new_const's fixed-size
		// array params, which is why only this shape needs the cast at all), so
		// the promoted-pieces side channel populated by the "const " case above
		// must survive this hop too, or reconstructFormatTemplate never sees it.
		if pcs, ok := st.piecesByLocal[placeOf(before)]; ok {
			st.piecesByLocal[dst] = pcs
		}
		return
	}
	if brace := strings.IndexByte(expr, '{'); brace >= 0 { // struct literal Name { f: op, .. }
		st.setAgg(dst, structFields(expr[brace:]), "builtin.aggregate", pos)
		return
	}
	// Unmodelled rvalue. It must NOT become a constant: a constant is clean data,
	// so taint dies here and the result reads as a legitimately safe value —
	// silence that costs findings. The intrinsic is what the coverage check sees.
	name := st.reg()
	st.instrs = append(st.instrs, &ir.Instruction{
		Name: name, Op: ir.OpCode_OP_CODE_INTRINSIC,
		Intrinsic: "rust.unsupported", Comment: expr, Pos: pos,
	})
	st.env[dst] = ssabuild.Reg(name)
}

// emitCall lowers a MIR call terminator. Method and free-function calls alike
// become OP_CODE_CALL with every operand (receiver first, for a method) in Args,
// so a sink's `#idx` injection point counts from operand 0 — the convention the
// Rust rule pack is written against.
func (st *lowerState) emitCall(dst, expr string, pos *ir.Position) {
	callee, argStr, ok := callShape(expr)
	name := st.reg()
	if !ok { // indirect call through a fn-pointer local: `(move _f)(args)`
		st.env[dst] = ssabuild.Reg(name)
		st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: &ir.CallCommon{}, Pos: pos})
		return
	}
	norm := normalizeName(callee)
	// `String + &str` overloads Add::add, which rustc lowers to a CALL rather than
	// the native numeric-add rvalue. Modeling it as the universal BIN_OP_ADD the
	// engine already interprets for `+` in every language (taint propagation, SSRF
	// prefix reconstruction) is what keeps Rust out of the engine as a special case.
	if norm == "add" {
		operands := st.operands(splitTop(argStr, ','))
		st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_BIN_OP, BinOp: ir.BinOpKind_BIN_OP_ADD, Operands: operands, Pos: pos})
		st.env[dst] = ssabuild.Reg(name)
		return
	}
	canonical := "rust:" + norm
	argToks := splitTop(argStr, ',')
	cc := &ir.CallCommon{
		Callee: canonical,
		Args:   st.operands(argToks),
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: canonical}},
	}
	inst := &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_CALL, Call: cc, Pos: pos}
	// Tag two shapes with a language-neutral marker so the engine's SSRF host
	// reconstruction reads the marker, not a Rust callee-name shape (both are inert
	// to taint propagation — only OP_CODE_INTRINSIC consults the
	// intrinsic-propagator table):
	//   - format! -> fmt::Arguments::new(<decoded template>, args): builtin.format
	//   - identity string conversions that forward their operand's text unchanged:
	//     builtin.identity
	// Both matches are anchored to the std paths and MIR's trait-qualified call form
	// — never a name suffix, which a user function merely named like a conversion
	// (my_into, W::clone) would trip, wrongly proving a fixed host and suppressing a
	// real SSRF finding.
	switch {
	case rustFormatArgsNew(callee):
		inst.Intrinsic = "builtin.format"
		// The inherent-impl `new_v1`/`new_const`/`new_v1_formatted` shapes (unlike
		// `Arguments::new`) never hand the template inline: fix Args[0] up from
		// the promoted-const pieces recovered above. ok=false (a shape none of
		// these recognize) leaves Args[0] as whatever st.operands already
		// resolved it to — unchanged, still safe.
		if tmpl, ok := st.reconstructFormatTemplate(callee, argToks); ok && len(cc.Args) > 0 {
			cc.Args[0] = ssabuild.Str(tmpl)
		}
	case rustIdentityConv(callee, norm) || st.forwardsFormatResult(norm, cc.Args):
		inst.Intrinsic = "builtin.identity"
	}
	if inst.Intrinsic != "" {
		st.intr[name] = inst.Intrinsic
	}
	st.instrs = append(st.instrs, inst)
	st.env[dst] = ssabuild.Reg(name)
	// A Command builder step returns its receiver, so bind the result to the
	// RECEIVER's value: arg[0] then resolves to Command::new's result at every
	// step, which is what lets a rule see the program at the `.arg` sink where
	// the taint lands. Aliasing here keeps builtin.identity meaning only "this
	// value's text is Args[0]'s text" — ssrf.go reads that marker too.
	if rustCommandStep(norm) && len(cc.Args) > 0 {
		st.env[dst] = cc.Args[0]
	}
}

// rustCommandStepCallees are the exact normalized callees (generics stripped by
// normalizeName, no `rust:` prefix) of the std::process::Command builder steps
// that return their receiver: every step method crossed with the std path forms
// MIR prints. The list must cover every step the API offers — the program is
// forwarded by aliasing, so one unlisted step breaks the chain and the program
// stops resolving at every step after it.
var rustCommandStepCallees = func() map[string]bool {
	steps := []string{
		"arg", "args", "arg0",
		"env", "envs", "env_remove", "env_clear",
		"current_dir", "stdin", "stdout", "stderr",
	}
	m := make(map[string]bool, 3*len(steps))
	for _, s := range steps {
		for _, prefix := range []string{"Command::", "process::Command::", "std::process::Command::"} {
			m[prefix+s] = true
		}
	}
	return m
}()

// rustCommandStep reports whether a normalized callee is a std::process::Command
// builder step that returns its receiver. Matching is by EXACT name anchored to
// the std path forms — never a name suffix, which a USER type merely named like
// Command (`MyCommand::arg`) would trip, wrongly aliasing the call's result to
// its receiver and dropping whatever taint the real return value carries.
func rustCommandStep(norm string) bool { return rustCommandStepCallees[norm] }

// rustFormatArgsNew reports whether a RAW MIR callee (generics still present)
// is the fmt::Arguments constructor family `format!` lowers to. Current stable
// rustc prints `Arguments::<'_>::new::<15, 1>`; an older rustc (observed:
// 1.90.0) prints the inherent-impl form `rt::<impl Arguments<'_>>::new_v1::<1,
// 1>` (args) / `rt::<impl Arguments<'_>>::new_const::<1>` (literal-only,
// `format!("...")` with no `{}`). The raw text is matched — not the normalized
// name — because in both shapes the `::<'_>` lifetime instantiation
// (respectively inside an `<impl Arguments<'_>>` block) is exactly what a
// plain user type named `Arguments` (printed `Arguments::new`, no lifetime
// group) cannot produce.
func rustFormatArgsNew(raw string) bool {
	for _, p := range []string{"core::fmt::", "std::fmt::", "fmt::"} {
		raw = strings.TrimPrefix(raw, p) // at most one applies
	}
	return strings.HasPrefix(raw, "Arguments::<'_>::new") ||
		strings.HasPrefix(raw, "rt::<impl Arguments<'_>>::new")
}

// newV1GenericsRe / newConstGenericRe read the piece and argument counts
// straight off the inherent-impl format! constructor's OWN const generics —
// `new_v1::<P, A>` or `new_const::<P>` (no `A`: it is the no-dynamic-argument
// form). Both counts are compiler output, not inferred, which is what makes
// reconstructFormatTemplate exact rather than a heuristic.
var (
	newV1GenericsRe   = regexp.MustCompile(`new_v1::<(\d+),\s*(\d+)>`)
	newConstGenericRe = regexp.MustCompile(`new_const::<(\d+)>`)
)

// formatArgsGenerics reports the (pieceCount, argCount) a RAW `new_v1`/
// `new_const` callee's const generics declare. ok=false for anything else —
// in particular `new_v1_formatted` (the width/precision-spec-bearing form,
// e.g. any placeholder like `{:>10}`), which carries no such generics; that
// shape is reconstructed separately, conservatively, in
// reconstructFormatTemplate.
func formatArgsGenerics(raw string) (pieces, args int, ok bool) {
	if m := newV1GenericsRe.FindStringSubmatch(raw); m != nil {
		return atoi(m[1]), atoi(m[2]), true
	}
	if m := newConstGenericRe.FindStringSubmatch(raw); m != nil {
		return atoi(m[1]), 0, true
	}
	return 0, 0, false
}

// isNewV1Formatted reports whether a RAW MIR callee is the format-spec-bearing
// inherent-impl constructor: `format!` lowers to this instead of `new_v1` the
// moment ANY placeholder carries a width/precision/fill spec (`{:>10}`).
// Unlike new_v1/new_const it takes no const generics, so its argument count is
// not compiler-supplied — see reconstructFormatTemplate for how that is
// handled without inferring one.
func isNewV1Formatted(raw string) bool {
	for _, p := range []string{"core::fmt::", "std::fmt::", "fmt::"} {
		raw = strings.TrimPrefix(raw, p) // at most one applies
	}
	return strings.HasPrefix(raw, "rt::<impl Arguments<'_>>::new_v1_formatted")
}

// reconstructFormatTemplate rebuilds format!'s "{}"-placeholder template for
// the inherent-impl lowering, whose first argument is a REFERENCE to a
// promoted const holding the literal pieces array rather than the inline
// byte-string constant decodeFmtTemplate expects (see the assign() hook that
// fills piecesByLocal). ok=false leaves the caller's Args[0] exactly as
// st.operands already resolved it — the existing, safe (empty/untainted)
// behavior — for any shape this does not recognize.
//
// new_v1/new_const carry their own piece/argument counts as const generics
// (read by formatArgsGenerics), so the reconstruction there is exact: rustc
// omits a WOULD-BE-EMPTY TRAILING piece from the array (observed across every
// literal-only, "prefix{}", "{}suffix", "{}" and multi-arg shape), so with P
// pieces and A arguments, P is always A or A+1 — the P<=A case (equivalently
// P==A, since P>=A always holds) is exactly that omission, and one more "{}"
// is appended after the interleave to account for it.
//
// new_v1_formatted has no such generics, so its argument count cannot be read
// off the callee at all. hostFixed() only needs the constant PREFIX, though,
// not an exact template, so the pieces are joined and ONE trailing "{}" is
// appended UNCONDITIONALLY — deliberately conservative: an extra placeholder
// that may not exist can only make the template look like it has MORE dynamic
// tail content than it really does, never less, while pieces[0] — the run
// that actually proves a fixed host — is reproduced exactly either way.
// Omitting the trailing "{}" instead would risk a genuinely dynamic tail
// (whatever the spec-bearing argument itself contributes) reading as
// constant, which is the unsafe direction.
func (st *lowerState) reconstructFormatTemplate(callee string, argToks []string) (string, bool) {
	if len(argToks) == 0 {
		return "", false
	}
	pieces, havePieces := st.piecesByLocal[placeOf(argToks[0])]
	if p, a, ok := formatArgsGenerics(callee); ok {
		if !havePieces || len(pieces) != p {
			return "", false
		}
		if len(pieces) == 0 { // format!("") — the const-generic pair is <0, 0>
			return "", true
		}
		var sb strings.Builder
		sb.WriteString(pieces[0])
		for _, s := range pieces[1:] {
			sb.WriteString("{}")
			sb.WriteString(s)
		}
		if p <= a {
			sb.WriteString("{}")
		}
		return sb.String(), true
	}
	if isNewV1Formatted(callee) {
		if !havePieces {
			return "", false
		}
		var sb strings.Builder
		for i, s := range pieces {
			if i > 0 {
				sb.WriteString("{}")
			}
			sb.WriteString(s)
		}
		sb.WriteString("{}") // unconditional: see doc comment above
		return sb.String(), true
	}
	return "", false
}

// promotedPieces scans a whole MIR dump for `format!`'s promoted-const literal
// pieces arrays — a top-level item (not inside any `fn` body) of the shape
// `const <path>: &[&str; N] = { .. _R = [const "a", const "b", ..]; .. }` —
// and returns path ("f::promoted[0]") -> ordered literal pieces.
//
// Only that exact single-array-literal shape is recognized; anything else
// inside the block (e.g. case f's `&[core::fmt::rt::Placeholder; N]` spec
// array, whose elements are `move`s, not `const` string literals) yields no
// entry for that path, which is the same "no template available" outcome as
// not calling this function at all — a promoted const is always compile-time
// data, so there is no taint-correctness reason to fail loudly here the way
// the instruction-coverage check requires for a live function body.
func promotedPieces(text string) map[string][]string {
	out := map[string][]string{}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "const ") {
			continue
		}
		rest := strings.TrimPrefix(lines[i], "const ")
		// Cut on ": " (colon-SPACE), not a bare ":": the path itself contains
		// "::" (e.g. "f::promoted[0]") with no space, so a bare-colon cut would
		// split inside it instead of at the path/type boundary.
		path, _, ok := strings.Cut(rest, ": ")
		if !ok {
			continue
		}
		path = strings.TrimSpace(path)
		var pieces []string
		matched := false
		depth := 0
		start := i
		for ; i < len(lines); i++ {
			code, _ := splitCodeComment(lines[i])
			depth += strings.Count(code, "{") - strings.Count(code, "}")
			if m := promotedArrayRe.FindStringSubmatch(strings.TrimSpace(code)); m != nil {
				matched = true
				for _, tok := range splitTop(m[1], ',') {
					if lit, ok := unquoteConstStr(tok); ok {
						pieces = append(pieces, lit)
					}
				}
			}
			if depth <= 0 && i > start {
				break
			}
		}
		if matched {
			out[path] = pieces
		}
	}
	return out
}

var promotedArrayRe = regexp.MustCompile(`^_\d+\s*=\s*\[(.*)\];?$`)

// unquoteConstStr extracts a plain (non-byte) string literal from a promoted
// const array element (`const "text"`), mirroring constFromLiteral's own
// string-literal branch (same raw-substring semantics, no escape decoding).
// ok=false for anything else — `move _2` (a non-literal element, e.g. case f's
// Placeholder array) — which is what keeps promotedPieces from treating a
// non-string-literal array as a piece list at all.
func unquoteConstStr(tok string) (string, bool) {
	tok = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(tok), "const "))
	if !strings.HasPrefix(tok, `"`) {
		return "", false
	}
	end := strings.LastIndexByte(tok, '"')
	if end <= 0 {
		return "", false
	}
	return tok[1:end], true
}

// rustIdentityTraitMethods maps a std conversion/formatting trait to its
// forwarding method: a callee printed in MIR's qualified form
// `<T as Trait<..>>::method` is an identity string conversion when
// (trait, method) is listed here. Matching that trait-qualified RAW form —
// never a suffix of the normalized name — is what keeps a plain user function
// `my_into` or a user inherent method `W::into` (both printed without the
// `<.. as ..>` qualifier) from acquiring identity semantics.
var rustIdentityTraitMethods = map[string]string{
	"ToString": "to_string",
	"ToOwned":  "to_owned",
	"AsRef":    "as_ref",
	"Into":     "into",
	"Clone":    "clone",
	"Deref":    "deref",
	"Borrow":   "borrow",
}

// rustIdentityCallees are exact normalized callees (generics stripped by
// normalizeName, no `rust:` prefix) of inherent std methods that forward their
// operand's text unchanged. Command::new(p) is included because the value's
// text is the program it will run (see the aliasing note in emitCall).
// String::from is listed for older toolchains that print it inherently; current
// rustc prints the trait form `<String as From<&str>>::from`, which normalizes
// to bare `from` and is deliberately NOT matched (From is implemented for far
// more than string-identity conversions).
var rustIdentityCallees = map[string]bool{
	"String::as_str":              true,
	"std::string::String::as_str": true,
	"string::String::as_str":      true,
	"String::from":                true,
	"std::string::String::from":   true,
	"Command::new":                true,
	"std::process::Command::new":  true,
	"process::Command::new":       true,
}

// rustIdentityConv reports whether a Rust callee is a string-valued conversion
// that forwards its operand's text unchanged, so the SSRF prefix
// reconstruction can look one hop deeper (builtin.identity — see
// internal/analysis/ssrf.go). raw is the MIR callee text before
// generic-stripping (the trait-qualified form lives only there), norm its
// normalizeName form (for the inherent-method table).
func rustIdentityConv(raw, norm string) bool {
	if rustIdentityCallees[norm] {
		return true
	}
	trait, method, ok := traitCall(raw)
	return ok && rustIdentityTraitMethods[trait] == method
}

// forwardsFormatResult reports whether a call is the `format!` expansion's
// result plumbing — alloc's `format(Arguments) -> String` and hint::must_use —
// which forwards its argument's text unchanged. These print as bare names
// (`format(move _7)`), so the name alone cannot be anchored; instead the single
// argument must itself be the result of an already-marker-tagged call (the
// Arguments::new / format chain), which a user function merely named `format`
// or `must_use` is never handed.
func (st *lowerState) forwardsFormatResult(norm string, args []*ir.Value) bool {
	switch norm {
	case "format", "fmt::format", "alloc::fmt::format", "std::fmt::format",
		"must_use", "hint::must_use", "core::hint::must_use", "std::hint::must_use":
	default:
		return false
	}
	if len(args) != 1 {
		return false
	}
	switch st.intr[args[0].GetRegName()] {
	case "builtin.format", "builtin.identity":
		return true
	}
	return false
}

// traitCall parses MIR's qualified-call form `<Type as Trait<..>>::method`,
// returning the trait path's LAST segment (generic args dropped) and the
// method name. ok=false for any other callee shape — in particular a plain
// path call, which is how every user free function and inherent method prints.
func traitCall(raw string) (trait, method string, ok bool) {
	if !strings.HasPrefix(raw, "<") {
		return "", "", false
	}
	end := matchDelim(raw, 0, '<', '>')
	if end < 0 || !strings.HasPrefix(raw[end+1:], "::") {
		return "", "", false
	}
	qual := raw[1:end] // `Type as Trait<..>`
	// Find the type/trait separator: the first ` as ` outside any nested <...>
	// group (a nested qualified type like `<<T as A>::B as C>` keeps its inner
	// ` as ` behind an angle bracket).
	as, depth := -1, 0
	for i := 0; i+4 <= len(qual) && as < 0; i++ {
		switch qual[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && qual[i:i+4] == " as " {
			as = i
		}
	}
	if as < 0 {
		return "", "", false
	}
	trait = normalizeName(qual[as+4:])
	if j := strings.LastIndex(trait, "::"); j >= 0 {
		trait = trait[j+2:]
	}
	method = normalizeName(raw[end+3:])
	if strings.Contains(method, "::") { // deeper assoc path, not a method call
		return "", "", false
	}
	return trait, method, true
}

// setAgg records an aggregate construction: it both emits a builtin.aggregate
// intrinsic (so a whole-aggregate use propagates taint from any element) and
// remembers the element values so a later field read `(_dst.i)` folds directly
// to element i (precise field-sensitive flow through tuples/arrays/structs).
func (st *lowerState) setAgg(dst string, operandToks []string, intrinsic string, pos *ir.Position) {
	vals := st.operands(operandToks)
	name := st.reg()
	st.instrs = append(st.instrs, &ir.Instruction{Name: name, Op: ir.OpCode_OP_CODE_INTRINSIC, Intrinsic: intrinsic, Operands: vals, Pos: pos})
	st.env[dst] = ssabuild.Reg(name)
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
	return ssabuild.Str("")
}

// local returns the current gIR value bound to a MIR local, or an untainted
// placeholder for one not yet seen (e.g. defined in an unvisited block).
func (st *lowerState) local(name string) *ir.Value {
	if v, ok := st.env[name]; ok {
		return v
	}
	return ssabuild.Str("")
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
	return ssabuild.Reg(name)
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
	} else if !filepath.IsAbs(file) && st.root != "" {
		// A cargo build runs rustc IN the crate directory, so its spans are
		// crate-relative ("src/lib.rs"). Stored verbatim that names no particular
		// file -- every crate in a workspace has one -- and neither srclines nor a
		// SARIF consumer can open it. Resolving against the crate directory (the
		// root this module was lowered with) is what makes the built path agree
		// with the source-lowered one, which reports absolute paths.
		file = filepath.Join(st.root, file)
	}
	// Anything expanded from a macro carries a span into rustc's OWN sysroot
	// (`/rustc/<hash>/library/alloc/src/macros.rs` for everything through
	// `format!`, i.e. most string-building Rust). That file does not exist on the
	// scanning machine, so a finding pinned there is unreadable and GitHub code
	// scanning cannot annotate it. The last accepted span is the macro's call
	// site, which is the line the reader wants.
	if !st.underRoot(file) {
		return st.lastPos
	}
	pos := &ir.Position{Filename: file, Line: int32(atoi(m[2])), Column: int32(atoi(m[3]))}
	if st.firstPos == nil {
		st.firstPos = pos
	}
	st.lastPos = pos
	return pos
}

// underRoot reports whether a span's file lies inside the tree being scanned.
func (st *lowerState) underRoot(file string) bool {
	if st.root == "" {
		return true
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(st.root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	out = append(out, s[start:])
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

// constFromLiteral models a MIR constant. String literals are preserved (so the
// secrets scanner can see them and taint stays constant-free); every other
// constant becomes an empty string constant — untainted, which is correct since
// compile-time constants are never attacker-controlled.
func constFromLiteral(lit string) *ir.Value {
	lit = strings.TrimSpace(lit)
	if strings.HasPrefix(lit, `"`) {
		if end := strings.LastIndexByte(lit, '"'); end > 0 {
			return ssabuild.Str(lit[1:end])
		}
	}
	// A byte-string literal `b"..."` is how MIR renders the packed template that
	// `format!` hands to fmt::Arguments::new (assigned to a temp, then passed in).
	// Decode a well-formed template into a readable `{}`-placeholder string so the
	// SSRF URL-host reconstruction can see its constant pieces; anything that is
	// not a clean template stays an empty constant (unchanged behavior).
	if strings.HasPrefix(lit, `b"`) {
		if tmpl, ok := decodeFmtTemplate(lit); ok {
			return ssabuild.Str(tmpl)
		}
	}
	return ssabuild.Str("")
}

// decodeFmtTemplate decodes the packed byte-string template that `format!` passes
// to `fmt::Arguments::new` into a readable format string with `{}` at each
// argument position. The template (rustc's `fmt::rt` encoding) is a sequence of
// tokens: the byte 0xC0 marks an argument insertion, and a byte < 0x80 is the
// length of a literal run that immediately follows. tok is the raw MIR operand,
// e.g. `const b"\x14https://h/v1/\xc0\x00"`. Returns ok=false only when the
// operand is not a decodable byte string at all.
//
// A token the encoding uses but this decoder does not model -- an explicit-index
// or spec-bearing argument, `{0}` or `{:>10}` -- ends the decode at that point
// rather than failing it: the text decoded so far came from literal-run tokens,
// which are compile-time text and cannot carry taint, and the remainder is
// rendered as one argument insertion, i.e. dynamic. Failing the whole decode
// instead left an EMPTY template, which reads downstream as the positive claim
// that the format string contains no host -- and so turned a provably safe
// `format!("https://api.example.com/v1/{:>10}", p)` into a high-confidence
// CWE-918 that the same code without the width specifier does not produce.
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
		default: // a token this decoder does not model; the rest is unknown
			sb.WriteString("{}")
			i = len(raw)
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

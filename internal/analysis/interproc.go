package analysis

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// Analyze runs inter-procedural taint analysis over prog for every rule in the
// engine's rule set and returns all findings.
//
// Taint flows across call boundaries via context-insensitive function
// summaries: a tainted argument taints the callee's corresponding parameter,
// and a function that can return tainted data taints its callers' call
// results. A worklist re-analyzes functions until this state stabilizes.
func (e *Engine) Analyze(prog *ir.Program) []Finding {
	var findings []Finding
	if e == nil || e.rs == nil || prog == nil {
		return findings
	}

	cg := BuildCallGraph(prog)

	// Key every function by its canonical name (with a unique fallback for
	// functions that lack one, so they are still analyzed intra-procedurally).
	byKey := map[string]*ir.Function{}
	modByKey := map[string]*ir.Module{}
	local := 0
	for _, mod := range prog.Modules {
		if mod == nil {
			continue
		}
		for _, fn := range mod.Functions {
			if fn == nil {
				continue
			}
			key := fn.CanonicalName
			if key == "" {
				key = fmt.Sprintf("__local%d", local)
				local++
			}
			byKey[key] = fn
			modByKey[key] = mod
		}
	}

	// Class-hierarchy index for interface dynamic dispatch, built ONCE and shared
	// by every rule: a Go bare method name -> every lowered concrete method that
	// implements it. It depends only on the immutable function index, so rebuilding
	// it per rule (as before) wasted O(rules x functions) work.
	methodImpls := buildMethodImpls(byKey)

	// Each rule's analysis is independent — it reads the shared, immutable call
	// graph / function index and writes only its own local state — so run the
	// rules concurrently (bounded by GOMAXPROCS). Results are collected per rule
	// index and concatenated in rule order, so output stays deterministic.
	results := make([][]Finding, len(e.rs.Rules))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i := range e.rs.Rules {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = analyzeInterproc(cg, byKey, modByKey, methodImpls, &e.rs.Rules[i])
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		findings = append(findings, r...)
	}
	return findings
}

// callEffect records that a tainted argument at a call site flows into the
// callee's parameter #param, carrying the ultimate source origin.
type callEffect struct {
	callee string
	param  int
	origin *ir.Position
}

// funcResult is the outcome of analyzing one function under a set of
// tainted-parameter seeds.
type funcResult struct {
	findings      []Finding
	returnsOrigin *ir.Position // non-nil if the function can return tainted data
	callEffects   []callEffect
}

// logicalArgs returns a call's arguments in SOURCE-LEVEL order, dropping the
// method receiver that Go SSA carries as args[0]. Python/JS frontends already
// omit the receiver from args (the object lives in the callee name), so logical
// argument indices are consistent across languages: index 0 is the first real
// argument. A Go method callee is recognizable by its receiver-type syntax, e.g.
// "go:(*database/sql.DB).Query".
func logicalArgs(callee string, args []*ir.Value) []*ir.Value {
	if strings.HasPrefix(callee, "go:(") && len(args) > 0 {
		return args[1:]
	}
	return args
}

// injectableArgs returns the subset of a sink call's arguments that are actual
// injection points, given the matched sink's logical injection-point indices.
// Empty indices means every argument is an injection point (the default). This
// lets a sink ignore SAFE argument positions — e.g. the bound parameters of a
// parameterized SQL query — so taint reaching them does not raise a finding.
func injectableArgs(sinkArgs []int32, callee string, args []*ir.Value) []*ir.Value {
	if len(sinkArgs) == 0 {
		return args
	}
	la := logicalArgs(callee, args)
	sel := make([]*ir.Value, 0, len(sinkArgs))
	for _, idx := range sinkArgs {
		if idx >= 0 && int(idx) < len(la) {
			sel = append(sel, la[int(idx)])
		}
	}
	return sel
}

// buildMethodImpls builds the class-hierarchy index for interface dynamic
// dispatch: a Go bare method name -> every lowered concrete method that
// implements it. An INVOKE call names an abstract interface method (not a
// concrete function), so this lets taint flow through the interface into the
// concrete implementations. It over-approximates (any same-named method
// matches), which is why such findings stay Medium confidence. It depends only
// on the immutable function index, so it is built once and shared by every rule.
func buildMethodImpls(byKey map[string]*ir.Function) map[string][]string {
	methodImpls := map[string][]string{}
	for name := range byKey {
		if strings.HasPrefix(name, "go:(") { // a Go method (receiver-type syntax)
			if i := strings.LastIndex(name, "."); i >= 0 {
				bare := name[i+1:]
				methodImpls[bare] = append(methodImpls[bare], name)
			}
		}
	}
	return methodImpls
}

// analyzeInterproc runs the worklist-based inter-procedural taint analysis for
// a single rule. State (parameter taint, return taint) grows monotonically, so
// iteration converges.
func analyzeInterproc(cg *CallGraph, byKey map[string]*ir.Function, modByKey map[string]*ir.Module, methodImpls map[string][]string, rule *rules.Rule) []Finding {
	paramTaint := map[string]map[int]*ir.Position{}
	returnTaint := map[string]*ir.Position{}
	reported := map[*ir.Instruction]bool{}
	var findings []Finding

	// Reverse edges: callee -> callers, so a callee becoming taint-returning
	// re-enqueues its callers.
	callers := map[string][]string{}
	for caller, callees := range cg.Edges {
		for _, callee := range callees {
			callers[callee] = append(callers[callee], caller)
		}
	}

	queued := map[string]bool{}
	var queue []string
	enqueue := func(name string) {
		if byKey[name] == nil {
			return
		}
		if mod := modByKey[name]; mod == nil || !rule.AppliesTo(mod.Language) {
			return
		}
		if !queued[name] {
			queued[name] = true
			queue = append(queue, name)
		}
	}

	// Seed the worklist with every applicable function, in a deterministic order.
	keys := make([]string, 0, len(byKey))
	for name := range byKey {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		enqueue(name)
	}

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		queued[name] = false

		fn := byKey[name]
		mod := modByKey[name]
		if fn == nil || mod == nil {
			continue
		}

		res := analyzeFunc(mod, fn, rule, paramTaint[name], returnTaint, byKey, methodImpls, reported)
		findings = append(findings, res.findings...)

		if res.returnsOrigin != nil && returnTaint[name] == nil {
			returnTaint[name] = res.returnsOrigin
			for _, caller := range callers[name] {
				enqueue(caller)
			}
		}

		for _, ce := range res.callEffects {
			m := paramTaint[ce.callee]
			if m == nil {
				m = map[int]*ir.Position{}
				paramTaint[ce.callee] = m
			}
			if _, exists := m[ce.param]; !exists {
				m[ce.param] = ce.origin
				enqueue(ce.callee)
			}
		}
	}

	return findings
}

// propagatorOperands returns the values whose taint a propagating call carries
// to its result: the explicit arguments plus, for a method/INVOKE call, the
// receiver (Call.Value). A transform like `tainted.trim()` taints its result
// through the receiver — which Java/JS keep in Call.Value, not args — so
// omitting it would drop taint at the most common propagator shape.
func propagatorOperands(inst *ir.Instruction) []*ir.Value {
	args := inst.Call.GetArgs()
	if v := inst.Call.GetValue(); v != nil {
		return append([]*ir.Value{v}, args...)
	}
	return args
}

// analyzeFunc runs the intra-procedural fixpoint for one function, seeded with
// tainted parameters, and reports the sinks it hits, whether it returns taint,
// and the taint it passes to callees.
func analyzeFunc(
	mod *ir.Module,
	fn *ir.Function,
	rule *rules.Rule,
	seeds map[int]*ir.Position,
	returnTaint map[string]*ir.Position,
	byKey map[string]*ir.Function,
	methodImpls map[string][]string,
	reported map[*ir.Instruction]bool,
) funcResult {
	tainted := map[string]*ir.Position{}
	defs := buildDefs(fn)

	// Seed tainted parameters. A flow that enters through a parameter is
	// inter-procedural, which lowers the confidence of any finding it feeds.
	// interprocOrigins records every source origin whose taint crossed a function
	// boundary to reach this function — parameter seeds here, plus taint pulled
	// back from a callee's return summary in handleCall. confidenceFor consults it
	// so all cross-function findings are Medium (and thus seen by the LLM reviewer).
	interprocOrigins := map[*ir.Position]bool{}
	for idx, origin := range seeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				markTainted(tainted, reg, origin)
				interprocOrigins[origin] = true
			}
		}
	}

	var res funcResult
	effectSeen := map[string]bool{}

	addEffect := func(callee string, param int, origin *ir.Position) {
		key := callee + "#" + strconv.Itoa(param)
		if effectSeen[key] {
			return
		}
		effectSeen[key] = true
		res.callEffects = append(res.callEffects, callEffect{callee: callee, param: param, origin: origin})
	}

	confidenceFor := func(origin *ir.Position) Confidence {
		if interprocOrigins[origin] {
			return ConfidenceMedium
		}
		return ConfidenceHigh
	}

	// handleCall applies the taint transfer for any call-carrying instruction:
	// direct CALL, dynamic INVOKE, and the call-carrying intrinsics go.defer /
	// go.goroutine (whose sink/source/propagator and cross-function effects would
	// otherwise be invisible to the engine).
	handleCall := func(inst *ir.Instruction) {
		if inst.Call == nil {
			return
		}
		callee := inst.Call.GetCallee()
		args := inst.Call.GetArgs()
		sinkArgs, isSink := rule.SinkInjectionArgs(callee)

		switch {
		case rule.IsSanitizer(callee):
			// A sanitizer neutralizes taint: its result is clean. Critically, we
			// must NOT fall through to the inter-procedural summary blocks below —
			// when the sanitizer is a function lowered from the scanned repo
			// (byKey[callee] != nil), that path would re-taint the sanitizer's
			// result from its own return summary and defeat the sanitizer. Stop here.
			return
		case rule.IsSource(callee):
			if inst.Name != "" {
				markTainted(tainted, inst.Name, inst.Pos)
			}
		case isSink:
			inj := injectableArgs(sinkArgs, callee, args)
			if pos, ok := firstTaintedOrigin(tainted, inj); ok && !reported[inst] {
				reported[inst] = true
				// SSRF (CWE-918): keep the finding only if the taint can reach the
				// request URL's host. Taint confined to the path/query of a fixed
				// host cannot redirect the request and is a false positive; the
				// check is structural/deterministic, so marking reported is safe.
				if rule.CWE != "CWE-918" || urlHostControllable(inj, tainted, defs) {
					steps := reconstructPath(defs, tainted, firstTaintedReg(tainted, inj), pos, inst.Pos)
					res.findings = append(res.findings, Finding{
						RuleID:     rule.ID,
						Severity:   rule.Severity,
						Confidence: confidenceFor(pos),
						CWE:        rule.CWE,
						Message:    rule.Message,
						Language:   mod.Language,
						Function:   fn.CanonicalName,
						SourcePos:  pos,
						SinkPos:    inst.Pos,
						SinkCallee: callee,
						Steps:      steps,
					})
				}
			}
		case rule.IsPropagator(callee) || isConcatAddCallee(callee) || rules.IsDefaultPropagator(callee):
			// A propagating call carries taint from any of its operands to its
			// result. This covers the rule's own propagators, a Rust concat-add
			// call (`String + &str` lowered to `Add::add` — the call-shaped
			// analogue of the universal BIN_OP_ADD propagator), and the built-in
			// default propagators (stdlib string/encoding transforms that real
			// code interposes between a source and a sink; without them one
			// `strings.TrimSpace`/`.toLowerCase()` silently drops taint). Operands
			// include the RECEIVER of a method call (Call.Value, e.g. Java/JS
			// `tainted.trim()`), not just the explicit arguments.
			if inst.Name != "" {
				markTaintFromOperands(tainted, inst.Name, propagatorOperands(inst))
			}
		}

		// Inter-procedural, direct call: if the callee is a function we lowered,
		// pass tainted arguments into its parameters and pull back its return taint.
		if byKey[callee] != nil {
			if inst.Call.GetIsInvoke() {
				// A concrete instance-method call (e.g. Java) whose method we
				// lowered: the receiver lives in Call.Value and maps to param 0,
				// and the real arguments EXCLUDE the receiver, so they map to the
				// callee's params shifted by one. Mapping args[j]->param j here
				// would seed the receiver slot and drop the last argument — an
				// off-by-one that silently loses every cross-function instance
				// flow. (Go interface INVOKEs name an abstract method absent from
				// byKey, so they skip this and are handled by the CHA block below.)
				if p, ok := isTaintedArg(tainted, inst.Call.GetValue()); ok {
					addEffect(callee, 0, p)
				}
				for j, a := range args {
					if p, ok := isTaintedArg(tainted, a); ok {
						addEffect(callee, j+1, p)
					}
				}
			} else {
				// Static/free function or Go method call: args already align with
				// params (Args[0]==Params[0]==receiver for a Go method). isTaintedArg
				// also seeds when an argument is a struct carrying a tainted field,
				// so a field-tainted struct passed by value/pointer still flows into
				// the callee (see fieldAnyKey / ENG-3).
				for j, a := range args {
					if p, ok := isTaintedArg(tainted, a); ok {
						addEffect(callee, j, p)
					}
				}
			}
			if ro := returnTaint[callee]; ro != nil && inst.Name != "" {
				markTainted(tainted, inst.Name, ro)
				// Taint entered via a callee's return summary: this is a
				// cross-function flow, so any finding it feeds must be Medium.
				interprocOrigins[ro] = true
			}
		}

		// Inter-procedural, interface dynamic dispatch: an INVOKE call's callee is
		// the abstract interface method, so resolve to concrete implementations by
		// method name (CHA) and flow taint into each. INVOKE args exclude the
		// receiver (it lives in Call.Value), so they map to a concrete method's
		// params shifted by one — param 0 is the receiver.
		if inst.Call.GetIsInvoke() {
			for _, impl := range methodImpls[inst.Call.GetMethodName()] {
				if p, ok := isTaintedArg(tainted, inst.Call.GetValue()); ok {
					addEffect(impl, 0, p)
				}
				for j, a := range args {
					if p, ok := isTaintedArg(tainted, a); ok {
						addEffect(impl, j+1, p)
					}
				}
				if ro := returnTaint[impl]; ro != nil && inst.Name != "" {
					markTainted(tainted, inst.Name, ro)
					interprocOrigins[ro] = true // cross-function return -> Medium
				}
			}
		}
	}

	// handleMakeClosure flows taint through a builtin.make_closure intrinsic,
	// whose operands are [Fn, binding0, binding1, ...]. The frontend appends the
	// closure's captured free variables as its trailing params, so a tainted
	// binding must flow into the closure's matching free-var param — this is how
	// taint reaches a `go func(){ ...captured... }()` goroutine body.
	handleMakeClosure := func(inst *ir.Instruction) {
		ops := inst.GetOperands()
		if len(ops) < 2 {
			return
		}
		closureName := ops[0].GetFuncName()
		if closureName == "" {
			return
		}
		closure := byKey[closureName]
		if closure == nil {
			return
		}
		bindings := ops[1:]
		base := len(closure.Params) - len(bindings)
		if base < 0 {
			return
		}
		for i, b := range bindings {
			if p, ok := isTainted(tainted, b); ok {
				addEffect(closureName, base+i, p)
			}
		}
	}

	visit := func(inst *ir.Instruction) {
		switch inst.Op {
		case ir.OpCode_OP_CODE_CALL, ir.OpCode_OP_CODE_INVOKE:
			handleCall(inst)
		case ir.OpCode_OP_CODE_STORE:
			visitStore(inst, defs, tainted)
		case ir.OpCode_OP_CODE_FIELD, ir.OpCode_OP_CODE_FIELD_ADDR:
			visitFieldRead(inst, tainted)
		case ir.OpCode_OP_CODE_INTRINSIC:
			// go.defer / go.goroutine carry a CallCommon; route them through the
			// call transfer so sinks/sources/propagation aren't lost.
			if inst.Call != nil {
				handleCall(inst)
			}
			if inst.GetIntrinsic() == "builtin.make_closure" {
				handleMakeClosure(inst)
			}
			visitIntrinsic(inst, defs, tainted)
		case ir.OpCode_OP_CODE_RET:
			if pos, ok := firstTaintedOrigin(tainted, inst.GetOperands()); ok && res.returnsOrigin == nil {
				res.returnsOrigin = pos
			}
		default:
			if propagatingOps[inst.Op] {
				markTaintFromOperands(tainted, inst.Name, inst.GetOperands())
			}
		}
	}

	for {
		beforeTaint := len(tainted)
		beforeEffects := len(res.callEffects)
		beforeReturn := res.returnsOrigin
		for _, blk := range fn.Blocks {
			if blk == nil {
				continue
			}
			for _, inst := range blk.Instrs {
				if inst != nil {
					visit(inst)
				}
			}
		}
		if len(tainted) == beforeTaint && len(res.callEffects) == beforeEffects && res.returnsOrigin == beforeReturn {
			break
		}
	}

	return res
}

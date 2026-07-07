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

	// These three indexes are likewise rule-independent (derived only from the
	// immutable call graph / function set), so build them ONCE here and share them
	// read-only across the parallel per-rule analyses. Rebuilding them inside
	// analyzeInterproc — as before — repeated an O(program) instruction walk and a
	// large allocation per rule, which starved the goroutines' shared allocator and
	// capped parallel scaling (~1.9x on 4 cores). callers is the reverse call graph;
	// globalReaders maps a global name to the functions that read it (ENG-6); keys
	// is the deterministic worklist seed order.
	callers := buildCallers(cg)
	globalReaders := buildGlobalReaders(byKey)
	keys := make([]string, 0, len(byKey))
	for name := range byKey {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	idx := &sharedIndex{
		byKey: byKey, modByKey: modByKey, methodImpls: methodImpls,
		callers: callers, globalReaders: globalReaders, keys: keys,
		reportable: e.reportable,
	}

	// Precompile every rule's glob patterns ONCE, single-threaded, before the
	// parallel analysis. This moves shape-classification (and the "#idx" sink
	// parse) out of the hot per-(call-site × pattern) matching path — which then
	// does a lock-free slice walk instead of a mutexed cache lookup per match, the
	// dominant engine cost as rule packs grow. Doing it here (not lazily inside a
	// goroutine) avoids a data race on the shared matcher cache.
	for i := range e.rs.Rules {
		e.rs.Rules[i].Compile()
	}

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
			results[i] = analyzeInterproc(idx, &e.rs.Rules[i])
		}(i)
	}
	wg.Wait()
	// Size the combined slice exactly and copy once. Appending each rule's results
	// to a growing slice reallocated it by repeated doubling — copying every
	// (large) Finding many times, the single biggest allocation in a finding-heavy
	// scan.
	total := 0
	for _, r := range results {
		total += len(r)
	}
	findings = make([]Finding, 0, total)
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

// globalEffect records that a function stored tainted data into a package/
// module-level global, carrying the ultimate source origin. It publishes taint
// program-wide (ENG-6): any function that later loads that global observes it.
type globalEffect struct {
	name   string
	origin *ir.Position
}

// funcResult is the outcome of analyzing one function under a set of
// tainted-parameter seeds.
type funcResult struct {
	findings      []Finding
	returnsOrigin *ir.Position // non-nil if the function can return tainted data
	callEffects   []callEffect
	// reqEffects records that a request-object-tainted value (see reqTainted) was
	// passed as an argument to a lowered callee, so the callee's matching
	// parameter becomes a request object too — this is what carries the
	// request-object method-sugar coverage across function boundaries (e.g. a
	// handler passing *http.Request / *gin.Context to a helper that calls an
	// accessor on it). Mirrors callEffects, but for provenance rather than taint.
	reqEffects    []callEffect
	globalEffects []globalEffect
	// taintsParamMemory[i] is set when the function writes tainted data into
	// memory reachable from parameter i (an out-parameter fill, ENG-6b): a store
	// whose address roots at param i. Callers then mark the argument they pass at
	// that position tainted, so `fill(&dst); use(dst)` flows.
	taintsParamMemory map[int]*ir.Position
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
// sharedIndex holds the rule-independent indexes over the immutable program,
// built once in Analyze and shared read-only across the parallel per-rule
// analyses (no goroutine mutates them). Hoisting them here — rather than
// rebuilding per rule — removes an O(program × rules) instruction walk and the
// allocation that capped parallel scaling.
type sharedIndex struct {
	byKey         map[string]*ir.Function
	modByKey      map[string]*ir.Module
	methodImpls   map[string][]string
	callers       map[string][]string // callee -> its callers (reverse call graph)
	globalReaders map[string][]string // global name -> functions that read it (ENG-6)
	keys          []string            // byKey names, sorted (deterministic worklist seed)
	// reportable, when non-empty, restricts the initial worklist seed to functions
	// whose module is user-authored; dependency functions are then reached
	// demand-driven via callEffects. Empty seeds every function.
	reportable map[string]bool
}

// buildCallers inverts the call graph: callee -> callers, so a callee becoming
// taint-returning re-enqueues its callers.
func buildCallers(cg *CallGraph) map[string][]string {
	callers := map[string][]string{}
	for caller, callees := range cg.Edges {
		for _, callee := range callees {
			callers[callee] = append(callers[callee], caller)
		}
	}
	return callers
}

// buildGlobalReaders indexes global name -> every function that reads it (ENG-6),
// so a global becoming tainted re-enqueues exactly its readers. A read is any
// named instruction with a GlobalName operand (Go lowers a global read as
// UN_OP(MUL), others as LOAD); a STORE writes its global operand but has no
// result Name, so it is not counted as a reader.
func buildGlobalReaders(byKey map[string]*ir.Function) map[string][]string {
	globalReaders := map[string][]string{}
	for name, fn := range byKey {
		for _, blk := range fn.Blocks {
			if blk == nil {
				continue
			}
			for _, inst := range blk.Instrs {
				if inst == nil || inst.Name == "" {
					continue
				}
				for _, op := range inst.GetOperands() {
					if g := op.GetGlobalName(); g != "" {
						globalReaders[g] = append(globalReaders[g], name)
					}
				}
			}
		}
	}
	return globalReaders
}

func analyzeInterproc(idx *sharedIndex, rule *rules.Rule) []Finding {
	byKey, modByKey, methodImpls := idx.byKey, idx.modByKey, idx.methodImpls
	callers, globalReaders := idx.callers, idx.globalReaders
	paramTaint := map[string]map[int]*ir.Position{}
	paramReqTaint := map[string]map[int]*ir.Position{} // callee -> param index -> request-object provenance origin (PR4)
	returnTaint := map[string]*ir.Position{}
	globalTaint := map[string]*ir.Position{}
	paramMemTaint := map[string]map[int]*ir.Position{} // callee -> out-param index -> origin (ENG-6b)
	reported := map[*ir.Instruction]bool{}
	var findings []Finding

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

	// Seed the worklist. Normally every function is seeded (so an intra-procedural
	// source->sink flow is found wherever it lives). When a reportable scope is set
	// (dependencies were lowered), seed ONLY user-authored functions: a dependency
	// function is then analyzed DEMAND-DRIVEN — enqueued only when taint reaches it
	// through a call (addEffect -> enqueue below) — so we pay for library code only
	// on the taint paths that actually traverse it, not the whole closure.
	for _, name := range idx.keys {
		// Skip only a Go DEPENDENCY function (a Go module not in the user's
		// reportable set) — it is reached demand-driven. Non-Go modules and Go
		// user code are always seeded, so other languages are unaffected.
		if len(idx.reportable) > 0 {
			if mod := idx.modByKey[name]; mod != nil && mod.Language == "go" && !idx.reportable[mod.Name] {
				continue
			}
		}
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

		res := analyzeFunc(mod, fn, rule, paramTaint[name], paramReqTaint[name], returnTaint, globalTaint, paramMemTaint, byKey, methodImpls, reported)
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

		// Request-object provenance flowing into a callee parameter (PR4): merged
		// and re-enqueued exactly like callEffects, so a request object passed to a
		// helper makes that helper's parameter a request object too.
		for _, ce := range res.reqEffects {
			m := paramReqTaint[ce.callee]
			if m == nil {
				m = map[int]*ir.Position{}
				paramReqTaint[ce.callee] = m
			}
			if _, exists := m[ce.param]; !exists {
				m[ce.param] = ce.origin
				enqueue(ce.callee)
			}
		}

		// A tainted store into a global publishes it program-wide: record the
		// taint and re-enqueue every function that reads that global (ENG-6a).
		for _, ge := range res.globalEffects {
			if _, exists := globalTaint[ge.name]; !exists {
				globalTaint[ge.name] = ge.origin
				for _, reader := range globalReaders[ge.name] {
					enqueue(reader)
				}
			}
		}

		// This function fills tainted data into one of its out-parameters
		// (ENG-6b): record it on the callee's summary and re-enqueue its callers
		// so the argument they pass at that position picks up the taint.
		if len(res.taintsParamMemory) > 0 {
			m := paramMemTaint[name]
			if m == nil {
				m = map[int]*ir.Position{}
				paramMemTaint[name] = m
			}
			changed := false
			for idx, origin := range res.taintsParamMemory {
				if _, exists := m[idx]; !exists {
					m[idx] = origin
					changed = true
				}
			}
			if changed {
				for _, caller := range callers[name] {
					enqueue(caller)
				}
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

// requestObjectSource is the canonical name of the synthetic source the Go
// frontend injects for an HTTP handler's request object (converters/go
// addHTTPRequestSource). Taint seeded from it additionally carries
// request-object provenance (reqTainted), which unlocks the framework-agnostic
// accessor rule below: a method call on a request object yields untrusted data
// even for a web framework we have no rules for.
const requestObjectSource = "go:@net/http.Request"

func isRequestObjectSource(callee string) bool { return callee == requestObjectSource }

// methodReceiverReg returns the register of a method call's receiver, or "" if
// the call is not a method call whose receiver we can identify. For an INVOKE
// (interface/virtual dispatch) the receiver is Call.Value; for a Go static
// method call the callee is printed as "go:(recv).Method" and the receiver is
// Args[0]. Free-function calls (no parenthesized receiver, not an invoke) return
// "" so their first argument is never mistaken for a receiver.
func methodReceiverReg(inst *ir.Instruction) string {
	if inst.Call.GetIsInvoke() {
		return inst.Call.GetValue().GetRegName()
	}
	if strings.HasPrefix(inst.Call.GetCallee(), "go:(") {
		if args := inst.Call.GetArgs(); len(args) > 0 {
			return args[0].GetRegName()
		}
	}
	return ""
}

// methodOutParamArgs returns a method call's real arguments (receiver excluded),
// for out-parameter tainting like c.Bind(&dst). A Go static method call keeps
// the receiver in Args[0], so its real args are Args[1:]; an INVOKE keeps the
// receiver in Call.Value, so all Args are real.
func methodOutParamArgs(inst *ir.Instruction) []*ir.Value {
	args := inst.Call.GetArgs()
	if !inst.Call.GetIsInvoke() && strings.HasPrefix(inst.Call.GetCallee(), "go:(") && len(args) > 0 {
		return args[1:]
	}
	return args
}

// isAddressArg reports whether reg is defined by an address-producing
// instruction (&x, &s.f, &a[i], or an alloc) — i.e. a plausible out-parameter
// target such as the &dst in c.Bind(&dst).
func isAddressArg(defs map[string]*ir.Instruction, reg string) bool {
	def := defs[reg]
	if def == nil {
		return false
	}
	switch def.GetOp() {
	case ir.OpCode_OP_CODE_ALLOC, ir.OpCode_OP_CODE_FIELD_ADDR, ir.OpCode_OP_CODE_INDEX_ADDR:
		return true
	case ir.OpCode_OP_CODE_UN_OP:
		return def.GetUnOp() == ir.UnOpKind_UN_OP_ADDR
	}
	return false
}

// analyzeFunc runs the intra-procedural fixpoint for one function, seeded with
// tainted parameters, and reports the sinks it hits, whether it returns taint,
// and the taint it passes to callees.
func analyzeFunc(
	mod *ir.Module,
	fn *ir.Function,
	rule *rules.Rule,
	seeds map[int]*ir.Position,
	reqSeeds map[int]*ir.Position,
	returnTaint map[string]*ir.Position,
	globalTaint map[string]*ir.Position,
	paramMemTaint map[string]map[int]*ir.Position,
	byKey map[string]*ir.Function,
	methodImpls map[string][]string,
	reported map[*ir.Instruction]bool,
) funcResult {
	// tainted is the CURRENT block's taint state; the flow-sensitive driver
	// (ENG-2) reassigns it to each block's entry state before visiting the block,
	// so the transfer closures below (which capture this variable) always operate
	// on the right per-block facts.
	tainted := map[string]*ir.Position{}
	defs := buildDefs(fn)
	nonEscaping := nonEscapingAllocs(fn, defs)

	// Guard/barrier index (ENG-9), built once and only for a rule that declares
	// validators (nil otherwise, so the common path pays nothing). curBlock tracks
	// the block being visited so a sink can ask whether a validator guard
	// dominates it on the path taken.
	guards := buildGuardIndex(fn, rule, defs)
	var curBlock int32

	// Seed tainted parameters into the entry block's in-state. A flow that enters
	// through a parameter is inter-procedural, which lowers the confidence of any
	// finding it feeds. interprocOrigins records every source origin whose taint
	// crossed a function boundary to reach this function — parameter seeds here,
	// plus taint pulled back from a callee's return summary in handleCall.
	// confidenceFor consults it so all cross-function findings are Medium (and
	// thus seen by the LLM reviewer).
	interprocOrigins := map[*ir.Position]bool{}

	// reqTainted records registers holding a request object (a value seeded from
	// a request-object source, e.g. an HTTP handler's *http.Request or a
	// route-registered framework context). It is function-scoped and monotonic —
	// request-object-ness is a property of the value, not a per-block fact — so it
	// is NOT reset by the flow-sensitive block driver like `tainted` is. It gates
	// the request-object method-sugar rule in handleCall so that ordinary taint is
	// never affected.
	reqTainted := map[string]*ir.Position{}

	seedState := taintState{}
	for idx, origin := range seeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				seedState[reg] = origin
				interprocOrigins[origin] = true
			}
		}
	}
	// Seed request-object provenance passed in from callers (inter-procedural):
	// a parameter that a caller filled with a request object is itself a request
	// object here, so accessor method calls on it are covered by the method-sugar
	// rule even across the call boundary.
	for idx, origin := range reqSeeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				reqTainted[reg] = origin
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

	// addReqEffect mirrors addEffect but records request-object provenance flowing
	// into a callee parameter (see funcResult.reqEffects). Keyed separately so it
	// does not collide with the taint-effect dedup.
	reqEffectSeen := map[string]bool{}
	addReqEffect := func(callee string, param int, origin *ir.Position) {
		key := callee + "#" + strconv.Itoa(param)
		if reqEffectSeen[key] {
			return
		}
		reqEffectSeen[key] = true
		res.reqEffects = append(res.reqEffects, callEffect{callee: callee, param: param, origin: origin})
	}
	reqTaintedArg := func(v *ir.Value) (*ir.Position, bool) {
		if v == nil {
			return nil, false
		}
		if reg := v.GetRegName(); reg != "" {
			if pos, ok := reqTainted[reg]; ok {
				return pos, true
			}
		}
		return nil, false
	}

	// ENG-6(a): taint through package/module-level globals. A store of tainted
	// data into a global publishes the taint program-wide (recorded as a global
	// effect the orchestrator merges); a load from a global that is already tainted
	// seeds the loaded register. Both cross a function boundary, so any finding
	// they feed is Medium confidence (interprocOrigins), matching the confidence
	// contract for over-approximating flows.
	recordGlobalStore := func(inst *ir.Instruction) {
		ops := inst.GetOperands()
		if len(ops) < 2 {
			return
		}
		g := ops[0].GetGlobalName()
		if g == "" {
			return
		}
		pos, ok := isTainted(tainted, ops[1])
		if !ok {
			return
		}
		key := "g:" + g
		if effectSeen[key] {
			return
		}
		effectSeen[key] = true
		res.globalEffects = append(res.globalEffects, globalEffect{name: g, origin: pos})
	}

	// ENG-6(b): out-parameter fill. When this function stores tainted data into
	// memory reachable from one of its own parameters (the store address roots at
	// a param — `*out = tainted`, `out.f = tainted`, `out[i] = tainted`), record
	// it so callers mark the argument they pass at that position tainted. Only
	// parameters carrying address semantics can be a store root (a value param
	// that is reassigned is a fresh local in SSA, not a store target), so this
	// does not falsely taint by-value arguments.
	paramReg := map[string]int{}
	for i, p := range fn.Params {
		if r := p.GetRegName(); r != "" {
			paramReg[r] = i
		}
	}
	recordParamMemoryTaint := func(inst *ir.Instruction) {
		if len(paramReg) == 0 {
			return
		}
		ops := inst.GetOperands()
		if len(ops) < 2 {
			return
		}
		pos, ok := isTainted(tainted, ops[1])
		if !ok {
			return
		}
		addrReg := ops[0].GetRegName()
		if addrReg == "" {
			return
		}
		idx, ok := paramReg[rootBaseReg(defs, addrReg)]
		if !ok {
			return
		}
		key := "pm:" + strconv.Itoa(idx)
		if effectSeen[key] {
			return
		}
		effectSeen[key] = true
		if res.taintsParamMemory == nil {
			res.taintsParamMemory = map[int]*ir.Position{}
		}
		res.taintsParamMemory[idx] = pos
	}

	// readGlobalTaint seeds the result of any named instruction that reads a
	// tainted global. A global read is not one fixed opcode: the Go frontend
	// lowers `x := pkgVar` as UN_OP(MUL) over a GlobalName operand, others as
	// LOAD — so this keys on the presence of a tainted GlobalName operand rather
	// than the opcode. A STORE's global operand is its write target, but a STORE
	// has no result Name, so it is naturally excluded.
	readGlobalTaint := func(inst *ir.Instruction) {
		if inst.Name == "" {
			return
		}
		for _, op := range inst.GetOperands() {
			g := op.GetGlobalName()
			if g == "" {
				continue
			}
			if pos, ok := globalTaint[g]; ok {
				markTainted(tainted, inst.Name, pos)
				interprocOrigins[pos] = true // cross-function -> Medium
			}
		}
	}

	confidenceFor := func(origin *ir.Position) Confidence {
		if interprocOrigins[origin] {
			return ConfidenceMedium
		}
		return ConfidenceHigh
	}

	// taintCallerArg marks a call argument register tainted because the callee
	// filled tainted data into the memory it points at (ENG-6b out-parameter).
	// The taint reaches the caller through a pointer, so it is a cross-function
	// flow (Medium confidence). Walking the container chain covers `&dst.field`.
	taintCallerArg := func(v *ir.Value, origin *ir.Position) {
		if v == nil {
			return
		}
		reg := v.GetRegName()
		if reg == "" {
			return
		}
		markTainted(tainted, reg, origin)
		taintContainer(defs, tainted, reg, origin)
		interprocOrigins[origin] = true
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
		// Classify the callee once. These globs are the engine's hottest per-(call
		// × rule) work; the switch below and the request-object method-sugar gate
		// both consult the same predicates, so compute them a single time.
		sinkArgs, isSink := rule.SinkInjectionArgs(callee)
		isSan := rule.IsSanitizer(callee)
		isSrc := rule.IsSource(callee)
		isProp := rule.IsPropagator(callee) || isConcatAddCallee(callee) || rules.IsDefaultPropagator(callee)

		// seedInvokeArgs maps an INVOKE call's operands onto target's params: the
		// receiver (Call.Value) to param 0, then each explicit arg shifted by one.
		// Shared by the lowered-method branch and the CHA dynamic-dispatch loop
		// below, which resolve different targets but seed them identically.
		seedInvokeArgs := func(target string) {
			if p, ok := isTaintedArg(tainted, inst.Call.GetValue()); ok {
				addEffect(target, 0, p)
			}
			if p, ok := reqTaintedArg(inst.Call.GetValue()); ok {
				addReqEffect(target, 0, p)
			}
			for j, a := range args {
				if p, ok := isTaintedArg(tainted, a); ok {
					addEffect(target, j+1, p)
				}
				if p, ok := reqTaintedArg(a); ok {
					addReqEffect(target, j+1, p)
				}
			}
		}
		// pullReturnTaint taints this call's result register from target's return
		// summary; taint entered via a callee return crossed a function boundary,
		// so any finding it feeds must be Medium (interprocOrigins).
		pullReturnTaint := func(target string) {
			if ro := returnTaint[target]; ro != nil && inst.Name != "" {
				markTainted(tainted, inst.Name, ro)
				interprocOrigins[ro] = true
			}
		}

		switch {
		case isSan:
			// A sanitizer neutralizes taint: its result is clean. Critically, we
			// must NOT fall through to the inter-procedural summary blocks below —
			// when the sanitizer is a function lowered from the scanned repo
			// (byKey[callee] != nil), that path would re-taint the sanitizer's
			// result from its own return summary and defeat the sanitizer. Stop here.
			return
		case isSrc:
			if inst.Name != "" {
				markTainted(tainted, inst.Name, inst.Pos)
				// Request-object sources additionally carry provenance so the
				// method-sugar rule below can treat accessor calls on the request
				// object as sources — even for a framework we have no rules for.
				if isRequestObjectSource(callee) {
					reqTainted[inst.Name] = inst.Pos
				}
			}
		case isSink:
			inj := injectableArgs(sinkArgs, callee, args)
			if pos, ok := firstTaintedOrigin(tainted, inj); ok && !reported[inst] {
				// ENG-9: suppress when a validator guard on this flow's source
				// value dominates the sink on the path taken to reach it. The check
				// is left un-reported (not marked) so a later iteration re-evaluates
				// it — it stays suppressed as long as the guard holds.
				if guards.guarded(curBlock, pos, tainted) {
					break
				}
				// SSRF (CWE-918): keep the finding only if the taint can reach the
				// request URL's host. Taint confined to the path/query of a fixed
				// host cannot redirect the request and is a false positive.
				if rule.CWE != "CWE-918" || urlHostControllable(inj, tainted, defs) {
					// Mark reported ONLY when a finding is actually emitted (ENG-8).
					// Setting it before the CWE-918 check masked a real SSRF: a
					// benign, host-fixed flow to this sink would set reported and
					// suppress, blocking a later flow whose taint DOES reach the host
					// (e.g. once an interprocedural summary taints the host segment).
					// Leaving reported unset on suppression lets that real flow fire.
					reported[inst] = true
					steps := reconstructPath(defs, tainted, firstTaintedReg(tainted, inj), pos, inst.Pos)
					res.findings = append(res.findings, Finding{
						RuleID:         rule.ID,
						Severity:       rule.Severity,
						Confidence:     confidenceFor(pos),
						CWE:            rule.CWE,
						Message:        rule.Message,
						Language:       mod.Language,
						Function:       fn.CanonicalName,
						Package:        fn.PackageName,
						SourcePos:      pos,
						SinkPos:        inst.Pos,
						SinkCallee:     callee,
						Steps:          steps,
						RuleSanitizers: rule.Sanitizers,
						RuleSources:    rule.Sources,
					})
				}
			}
		case isProp:
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
				seedInvokeArgs(callee)
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
					if p, ok := reqTaintedArg(a); ok {
						addReqEffect(callee, j, p)
					}
				}
			}
			pullReturnTaint(callee)
			// The callee fills tainted data into one of its out-parameters: taint
			// the argument passed at that position (ENG-6b), using the same
			// arg->param mapping as the seeding above (receiver = param 0 for an
			// INVOKE, args shifted by one; direct alignment otherwise).
			if pm := paramMemTaint[callee]; len(pm) > 0 {
				if inst.Call.GetIsInvoke() {
					if o, ok := pm[0]; ok {
						taintCallerArg(inst.Call.GetValue(), o)
					}
					for j, a := range args {
						if o, ok := pm[j+1]; ok {
							taintCallerArg(a, o)
						}
					}
				} else {
					for j, a := range args {
						if o, ok := pm[j]; ok {
							taintCallerArg(a, o)
						}
					}
				}
			}
		}

		// Inter-procedural, interface dynamic dispatch: an INVOKE call's callee is
		// the abstract interface method, so resolve to concrete implementations by
		// method name (CHA) and flow taint into each. INVOKE args exclude the
		// receiver (it lives in Call.Value), so they map to a concrete method's
		// params shifted by one — param 0 is the receiver.
		if inst.Call.GetIsInvoke() {
			for _, impl := range methodImpls[inst.Call.GetMethodName()] {
				seedInvokeArgs(impl)
				pullReturnTaint(impl)
			}
		}

		// Request-object method sugar (framework-agnostic accessor coverage): a
		// method call whose receiver is a request object — c.Query(), c.Param(),
		// c.Bind(&dst) on a value seeded from a request-object source — yields
		// untrusted data, even for a web framework we have no rules for. This is
		// the typed-Go analogue of the JS "every member read off req is a source"
		// heuristic. It is gated on request-object provenance (reqTainted), so
		// ordinary taint is unaffected, and only fires for an unresolved/external
		// callee that the switch above did not already classify as a
		// source/sink/sanitizer/propagator.
		if byKey[callee] == nil && !isSink && !isSrc && !isSan && !isProp {
			if recv := methodReceiverReg(inst); recv != "" {
				if origin, ok := reqTainted[recv]; ok {
					if inst.Name != "" {
						markTainted(tainted, inst.Name, origin)
					}
					// c.Bind(&dst): the accessor fills untrusted data into a
					// pointer argument's memory. Restrict to address-typed args so
					// a by-value argument is never falsely tainted.
					for _, a := range methodOutParamArgs(inst) {
						if reg := a.GetRegName(); reg != "" && isAddressArg(defs, reg) {
							taintCallerArg(a, origin)
						}
					}
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
		// A read of a tainted global seeds the result regardless of the reading
		// opcode (ENG-6); runs before the switch so the register is tainted for
		// any subsequent same-pass use.
		readGlobalTaint(inst)
		switch inst.Op {
		case ir.OpCode_OP_CODE_CALL, ir.OpCode_OP_CODE_INVOKE:
			handleCall(inst)
		case ir.OpCode_OP_CODE_STORE:
			visitStore(inst, defs, tainted, nonEscaping)
			recordGlobalStore(inst)
			recordParamMemoryTaint(inst)
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

	// Flow-sensitive intra-procedural dataflow (ENG-2). Each block's entry state
	// is the union of its predecessors' exit states (plus the parameter seeds at
	// the entry block); the block is then transferred forward over its
	// instructions, with STORE giving non-escaping alloc cells strong-update
	// (un-taint) semantics. Blocks are processed in reverse-post-order and the
	// per-block exit states are iterated to a fixpoint. The join is a union so
	// taint that reaches a program point on ANY path is retained — the pass is
	// strictly more precise than the previous whole-function flat map yet never
	// drops a real flow. Interprocedural effects and findings accumulate
	// monotonically across passes (deduped by effectSeen / reported).
	// Fast path: a function with a single basic block has no control-flow merges
	// or back-edges, so its taint converges in one forward pass. Skip the whole
	// flow-sensitive fixpoint — the per-block `in`/`blockOut` maps, cloneState,
	// preds/rpo indexes, and the multi-pass loop — and just seed and visit once.
	// This is the majority of functions (every straight-line-lowered Python / JS /
	// Ruby / Java / Go-closure body), so it removes most of the engine's
	// per-(rule × function) allocation. seedState is a fresh map owned by this
	// analysis, so visiting mutates it in place harmlessly.
	nBlocks := 0
	var onlyBlock *ir.BasicBlock
	for _, blk := range fn.Blocks {
		if blk != nil {
			nBlocks++
			onlyBlock = blk
		}
	}
	if nBlocks <= 1 {
		tainted = seedState
		if onlyBlock != nil {
			curBlock = onlyBlock.GetIndex()
			for _, inst := range onlyBlock.Instrs {
				if inst != nil {
					visit(inst)
				}
			}
		}
		return res
	}

	rpo := reversePostOrder(fn)
	idxToBlock := map[int32]*ir.BasicBlock{}
	preds := map[int32][]int32{}
	for _, blk := range fn.Blocks {
		if blk == nil {
			continue
		}
		idxToBlock[blk.GetIndex()] = blk
		preds[blk.GetIndex()] = blk.GetPreds()
	}
	entry := int32(-1)
	if len(fn.Blocks) > 0 && fn.Blocks[0] != nil {
		entry = fn.Blocks[0].GetIndex()
	}
	blockOut := map[int32]taintState{}

	// The block-out states ascend monotonically over a finite lattice, so this
	// terminates; maxPasses is a defensive backstop against a pathological CFG.
	const maxPasses = 100000
	for pass := 0; pass < maxPasses; pass++ {
		changed := false
		for _, idx := range rpo {
			blk := idxToBlock[idx]
			if blk == nil {
				continue
			}
			in := taintState{}
			if idx == entry {
				for k, v := range seedState {
					in[k] = v
				}
			}
			for _, p := range preds[idx] {
				for k, v := range blockOut[p] {
					if _, exists := in[k]; !exists {
						in[k] = v
					}
				}
			}
			tainted = in
			curBlock = idx
			for _, inst := range blk.Instrs {
				if inst != nil {
					visit(inst)
				}
			}
			if !statesEqual(blockOut[idx], tainted) {
				blockOut[idx] = cloneState(tainted)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	return res
}

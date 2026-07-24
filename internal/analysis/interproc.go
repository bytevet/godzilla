package analysis

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strconv"
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
	indirectCallees := buildIndirectCallees(byKey)
	keys := slices.Sorted(maps.Keys(byKey))
	idx := &sharedIndex{
		byKey: byKey, modByKey: modByKey, methodImpls: methodImpls,
		callers: callers, globalReaders: globalReaders, indirectCallees: indirectCallees, keys: keys,
		reportable:     e.reportable,
		reqSourceHosts: buildReqSourceHosts(byKey, modByKey, e.rs, e.reportable),
	}

	// Precompile every rule's glob patterns ONCE, single-threaded, before the
	// parallel analysis. This moves shape-classification (and the "#idx" sink
	// parse) out of the hot per-(call-site × pattern) matching path — which then
	// does a lock-free slice walk instead of a mutexed cache lookup per match, the
	// dominant engine cost as rule packs grow. Doing it here (not lazily inside a
	// goroutine) avoids a data race on the shared matcher cache.
	e.rs.Compile()

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

// funcValEffect records that a FUNCTION VALUE (the concrete lowered function
// `target`) was passed as the argument at position `param` of `callee`. It is the
// points-to analogue of callEffect: where callEffect flows taint into a param,
// funcValEffect flows a *callable identity* into a param, so an indirect call on
// that param inside the callee (`fn(x)` where `fn` is a parameter) can be resolved
// back to `target`. This is what makes higher-order-callback taint work — a
// callback passed into a generic helper is tracked across the call boundary — and,
// combined with a frontend that rewrites a deferral API to a synthesized indirect
// call, also covers thread/async dispatch. Mirrors callEffect but carries a target
// function name rather than a source origin.
type funcValEffect struct {
	callee string
	param  int
	target string
}

// funcParamRef identifies a callee parameter slot. It is the key for the
// opaque-callback channel (funcResult.funcOpaque): it records that SOME call site
// passed a value the engine could not resolve to a concrete function into this
// slot. That matters for soundness — the function-value points-to set is then
// INCOMPLETE, so a lone resolved target in it is not provably the only callee and
// an indirect call on the parameter must not bind (otherwise one site's callback
// identity could be paired with another site's taint, a cross-context FP).
type funcParamRef struct {
	callee string
	param  int
}

// paramPositions maps a function-parameter index to a source position. It is the
// shape of every per-function parameter summary: which parameters an out-parameter
// fill writes taint into (taintsParamMemory), which route a string parameter into
// a sink (taintsParamSink), and which arrive already tainted (a callee's seeds).
type paramPositions map[int]*ir.Position

// paramSummaries is the orchestrator's callee-keyed collection of paramPositions —
// one entry per lowered function, accumulated across the worklist. The parameter
// summary channels (paramTaint, paramMemTaint, paramSinkTaint) all share this
// shape and merge/re-enqueue the same way (see merge).
type paramSummaries map[string]paramPositions

// merge records src on callee `name`'s summary with first-seen-wins semantics and,
// when a new parameter index is added, re-enqueues the callee's callers so they
// pick up the new fact. Shared by the out-parameter-memory and sink-wrapper
// channels, which differ only in what they record, not how it propagates.
func (s paramSummaries) merge(name string, src paramPositions, callers map[string][]string, enqueue func(string)) {
	m := s[name]
	if m == nil {
		m = paramPositions{}
		s[name] = m
	}
	changed := false
	for idx, pos := range src {
		if _, exists := m[idx]; !exists {
			m[idx] = pos
			changed = true
		}
	}
	if changed {
		for _, caller := range callers[name] {
			enqueue(caller)
		}
	}
}

// funcResult is the outcome of analyzing one function under a set of
// tainted-parameter seeds.
type funcResult struct {
	findings      []Finding
	returnsOrigin *ir.Position // non-nil if the function can return tainted data
	callEffects   []callEffect
	// funcEffects records that a function value was passed as an argument to a
	// callee (see funcValEffect): the callee's matching parameter then holds that
	// callable, so an indirect call on the parameter resolves to it. This is the
	// cross-function channel for higher-order-callback taint. Mirrors callEffects
	// (a points-to fact rather than taint), but its target store is a SET — a
	// context-insensitive helper called from several sites accumulates the union of
	// callbacks passed to it, and the engine only binds when that set is a singleton.
	funcEffects []funcValEffect
	// funcOpaque records (callee, param) slots that received an UNRESOLVABLE value at
	// some call site (a call-result callback, a lambda, an unmodeled import). Its
	// presence marks the param's points-to set incomplete, disabling the singleton
	// gate for an indirect call on that param — the FP-safety complement of funcEffects.
	funcOpaque    []funcParamRef
	globalEffects []globalEffect
	// taintsParamMemory[i] is set when the function writes tainted data into
	// memory reachable from parameter i (an out-parameter fill, ENG-6b): a store
	// whose address roots at param i. Callers then mark the argument they pass at
	// that position tainted, so `fill(&dst); use(dst)` flows.
	taintsParamMemory paramPositions
	// taintsParamSink[i] is set when tainted data reaching THIS function through
	// STRING parameter i flows into a sink inside its (or a callee's) body — a
	// dependency "sink wrapper" (e.g. Run(cmd string) -> exec.Command(cmd)). The
	// dep-internal finding is scoped out (internal/scan scopeFindings), so the
	// caller reports the flow at ITS call site instead, where the bug actually is
	// (user code passing untrusted data in). The value is the wrapped sink's Pos.
	//
	// Restricted to STRING params on purpose: a raw string flowing into a sink is a
	// precise injection flow, whereas taint reaching a sink through an interface{}/
	// struct/slice param is usually an OVER-APPROXIMATION of reflective library code
	// — an ORM binds the value as a bound parameter (a `?` placeholder), it does not
	// concatenate it into the query string — so summarizing those floods findings
	// (xorm Find/Get/Update et al.). String-only keeps the real wrapper class and
	// drops the reflective-container noise. See the isSink branch in analyzeFunc.
	taintsParamSink paramPositions
}

// logicalArgs returns a call's arguments in SOURCE-LEVEL order, dropping a method
// receiver carried as args[0]. Whether args[0] is a receiver is read from the IR
// the converter supplies, not from the callee-name shape: a statically-resolved
// method call is a non-invoke call that names its method (MethodName set), and
// puts the receiver first; an INVOKE keeps the receiver in Call.Value (args are
// already logical); a free function has no receiver. So logical argument indices
// line up across every language: index 0 is the first real argument.
func logicalArgs(cc *ir.CallCommon) []*ir.Value {
	args := cc.GetArgs()
	if !cc.GetIsInvoke() && cc.GetMethodName() != "" && len(args) > 0 {
		return args[1:]
	}
	return args
}

// injectableArgs returns the subset of a sink call's arguments that are actual
// injection points, given the matched sink's logical injection-point indices.
// Empty indices means every argument is an injection point (the default). This
// lets a sink ignore SAFE argument positions — e.g. the bound parameters of a
// parameterized SQL query — so taint reaching them does not raise a finding.
func injectableArgs(sinkArgs []int32, cc *ir.CallCommon) []*ir.Value {
	if len(sinkArgs) == 0 {
		return cc.GetArgs()
	}
	la := logicalArgs(cc)
	sel := make([]*ir.Value, 0, len(sinkArgs))
	for _, idx := range sinkArgs {
		if idx >= 0 && int(idx) < len(la) {
			sel = append(sel, la[int(idx)])
		}
	}
	return sel
}

// buildIndirectCallees indexes every function that CONTAINS an indirect call — a
// CALL whose callee names no function (Callee == "") and is not an INVOKE, i.e. a
// call through a function VALUE. A function-value points-to fact about a
// parameter is only ever consulted at such a call site, so recording (and
// re-enqueuing on) those facts for a function that has no indirect call is pure
// waste. Gating the higher-order channel on this set keeps its cost off the vast
// majority of functions — critically the large dependency closure a Go scan
// lowers, where nearly every function receives some non-function argument but
// almost none dispatch through a parameter.
func buildIndirectCallees(byKey map[string]*ir.Function) map[string]bool {
	has := map[string]bool{}
	for name, fn := range byKey {
		for _, blk := range fn.Blocks {
			if blk == nil {
				continue
			}
			for _, inst := range blk.Instrs {
				if inst == nil || inst.Call == nil {
					continue
				}
				if inst.Op == ir.OpCode_OP_CODE_CALL && inst.Call.GetCallee() == "" && !inst.Call.GetIsInvoke() {
					has[name] = true
					break
				}
			}
			if has[name] {
				break
			}
		}
	}
	return has
}

// buildMethodImpls builds the class-hierarchy index for dynamic dispatch: a bare
// method name -> every lowered concrete method exposing it. An INVOKE call names
// a method abstractly (not a concrete function), so this lets taint flow into the
// implementations. It over-approximates (any same-named method matches), which is
// why such findings stay Medium confidence. It depends only on the immutable
// function index, so it is built once and shared by every rule.
//
// A frontend marks every method — Go, Python, … — with Function.method_name, so
// the engine identifies methods and their bare name from IR alone, parsing no
// canonical name. The DISPATCH policy (fan out to all implementers vs. resolve
// only when the name is unambiguous) is likewise chosen from IR at the call site,
// via CallCommon.untyped_dispatch, not from any language check here.
func buildMethodImpls(byKey map[string]*ir.Function) map[string][]string {
	methodImpls := map[string][]string{}
	for name, fn := range byKey {
		if bare := fn.GetMethodName(); bare != "" {
			methodImpls[bare] = append(methodImpls[bare], name)
		}
	}
	return methodImpls
}

// sharedIndex holds the rule-independent indexes over the immutable program,
// built once in Analyze and shared read-only across the parallel per-rule
// analyses (no goroutine mutates them). Hoisting them here — rather than
// rebuilding per rule — removes an O(program × rules) instruction walk and the
// allocation that capped parallel scaling.
type sharedIndex struct {
	byKey           map[string]*ir.Function
	modByKey        map[string]*ir.Module
	methodImpls     map[string][]string
	callers         map[string][]string // callee -> its callers (reverse call graph)
	globalReaders   map[string][]string // global name -> functions that read it (ENG-6)
	indirectCallees map[string]bool     // functions containing an indirect (function-value) call
	keys            []string            // byKey names, sorted (deterministic worklist seed)
	// reportable, when non-empty, restricts the initial worklist seed to functions
	// whose module is user-authored; dependency functions are then reached
	// demand-driven via callEffects. Empty seeds every function.
	reportable map[string]bool
	// reqSourceHosts is the set of function keys that CONTAIN a request-object
	// source call (e.g. the Go frontend's synthetic `go:@net/http.Request`,
	// planted at every inbound *http.Request value — including field reads deep
	// inside a lowered framework body like beego/macaron). Such a function is a
	// taint ORIGIN, so it must seed the worklist even when it lives in a
	// dependency module the reportable scope would otherwise reach only
	// demand-driven — a source that never runs produces no taint. Built once,
	// rule-independent (the union of all rules' request_object_sources).
	reqSourceHosts map[string]bool
	// fnDefs memoizes the rule-independent per-function structures (the def map +
	// the non-escaping-alloc set). Both depend only on the immutable function and
	// are read-only after build, so they are built once and shared across the
	// parallel per-rule analyses instead of being rebuilt on every
	// (function x rule x re-enqueue) call — the same O(rules x program) hoist the
	// indexes above already apply to methodImpls/callers/globalReaders.
	fnDefs sync.Map // *ir.Function -> *fnDefsEntry
}

// fnDefsEntry holds the memoized rule-independent per-function analysis inputs.
type fnDefsEntry struct {
	defs        map[string]*ir.Instruction
	nonEscaping map[string]bool
}

// defsFor returns the (def map, non-escaping-alloc set) for fn, building them once
// and caching on the shared index. Both are deterministic pure functions of the
// immutable fn and read-only after build, so concurrent readers share one copy.
func (idx *sharedIndex) defsFor(fn *ir.Function) (map[string]*ir.Instruction, map[string]bool) {
	if v, ok := idx.fnDefs.Load(fn); ok {
		e := v.(*fnDefsEntry)
		return e.defs, e.nonEscaping
	}
	defs := buildDefs(fn)
	e := &fnDefsEntry{defs: defs, nonEscaping: nonEscapingAllocs(fn, defs)}
	actual, _ := idx.fnDefs.LoadOrStore(fn, e)
	e = actual.(*fnDefsEntry)
	return e.defs, e.nonEscaping
}

// buildReqSourceHosts returns the set of DEPENDENCY function keys that both
// (a) contain a request-object source (the union of every rule's
// request_object_sources globs) and (b) are DIRECTLY CALLED by user (reportable)
// code. Such a function — e.g. beego's `Controller.Input`, which reads
// `c.Ctx.Request` internally — generates request taint but takes no tainted
// argument, so the demand-driven dependency scope never enqueues it; seeding it
// lets its request taint escape to the user code that called it. Seeding
// (analyzing the body) rather than tainting the call result unconditionally is
// what keeps a SAFE accessor that reads the request but returns a constant from
// being a false positive: its body has no tainted return, so nothing propagates.
//
// The DIRECT-CALL bound keeps this cheap and correct. A framework reads
// *http.Request in many internal functions, but the ones that matter are the
// accessor methods the app actually invokes (`c.Input()`, `c.Query()`). Crucially
// it EXCLUDES a framework's request-pipeline entry like gin's ServeHTTP: that also
// carries a request source, but user code never CALLS it (it calls user code via
// an indirect dispatch), and seeding it made the worklist analyze a framework's
// whole request pipeline — a large dep-heavy blow-up — for taint no user sink can
// reach. Consulted ONLY under a reportable scope (with no scope every function is
// already seeded), so the whole-program walk is skipped otherwise.
func buildReqSourceHosts(byKey map[string]*ir.Function, modByKey map[string]*ir.Module, rs *rules.RuleSet, reportable map[string]bool) map[string]bool {
	if len(reportable) == 0 {
		return nil
	}
	// Two tiers of source, seeded under different bounds:
	//
	//   reqObjGlobs — request_object_sources: the synthetic *http.Request, which
	//     the frontend also plants on a framework's request-pipeline ENTRY (gin's
	//     ServeHTTP receives the request too). Seeding such an entry makes the
	//     worklist push request taint through the whole framework pipeline — a
	//     dep-heavy blow-up — so these are seeded ONLY when user code calls the
	//     host DIRECTLY (an app calls `c.Input()`, never the pipeline entry).
	//
	//   srcGlobs — ordinary sources (framework accessors: gin `c.Query`, echo
	//     `c.Param`, …). A function hosting one of these CALLS the accessor and
	//     yields a bounded string result; the pipeline entry does not call them.
	//     So these are seeded at ANY depth, no direct-call bound — that closes the
	//     nested-wrapper case (user → svc.Fetch → requtil.ReadQuery → c.Query):
	//     seeding the innermost host fires the source, and the engine's
	//     caller-re-enqueue then carries the return taint up the wrapper chain.
	//
	// @net/http.Request appears in BOTH lists (it is declared as a plain source
	// too), so it is removed from srcGlobs below to keep it gated — otherwise the
	// pipeline entry would be ungated and the blow-up would return.
	reqObjSet := map[string]bool{}
	var reqObjGlobs, srcGlobs []string
	seen := map[string]bool{}
	for i := range rs.Rules {
		for _, s := range rs.Rules[i].RequestObjectSources {
			if !reqObjSet[s] {
				reqObjSet[s] = true
				reqObjGlobs = append(reqObjGlobs, s)
			}
		}
	}
	for i := range rs.Rules {
		for _, s := range rs.Rules[i].Sources {
			if !seen[s] && !reqObjSet[s] {
				seen[s] = true
				srcGlobs = append(srcGlobs, s)
			}
		}
	}
	if len(reqObjGlobs) == 0 && len(srcGlobs) == 0 {
		return nil
	}
	// Callees invoked DIRECTLY by user code (by canonical name — byKey is keyed on
	// it), the gate for the request-object tier.
	userCallees := map[string]bool{}
	for key, fn := range byKey {
		if fn == nil {
			continue
		}
		if mod := modByKey[key]; mod == nil || !reportable[mod.Name] {
			continue
		}
		for _, b := range fn.Blocks {
			for _, inst := range b.Instrs {
				if inst.GetCall() == nil {
					continue
				}
				if callee := inst.Call.GetCallee(); callee != "" {
					userCallees[callee] = true
				}
			}
		}
	}

	hosts := map[string]bool{}
	for key, fn := range byKey {
		if fn == nil {
			continue
		}
		// Dependency functions only (user code is already seeded).
		if mod := modByKey[key]; mod == nil || reportable[mod.Name] {
			continue
		}
		userCalled := userCallees[key]
	scan:
		for _, b := range fn.Blocks {
			for _, inst := range b.Instrs {
				if inst.GetCall() == nil {
					continue
				}
				callee := inst.Call.GetCallee()
				if callee == "" {
					continue
				}
				// Ordinary framework-accessor source: seed at any depth.
				if rules.MatchAny(srcGlobs, callee) {
					hosts[key] = true
					break scan
				}
				// Request-object source: seed only if user code calls this host
				// directly (excludes the framework's pipeline entry).
				if userCalled && rules.MatchAny(reqObjGlobs, callee) {
					hosts[key] = true
					break scan
				}
			}
		}
	}
	return hosts
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

// analyzeInterproc runs the worklist-based inter-procedural taint analysis for
// a single rule. State (parameter taint, return taint) grows monotonically, so
// iteration converges.
func analyzeInterproc(idx *sharedIndex, rule *rules.Rule) []Finding {
	byKey, modByKey, methodImpls := idx.byKey, idx.modByKey, idx.methodImpls
	callers, globalReaders := idx.callers, idx.globalReaders
	indirectCallees := idx.indirectCallees
	paramTaint := paramSummaries{}
	// paramFuncVal is the function-value points-to summary: callee -> param index ->
	// the SET of concrete functions that param can hold, accumulated across every
	// call site (context-insensitive). An indirect call on that param binds only
	// when the set is a singleton (see the resolution branch in handleCall), the
	// same unambiguous-only discipline untyped_dispatch uses. Higher-order channel.
	paramFuncVal := map[string]map[int]map[string]bool{}
	// paramFuncOpaque[callee][param] is set when some call site passed an
	// unresolvable value into that function-value slot, so its points-to set is
	// incomplete and the singleton gate must not fire for it (see funcParamRef).
	paramFuncOpaque := map[string]map[int]bool{}
	returnTaint := map[string]*ir.Position{}
	globalTaint := map[string]*ir.Position{}
	paramMemTaint := paramSummaries{}  // callee -> out-param index -> origin (ENG-6b)
	paramSinkTaint := paramSummaries{} // callee -> string-param index -> wrapped sink pos (dep sink wrapper)
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
		// When a reportable scope is set, seed only its modules (user code); a
		// module outside it is a lowered dependency, reached demand-driven. The
		// scope is a neutral module-name set the caller supplies (ScopeSeed) — the
		// engine makes no language distinction. An empty scope seeds everything.
		if len(idx.reportable) > 0 {
			if mod := idx.modByKey[name]; mod != nil && !idx.reportable[mod.Name] {
				// A dependency function is reached demand-driven. But a source-host that
				// user code DIRECTLY CALLS (idx.reqSourceHosts) is seeded: it generates
				// request taint internally (no tainted arg would ever enqueue it), and
				// analyzing its body is what correctly decides whether its RESULT is
				// actually request-derived (vs a safe accessor that reads the request but
				// returns a constant). Its own findings stay scoped out to user code.
				if !idx.reqSourceHosts[name] {
					continue
				}
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

		// funcReportable: a finding raised HERE survives scopeFindings (it is user
		// code). When false (a lowered dependency), a sink reached inside this
		// function is scoped out, so we summarize its string-param sink flows for the
		// caller to report instead (taintsParamSink). An empty scope makes every
		// function reportable, matching the "seed everything" mode above.
		funcReportable := len(idx.reportable) == 0 || idx.reportable[mod.Name]
		res := analyzeFunc(idx, mod, fn, rule, paramTaint[name], paramFuncVal[name], paramFuncOpaque[name], returnTaint, globalTaint, paramMemTaint, paramSinkTaint, byKey, methodImpls, indirectCallees, reported, funcReportable)
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
				m = paramPositions{}
				paramTaint[ce.callee] = m
			}
			if _, exists := m[ce.param]; !exists {
				m[ce.param] = ce.origin
				enqueue(ce.callee)
			}
		}

		// A function value flowing into a callee parameter (higher-order channel):
		// merge the target into paramFuncVal[callee][param] and re-enqueue the callee
		// so an indirect call on that parameter can now resolve. Merge is first-seen
		// per (callee, param, target) so the worklist stays monotonic and converges;
		// a new distinct target for an already-seen param still re-enqueues, because a
		// param that was a resolvable singleton can become ambiguous and must be
		// re-analyzed under the singleton gate.
		for _, fe := range res.funcEffects {
			m := paramFuncVal[fe.callee]
			if m == nil {
				m = map[int]map[string]bool{}
				paramFuncVal[fe.callee] = m
			}
			set := m[fe.param]
			if set == nil {
				set = map[string]bool{}
				m[fe.param] = set
			}
			if !set[fe.target] {
				set[fe.target] = true
				enqueue(fe.callee)
			}
		}

		// An unresolvable value reached a function-value slot: mark it opaque so the
		// singleton gate no longer trusts a lone resolved target there. First-seen
		// gated and re-enqueues the callee, mirroring the funcEffects merge.
		for _, fo := range res.funcOpaque {
			m := paramFuncOpaque[fo.callee]
			if m == nil {
				m = map[int]bool{}
				paramFuncOpaque[fo.callee] = m
			}
			if !m[fo.param] {
				m[fo.param] = true
				enqueue(fo.callee)
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
			paramMemTaint.merge(name, res.taintsParamMemory, callers, enqueue)
		}

		// This (dependency) function routes one of its string parameters into a sink
		// (taintsParamSink): record it on the callee's summary and re-enqueue its
		// callers so a call passing tainted data at that position reports the flow at
		// its own site. Mirrors the out-parameter-memory channel above.
		if len(res.taintsParamSink) > 0 {
			paramSinkTaint.merge(name, res.taintsParamSink, callers, enqueue)
		}
	}

	return findings
}

// newTaintFinding builds a source->sink Finding with the fields shared by every
// taint report: the matched rule's identity/severity/message/globs, the enclosing
// function's name+package (for user-code scoping), and the flow's positions. The
// two call sites (a direct sink, and a dependency sink-wrapper reported at the
// caller) differ only in Confidence and which positions they pass, so they share
// this constructor to stay in lockstep as Finding evolves.
func newTaintFinding(rule *rules.Rule, mod *ir.Module, fn *ir.Function, srcPos, sinkPos *ir.Position, callee string, steps []*ir.Position, conf Confidence) Finding {
	return Finding{
		RuleID:         rule.ID,
		Severity:       rule.Severity,
		Confidence:     conf,
		CWE:            rule.CWE,
		Message:        rule.Message,
		Language:       mod.Language,
		Function:       fn.CanonicalName,
		Package:        fn.PackageName,
		SourcePos:      srcPos,
		SinkPos:        sinkPos,
		SinkCallee:     callee,
		Steps:          steps,
		RuleSanitizers: rule.Sanitizers,
		RuleSources:    rule.Sources,
	}
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

// isStringType reports whether a gIR type is a string: a basic string, or a
// named type whose underlying type is a string (e.g. `type Host string`). Used to
// restrict dependency sink-wrapper summaries to string parameters (taintsParamSink).
func isStringType(t *ir.Type) bool {
	if t == nil {
		return false
	}
	switch t.GetKind() {
	case ir.TypeKind_TYPE_KIND_BASIC:
		return t.GetBasicKind() == ir.BasicTypeKind_BASIC_TYPE_KIND_STRING
	case ir.TypeKind_TYPE_KIND_NAMED:
		return isStringType(t.GetUnderlyingType())
	default:
		return false
	}
}

// analyzeFunc runs the intra-procedural fixpoint for one function, seeded with
// tainted parameters, and reports the sinks it hits, whether it returns taint,
// and the taint it passes to callees.
func analyzeFunc(
	idx *sharedIndex,
	mod *ir.Module,
	fn *ir.Function,
	rule *rules.Rule,
	seeds paramPositions,
	funcSeeds map[int]map[string]bool,
	opaqueSeeds map[int]bool,
	returnTaint map[string]*ir.Position,
	globalTaint map[string]*ir.Position,
	paramMemTaint paramSummaries,
	paramSinkTaint paramSummaries,
	byKey map[string]*ir.Function,
	methodImpls map[string][]string,
	indirectCallees map[string]bool,
	reported map[*ir.Instruction]bool,
	funcReportable bool,
) funcResult {
	// tainted is the CURRENT block's taint state; the flow-sensitive driver
	// (ENG-2) reassigns it to each block's entry state before visiting the block,
	// so the transfer closures below (which capture this variable) always operate
	// on the right per-block facts.
	tainted := map[string]*ir.Position{}
	defs, nonEscaping := idx.defsFor(fn)

	// Guard/barrier index (ENG-9), built once and only for a rule that declares
	// validators (nil otherwise, so the common path pays nothing). curBlock tracks
	// the block being visited so a sink can ask whether a validator guard
	// dominates it on the path taken.
	guards := buildGuardIndex(fn, rule, defs)
	var curBlock int32

	// linearFn marks a single-basic-block function — the straight-line-lowered
	// Python/JS/Ruby/Java bodies, which carry NO CFG, so the dominance-based guard
	// index above can never fire for them. In one linear block, program order IS
	// dominance: a validator applied to a value before that value is returned
	// guards the return just as a dominating branch would. validated records the
	// registers a rule validator has been applied to, consulted only in the linear
	// case at a RET (the CFG path keeps using the precise dominator guard).
	// Count non-nil blocks once (reused by the single-block fast path below). A
	// single-block function is linear: it has no CFG for the dominator guard, so
	// program order stands in for dominance at a RET (see validated).
	nBlocks := 0
	var onlyBlock *ir.BasicBlock
	for _, blk := range fn.Blocks {
		if blk != nil {
			nBlocks++
			onlyBlock = blk
		}
	}
	linearFn := nBlocks <= 1
	validated := map[string]bool{}

	// Seed tainted parameters into the entry block's in-state. A flow that enters
	// through a parameter is inter-procedural, which lowers the confidence of any
	// finding it feeds. interprocOrigins records every source origin whose taint
	// crossed a function boundary to reach this function — parameter seeds here,
	// plus taint pulled back from a callee's return summary in handleCall.
	// confidenceFor consults it so all cross-function findings are Medium (and
	// thus seen by the LLM reviewer).
	interprocOrigins := map[*ir.Position]bool{}

	seedState := taintState{}
	for idx, origin := range seeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				seedState[reg] = origin
				interprocOrigins[origin] = true
			}
		}
	}

	// paramOrigins inverts the parameter seeds: a tainted value whose origin is a
	// seed origin entered THIS function through that parameter (even after a
	// propagator transforms it, since propagation preserves the origin position).
	// Used to attribute a sink-reaching value back to the string parameter it
	// arrived on, for the dependency sink-wrapper summary (taintsParamSink).
	paramOrigins := map[*ir.Position]int{}
	for idx, origin := range seeds {
		paramOrigins[origin] = idx
	}
	// fnIsSink marks a function that is itself a modeled sink for this rule (e.g.
	// gorm db.Raw). Its direct call site already fires, so it must NOT also form a
	// sink-wrapper summary — that would double-report every db.Raw(tainted) call.
	_, fnIsSink := rule.SinkInjectionArgs(fn.CanonicalName)
	// stringParam reports whether logical parameter i (an index into fn.Params) is
	// a string. Only string-param sink flows form a taintsParamSink summary — see
	// that field's doc. fn.Params carries the SSA receiver at index 0 for a method,
	// while Signature.Params excludes it, so shift by the receiver when present.
	recvOffset := 0
	if fn.GetSignature().GetRecv() != nil {
		recvOffset = 1
	}
	sigParams := fn.GetSignature().GetParams()
	stringParam := func(i int) bool {
		si := i - recvOffset
		if si < 0 || si >= len(sigParams) {
			return false // receiver or captured free variable: not a wrapper param
		}
		return isStringType(sigParams[si])
	}
	// funcVal maps a register to the SET of concrete functions it can hold (a
	// points-to fact). It is function-scoped and monotonic — a callable identity is
	// a property of the value, not a per-block fact — so it is NOT
	// reset by the flow-sensitive block driver. Seeded from the caller-supplied
	// funcSeeds (which param holds which callback), so an indirect call on a
	// parameter can be resolved to the function value the caller passed in.
	funcVal := map[string]map[string]bool{}
	for idx, targets := range funcSeeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				funcVal[reg] = maps.Clone(targets)
			}
		}
	}
	// funcValOpaque marks a register whose function-value set is incomplete (some
	// caller passed an unresolvable value into the parameter it was seeded from), so
	// the indirect-call singleton gate must not fire for it. Function-scoped and
	// monotonic, like funcVal.
	funcValOpaque := map[string]bool{}
	for idx := range opaqueSeeds {
		if idx >= 0 && idx < len(fn.Params) {
			if reg := fn.Params[idx].GetRegName(); reg != "" {
				funcValOpaque[reg] = true
			}
		}
	}

	// targetsOf resolves a value to the concrete lowered function(s) it may hold:
	// a FuncName is looked up directly in byKey (the make_closure resolution
	// pattern) — this covers a function passed by reference and a frontend-
	// synthesized deferral call whose target is known at the site; a RegName is
	// resolved through the function-scoped funcVal points-to set (a callback
	// received as a parameter). Anything else — an opaque/foreign callable we did
	// not lower — yields nil, so an unresolvable value binds nothing (a false
	// negative, never a false positive). Keys are sorted for determinism.
	targetsOf := func(v *ir.Value) []string {
		if v == nil {
			return nil
		}
		if name := v.GetFuncName(); name != "" {
			if byKey[name] != nil {
				return []string{name}
			}
			return nil
		}
		if reg := v.GetRegName(); reg != "" {
			if set := funcVal[reg]; len(set) > 0 {
				return slices.Sorted(maps.Keys(set))
			}
		}
		return nil
	}
	// indirectOpaque reports whether a callback value's points-to set is known to be
	// incomplete (a caller passed an unresolvable value into the param it came from),
	// so the singleton gate must not fire. Only a register-held callback can be
	// opaque; a FuncName is an exact, complete target.
	indirectOpaque := func(v *ir.Value) bool {
		if reg := v.GetRegName(); reg != "" {
			return funcValOpaque[reg]
		}
		return false
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

	// addFuncEffect records that a function value flowed into a callee parameter
	// (the higher-order channel). Dedup is keyed on callee#param#target — unlike the
	// taint/req channels, which store a single origin per (callee,param), this stores
	// a SET, so two distinct callbacks passed to the same param must BOTH be recorded
	// (that is exactly what makes the param ambiguous and disables the singleton gate).
	funcEffectSeen := map[string]bool{}
	addFuncEffect := func(callee string, param int, target string) {
		if callee == "" || target == "" {
			return
		}
		key := callee + "#" + strconv.Itoa(param) + "#" + target
		if funcEffectSeen[key] {
			return
		}
		funcEffectSeen[key] = true
		res.funcEffects = append(res.funcEffects, funcValEffect{callee: callee, param: param, target: target})
	}

	// addFuncOpaque records that an unresolvable value reached a callee's
	// function-value slot (struct-keyed dedup, no per-arg string alloc). Called only
	// for a non-constant argument that targetsOf could not resolve.
	funcOpaqueSeen := map[funcParamRef]bool{}
	addFuncOpaque := func(callee string, param int) {
		if callee == "" {
			return
		}
		k := funcParamRef{callee: callee, param: param}
		if funcOpaqueSeen[k] {
			return
		}
		funcOpaqueSeen[k] = true
		res.funcOpaque = append(res.funcOpaque, k)
	}

	// recordFuncArg emits the points-to effect for a callback argument: each
	// resolved target, or an opaque marker when the value is a non-constant the
	// resolver could not pin to a concrete function. A constant can never be a
	// callable, so it contributes neither. Gated on the callee actually containing
	// an indirect call — a function that never dispatches through a parameter can
	// never consult these facts, so recording them (and re-enqueuing on them) would
	// be pure overhead on the large dependency closure a Go scan lowers.
	recordFuncArg := func(callee string, param int, a *ir.Value) {
		if !indirectCallees[callee] {
			return
		}
		if ts := targetsOf(a); len(ts) > 0 {
			for _, t := range ts {
				addFuncEffect(callee, param, t)
			}
		} else if a.GetConstant() == nil {
			addFuncOpaque(callee, param)
		}
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
			res.taintsParamMemory = paramPositions{}
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
		// An indirect call names no callee (Callee == ""); its callee is a function
		// VALUE in Call.Value, resolved below. Skip source/sink/sanitizer/propagator
		// classification entirely for it — a glob has no callee string to match, and
		// this also neutralizes a latent coupling where an empty pattern would match
		// the empty name. Purely structural; no language check.
		indirect := callee == ""
		var sinkArgs []int32
		var isSink, isSan, isSrc, isProp bool
		if !indirect {
			// Classify the callee once. These globs are the engine's hottest per-(call
			// × rule) work; the switch below and the request-object method-sugar gate
			// both consult the same predicates, so compute them a single time.
			sinkArgs, isSink = rule.SinkInjectionArgs(callee)
			isSan = rule.IsSanitizer(callee)
			isSrc = rule.IsSource(callee)
			isProp = rule.IsPropagator(callee) || rules.IsDefaultPropagator(callee)
			// The Go `append` builtin propagates taint ONLY when its result is a
			// byte/rune slice — i.e. character-level string reconstruction (the
			// make([]byte); append(data, s[i]); string(data) idiom of a non-sanitizing
			// normalize/snake_case helper). It is NOT a blanket propagator: append is
			// called on every slice in a program, so tainting through slices of structs
			// /pointers explodes the taint set in framework code (a large scan slowdown).
			if !isProp && callee == "builtin.append" && isByteOrRuneSlice(inst.GetType()) {
				isProp = true
			}
		}

		// Record a validator application (ENG-9, linear case): mark the checked
		// registers so a later RET of one of them in this same straight-line block
		// is treated as validated. Cheap and gated on the rule declaring validators.
		if linearFn && rule.HasValidators() && rule.IsValidator(callee) {
			if v := inst.Call.GetValue(); v != nil {
				if r := v.GetRegName(); r != "" {
					validated[r] = true
				}
			}
			for _, a := range args {
				if r := a.GetRegName(); r != "" {
					validated[r] = true
				}
			}
		}

		// seedInvokeArgs maps an INVOKE call's operands onto target's params: the
		// receiver (Call.Value) to param 0, then each explicit arg shifted by one.
		// Shared by the lowered-method branch and the CHA dynamic-dispatch loop
		// below, which resolve different targets but seed them identically.
		seedInvokeArgs := func(target string) {
			if p, ok := isTaintedArg(tainted, inst.Call.GetValue()); ok {
				addEffect(target, 0, p)
			}
			for j, a := range args {
				if p, ok := isTaintedArg(tainted, a); ok {
					addEffect(target, j+1, p)
				}
				recordFuncArg(target, j+1, a)
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
			}
		case isSink:
			inj := injectableArgs(sinkArgs, inst.Call)
			if srcReg, pos, ok := firstTainted(tainted, inj); ok && !reported[inst] {
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
					steps := reconstructPath(defs, tainted, srcReg, pos, inst.Pos)
					res.findings = append(res.findings, newTaintFinding(rule, mod, fn, pos, inst.Pos, callee, steps, confidenceFor(pos)))
					// Dependency sink wrapper: this finding will be scoped out (the sink
					// sits in a library). If the tainted value entered through one of THIS
					// function's string parameters, summarize it so the caller reports the
					// flow at its own (user-code) call site. Skip when this function is
					// itself a modeled sink — its direct call site already fires, so a
					// summary would double-report. See taintsParamSink.
					if !funcReportable && !fnIsSink {
						if k, isParam := paramOrigins[pos]; isParam && stringParam(k) {
							if res.taintsParamSink == nil {
								res.taintsParamSink = paramPositions{}
							}
							if _, exists := res.taintsParamSink[k]; !exists {
								res.taintsParamSink[k] = inst.Pos
							}
						}
					}
				}
			}
		case isProp:
			// A propagating call carries taint from any of its operands to its
			// result. This covers the rule's own propagators and the built-in
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
					// A function value passed as an argument records a points-to fact
					// on the callee's param, so an indirect call on that param inside
					// the callee resolves back to it (higher-order channel); an
					// unresolvable value marks the slot opaque (FP-safety).
					recordFuncArg(callee, j, a)
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

		// Dependency sink-wrapper summary (taintsParamSink): the callee routes one of
		// its string parameters into a sink internally, and that sink's own finding was
		// scoped out. If we pass tainted data at that position, the vulnerability is
		// HERE. In user code, report it at this call site; in another dependency,
		// propagate it up as this function's own sink-param summary so the finding
		// ultimately lands on user code. Uses the same arg->param mapping as the seeding
		// above (receiver = param 0 for an INVOKE, args shifted by one; direct otherwise).
		if psk := paramSinkTaint[callee]; len(psk) > 0 {
			consumeSink := func(paramIdx int, a *ir.Value) {
				sinkPos, summarized := psk[paramIdx]
				if !summarized {
					return
				}
				pos, ok := isTaintedArg(tainted, a)
				if !ok {
					return
				}
				// A validator dominating this flow's source suppresses it, exactly as at
				// a direct sink (ENG-9).
				if guards.guarded(curBlock, pos, tainted) {
					return
				}
				if funcReportable {
					if reported[inst] {
						return
					}
					reported[inst] = true
					steps := reconstructPath(defs, tainted, a.GetRegName(), pos, inst.Pos)
					res.findings = append(res.findings, newTaintFinding(rule, mod, fn, pos, inst.Pos, callee, steps, ConfidenceMedium)) // SinkPos = user call into the wrapper; Medium: sink across a call boundary
				} else if !fnIsSink {
					// Still inside a dependency: propagate the summary up if the tainted
					// arg forwards one of THIS function's string parameters.
					if k, isParam := paramOrigins[pos]; isParam && stringParam(k) {
						if res.taintsParamSink == nil {
							res.taintsParamSink = paramPositions{}
						}
						if _, exists := res.taintsParamSink[k]; !exists {
							res.taintsParamSink[k] = sinkPos
						}
					}
				}
			}
			if inst.Call.GetIsInvoke() {
				consumeSink(0, inst.Call.GetValue())
				for j, a := range args {
					consumeSink(j+1, a)
				}
			} else {
				for j, a := range args {
					consumeSink(j, a)
				}
			}
		}

		// Inter-procedural, INDIRECT call through a function value: the callee is not
		// a named function (byKey[callee]==nil) and this is not an INVOKE — the target
		// is a function VALUE in Call.Value. This is the unifying primitive for
		// higher-order callbacks (`fn(x)` where fn is a callback parameter, resolved
		// via funcVal) and frontend-synthesized deferral/thread dispatch (target a
		// FuncName known at the site). Resolve the value and flow the args into the
		// target's FRONT params (no receiver shift — a plain call), then pull the
		// target's return taint back into this call's result.
		//
		// Binds ONLY when the resolved target set is a singleton — the same
		// unambiguous-only discipline untyped_dispatch uses. A generic helper called
		// with several distinct callbacks accumulates a union in funcVal; binding one
		// caller's taint into a different caller's callback would be an unsound,
		// FP-generating cross-context pairing, so an ambiguous set binds nothing.
		if indirect && !inst.Call.GetIsInvoke() {
			v := inst.Call.GetValue()
			// Bind only a singleton, COMPLETE points-to set: an opaque contribution
			// (some caller passed an unresolvable value into this callback slot) means
			// the lone resolved target is not provably the only callee, so binding it
			// would risk pairing one site's callback with another site's taint.
			if targets := targetsOf(v); len(targets) == 1 && !indirectOpaque(v) {
				target := targets[0]
				for j, a := range args {
					if p, ok := isTaintedArg(tainted, a); ok {
						addEffect(target, j, p)
					}
					recordFuncArg(target, j, a)
				}
				pullReturnTaint(target)
			}
		}

		// Inter-procedural, interface dynamic dispatch: an INVOKE call's callee is
		// the abstract interface method, so resolve to concrete implementations by
		// method name (CHA) and flow taint into each. INVOKE args exclude the
		// receiver (it lives in Call.Value), so they map to a concrete method's
		// params shifted by one — param 0 is the receiver.
		if inst.Call.GetIsInvoke() {
			// The dispatch discipline comes from IR the converter supplies, not from
			// any language check in the engine. When the frontend resolved the call
			// by bare method NAME with no static receiver type (untyped_dispatch —
			// the untyped languages), apply it ONLY when the name is unambiguous:
			// otherwise a polymorphic name like `run_query`/`execute` would seed
			// taint into every same-named method across unrelated classes, a
			// cross-object fan-out that floods real code with false positives. A
			// type-resolved invoke (a Go interface method) carries the standard,
			// type-bounded CHA over-approximation, so it fans out to every implementer.
			impls := methodImpls[inst.Call.GetMethodName()]
			if inst.Call.GetUntypedDispatch() {
				if len(impls) == 1 {
					seedInvokeArgs(impls[0])
					pullReturnTaint(impls[0])
				}
			} else {
				for _, impl := range impls {
					seedInvokeArgs(impl)
					pullReturnTaint(impl)
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
			if _, pos, ok := firstTainted(tainted, inst.GetOperands()); ok && res.returnsOrigin == nil {
				// Interprocedural ENG-9: a tainted value returned on a path a
				// validator guard dominates (`if !valid(x) { return "" }; return x`)
				// is validated on every returning path, so the function is not
				// taint-returning for this rule. Suppressing the return summary
				// stops a sanitized value from tainting callers — the cross-function
				// analogue of the intra-procedural guarded-sink suppression below.
				// The CFG guard covers multi-block functions; validated covers the
				// single-block (no-CFG) straight-line case where order is dominance.
				retValidated := false
				if linearFn {
					for _, op := range inst.GetOperands() {
						if r := op.GetRegName(); r != "" && validated[r] {
							retValidated = true
							break
						}
					}
				}
				if !retValidated && !guards.guarded(curBlock, pos, tainted) {
					res.returnsOrigin = pos
				}
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
	// analysis, so visiting mutates it in place harmlessly. nBlocks/onlyBlock were
	// computed once above (also feeding linearFn).
	if linearFn {
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
				maps.Copy(in, seedState)
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

package analysis

import (
	"fmt"
	"godzilla/internal/irwalk"
	"maps"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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

	// The name->function index (see buildFuncIndex) and the class-hierarchy
	// method index for interface dynamic dispatch (a bare method name -> every
	// lowered concrete method that implements it, see buildMethodImpls). Both
	// depend only on the immutable program, so each is built ONCE and shared by
	// every rule AND by the call graph — rebuilding either per rule (as before)
	// wasted O(rules x functions) work, and the call graph keeping near-duplicate
	// private copies invited the two policies to drift.
	byKey, modByKey := buildFuncIndex(prog)
	methodImpls := buildMethodImpls(byKey)

	cg := buildCallGraph(byKey, methodImpls)

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
		fnIdx:          make(map[*ir.Function]fnIndex, len(byKey)),
	}

	// Precompile every rule's glob patterns ONCE, single-threaded, before the
	// parallel analysis. This moves shape-classification (and the "#idx" sink
	// parse) out of the hot per-(call-site × pattern) matching path — which then
	// does a lock-free slice walk instead of a mutexed cache lookup per match, the
	// dominant engine cost as rule packs grow. Doing it here (not lazily inside a
	// goroutine) avoids a data race on the shared matcher cache.
	_ = e.rs.Compile() // guard-compile errors are already reported by the loader at load

	// Languages actually present in this program, for the language half of
	// canProduceFinding below.
	progLangs := map[string]bool{}
	for _, mod := range prog.Modules {
		if mod != nil {
			progLangs[mod.GetLanguage()] = true
		}
	}

	// canProduceFinding decides whether a rule is worth a goroutine and a seeded
	// worklist at all. A pass costs an O(functions × instructions) walk, so a rule
	// that CANNOT yield a finding must not get one — with a 78-rule pack, 61-74% of
	// the passes were exactly that.
	//
	// Two independent reasons a rule is a guaranteed no-op:
	//
	//   - NO SINKS. Dataflow findings are emitted in exactly two places, and both
	//     sit behind a sink match: the isSink branch, and the dependency
	//     sink-wrapper path, whose summary recordSinkParam only ever writes from
	//     inside that same branch. MatchSink over an empty sink list always returns
	//     false, so there is no path to a finding. This is what excludes the
	//     `kind: secret` and `kind: dangerous-call` rules — they are evaluated by
	//     ScanSecrets and ScanDangerousCalls, not here — and it catches a malformed
	//     rule too. Tested on the CONCRETE property (no sinks) rather than on the
	//     kind, because that property is the actual reason.
	//
	//   - NO LANGUAGE IN COMMON with the program. enqueue rejects every function
	//     whose module language fails AppliesTo, so the worklist would stay empty.
	//     A rule declaring no languages applies everywhere and is never skipped.
	//
	//   - NO SINK CALLEE PRESENT. Every one of the rule's sink globs matches
	//     nothing this program actually calls, so no call site can ever be a sink
	//     for it. This is what makes a broad multi-language pack cheap on a repo
	//     that uses few of the modeled libraries: the distinct-callee set is a
	//     BY-PRODUCT of buildCallGraph (cg.Callees) rather than its own walk, and
	//     it is far smaller than the instruction count (54 vs 637 on
	//     test/go/sql_injection), so the check costs |callees| × |sink patterns|
	//     once instead of a full worklist pass. Collecting it in a separate walk
	//     measured +6.6% on a dependency-heavy Go scan — more than it saved.
	//
	//     Gated on SINKS ONLY, never sources. Taint also enters through seeding
	//     that is not a callee-glob match at all — addHTTPRequestSource,
	//     buildReqSourceHosts, request-object provenance — so a source-side
	//     prefilter could drop real findings. A sink is always a call.
	hasSinkCallee := func(r *rules.Rule) bool {
		for callee := range cg.Callees {
			if _, _, ok := r.MatchSink(callee); ok {
				return true
			}
		}
		return false
	}
	canProduceFinding := func(r *rules.Rule) bool {
		if len(r.Sinks) == 0 {
			return false
		}
		if len(r.Languages) > 0 {
			any := false
			for lang := range progLangs {
				if r.AppliesTo(lang) {
					any = true
					break
				}
			}
			if !any {
				return false
			}
		}
		return hasSinkCallee(r)
	}

	// Phase 1: decide which rules can produce a finding at all. An inert rule
	// must cost one boolean and NEVER a goroutine — with a pack of mostly-inert
	// rules the per-rule spawn/semaphore overhead dominated the skip it bought
	// (Engine_InertRules regressed 2x when this check briefly ran inside the
	// per-rule goroutines). The check is |callees| × |sink patterns| per rule,
	// so on a dependency-heavy scan (tens of thousands of distinct callees) the
	// serial ramp in front of the workers is real — parallelize it across a
	// small fixed pool, but only past a size threshold so small scans and
	// microbenchmarks keep the zero-spawn serial path. Safe concurrently:
	// every matcher was compiled by e.rs.Compile() above, so this only reads.
	live := make([]bool, len(e.rs.Rules))
	if len(e.rs.Rules)*len(cg.Callees) >= 1<<15 {
		var pre sync.WaitGroup
		var next atomic.Int64
		for w := 0; w < min(runtime.GOMAXPROCS(0), len(e.rs.Rules)); w++ {
			pre.Add(1)
			go func() {
				defer pre.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= len(e.rs.Rules) {
						return
					}
					live[i] = canProduceFinding(&e.rs.Rules[i])
				}
			}()
		}
		pre.Wait()
	} else {
		for i := range e.rs.Rules {
			live[i] = canProduceFinding(&e.rs.Rules[i])
		}
	}

	// Phase 2: each live rule's analysis is independent — it reads the shared,
	// immutable call graph / function index and writes only its own local state —
	// so run the rules concurrently (bounded by GOMAXPROCS). Results are
	// collected per rule index and concatenated in rule order, so output stays
	// deterministic; a skipped rule's nil slot is exactly what an empty worklist
	// returns.
	results := make([][]Finding, len(e.rs.Rules))
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i := range e.rs.Rules {
		if !live[i] {
			continue
		}
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
	// drops the reflective-container noise. See the isSink branch in
	// funcAnalysis.handleCall.
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

// argVals reconstructs each logical argument as a guard's `arg[i]` (see
// rules.Arg for the fields). tainted may be nil (a dangerous-call guard has no flow
// behind it), in which case every Arg reports Tainted false, so a rule keying on
// it simply never suppresses there. The structure budget is shared across the
// whole call, not per argument.
func argVals(cc *ir.CallCommon, defs map[string]*ir.Instruction, tainted taintState, expand bool) []rules.Arg {
	la := logicalArgs(cc)
	out := make([]rules.Arg, len(la))
	// A guard that never names .Elems/.Entries cannot observe the structure, so
	// a zero budget skips reconstructing it entirely.
	budget := maxArgNodes
	if !expand {
		budget = 0
	}
	for i, v := range la {
		out[i] = argOf(v, defs, tainted, &budget)
	}
	return out
}

// maxArgNodes bounds the TOTAL argument nodes one call's reconstruction may
// build. A per-level cap would not: 32 wide by 3 deep is 33k nodes per guard
// evaluation, and a suppressing guard re-runs on every fixpoint pass.
//
// A container that does not fit contributes NO structure rather than partial
// structure — half a container could let a rule clear it on the part that fit.
const maxArgNodes = 256

// argOf renders one call argument for a guard, expanding container literals
// while the shared budget allows.
func argOf(v *ir.Value, defs map[string]*ir.Instruction, tainted taintState, budget *int) rules.Arg {
	// A keyword argument arrives wrapped in a name marker; unwrap it once here so
	// the skeleton, type and structure all describe the VALUE while .Name carries
	// the keyword it was passed under.
	name, uv := unwrapKwarg(v, defs)
	def := defs[uv.GetRegName()]
	a := scalarArg(name, uv, def, defs, tainted)
	expandStructure(&a, def, defs, tainted, budget)
	return a
}

// expandStructure fills in a's Elems/Entries from its defining container
// construction, while the shared budget allows, and records whether any of them
// carries the taint.
func expandStructure(a *rules.Arg, def *ir.Instruction, defs map[string]*ir.Instruction, tainted taintState, budget *int) {
	ops := def.GetOperands()
	if len(ops) == 0 || len(ops) > *budget {
		return
	}
	switch def.GetIntrinsic() {
	case aggregateIntrinsic:
		*budget -= len(ops)
		a.Elems = make([]rules.Arg, 0, len(ops))
		for _, o := range ops {
			c := argOf(o, defs, tainted, budget)
			a.TaintInChildren = a.TaintInChildren || c.Tainted
			a.Elems = append(a.Elems, c)
		}
	case aggregateMapIntrinsic:
		if len(ops)%2 != 0 {
			return // not a clean key,value run: claim no key structure
		}
		*budget -= len(ops)
		for i := 0; i+1 < len(ops); i += 2 {
			// A key is only ever read for its constant text, so it needs no
			// structure of its own — a tuple key would otherwise expand a whole
			// subtree that is then discarded.
			k := scalarArg("", ops[i], defs[ops[i].GetRegName()], defs, tainted)
			// Only a fully constant key names an entry; a computed key cannot be
			// addressed by a rule, so its pair is left out of Entries (the value
			// still carries taint through the aggregate itself).
			if !k.Complete {
				continue
			}
			if a.Entries == nil {
				a.Entries = make(map[string]rules.Arg, len(ops)/2)
			}
			if _, dup := a.Entries[k.String]; !dup {
				v := argOf(ops[i+1], defs, tainted, budget)
				a.TaintInChildren = a.TaintInChildren || v.Tainted
				a.Entries[k.String] = v
			}
		}
	}
}

// scalarArg renders an argument's own value — skeleton, completeness, type,
// keyword name and taint — without recursing into any structure. name, v and def
// come from the caller's single unwrap so nothing is resolved twice.
func scalarArg(name string, v *ir.Value, def *ir.Instruction, defs map[string]*ir.Instruction, tainted taintState) rules.Arg {
	s, complete := constSkeleton(v, defs, map[string]bool{})
	// constSkeleton reconstructs STRING text, so a bool/int/float constant comes
	// back as an empty, incomplete skeleton. Render it here — in the guard path
	// only — so a guard can read a flag argument: `shell=True` is what separates
	// an injectable subprocess call from a safe list-argv one, and without this
	// `arg[i].String == "true"` could never hold. Deliberately NOT pushed down
	// into constSkeleton/constStr: those also back the SSRF host reconstruction,
	// where a non-string operand is not part of the URL text and making one
	// "complete" could wrongly prove a fixed host and suppress a real finding.
	if !complete {
		if sc, ok := constScalar(v); ok {
			s, complete = sc, true
		}
	}
	isTaint := false
	if tainted != nil {
		_, isTaint = isTainted(tainted, v)
	}
	return rules.Arg{String: s, Complete: complete, Type: argType(v, s, def), Name: name, Tainted: isTaint}
}

// constScalar renders a non-string constant (bool/int/float) as its literal text,
// reporting false for anything else (including a string constant, which
// constSkeleton already handles, and a nil/absent constant). Bools render as
// "true"/"false" — the Go spelling, matching how every other engine-produced
// string in a guard is lowercase — so a rule writes `arg[i].String == "true"`
// regardless of whether the source language spelled it True, true, or TRUE.
func constScalar(v *ir.Value) (string, bool) {
	c := v.GetConstant()
	if c == nil {
		return "", false
	}
	switch k := c.Value.(type) {
	case *ir.Constant_BoolVal:
		return strconv.FormatBool(k.BoolVal), true
	case *ir.Constant_IntVal:
		return strconv.FormatInt(k.IntVal, 10), true
	case *ir.Constant_FloatVal:
		return strconv.FormatFloat(k.FloatVal, 'g', -1, 64), true
	}
	return "", false
}

// argType is an argument's best-effort static type for a guard's `.Type`: a
// constant's kind, else "string" when we recovered constant text or the defining
// instruction is string-typed, else "" (unknown). The IR-type fallback matters:
// without it a fully tainted string — the common guarded case — would report "".
// def is v's defining instruction, already resolved by the caller.
func argType(v *ir.Value, skeleton string, def *ir.Instruction) string {
	// A container CONSTRUCTED IN PLACE — a Python list/dict/set literal or
	// comprehension — reports "aggregate". This is what lets a rule tell the
	// safe argv form apart from a shell string: in
	// `subprocess.run(["ls", name])` the tainted value is an element of an
	// aggregate, not the command text. Checked before the skeleton fallbacks,
	// which would otherwise type it by its reconstructed text.
	switch def.GetIntrinsic() {
	case aggregateIntrinsic:
		return "aggregate"
	case aggregateMapIntrinsic:
		return "map"
	}
	if c := v.GetConstant(); c != nil {
		switch c.Value.(type) {
		case *ir.Constant_StringVal:
			return "string"
		case *ir.Constant_IntVal:
			return "int"
		case *ir.Constant_FloatVal:
			return "float"
		case *ir.Constant_BoolVal:
			return "bool"
		}
	}
	if skeleton != rules.DynMarker {
		return "string" // recovered constant text => string-valued
	}
	if isStringType(def.GetType()) {
		return "string"
	}
	return ""
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

// buildFuncIndex keys every function by its canonical name — with a unique
// "__local<N>" fallback for functions that lack one, so they are still analyzed
// intra-procedurally — and records each key's owning module. It is the ONE
// place the __localN augmentation lives; Analyze and buildCallGraph both
// consume its function index (CallGraph.Funcs IS this index).
func buildFuncIndex(prog *ir.Program) (map[string]*ir.Function, map[string]*ir.Module) {
	byKey := map[string]*ir.Function{}
	modByKey := map[string]*ir.Module{}
	local := 0
	for mod, fn := range irwalk.Funcs(prog) {
		key := fn.CanonicalName
		if key == "" {
			key = fmt.Sprintf("__local%d", local)
			local++
		}
		byKey[key] = fn
		modByKey[key] = mod
	}
	return byKey, modByKey
}

// buildMethodImpls builds the class-hierarchy index for dynamic dispatch: a bare
// method name -> every lowered concrete method exposing it. An INVOKE call names
// a method abstractly (not a concrete function), so this lets taint flow into the
// implementations. It over-approximates (any same-named method matches), which is
// why such findings stay Medium confidence. It depends only on the immutable
// function index, so it is built once and shared by every rule and by the call
// graph's CHA edge resolution (buildCallGraph) — one index, one policy.
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

	// fnIdx memoizes the per-function structural indexes, filled lazily on first
	// use and guarded because the per-rule analyses run concurrently. A plain
	// pre-sized map under an RWMutex, and entries stored BY VALUE: sync.Map cost
	// an interface box plus an entry allocation per function, and a *fnIndex cost
	// one more — together ~2.4 allocations per function that a single-rule scan
	// has nothing to amortize them against. Copying the struct is free (two map
	// headers), and safe because an entry is immutable once built.
	fnIdxMu sync.RWMutex
	fnIdx   map[*ir.Function]fnIndex
}

// fnIndex holds the per-function structural indexes derived ONLY from the
// function's (immutable) body: the SSA def map, the non-escaping-alloc set,
// and the flow-sensitive driver's CFG inputs (fnCFG; nil for a linear
// function). A funcAnalysis visit runs once per (function × rule × worklist
// visit), so building these there multiplied an O(instructions) walk and the
// map allocations by the rule count — the very rebuild-per-rule cost
// sharedIndex exists to remove for the program-wide indexes.
//
// INVARIANT: an entry is immutable once constructed and is shared read-only
// across the parallel per-rule goroutines (buildDefs is the only writer of defs;
// nonEscaping and cfg are only ever read). This is what makes copying the
// struct out of the memo safe — the copy shares the maps. A future consumer
// that wants to mutate any of them must clone it first.
type fnIndex struct {
	defs        map[string]*ir.Instruction
	nonEscaping map[string]bool
	cfg         *fnCFG
}

// fnIndexFor returns fn's memoized structural index. Deliberately LAZY rather
// than a pre-pass over byKey: under the demand-driven dependency scope most
// dependency functions are never analyzed, so building eagerly would bound
// neither time nor retained memory by what the scan actually touches.
func (s *sharedIndex) fnIndexFor(fn *ir.Function) fnIndex {
	s.fnIdxMu.RLock()
	fx, ok := s.fnIdx[fn]
	s.fnIdxMu.RUnlock()
	if ok {
		return fx
	}
	defs := buildDefs(fn)
	fx = fnIndex{defs: defs, nonEscaping: nonEscapingAllocs(fn, defs), cfg: buildFnCFG(fn)}
	s.fnIdxMu.Lock()
	if prev, ok := s.fnIdx[fn]; ok {
		fx = prev // another goroutine won the race; keep the single shared copy
	} else {
		s.fnIdx[fn] = fx
	}
	s.fnIdxMu.Unlock()
	return fx
}

// buildReqSourceHosts returns the DEPENDENCY functions that host a request
// source and should be seeded anyway. Such a function — beego's
// `Controller.Input`, which reads `c.Ctx.Request` internally — generates request
// taint but takes no tainted argument, so the demand-driven dependency scope
// never enqueues it. Seeding its BODY (rather than tainting its call result
// outright) is what keeps a safe accessor that reads the request and returns a
// constant from becoming a false positive: nothing propagates out of it.
//
// The two tiers below differ in how far they may be seeded. Consulted only under
// a reportable scope, since without one every function is seeded already.
func buildReqSourceHosts(byKey map[string]*ir.Function, modByKey map[string]*ir.Module, rs *rules.RuleSet, reportable map[string]bool) map[string]bool {
	if len(reportable) == 0 {
		return nil
	}
	//   reqObjGlobs — request_object_sources: the synthetic *http.Request. The
	//     frontend also plants it on a framework's request-pipeline ENTRY (gin's
	//     ServeHTTP), which user code never calls directly, and seeding that
	//     pushed taint through the framework's whole pipeline — a dep-heavy
	//     blow-up. So these are seeded only on a DIRECT call from user code.
	//
	//   srcGlobs — ordinary framework accessors (gin `c.Query`, echo `c.Param`).
	//     A host CALLS one and yields a bounded string; the pipeline entry does
	//     not. Seeded at ANY depth, which closes the nested-wrapper case (user →
	//     svc.Fetch → requtil.ReadQuery → c.Query): the innermost host fires the
	//     source and caller-re-enqueue carries the taint up the chain.
	//
	// @net/http.Request is declared as a plain source too, so it is removed from
	// srcGlobs below — otherwise the pipeline entry would be ungated again.
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
	// Precompile both lists into GlobSets: the scan below matches them against
	// EVERY call instruction of every lowered dependency function, and a GlobSet
	// pays the pattern compilation once up front so each match is a plain,
	// lock-free walk over the compiled patterns.
	srcSet := rules.NewGlobSet(srcGlobs)
	reqObjSetGlobs := rules.NewGlobSet(reqObjGlobs)
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
				if srcSet.Match(callee) {
					hosts[key] = true
					break scan
				}
				// Request-object source: seed only if user code calls this host
				// directly (excludes the framework's pipeline entry).
				if userCalled && reqObjSetGlobs.Match(callee) {
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

// ruleState is one rule pass's mutable state: the cross-function summary
// channels the worklist accumulates plus the pass-wide memos. analyzeInterproc
// owns it — goroutine-local, one per rule pass, never shared across rules —
// and each funcAnalysis visit reads and records through its rs pointer rather
// than carrying every map as a separate field.
type ruleState struct {
	// paramTaint is the parameter-taint summary channel: callee -> param index
	// -> the source origin some call site passed at that position.
	paramTaint paramSummaries
	// paramFuncVal is the function-value points-to summary: callee -> param index ->
	// the SET of concrete functions that param can hold, accumulated across every
	// call site (context-insensitive). An indirect call on that param binds only
	// when the set is a singleton (see the resolution branch in handleCall), the
	// same unambiguous-only discipline untyped_dispatch uses. Higher-order channel.
	// Each set is a small SORTED slice (near-always size 1), kept sorted on insert,
	// so targetsOf reads it allocation-free instead of re-sorting map keys on every
	// revisit of every indirect call site.
	paramFuncVal map[string]map[int][]string
	// paramFuncOpaque[callee][param] is set when some call site passed an
	// unresolvable value into that function-value slot, so its points-to set is
	// incomplete and the singleton gate must not fire for it (see funcParamRef).
	paramFuncOpaque map[string]map[int]bool
	// returnTaint marks each function known to return tainted data, with the
	// flow's source origin.
	returnTaint map[string]*ir.Position
	// globalTaint records each program global known to hold tainted data (ENG-6a).
	globalTaint    map[string]*ir.Position
	paramMemTaint  paramSummaries // callee -> out-param index -> origin (ENG-6b)
	paramSinkTaint paramSummaries // callee -> string-param index -> wrapped sink pos (dep sink wrapper)
	// reported dedups findings per sink instruction across worklist revisits.
	reported map[*ir.Instruction]bool
	// guardMemo memoizes each function's guard/dominator index (ENG-9) for this
	// rule: the index is purely structural — immutable body plus the rule's fixed
	// validator list — so rebuilding it on every worklist revisit repeated the
	// dominator computation for nothing. A nil entry (no validators / no guards)
	// is memoized too, hence the presence check at the visit site.
	guardMemo map[*ir.Function]*guardIndex
	// classMemo memoizes each distinct callee's rule classification for this
	// pass (see calleeClass), shared across every funcAnalysis visit the pass runs.
	classMemo map[string]calleeClass
}

// analyzeInterproc runs the worklist-based inter-procedural taint analysis for
// a single rule. State (parameter taint, return taint) grows monotonically, so
// iteration converges.
func analyzeInterproc(idx *sharedIndex, rule *rules.Rule) []Finding {
	byKey, modByKey := idx.byKey, idx.modByKey
	callers, globalReaders := idx.callers, idx.globalReaders
	rs := &ruleState{
		paramTaint:      paramSummaries{},
		paramFuncVal:    map[string]map[int][]string{},
		paramFuncOpaque: map[string]map[int]bool{},
		returnTaint:     map[string]*ir.Position{},
		globalTaint:     map[string]*ir.Position{},
		paramMemTaint:   paramSummaries{},
		paramSinkTaint:  paramSummaries{},
		reported:        map[*ir.Instruction]bool{},
		guardMemo:       map[*ir.Function]*guardIndex{},
		classMemo:       map[string]calleeClass{},
	}
	var findings []Finding

	// The rule is fixed for this whole pass, so decide per LANGUAGE once instead of
	// re-running AppliesTo (a slice scan with a case-insensitive compare) on every
	// enqueue — which happens once per function seeded and again per call edge.
	langOK := map[string]bool{}
	ruleAppliesToLang := func(lang string) bool {
		ok, seen := langOK[lang]
		if !seen {
			ok = rule.AppliesTo(lang)
			langOK[lang] = ok
		}
		return ok
	}

	queued := map[string]bool{}
	var queue []string
	enqueue := func(name string) {
		if byKey[name] == nil {
			return
		}
		if mod := modByKey[name]; mod == nil || !ruleAppliesToLang(mod.Language) {
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

		fx := idx.fnIndexFor(fn)
		guards, ok := rs.guardMemo[fn]
		if !ok {
			guards = buildGuardIndex(fn, rule, fx.defs)
			rs.guardMemo[fn] = guards
		}
		fa := funcAnalysis{
			mod:         mod,
			fn:          fn,
			rule:        rule,
			idx:         idx,
			rs:          rs,
			guards:      guards,
			seeds:       rs.paramTaint[name],
			funcSeeds:   rs.paramFuncVal[name],
			opaqueSeeds: rs.paramFuncOpaque[name],
			// See the funcReportable field doc for what the flag decides.
			funcReportable: len(idx.reportable) == 0 || idx.reportable[mod.Name],
			defs:           fx.defs,
			nonEscaping:    fx.nonEscaping,
			cfg:            fx.cfg,
		}
		res := fa.run()
		findings = append(findings, res.findings...)

		if res.returnsOrigin != nil && rs.returnTaint[name] == nil {
			rs.returnTaint[name] = res.returnsOrigin
			for _, caller := range callers[name] {
				enqueue(caller)
			}
		}

		for _, ce := range res.callEffects {
			m := rs.paramTaint[ce.callee]
			if m == nil {
				m = paramPositions{}
				rs.paramTaint[ce.callee] = m
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
			m := rs.paramFuncVal[fe.callee]
			if m == nil {
				m = map[int][]string{}
				rs.paramFuncVal[fe.callee] = m
			}
			set := m[fe.param]
			if at, found := slices.BinarySearch(set, fe.target); !found {
				m[fe.param] = slices.Insert(set, at, fe.target)
				enqueue(fe.callee)
			}
		}

		// An unresolvable value reached a function-value slot: mark it opaque so the
		// singleton gate no longer trusts a lone resolved target there. First-seen
		// gated and re-enqueues the callee, mirroring the funcEffects merge.
		for _, fo := range res.funcOpaque {
			m := rs.paramFuncOpaque[fo.callee]
			if m == nil {
				m = map[int]bool{}
				rs.paramFuncOpaque[fo.callee] = m
			}
			if !m[fo.param] {
				m[fo.param] = true
				enqueue(fo.callee)
			}
		}

		// A tainted store into a global publishes it program-wide: record the
		// taint and re-enqueue every function that reads that global (ENG-6a).
		for _, ge := range res.globalEffects {
			if _, exists := rs.globalTaint[ge.name]; !exists {
				rs.globalTaint[ge.name] = ge.origin
				for _, reader := range globalReaders[ge.name] {
					enqueue(reader)
				}
			}
		}

		// This function fills tainted data into one of its out-parameters
		// (ENG-6b): record it on the callee's summary and re-enqueue its callers
		// so the argument they pass at that position picks up the taint.
		if len(res.taintsParamMemory) > 0 {
			rs.paramMemTaint.merge(name, res.taintsParamMemory, callers, enqueue)
		}

		// This (dependency) function routes one of its string parameters into a sink
		// (taintsParamSink): record it on the callee's summary and re-enqueue its
		// callers so a call passing tainted data at that position reports the flow at
		// its own site. Mirrors the out-parameter-memory channel above.
		if len(res.taintsParamSink) > 0 {
			rs.paramSinkTaint.merge(name, res.taintsParamSink, callers, enqueue)
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

// stringParamOrigin reports whether a tainted value with origin `pos` entered fn
// through a STRING parameter, returning that parameter's index. It attributes the
// value back to the seed it arrived on (origins are preserved across propagators),
// then checks that parameter's declared type. fn.Params carries the SSA receiver
// at index 0 for a method while Signature.Params excludes it, so the receiver is
// shifted out. Computed on demand at a sink (rare), so no per-function state is
// built on the hot path — see recordSinkParam.
func stringParamOrigin(fn *ir.Function, seeds paramPositions, pos *ir.Position) (int, bool) {
	idx := -1
	for i, origin := range seeds {
		if origin == pos {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0, false
	}
	sig := fn.GetSignature()
	off := 0
	if sig.GetRecv() != nil {
		off = 1
	}
	sp := sig.GetParams()
	si := idx - off
	if si < 0 || si >= len(sp) {
		return 0, false // receiver or captured free variable: not a wrapper param
	}
	return idx, isStringType(sp[si])
}

// recordSinkParam summarizes a dependency sink wrapper: when a tainted value that
// entered fn through a string parameter reaches a sink — directly, or by forwarding
// into an already-summarized callee at sinkPos — record that parameter so the
// caller reports the flow at its own (user-code) call site. Skipped for a function
// that is itself a modeled sink (its direct call site already fires, so summarizing
// would double-report). A package function called only when a sink actually fires
// on a dependency, so it adds no per-function allocation.
func recordSinkParam(res *funcResult, fn *ir.Function, rule *rules.Rule, seeds paramPositions, pos, sinkPos *ir.Position) {
	k, ok := stringParamOrigin(fn, seeds, pos)
	if !ok {
		return
	}
	if rule.IsSink(fn.CanonicalName) {
		return
	}
	if res.taintsParamSink == nil {
		res.taintsParamSink = paramPositions{}
	}
	if _, exists := res.taintsParamSink[k]; !exists {
		res.taintsParamSink[k] = sinkPos
	}
}

// funcAnalysis is one visit of the inter-procedural worklist: the
// intra-procedural fixpoint for one function under one rule, seeded with
// tainted parameters. Running it (run) reports the sinks it hits, whether the
// function returns taint, and the taint it passes to callees (res).
// analyzeInterproc constructs a fresh one per (function × rule × worklist
// visit); the fields down to cfg are the caller's inputs — the program-wide
// indexes (idx), the pass's summaries and memos (rs), and the genuinely
// per-visit values — the rest is per-visit working state shared by the
// transfer methods.
type funcAnalysis struct {
	mod  *ir.Module
	fn   *ir.Function
	rule *rules.Rule
	// idx is the rule-independent program index (shared read-only across
	// rules); rs is this rule pass's mutable summary/memo state.
	idx *sharedIndex
	rs  *ruleState
	// guards is the memoized guard/barrier index (ENG-9), built once per
	// (function, rule) by the caller (rs.guardMemo) and nil for a rule without
	// validators, so the common path pays nothing.
	guards *guardIndex
	// seeds is the caller's parameter-taint summary for this function: which
	// parameters arrive tainted, and carrying which source origin.
	seeds paramPositions
	// funcSeeds / opaqueSeeds are the function-value points-to summaries for
	// this function's parameters — which param holds which callback, and which
	// slots are incomplete. See ruleState.paramFuncVal / paramFuncOpaque.
	funcSeeds   map[int][]string
	opaqueSeeds map[int]bool
	// funcReportable: a finding raised HERE survives scopeFindings (it is user
	// code). When false (a lowered dependency), a sink reached inside this
	// function is scoped out, so its string-param sink flows are summarized for
	// the caller to report instead (taintsParamSink). An empty scope makes
	// every function reportable, matching the seed-everything worklist mode.
	funcReportable bool
	// defs, nonEscaping and cfg are read-only views onto the shared
	// per-function memo (see fnIndex). cfg is nil for a linear function.
	defs        map[string]*ir.Instruction
	nonEscaping map[string]bool
	cfg         *fnCFG

	// tainted is the CURRENT block's taint state; the flow-sensitive driver
	// (ENG-2, see run) reassigns it to each block's entry state before visiting
	// the block, so the transfer methods below always operate on the right
	// per-block facts.
	tainted taintState
	// curBlock tracks the block being visited so a sink can ask whether a
	// validator guard dominates it on the path taken.
	curBlock int32
	// linearFn marks a branch-free function, in ANY language — the majority of
	// bodies even now that every frontend emits a real CFG. In one linear block
	// the dominance-based guard index (guards) cannot add anything, because
	// program order IS dominance: a validator applied to a value before that
	// value is returned guards the return just as a dominating branch would.
	// validated records the registers a rule validator has been applied to,
	// consulted only in the linear case at a RET (the CFG path keeps using the
	// precise dominator guard).
	linearFn  bool
	validated map[string]bool
	// interprocOrigins records every source origin whose taint crossed a
	// function boundary to reach this function — parameter seeds, plus taint
	// pulled back from a callee's return summary in handleCall. A flow that
	// enters through a parameter is inter-procedural, which lowers the
	// confidence of any finding it feeds: confidenceFor consults this so all
	// cross-function findings are Medium (and thus seen by the LLM reviewer).
	interprocOrigins map[*ir.Position]bool
	// funcVal maps a register to the SET of concrete functions it can hold (a
	// points-to fact). It is function-scoped and monotonic — a callable identity
	// is a property of the value, not a per-block fact — so it is NOT reset by
	// the flow-sensitive block driver. Seeded from the caller-supplied funcSeeds
	// (which param holds which callback), so an indirect call on a parameter can
	// be resolved to the function value the caller passed in. Each set is the
	// orchestrator's sorted slice, shared READ-ONLY: nothing here mutates it,
	// and the orchestrator only merges between visits, so no clone.
	funcVal map[string][]string
	// funcValOpaque marks a register whose function-value set is incomplete
	// (some caller passed an unresolvable value into the parameter it was seeded
	// from), so the indirect-call singleton gate must not fire for it.
	// Function-scoped and monotonic, like funcVal.
	funcValOpaque map[string]bool
	// paramReg maps a parameter register to its index, for the ENG-6b
	// out-parameter fill; built lazily on the first STORE
	// (recordParamMemoryTaint), since a body without one never consults it.
	paramReg      map[string]int
	paramRegBuilt bool

	// res accumulates this visit's outcome; the *Seen maps dedup the
	// cross-function effects appended to it. All the working-state maps above
	// and below are allocated lazily on first write: a visit runs once per
	// (function × rule × worklist revisit) and the overwhelmingly common
	// no-taint visit writes none of them, so eager allocation here multiplied
	// map allocations by exactly that product for nothing.
	res            funcResult
	effectSeen     map[funcParamRef]bool
	funcEffectSeen map[funcValEffect]bool
	funcOpaqueSeen map[funcParamRef]bool
	globalSeen     map[string]bool
}

// run drives one visit: it seeds the entry state from the caller's summaries,
// executes the flow-sensitive fixpoint (or the single-block fast path), and
// returns the accumulated result.
func (fa *funcAnalysis) run() funcResult {
	// Count non-nil blocks once (reused by the single-block fast path below). A
	// single-block function is linear: it has no CFG for the dominator guard, so
	// program order stands in for dominance at a RET (see validated).
	nBlocks := 0
	var onlyBlock *ir.BasicBlock
	for _, blk := range fa.fn.Blocks {
		if blk != nil {
			nBlocks++
			onlyBlock = blk
		}
	}
	fa.linearFn = nBlocks <= 1

	// Seed tainted parameters into the entry block's in-state. seedState (and
	// every other working map) is allocated only when a seed actually lands.
	var seedState taintState
	for idx, origin := range fa.seeds {
		if idx >= 0 && idx < len(fa.fn.Params) {
			if reg := fa.fn.Params[idx].GetRegName(); reg != "" {
				if seedState == nil {
					seedState = taintState{}
				}
				seedState[reg] = origin
				fa.markInterproc(origin)
			}
		}
	}

	for idx, targets := range fa.funcSeeds {
		if idx >= 0 && idx < len(fa.fn.Params) {
			if reg := fa.fn.Params[idx].GetRegName(); reg != "" {
				if fa.funcVal == nil {
					fa.funcVal = map[string][]string{}
				}
				fa.funcVal[reg] = targets
			}
		}
	}
	for idx := range fa.opaqueSeeds {
		if idx >= 0 && idx < len(fa.fn.Params) {
			if reg := fa.fn.Params[idx].GetRegName(); reg != "" {
				if fa.funcValOpaque == nil {
					fa.funcValOpaque = map[string]bool{}
				}
				fa.funcValOpaque[reg] = true
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
	// flow-sensitive fixpoint — the per-block `in`/`blockOut` maps and the
	// multi-pass loop (buildFnCFG likewise builds no CFG indexes for a linear
	// function) — and just seed and visit once.
	// This is the majority of functions (every straight-line-lowered Python / JS /
	// Ruby / Java / Go-closure body), so it removes most of the engine's
	// per-(rule × function) allocation. seedState is a fresh map owned by this
	// analysis, so visiting mutates it in place harmlessly. nBlocks/onlyBlock were
	// computed once above (also feeding linearFn).
	if fa.linearFn {
		if seedState == nil {
			seedState = taintState{} // visit writes through fa.tainted, so it must be non-nil
		}
		fa.tainted = seedState
		if onlyBlock != nil {
			fa.curBlock = onlyBlock.GetIndex()
			for _, inst := range onlyBlock.Instrs {
				if inst != nil {
					fa.visit(inst)
				}
			}
		}
		return fa.res
	}

	// The RPO order and the index/predecessor lookups are structural
	// (rule-independent), so they come from the shared per-function memo
	// (fnIndex.cfg) rather than being rebuilt per (rule × worklist visit).
	// Non-nil here: buildFnCFG and linearFn use the same ≤1-block predicate.
	cfg := fa.cfg
	blockOut := map[int32]taintState{}

	// The block-out states ascend monotonically over a finite lattice, so this
	// terminates; maxPasses is a defensive backstop against a pathological CFG.
	const maxPasses = 100000
	for pass := 0; pass < maxPasses; pass++ {
		changed := false
		for _, idx := range cfg.rpo {
			blk := cfg.idxToBlock[idx]
			if blk == nil {
				continue
			}
			in := taintState{}
			if idx == cfg.entry {
				maps.Copy(in, seedState)
			}
			for _, p := range cfg.preds[idx] {
				for k, v := range blockOut[p] {
					if _, exists := in[k]; !exists {
						in[k] = v
					}
				}
			}
			fa.tainted = in
			fa.curBlock = idx
			for _, inst := range blk.Instrs {
				if inst != nil {
					fa.visit(inst)
				}
			}
			// `in` is fresh this pass and nothing else references it once the
			// block is done, so the out state can take it without a clone.
			if !statesEqual(blockOut[idx], fa.tainted) {
				blockOut[idx] = fa.tainted
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	return fa.res
}

// targetsOf resolves a value to the concrete lowered function(s) it may hold:
// a FuncName is looked up directly in byKey (the make_closure resolution
// pattern) — this covers a function passed by reference and a frontend-
// synthesized deferral call whose target is known at the site; a RegName is
// resolved through the function-scoped funcVal points-to set (a callback
// received as a parameter). Anything else — an opaque/foreign callable we did
// not lower — yields nil, so an unresolvable value binds nothing (a false
// negative, never a false positive). The funcVal sets are already sorted (see
// paramFuncVal), so a register lookup is allocation-free and deterministic.
func (fa *funcAnalysis) targetsOf(v *ir.Value) []string {
	if v == nil {
		return nil
	}
	if name := v.GetFuncName(); name != "" {
		if fa.idx.byKey[name] != nil {
			return []string{name}
		}
		return nil
	}
	if reg := v.GetRegName(); reg != "" {
		return fa.funcVal[reg]
	}
	return nil
}

// indirectOpaque reports whether a callback value's points-to set is known to be
// incomplete (a caller passed an unresolvable value into the param it came from),
// so the singleton gate must not fire. Only a register-held callback can be
// opaque; a FuncName is an exact, complete target.
func (fa *funcAnalysis) indirectOpaque(v *ir.Value) bool {
	if reg := v.GetRegName(); reg != "" {
		return fa.funcValOpaque[reg]
	}
	return false
}

// addEffect records that a tainted value flowed into a callee parameter
// (deduped per (callee, param) — the summary keeps one origin per slot).
func (fa *funcAnalysis) addEffect(callee string, param int, origin *ir.Position) {
	key := funcParamRef{callee: callee, param: param}
	if fa.effectSeen[key] {
		return
	}
	if fa.effectSeen == nil {
		fa.effectSeen = map[funcParamRef]bool{}
	}
	fa.effectSeen[key] = true
	fa.res.callEffects = append(fa.res.callEffects, callEffect{callee: callee, param: param, origin: origin})
}

// addFuncEffect records that a function value flowed into a callee parameter
// (the higher-order channel). Dedup is keyed on the full (callee, param, target)
// effect — unlike the taint/req channels, which store a single origin per
// (callee,param), this stores a SET, so two distinct callbacks passed to the same
// param must BOTH be recorded (that is exactly what makes the param ambiguous and
// disables the singleton gate).
func (fa *funcAnalysis) addFuncEffect(callee string, param int, target string) {
	if callee == "" || target == "" {
		return
	}
	fe := funcValEffect{callee: callee, param: param, target: target}
	if fa.funcEffectSeen[fe] {
		return
	}
	if fa.funcEffectSeen == nil {
		fa.funcEffectSeen = map[funcValEffect]bool{}
	}
	fa.funcEffectSeen[fe] = true
	fa.res.funcEffects = append(fa.res.funcEffects, fe)
}

// addFuncOpaque records that an unresolvable value reached a callee's
// function-value slot (struct-keyed dedup, no per-arg string alloc). Called only
// for a non-constant argument that targetsOf could not resolve.
func (fa *funcAnalysis) addFuncOpaque(callee string, param int) {
	if callee == "" {
		return
	}
	k := funcParamRef{callee: callee, param: param}
	if fa.funcOpaqueSeen[k] {
		return
	}
	if fa.funcOpaqueSeen == nil {
		fa.funcOpaqueSeen = map[funcParamRef]bool{}
	}
	fa.funcOpaqueSeen[k] = true
	fa.res.funcOpaque = append(fa.res.funcOpaque, k)
}

// recordFuncArg emits the points-to effect for a callback argument: each
// resolved target, or an opaque marker when the value is a non-constant the
// resolver could not pin to a concrete function. A constant can never be a
// callable, so it contributes neither. Gated on the callee actually containing
// an indirect call — a function that never dispatches through a parameter can
// never consult these facts, so recording them (and re-enqueuing on them) would
// be pure overhead on the large dependency closure a Go scan lowers.
func (fa *funcAnalysis) recordFuncArg(callee string, param int, arg *ir.Value) {
	if !fa.idx.indirectCallees[callee] {
		return
	}
	if ts := fa.targetsOf(arg); len(ts) > 0 {
		for _, t := range ts {
			fa.addFuncEffect(callee, param, t)
		}
	} else if arg.GetConstant() == nil {
		fa.addFuncOpaque(callee, param)
	}
}

// recordGlobalStore implements half of ENG-6(a): taint through package/
// module-level globals. A store of tainted data into a global publishes the
// taint program-wide (recorded as a global effect the orchestrator merges);
// readGlobalTaint is the other half, seeding a load from an already-tainted
// global. Both cross a function boundary, so any finding they feed is Medium
// confidence (interprocOrigins), matching the confidence contract for
// over-approximating flows.
func (fa *funcAnalysis) recordGlobalStore(inst *ir.Instruction) {
	ops := inst.GetOperands()
	if len(ops) < 2 {
		return
	}
	g := ops[0].GetGlobalName()
	if g == "" {
		return
	}
	pos, ok := isTainted(fa.tainted, ops[1])
	if !ok {
		return
	}
	if fa.globalSeen[g] {
		return
	}
	if fa.globalSeen == nil {
		fa.globalSeen = map[string]bool{}
	}
	fa.globalSeen[g] = true
	fa.res.globalEffects = append(fa.res.globalEffects, globalEffect{name: g, origin: pos})
}

// recordParamMemoryTaint implements ENG-6(b): out-parameter fill. When this
// function stores tainted data into memory reachable from one of its own
// parameters (the store address roots at a param — `*out = tainted`,
// `out.f = tainted`, `out[i] = tainted`), record it so callers mark the
// argument they pass at that position tainted. Only parameters carrying
// address semantics can be a store root (a value param that is reassigned is a
// fresh local in SSA, not a store target), so this does not falsely taint
// by-value arguments.
func (fa *funcAnalysis) recordParamMemoryTaint(inst *ir.Instruction) {
	if !fa.paramRegBuilt {
		fa.paramRegBuilt = true
		for i, p := range fa.fn.Params {
			if r := p.GetRegName(); r != "" {
				if fa.paramReg == nil {
					fa.paramReg = make(map[string]int, len(fa.fn.Params))
				}
				fa.paramReg[r] = i
			}
		}
	}
	if len(fa.paramReg) == 0 {
		return
	}
	ops := inst.GetOperands()
	if len(ops) < 2 {
		return
	}
	pos, ok := isTainted(fa.tainted, ops[1])
	if !ok {
		return
	}
	addrReg := ops[0].GetRegName()
	if addrReg == "" {
		return
	}
	idx, ok := fa.paramReg[rootBaseReg(fa.defs, addrReg)]
	if !ok {
		return
	}
	if fa.res.taintsParamMemory == nil {
		fa.res.taintsParamMemory = paramPositions{}
	} else if _, seen := fa.res.taintsParamMemory[idx]; seen {
		return
	}
	fa.res.taintsParamMemory[idx] = pos
}

// readGlobalTaint seeds the result of any named instruction that reads a
// tainted global. A global read is not one fixed opcode: the Go frontend
// lowers `x := pkgVar` as UN_OP(MUL) over a GlobalName operand, others as
// LOAD — so this keys on the presence of a tainted GlobalName operand rather
// than the opcode. A STORE's global operand is its write target, but a STORE
// has no result Name, so it is naturally excluded.
func (fa *funcAnalysis) readGlobalTaint(inst *ir.Instruction) {
	if inst.Name == "" {
		return
	}
	for _, op := range inst.GetOperands() {
		g := op.GetGlobalName()
		if g == "" {
			continue
		}
		if pos, ok := fa.rs.globalTaint[g]; ok {
			markTainted(fa.tainted, inst.Name, pos)
			fa.markInterproc(pos) // cross-function -> Medium
		}
	}
}

func (fa *funcAnalysis) confidenceFor(origin *ir.Position) Confidence {
	if fa.interprocOrigins[origin] {
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// markInterproc records a source origin whose taint crossed a function
// boundary to reach this function (see interprocOrigins).
func (fa *funcAnalysis) markInterproc(origin *ir.Position) {
	if fa.interprocOrigins == nil {
		fa.interprocOrigins = map[*ir.Position]bool{}
	}
	fa.interprocOrigins[origin] = true
}

// taintCallerArg marks a call argument register tainted because the callee
// filled tainted data into the memory it points at (ENG-6b out-parameter).
// The taint reaches the caller through a pointer, so it is a cross-function
// flow (Medium confidence). Walking the container chain covers `&dst.field`.
func (fa *funcAnalysis) taintCallerArg(v *ir.Value, origin *ir.Position) {
	if v == nil {
		return
	}
	reg := v.GetRegName()
	if reg == "" {
		return
	}
	markTainted(fa.tainted, reg, origin)
	taintContainer(fa.defs, fa.tainted, reg, origin)
	fa.markInterproc(origin)
}

// eachArgParam calls f(paramIdx, arg) for each argument of cc, mapped to the
// callee's LOGICAL parameter index: an INVOKE's receiver (Call.Value) is
// param 0 and its explicit args shift by one; a direct call's args align.
// Shared by seedInvokeArgs and by the out-parameter-fill and sink-wrapper
// consumers in handleCall, which all need this receiver-offset mapping (easy
// to get off by one when inlined).
func eachArgParam(cc *ir.CallCommon, f func(paramIdx int, arg *ir.Value)) {
	args := cc.GetArgs()
	if cc.GetIsInvoke() {
		f(0, cc.GetValue())
		for j, arg := range args {
			f(j+1, arg)
		}
	} else {
		for j, arg := range args {
			f(j, arg)
		}
	}
}

// seedInvokeArgs seeds target's params from an INVOKE's operands, reusing
// eachArgParam's invoke branch rather than repeating its receiver shift.
// Shared by the lowered-method branch and the CHA dispatch loop in handleCall,
// which resolve different targets but seed them identically. Both call sites
// are under IsInvoke, so `pi > 0` is exactly "not the receiver".
func (fa *funcAnalysis) seedInvokeArgs(cc *ir.CallCommon, target string) {
	eachArgParam(cc, func(pi int, arg *ir.Value) {
		if p, ok := isTaintedArg(fa.tainted, arg); ok {
			fa.addEffect(target, pi, p)
		}
		if pi > 0 {
			fa.recordFuncArg(target, pi, arg)
		}
	})
}

// pullReturnTaint taints inst's result register from target's return
// summary; taint entered via a callee return crossed a function boundary,
// so any finding it feeds must be Medium (interprocOrigins).
func (fa *funcAnalysis) pullReturnTaint(inst *ir.Instruction, target string) {
	if ro := fa.rs.returnTaint[target]; ro != nil && inst.Name != "" {
		markTainted(fa.tainted, inst.Name, ro)
		fa.markInterproc(ro)
	}
}

// calleeClass is one callee's classification under the pass's rule: the result
// of the source/sink/sanitizer/propagator glob matches plus the matched sink's
// injection indices and guard. It depends only on the (rule, callee) pair, so
// analyzeInterproc memoizes it per pass (classMemo) — handleCall would
// otherwise re-run the glob walks per call site per fixpoint pass per worklist
// revisit.
type calleeClass struct {
	sinkArgs []int32
	guard    *rules.Guard
	isSink   bool
	isSan    bool
	isSrc    bool
	isProp   bool
}

// handleCall applies the taint transfer for any call-carrying instruction:
// direct CALL, dynamic INVOKE, and the call-carrying intrinsics go.defer /
// go.goroutine (whose sink/source/propagator and cross-function effects would
// otherwise be invisible to the engine).
func (fa *funcAnalysis) handleCall(inst *ir.Instruction) {
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
	var cls calleeClass
	if !indirect {
		// Classify the callee once per PASS, not once per call site: the globs
		// are the engine's hottest per-(call × rule) work (the default-propagator
		// list alone is ~100 patterns), yet the result depends only on the
		// (rule, callee) pair — both fixed for the whole analyzeInterproc pass —
		// and the distinct callees are far fewer than the call sites × worklist
		// revisits that consult them. The memo is goroutine-local (one per rule
		// pass), so no locking; the stored guard is the same *rules.Guard
		// MatchSink returns, preserving pointer identity.
		var seen bool
		cls, seen = fa.rs.classMemo[callee]
		if !seen {
			cls.sinkArgs, cls.guard, cls.isSink = fa.rule.MatchSink(callee)
			cls.isSan = fa.rule.IsSanitizer(callee)
			cls.isSrc = fa.rule.IsSource(callee)
			cls.isProp = fa.rule.IsPropagator(callee)
			fa.rs.classMemo[callee] = cls
		}
		// The Go `append` builtin propagates taint ONLY when its result is a
		// byte/rune slice — i.e. character-level string reconstruction (the
		// make([]byte); append(data, s[i]); string(data) idiom of a non-sanitizing
		// normalize/snake_case helper). It is NOT a blanket propagator: append is
		// called on every slice in a program, so tainting through slices of structs
		// /pointers explodes the taint set in framework code (a large scan slowdown).
		// Depends on the INSTRUCTION's result type, so it adjusts the local copy
		// and stays out of the per-callee memo.
		if !cls.isProp && callee == "builtin.append" && isByteOrRuneSlice(inst.GetType()) {
			cls.isProp = true
		}
	}

	// Record a validator application (ENG-9, linear case): mark the checked
	// registers so a later RET of one of them in this same straight-line block
	// is treated as validated. Cheap and gated on the rule declaring validators.
	if fa.linearFn && fa.rule.HasValidators() && fa.rule.IsValidator(callee) {
		if fa.validated == nil {
			fa.validated = map[string]bool{}
		}
		if v := inst.Call.GetValue(); v != nil {
			if r := v.GetRegName(); r != "" {
				fa.validated[r] = true
			}
		}
		for _, a := range args {
			if r := a.GetRegName(); r != "" {
				fa.validated[r] = true
			}
		}
	}

	switch {
	case cls.isSan:
		// A sanitizer neutralizes taint: its result is clean. Critically, we
		// must NOT fall through to the inter-procedural summary blocks below —
		// when the sanitizer is a function lowered from the scanned repo
		// (byKey[callee] != nil), that path would re-taint the sanitizer's
		// result from its own return summary and defeat the sanitizer. Stop here.
		return
	case cls.isSrc:
		if inst.Name != "" {
			markTainted(fa.tainted, inst.Name, inst.Pos)
		}
	case cls.isSink:
		inj := injectableArgs(cls.sinkArgs, inst.Call)
		if srcReg, pos, ok := firstTainted(fa.tainted, inj); ok && !fa.rs.reported[inst] {
			// Dynamic sink guard (`when:`): fire only if the guard confirms
			// against the call's statically-known argument values. An
			// unrecoverable (non-constant) arg makes the guard false, so the
			// sink is suppressed (required-confirmation). Left un-reported so a
			// later iteration re-evaluates as the arg's construction resolves.
			//
			// This runs BEFORE res.taintsParamSink is recorded below, so a
			// suppressed sink forms no wrapper summary and consumeSink needs no
			// guard of its own. Consequence: inside a dependency wrapper the
			// guarded arg is a parameter (always <DYN>), so a guarded sink is
			// never reported through a wrapper — documented in writing-rules.md.
			// hostFixed() is the engine fact (see rules.EvalHostFixed); expr calls
			// it only if the rule mentions it, so an unrelated guard pays nothing.
			if cls.guard != nil && !cls.guard.EvalWith(argVals(inst.Call, fa.defs, fa.tainted, cls.guard.NeedsStructure()),
				func() bool { return !urlHostControllable(inj, fa.tainted, fa.defs) }) {
				break
			}
			// ENG-9: suppress when a validator guard on this flow's source
			// value dominates the sink on the path taken to reach it. The check
			// is left un-reported (not marked) so a later iteration re-evaluates
			// it — it stays suppressed as long as the guard holds.
			if fa.guards.guarded(fa.curBlock, pos, fa.tainted) {
				break
			}
			// SSRF/open-redirect host-fixedness is no longer decided here. It is a
			// rule-layer policy now: the packs that want it declare
			// `when: 'not hostFixed()'` on their sinks, and the engine only supplies
			// the fact (see the cls.guard call above). Branching on rule.CWE meant a
			// custom SSRF rule tagged anything else silently lost the suppression, and
			// open-redirect could not opt in at all.
			// Mark reported ONLY when a finding is actually emitted (ENG-8).
			// A suppressing guard breaks out ABOVE without setting this, which is
			// what lets a later flow still fire: a benign host-fixed flow to this
			// sink must not mark it reported and block a subsequent flow whose
			// taint DOES reach the host (e.g. once an interprocedural summary
			// taints the host segment).
			fa.rs.reported[inst] = true
			steps := reconstructPath(fa.defs, fa.tainted, srcReg, pos, inst.Pos)
			fa.res.findings = append(fa.res.findings, newTaintFinding(fa.rule, fa.mod, fa.fn, pos, inst.Pos, callee, steps, fa.confidenceFor(pos)))
			// Dependency sink wrapper: this finding is scoped out (the sink sits in
			// a library), so if the tainted value entered through a string parameter,
			// summarize it for the caller to report at its own site. User code
			// reports in place and never summarizes.
			if !fa.funcReportable {
				recordSinkParam(&fa.res, fa.fn, fa.rule, fa.seeds, pos, inst.Pos)
			}
		}
	case cls.isProp:
		// A propagating call carries taint from any of its operands to its
		// result. This covers the rule's own propagators and the built-in
		// default propagators (stdlib string/encoding transforms that real
		// code interposes between a source and a sink; without them one
		// `strings.TrimSpace`/`.toLowerCase()` silently drops taint). Operands
		// include the RECEIVER of a method call (Call.Value, e.g. Java/JS
		// `tainted.trim()`), not just the explicit arguments.
		if inst.Name != "" {
			markTaintFromOperands(fa.tainted, inst.Name, propagatorOperands(inst))
		}
	default:
		// A frontend-synthesized member read (builtin.member_read) off a base it
		// kept in Call.Value: carry the base's taint to the result. Reading a
		// property off an already-tainted object is not a transform, so no rule
		// models it, yet it is how object-carried data is consumed once it
		// crosses a function boundary — without this the read returns clean and
		// the flow ends there.
		//
		// Placed in the DEFAULT arm on purpose: a callee that matches a
		// sanitizer, source or sink glob keeps that meaning, since the cases
		// above already returned. Reads Call.Value directly rather than going
		// through propagatorOperands, which allocates a slice per call, per rule,
		// per fixpoint pass — Args is always empty here, so that would be pure
		// waste on a gated allocation metric.
		if inst.Name != "" && inst.GetIntrinsic() == memberReadIntrinsic {
			if pos, ok := isTainted(fa.tainted, inst.Call.GetValue()); ok {
				markTainted(fa.tainted, inst.Name, pos)
			}
		}
	}

	// Inter-procedural, direct call: if the callee is a function we lowered,
	// pass tainted arguments into its parameters and pull back its return taint.
	if fa.idx.byKey[callee] != nil {
		if inst.Call.GetIsInvoke() {
			// A concrete instance-method call (e.g. Java) whose method we
			// lowered: the receiver lives in Call.Value and maps to param 0,
			// and the real arguments EXCLUDE the receiver, so they map to the
			// callee's params shifted by one. Mapping args[j]->param j here
			// would seed the receiver slot and drop the last argument — an
			// off-by-one that silently loses every cross-function instance
			// flow. (Go interface INVOKEs name an abstract method absent from
			// byKey, so they skip this and are handled by the CHA block below.)
			fa.seedInvokeArgs(inst.Call, callee)
		} else {
			// Static/free function or Go method call: args already align with
			// params (Args[0]==Params[0]==receiver for a Go method). isTaintedArg
			// also seeds when an argument is a struct carrying a tainted field,
			// so a field-tainted struct passed by value/pointer still flows into
			// the callee (see fieldAnyKey / ENG-3).
			for j, a := range args {
				if p, ok := isTaintedArg(fa.tainted, a); ok {
					fa.addEffect(callee, j, p)
				}
				// A function value passed as an argument records a points-to fact
				// on the callee's param, so an indirect call on that param inside
				// the callee resolves back to it (higher-order channel); an
				// unresolvable value marks the slot opaque (FP-safety).
				fa.recordFuncArg(callee, j, a)
			}
		}
		fa.pullReturnTaint(inst, callee)
		// The callee fills tainted data into one of its out-parameters: taint
		// the argument passed at that position (ENG-6b).
		if pm := fa.rs.paramMemTaint[callee]; len(pm) > 0 {
			eachArgParam(inst.Call, func(paramIdx int, a *ir.Value) {
				if o, ok := pm[paramIdx]; ok {
					fa.taintCallerArg(a, o)
				}
			})
		}
	}

	// Dependency sink-wrapper summary (taintsParamSink): the callee routes one of
	// its string parameters into a sink internally, and that sink's own finding was
	// scoped out. If we pass tainted data at that position, the vulnerability is
	// HERE. In user code, report it at this call site; in another dependency,
	// propagate it up as this function's own sink-param summary so the finding
	// ultimately lands on user code. Uses the same arg->param mapping as the seeding
	// above (receiver = param 0 for an INVOKE, args shifted by one; direct otherwise).
	if psk := fa.rs.paramSinkTaint[callee]; len(psk) > 0 {
		consumeSink := func(paramIdx int, a *ir.Value) {
			sinkPos, summarized := psk[paramIdx]
			if !summarized {
				return
			}
			pos, ok := isTaintedArg(fa.tainted, a)
			if !ok {
				return
			}
			// A validator dominating this flow's source suppresses it, exactly as at
			// a direct sink (ENG-9).
			if fa.guards.guarded(fa.curBlock, pos, fa.tainted) {
				return
			}
			if fa.funcReportable {
				if fa.rs.reported[inst] {
					return
				}
				fa.rs.reported[inst] = true
				steps := reconstructPath(fa.defs, fa.tainted, a.GetRegName(), pos, inst.Pos)
				fa.res.findings = append(fa.res.findings, newTaintFinding(fa.rule, fa.mod, fa.fn, pos, inst.Pos, callee, steps, ConfidenceMedium)) // SinkPos = user call into the wrapper; Medium: sink across a call boundary
			} else {
				// Still inside a dependency: propagate the summary up if the tainted
				// arg forwards a string parameter.
				recordSinkParam(&fa.res, fa.fn, fa.rule, fa.seeds, pos, sinkPos)
			}
		}
		eachArgParam(inst.Call, consumeSink)
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
		if targets := fa.targetsOf(v); len(targets) == 1 && !fa.indirectOpaque(v) {
			target := targets[0]
			for j, a := range args {
				if p, ok := isTaintedArg(fa.tainted, a); ok {
					fa.addEffect(target, j, p)
				}
				fa.recordFuncArg(target, j, a)
			}
			fa.pullReturnTaint(inst, target)
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
		impls := fa.idx.methodImpls[inst.Call.GetMethodName()]
		if inst.Call.GetUntypedDispatch() {
			// An ambiguous name is not always an unknown receiver: `h = C()` then
			// `h.load(x)` names the class right there. Narrowing by it recovers the
			// dispatch without the cross-object fan-out, and falls back to silence
			// when the receiver is genuinely opaque.
			if len(impls) > 1 {
				impls = fa.receiverImpls(inst.Call, impls)
			}
			if len(impls) == 1 {
				fa.seedInvokeArgs(inst.Call, impls[0])
				fa.pullReturnTaint(inst, impls[0])
			}
		} else {
			for _, impl := range impls {
				fa.seedInvokeArgs(inst.Call, impl)
				fa.pullReturnTaint(inst, impl)
			}
		}
	}
}

// receiverImpls narrows an ambiguous untyped-dispatch INVOKE to the
// implementations defined on the receiver's OWN class, when that class is named
// by the receiver's construction in this same function (`h = C()` — and `with
// C() as h`, which the frontends bind the same way).
//
// This is what separates "the name is ambiguous" from "the receiver is unknown".
// A global-uniqueness test conflates them, and in real code the second is much
// rarer than the first: a quarter of pyload's method call sites name a method
// two or more classes define, so the taint stops at `h.load(...)` even though the
// line above says exactly what `h` is.
//
// Returns nil when the receiver is not a locally-constructed value or its class
// implements nothing by this name — the caller then dispatches nowhere, which is
// the pre-existing conservative behavior for an opaque receiver.
func (fa *funcAnalysis) receiverImpls(cc *ir.CallCommon, impls []string) []string {
	def := fa.defs[cc.GetValue().GetRegName()]
	ctor := def.GetCall()
	// A constructor is a plain CALL. An INVOKE would be a method call whose
	// return type we do not track, and an indirect call names no class at all.
	if ctor == nil || ctor.GetIsInvoke() || ctor.GetCallee() == "" {
		return nil
	}
	class := simpleTypeName(ctor.GetCallee())
	var out []string
	for _, impl := range impls {
		if classOfMethodKey(impl) == class {
			out = append(out, impl)
		}
	}
	return out
}

// classOfMethodKey returns the class component of a method's canonical name --
// "HTTPRequest" for "py:net.http_request.HTTPRequest.load". Compared by SIMPLE
// name because a constructor's callee and its methods' keys are qualified by
// different module paths (`py:http.http_request.HTTPRequest` vs
// `py:http_request.HTTPRequest.load`), so only the class component is common.
func classOfMethodKey(key string) string {
	method := strings.LastIndexByte(key, '.')
	if method <= 0 {
		return ""
	}
	return simpleTypeName(key[:method])
}

// simpleTypeName strips both a module path and the `<lang>:` prefix, so an
// unqualified constructor ("py:A") and a qualified method key's class component
// ("py:min.A") reduce to the same "A". trailingName alone does not: it splits on
// '.' only, and leaves "py:A" whole.
func simpleTypeName(s string) string {
	if i := strings.LastIndexAny(s, ".:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// handleMakeClosure flows taint through a builtin.make_closure intrinsic,
// whose operands are [Fn, binding0, binding1, ...]. The frontend appends the
// closure's captured free variables as its trailing params, so a tainted
// binding must flow into the closure's matching free-var param — this is how
// taint reaches a `go func(){ ...captured... }()` goroutine body.
func (fa *funcAnalysis) handleMakeClosure(inst *ir.Instruction) {
	ops := inst.GetOperands()
	if len(ops) < 2 {
		return
	}
	closureName := ops[0].GetFuncName()
	if closureName == "" {
		return
	}
	closure := fa.idx.byKey[closureName]
	if closure == nil {
		return
	}
	bindings := ops[1:]
	base := len(closure.Params) - len(bindings)
	if base < 0 {
		return
	}
	for i, b := range bindings {
		if p, ok := isTainted(fa.tainted, b); ok {
			fa.addEffect(closureName, base+i, p)
		}
	}
}

// visit applies the taint transfer for one instruction of the current block.
func (fa *funcAnalysis) visit(inst *ir.Instruction) {
	// A read of a tainted global seeds the result regardless of the reading
	// opcode (ENG-6); runs before the switch so the register is tainted for
	// any subsequent same-pass use.
	fa.readGlobalTaint(inst)
	switch inst.Op {
	case ir.OpCode_OP_CODE_CALL, ir.OpCode_OP_CODE_INVOKE:
		fa.handleCall(inst)
	case ir.OpCode_OP_CODE_STORE:
		visitStore(inst, fa.defs, fa.tainted, fa.nonEscaping)
		fa.recordGlobalStore(inst)
		fa.recordParamMemoryTaint(inst)
	case ir.OpCode_OP_CODE_FIELD, ir.OpCode_OP_CODE_FIELD_ADDR:
		visitFieldRead(inst, fa.tainted)
	case ir.OpCode_OP_CODE_INTRINSIC:
		// go.defer / go.goroutine carry a CallCommon; route them through the
		// call transfer so sinks/sources/propagation aren't lost.
		if inst.Call != nil {
			fa.handleCall(inst)
		}
		if inst.GetIntrinsic() == "builtin.make_closure" {
			fa.handleMakeClosure(inst)
		}
		visitIntrinsic(inst, fa.defs, fa.tainted)
	case ir.OpCode_OP_CODE_RET:
		// The cheap check goes FIRST: once the function is already known
		// taint-returning the scan cannot change the outcome, and skipping it
		// avoids isTaintedArg's per-miss "#*" key allocation on every later
		// worklist pass over this RET.
		if pos, ok := firstTaintedArg(fa.tainted, inst.GetOperands()); fa.res.returnsOrigin == nil && ok {
			// Interprocedural ENG-9: a tainted value returned on a path a
			// validator guard dominates (`if !valid(x) { return "" }; return x`)
			// is validated on every returning path, so the function is not
			// taint-returning for this rule. Suppressing the return summary
			// stops a sanitized value from tainting callers — the cross-function
			// analogue of the intra-procedural guarded-sink suppression below.
			// The CFG guard covers multi-block functions; validated covers the
			// single-block (no-CFG) straight-line case where order is dominance.
			retValidated := false
			if fa.linearFn {
				for _, op := range inst.GetOperands() {
					if r := op.GetRegName(); r != "" && fa.validated[r] {
						retValidated = true
						break
					}
				}
			}
			if !retValidated && !fa.guards.guarded(fa.curBlock, pos, fa.tainted) {
				fa.res.returnsOrigin = pos
			}
		}
	default:
		if propagatingOps[inst.Op] {
			markTaintFromOperands(fa.tainted, inst.Name, inst.GetOperands())
		}
	}
}

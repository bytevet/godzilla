package go_converter

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type Converter struct {
	fset *token.FileSet

	typeCache map[types.Type]*ir.Type

	// baseTypes is a read-only view of the main converter's typeCache, shared
	// with workers. It is fully built (sequentially, by addPackageMembers)
	// before any worker starts, and never written afterwards, so concurrent
	// reads are race-free.
	baseTypes map[types.Type]*ir.Type

	// fnNames memoizes ssa.Function.String() — rendering it re-runs
	// RelString/TypeString every time, and the same name is consulted by every
	// sort comparison and callee reference.
	fnNames map[*ssa.Function]string

	// baseNames is a read-only view of the main converter's fnNames, shared with
	// workers — the same contract as baseTypes: fully built by lowerModules'
	// package loop (via the sort comparator and addPackageMembers) before any
	// worker starts, never written afterwards, so concurrent reads are race-free.
	baseNames map[*ssa.Function]string

	// valueCache interns the *ir.Value operand wrappers per function (cleared at
	// the top of convertFunction): one ssa.Value is typically referenced by many
	// instructions, and the wrappers are immutable once emitted, so one object per
	// value halves the converter's smallest-object churn.
	valueCache map[ssa.Value]*ir.Value

	// routeHandlers maps a function registered as an HTTP route handler
	// (passed to a router's GET/POST/Handle/Use/... call) to the register name
	// of its request/context parameter, so addHTTPRequestSource can taint the
	// request object even for a framework whose context type we have no rules
	// for. Populated by collectRouteHandlers.
	routeHandlers map[*ssa.Function]string

	// routeFormParams maps a route-registered handler to the register names of its
	// BOUND-FORM parameters: value-struct params that a binding middleware
	// (macaron/martini `binding.Bind`/`bindIgnErr`, etc.) reflectively fills from
	// the request. Such a param is request-derived, so addHTTPRequestSource seeds
	// it as a request source and its field reads carry taint. Populated by
	// collectRouteHandlers alongside routeHandlers.
	routeFormParams map[*ssa.Function][]string

	// funcAliases maps a package-level variable that holds a FUNCTION to that
	// function, so a call through the variable gets a callee name. Populated by
	// collectFuncAliases.
	funcAliases map[*ssa.Global]*ssa.Function

	// targetPkgs is the set of user-authored (scanned) package import paths.
	// Dependency bodies are lowered so taint flows through them, but findings are
	// scoped back to these packages so a sink reached inside a library is not
	// reported. Populated by ConvertFile.
	targetPkgs map[string]bool
}

// TargetPackages returns the set of user-authored package import paths from the
// most recent ConvertFile. Everything else in the returned program is a lowered
// dependency, whose findings the caller suppresses (see internal/scan).
func (c *Converter) TargetPackages() map[string]bool { return c.targetPkgs }

func NewConverter() *Converter {
	return &Converter{
		typeCache:  make(map[types.Type]*ir.Type),
		fnNames:    make(map[*ssa.Function]string),
		valueCache: make(map[ssa.Value]*ir.Value),
	}
}

// IsGoFile reports whether path is a Go source file this frontend lowers.
// Exported so internal/scan's language detection and dispatch share ONE
// predicate with the frontend instead of drifting copies.
func IsGoFile(path string) bool { return strings.HasSuffix(path, ".go") }

// fnString returns f.String(), memoized per converter and backed by the parent
// converter's already-built names on a worker (baseNames, read-only).
func (c *Converter) fnString(f *ssa.Function) string {
	if s, ok := c.fnNames[f]; ok {
		return s
	}
	if s, ok := c.baseNames[f]; ok {
		return s
	}
	s := f.String()
	c.fnNames[f] = s
	return s
}

// ConvertFile lowers the Go package(s) at path into gIR — a single .go file
// (loading its containing package) or a directory (loaded recursively). Package
// load errors are warnings, not failures, so partial/vulnerable code still
// converts.
func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// A file path loads its containing package; a directory loads recursively.
	dir, pattern := abs, "./..."
	if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
		dir, pattern = filepath.Dir(abs), "."
	}

	// Two-phase load, so dependency bodies are lowered WITHOUT paying for the
	// stdlib: Phase A (classifyPackages) is a metadata-only `go list` that
	// classifies the closure by module; Phase B (loadAndBuildSSA) loads syntax
	// for every non-stdlib package as an explicit root and builds SSA, with the
	// stdlib arriving as export data (bodyless SSA packages).
	reportable, stdlibPkgs, extraRoots, err := classifyPackages(dir, pattern)
	if err != nil {
		return nil, err
	}
	c.targetPkgs = reportable

	prog, fset, err := loadAndBuildSSA(dir, pattern, extraRoots)
	if err != nil {
		return nil, err
	}
	c.fset = fset
	// AllFunctions is a full-program traversal; compute it once and share it
	// between route-handler detection and the grouping below.
	allFns := ssautil.AllFunctions(prog)
	c.routeHandlers, c.routeFormParams = collectRouteHandlers(allFns)
	c.funcAliases = collectFuncAliases(allFns)

	// Lower only the functions REACHABLE from user (reportable) code. A whole
	// dependency closure runs to tens of thousands of functions, but the
	// demand-driven engine only ever analyses a dependency function when taint
	// reaches it from user code, so lowering the unreachable remainder is pure
	// retained-gIR memory that pushes a big scan into OOM.
	reach := reachableFuncs(allFns, reportable)

	// pkg.Members only exposes package-level funcs, not methods or closures — and
	// vulnerable code frequently lives inside a closure (e.g. an http.HandleFunc
	// handler). AllFunctions enumerates every function/method/closure.
	funcsByPkg := make(map[*ssa.Package][]*ssa.Function)
	for fn := range allFns {
		if fn.Pkg != nil && reach[fn] {
			funcsByPkg[fn.Pkg] = append(funcsByPkg[fn.Pkg], fn)
		}
	}

	return c.lowerModules(funcsByPkg, stdlibPkgs), nil
}

// reachableFuncs returns the functions reachable from user (reportable) code by
// following the same call edges the taint engine does: direct/static calls,
// function values referenced as instruction operands (MakeClosure, func-valued
// args, method values), and interface dispatch resolved by CHA — every concrete
// method whose name matches an invoked interface method, exactly as the engine's
// methodImpls index. It must stay a SOUND over-approximation of what the engine
// can analyse, so that a function it omits is one no reachable call site can
// target and skipping its lowering cannot change any finding. Reportable-package
// functions are always included (taint seeds; findings surface there), even ones
// with no static caller.
func reachableFuncs(allFns map[*ssa.Function]bool, reportable map[string]bool) map[*ssa.Function]bool {
	// method name -> concrete methods exposing it, for interface-call resolution.
	methodsByName := map[string][]*ssa.Function{}
	for fn := range allFns {
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			methodsByName[fn.Name()] = append(methodsByName[fn.Name()], fn)
		}
	}
	reach := make(map[*ssa.Function]bool, len(allFns))
	var queue []*ssa.Function
	add := func(fn *ssa.Function) {
		if fn != nil && allFns[fn] && !reach[fn] {
			reach[fn] = true
			queue = append(queue, fn)
		}
	}
	for fn := range allFns {
		if fn.Pkg != nil && fn.Pkg.Pkg != nil && reportable[fn.Pkg.Pkg.Path()] {
			add(fn)
		}
	}
	// Recycled operand buffer: Operands APPENDS into the slice it is given, so a
	// fresh nil per instruction allocates once per instruction of the whole
	// reachable closure. Nothing retains rands or its elements beyond the loop
	// body, so one buffer serves the entire traversal.
	var rands []*ssa.Value
	for len(queue) > 0 {
		fn := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(ssa.CallInstruction); ok {
					cc := call.Common()
					if callee := cc.StaticCallee(); callee != nil {
						add(callee)
					} else if cc.IsInvoke() {
						for _, m := range methodsByName[cc.Method.Name()] {
							add(m)
						}
					}
				}
				// Any function VALUE referenced here (MakeClosure.Fn, a
				// func-typed argument, a method value) can later be called.
				rands = instr.Operands(rands[:0])
				for _, op := range rands {
					if op == nil {
						continue
					}
					if f, ok := (*op).(*ssa.Function); ok {
						add(f)
					}
				}
			}
		}
	}
	return reach
}

// classifyPackages is Phase A of the two-phase load: a metadata-only `go list`
// (no parsing, no typechecking) that discovers the dependency closure and
// classifies every package by MODULE (go/packages NeedModule):
//   - stdlib (nil Module) is NOT lowered — modeled by rules. Its bodies are
//     never read downstream, so loading its source and building its SSA is pure
//     overhead;
//   - the user's own module(s) — reportable: findings here are surfaced;
//   - third-party modules — lowered so taint flows through their bodies, but
//     findings inside them are scoped out downstream (noise, not actionable).
//
// Keying on the MODULE (not a package-path heuristic) is why a single-word
// module path like `abccc` or one of the user's own sibling packages is not
// mistaken for the stdlib. Reportable = the scanned packages plus everything
// sharing their module, so scanning a subdir still reports the whole module.
// extraRoots is every non-stdlib package the pattern didn't match — Phase B
// loads them as explicit syntax roots.
func classifyPackages(dir, pattern string) (reportable, stdlibPkgs map[string]bool, extraRoots []string, err error) {
	metaCfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedImports | packages.NeedDeps | packages.NeedModule,
		Tests: false,
		Dir:   dir,
	}
	meta, err := packages.Load(metaCfg, pattern)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(meta) == 0 {
		return nil, nil, nil, fmt.Errorf("no Go packages found under %s", dir)
	}
	initialPaths := make(map[string]bool, len(meta))
	targetModules := map[string]bool{}
	for _, p := range meta {
		initialPaths[p.PkgPath] = true
		if p.Module != nil {
			targetModules[p.Module.Path] = true
		}
	}
	stdlibPkgs = map[string]bool{}
	reportable = map[string]bool{}
	seenPkg := map[string]bool{}
	var classify func(p *packages.Package)
	classify = func(p *packages.Package) {
		if p == nil || seenPkg[p.PkgPath] {
			return
		}
		seenPkg[p.PkgPath] = true
		switch {
		case initialPaths[p.PkgPath]:
			reportable[p.PkgPath] = true
		case p.Module == nil:
			stdlibPkgs[p.PkgPath] = true
		case targetModules[p.Module.Path]:
			// Same module as the scan target but outside the pattern (e.g.
			// scanning a subdir): still reportable, and it must be a Phase-B
			// root so its body keeps being lowered from source.
			reportable[p.PkgPath] = true
			extraRoots = append(extraRoots, p.PkgPath)
		default:
			extraRoots = append(extraRoots, p.PkgPath) // third-party
		}
		for _, imp := range p.Imports {
			classify(imp)
		}
	}
	for _, p := range meta {
		classify(p)
	}
	sort.Strings(extraRoots) // deterministic Phase-B roots
	return reportable, stdlibPkgs, extraRoots, nil
}

// loadAndBuildSSA is Phase B of the two-phase load: it loads SYNTAX only where
// bodies are actually lowered — the target pattern plus the explicit extraRoots
// (third-party deps and same-module packages outside the pattern) — and builds
// the SSA program. The stdlib is deliberately NOT a root and NeedDeps is NOT
// set, so it arrives as compiled export data — identical types to
// source-checking it, but with no stdlib parsing or typechecking, and (with no
// syntax) its SSA packages are created bodyless, so prog.Build() skips stdlib
// bodies too. Making every lowered package an explicit ROOT (never a bare dep)
// is what keeps its Syntax+TypesInfo complete without NeedDeps.
func loadAndBuildSSA(dir, pattern string, extraRoots []string) (*ssa.Program, *token.FileSet, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Tests: false,
		Dir:   dir,
	}
	initial, err := packages.Load(cfg, append([]string{pattern}, extraRoots...)...)
	if err != nil {
		return nil, nil, err
	}
	if len(initial) == 0 {
		return nil, nil, fmt.Errorf("no Go packages found under %s", dir)
	}
	// Conversion continues on whatever built, so partial/vulnerable code still
	// converts. The summary goes to stderr — a stdout write would corrupt
	// machine-readable output when the user pipes findings.
	if packages.PrintErrors(initial) > 0 {
		fmt.Fprintln(os.Stderr, "warning: some Go packages failed to load cleanly; findings from those packages may be incomplete")
	}

	// Create SSA for every loaded package. Non-stdlib roots have syntax, so
	// prog.Build() builds their bodies and AllFunctions yields them — the engine
	// can then flow taint through a library call instead of dropping at it.
	// Stdlib packages (export data, no syntax) are created bodyless: their
	// declarations still resolve callee names and method sets, but nothing is
	// built or lowered for them.
	//
	// ssautil.AllPackages is not enough here: it only visits the go/packages
	// graph, which without NeedDeps is truncated at the roots' direct imports.
	// Export data can reference packages BEYOND that frontier (e.g. a type alias
	// into a transitive stdlib package), and the SSA builder PANICS on any
	// referenced-but-uncreated package — hence the full transitive types.Package
	// closure created types-only below.
	//
	// Mode 0 builds generic functions ONCE in parameterized form rather than one
	// monomorphized copy per instantiation (ssa.InstantiateGenerics). The taint
	// engine is context-insensitive and merges all instantiations of a callee
	// anyway, so instantiation buys no precision it can use, while on a
	// generics-heavy dependency closure it multiplies the live SSA set enough to
	// OOM-kill a whole-repo scan. Every generic body is still analyzed
	// (AllFunctions yields it).
	prog := ssa.NewProgram(initial[0].Fset, 0)
	created := map[*types.Package]bool{}
	var createTypesOnly func(tp *types.Package)
	createTypesOnly = func(tp *types.Package) {
		if tp == nil || created[tp] {
			return
		}
		created[tp] = true
		for _, imp := range tp.Imports() {
			createTypesOnly(imp)
		}
		prog.CreatePackage(tp, nil, nil, true)
	}
	packages.Visit(initial, nil, func(p *packages.Package) {
		if p.Types == nil || p.IllTyped || created[p.Types] {
			return
		}
		created[p.Types] = true
		for _, imp := range p.Types.Imports() {
			createTypesOnly(imp)
		}
		prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
	})
	prog.Build()
	return prog, initial[0].Fset, nil
}

// lowerModules lowers the target packages and every non-stdlib dependency
// (third-party bodies, so taint flows through them; the stdlib is modeled by
// rules instead). No RTA pre-pass: analysis is demand-driven (the engine reaches
// a dependency function only when taint does — see Engine.ScopeSeed), so its cost
// does not scale with the lowered set and a reachability pass is pure overhead.
// The remaining cost is the lowering itself, parallelized here.
func (c *Converter) lowerModules(funcsByPkg map[*ssa.Package][]*ssa.Function, stdlibPkgs map[string]bool) *ir.Program {
	var pkgList []*ssa.Package
	for pkg := range funcsByPkg {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		if stdlibPkgs[pkg.Pkg.Path()] {
			continue // stdlib: modeled by rules, not lowered
		}
		pkgList = append(pkgList, pkg)
	}
	sort.Slice(pkgList, func(i, j int) bool { return pkgList[i].Pkg.Path() < pkgList[j].Pkg.Path() })

	// Build each module's shell (name, types, globals) sequentially on the main
	// converter, and collect its functions in deterministic order.
	irProg := &ir.Program{}
	irProg.Modules = make([]*ir.Module, 0, len(pkgList))
	type modWork struct {
		mod   *ir.Module
		funcs []*ssa.Function
	}
	works := make([]modWork, 0, len(pkgList))
	totalFuncs := 0
	for _, pkg := range pkgList {
		funcs := funcsByPkg[pkg]
		sort.Slice(funcs, func(i, j int) bool { return c.fnString(funcs[i]) < c.fnString(funcs[j]) })
		mod := &ir.Module{Name: pkg.Pkg.Path(), Language: "go"}
		c.addPackageMembers(mod, pkg)
		mod.Functions = make([]*ir.Function, len(funcs))
		works = append(works, modWork{mod, funcs})
		irProg.Modules = append(irProg.Modules, mod)
		totalFuncs += len(funcs)
	}

	// Convert functions concurrently — the dominant remaining cost once deps are
	// lowered. Each worker uses its OWN Converter: the caches are pure
	// memoization, so per-worker copies need no lock and cannot race, while the
	// read-only fset/routeHandlers are shared. Output stays deterministic:
	// functions are pre-sorted and written to fixed slice indices.
	type fnJob struct {
		mod *ir.Module
		idx int
		fn  *ssa.Function
	}
	jobs := make([]fnJob, 0, totalFuncs)
	for _, w := range works {
		for i, fn := range w.funcs {
			jobs = append(jobs, fnJob{w.mod, i, fn})
		}
	}
	nWorkers := max(1, min(runtime.GOMAXPROCS(0), len(jobs)))
	jobCh := make(chan fnJob)
	var wg sync.WaitGroup
	for range nWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := c.worker()
			for j := range jobCh {
				j.mod.Functions[j.idx] = w.convertFunction(j.fn)
			}
		}()
	}
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)
	wg.Wait()

	return irProg
}

// worker returns a lightweight Converter that shares this converter's read-only
// setup (fset, route tables, base types and base names) but has its own
// typeCache/fnNames, so it can lower functions concurrently without locking or
// racing on the shared caches. targetPkgs is intentionally NOT copied: it is read
// only via TargetPackages() on the top-level converter, never on the worker path.
// worker returns a Converter for one lowering goroutine. Every whole-program
// analysis result computed once in convertProgram has to be carried across here:
// a worker builds its own maps, so a field left out is silently EMPTY during
// lowering rather than nil-panicking, and the analysis it represents just stops
// having an effect.
func (c *Converter) worker() *Converter {
	w := NewConverter()
	w.fset = c.fset
	w.baseTypes = c.typeCache
	w.baseNames = c.fnNames
	w.routeHandlers = c.routeHandlers
	w.routeFormParams = c.routeFormParams
	w.funcAliases = c.funcAliases
	return w
}

// addPackageMembers lowers a package's exported types and globals into mod.
func (c *Converter) addPackageMembers(mod *ir.Module, pkg *ssa.Package) {
	for _, member := range pkg.Members {
		switch m := member.(type) {
		case *ssa.Type:
			mod.Types = append(mod.Types, c.convertType(m.Type()))
		case *ssa.Global:
			mod.Globals = append(mod.Globals, &ir.Global{
				Name: m.Name(),
				Type: c.convertType(m.Type()),
				Pos:  c.convertPos(m.Pos()),
			})
		}
	}
}

func (c *Converter) convertFunction(f *ssa.Function) *ir.Function {
	// The value-wrapper intern table is per function: registers are
	// function-scoped, so wrappers must not leak across functions.
	clear(c.valueCache)
	irFunc := &ir.Function{
		Name:          c.fnString(f),
		ObjectName:    f.Name(),
		PackageName:   f.Pkg.Pkg.Path(),
		Pos:           c.convertPos(f.Pos()),
		Synthetic:     f.Synthetic != "",
		CanonicalName: c.canonicalFunc(f),
	}
	// Tag a method with its bare name so the engine indexes it for CHA dynamic
	// dispatch without parsing the canonical name.
	if f.Signature != nil && f.Signature.Recv() != nil {
		irFunc.MethodName = f.Name()
	}

	if f.Signature != nil {
		irFunc.Signature = c.convertSignature(f.Signature)
	}

	if n := len(f.Params) + len(f.FreeVars); n > 0 {
		irFunc.Params = make([]*ir.Value, 0, n)
	}
	for _, p := range f.Params {
		irFunc.Params = append(irFunc.Params, &ir.Value{
			Kind: &ir.Value_RegName{RegName: p.Name()},
		})
	}
	// Append captured free variables as TRAILING parameters so taint flows from a
	// `builtin.make_closure` binding into the closure's use of that variable — the
	// engine maps the K bindings to the last K params, so the order matters.
	for _, fv := range f.FreeVars {
		irFunc.Params = append(irFunc.Params, &ir.Value{
			Kind: &ir.Value_RegName{RegName: fv.Name()},
		})
	}

	if n := len(f.Blocks); n > 0 {
		irFunc.Blocks = make([]*ir.BasicBlock, 0, n)
	}
	for _, b := range f.Blocks {
		irFunc.Blocks = append(irFunc.Blocks, c.convertBlock(b))
	}

	c.addHTTPRequestSource(f, irFunc)

	return irFunc
}

// httpRequestSourceCallee is the canonical name of the synthetic source injected
// for an HTTP handler's *http.Request parameter (see addHTTPRequestSource). The
// Go rule packs list it as a source, so every read off the request object carries
// taint — including field reads (r.URL.Path, r.Form, r.Body) that no method-call
// rule can match.
const httpRequestSourceCallee = "go:@net/http.Request"

// newHTTPRequestSource builds the synthetic request-object source CALL: setting
// its Name to a register holding an inbound *http.Request is what marks that
// register tainted at the engine.
func newHTTPRequestSource(name string, pos *ir.Position) *ir.Instruction {
	return &ir.Instruction{
		Name:    name,
		Op:      ir.OpCode_OP_CODE_CALL,
		Pos:     pos,
		Comment: "http-request-source",
		Call: &ir.CallCommon{
			Callee: httpRequestSourceCallee,
			Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: httpRequestSourceCallee}},
		},
	}
}

// addHTTPRequestSource injects synthetic request-object sources so every value
// holding an INBOUND *http.Request is tainted. The register defined by the
// synthetic source CALL is the value's own name, so the engine (which seeds taint
// by register name) marks the request tainted and whole-object taint flows to
// every field read off it.
//
// Three kinds of value are seeded:
//
//   - Any *http.Request PARAMETER of any function — an inbound request handed to
//     a function is attacker-controlled regardless of what else it takes, so no
//     ResponseWriter co-parameter is required (that would miss helpers and
//     framework internals which receive the request alone).
//   - Any framework CONTEXT parameter of a route-registered handler
//     (collectRouteHandlers) — a *gin.Context / echo.Context / *fiber.Ctx we have
//     no other knowledge of.
//   - Any FIELD-READ / LOAD value whose static type is *http.Request (macaron's
//     `ctx.Req`, beego's `c.Ctx.Request`), read INSIDE the lowered framework body.
//     This is what carries taint OUT of a framework whose request accessors bottom
//     out in a field read off the embedded *http.Request rather than a modeled
//     stdlib call.
//
// Only inbound requests are seeded: an OUTBOUND request is an http.NewRequest*
// call RESULT (a *ssa.Call / *ssa.Extract), never a parameter or a field read, so
// it is excluded structurally and no proven-safe outbound flow is tainted.
func (c *Converter) addHTTPRequestSource(f *ssa.Function, irFunc *ir.Function) {
	if len(irFunc.Blocks) == 0 {
		return
	}

	// (1) Parameters: inbound *http.Request params, plus a route handler's
	// framework context param — one source per distinct register, prepended.
	var paramSeeds []string
	seen := map[string]bool{}
	for _, p := range f.Params {
		if isNamedTypePtr(p.Type(), "net/http", "Request") && !seen[p.Name()] {
			paramSeeds = append(paramSeeds, p.Name())
			seen[p.Name()] = true
		}
	}
	if reg, ok := c.routeHandlers[f]; ok && reg != "" && !seen[reg] {
		paramSeeds = append(paramSeeds, reg)
		seen[reg] = true
	}
	// Bound-form params of a route handler: a binding middleware filled them from
	// the request, so field reads off them are attacker-controlled.
	for _, reg := range c.routeFormParams[f] {
		if reg != "" && !seen[reg] {
			paramSeeds = append(paramSeeds, reg)
			seen[reg] = true
		}
	}
	if len(paramSeeds) > 0 {
		srcs := make([]*ir.Instruction, 0, len(paramSeeds))
		for _, reg := range paramSeeds {
			srcs = append(srcs, newHTTPRequestSource(reg, irFunc.Pos))
		}
		entry := irFunc.Blocks[0]
		entry.Instrs = append(srcs, entry.Instrs...)
	}

	// (2) Field-read / load values of type *http.Request read inside this body.
	// SSA and IR blocks are 1:1 by index (see convertBlock), so instruction i of
	// SSA block b lowered to IR instruction i of IR block b; insert a synthetic
	// source right after each such IR instruction, re-using its register name.
	for bi, sb := range f.Blocks {
		if bi >= len(irFunc.Blocks) {
			break
		}
		irBlock := irFunc.Blocks[bi]
		if len(sb.Instrs) != len(irBlock.Instrs) {
			// Index-matching would misplace the source. NOT rare: part (1) prepends
			// parameter sources to the entry block, so block 0 is skipped whenever this
			// function got a param seed — its entry-block *http.Request field read needs
			// no second source, being already seeded above. Any other mismatch is a
			// lowering bug; skipping is safe either way.
			continue
		}
		// Fast path: most blocks read no inbound *http.Request, so the rebuilt slice
		// would be value-identical. Skip the allocation for them.
		hasReq := false
		for _, sinst := range sb.Instrs {
			if inboundRequestValue(sinst) {
				hasReq = true
				break
			}
		}
		if !hasReq {
			continue
		}
		out := make([]*ir.Instruction, 0, len(irBlock.Instrs)+1)
		for ii, sinst := range sb.Instrs {
			irInst := irBlock.Instrs[ii]
			out = append(out, irInst)
			if !inboundRequestValue(sinst) {
				continue
			}
			if reg := irInst.GetName(); reg != "" {
				out = append(out, newHTTPRequestSource(reg, irInst.GetPos()))
			}
		}
		irBlock.Instrs = out
	}
}

// inboundRequestValue reports whether an SSA instruction reads an inbound
// *http.Request out of a field or a load — the request being unwrapped from a
// framework context (macaron `ctx.Req`, beego `c.Ctx.Request`). A *ssa.Call is
// deliberately excluded so an OUTBOUND request (http.NewRequest*) is never seeded.
func inboundRequestValue(inst ssa.Instruction) bool {
	switch v := inst.(type) {
	case *ssa.Field:
		return isNamedTypePtr(v.Type(), "net/http", "Request")
	case *ssa.UnOp:
		// A load (*p) — the FieldAddr+load shape `ctx.Req` lowers to.
		return v.Op == token.MUL && isNamedTypePtr(v.Type(), "net/http", "Request")
	default:
		return false
	}
}

func isNamedTypePtr(t types.Type, pkgPath, name string) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	return isNamedType(ptr.Elem(), pkgPath, name)
}

func isNamedType(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath && obj.Name() == name
}

// templateTrustedTypes are the html/template string types whose conversion marks
// a value ALREADY-SAFE and BYPASSES the package's context-aware auto-escaping.
// Converting attacker-controlled data to one is the canonical Go XSS pattern
// (gosec G203). A conversion is not a call, so it carries no callee for a sink
// rule to match — the frontend synthesizes one (see emitTemplateTrustedConv).
var templateTrustedTypes = map[string]bool{
	"HTML": true, "HTMLAttr": true, "JS": true, "JSStr": true,
	"URL": true, "CSS": true, "Srcset": true,
}

// emitTemplateTrustedConv, when t is an html/template trusted-string type, lowers
// the conversion as a synthetic CALL `go:html/template.<Type>` (arg 0 = the
// converted value) instead of an opaque OP_CODE_CONVERT, so the rule engine can
// treat it as an XSS sink. It is also a default propagator, so for every non-XSS
// rule the result still carries taint as a plain conversion would. Returns false
// when t is not a trusted type.
func (c *Converter) emitTemplateTrustedConv(irInst *ir.Instruction, t types.Type, x ssa.Value) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "html/template" || !templateTrustedTypes[obj.Name()] {
		return false
	}
	callee := "go:html/template." + obj.Name()
	irInst.Op = ir.OpCode_OP_CODE_CALL
	irInst.Call = &ir.CallCommon{
		Callee: callee,
		Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: callee}},
		Args:   []*ir.Value{c.convertValue(x)},
	}
	return true
}

// lowerConversion lowers a Go SSA type conversion (ChangeType / Convert): a
// trusted-template-type sink CALL when the destination is an html/template
// trusted type, otherwise a plain CONVERT of the operand.
func (c *Converter) lowerConversion(irInst *ir.Instruction, t types.Type, x ssa.Value) {
	if !c.emitTemplateTrustedConv(irInst, t, x) {
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(x))
	}
}

// routingVerbs are the method names (lowercased) that register an HTTP handler
// across the common Go routers. A call to a method with one of these names that
// is passed a function value is treated as a route registration, which is how the
// frontend recognizes a handler for a framework context type it has no other
// knowledge of.
var routingVerbs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "options": true, "connect": true, "trace": true,
	"any": true, "all": true, "handle": true, "handlefunc": true, "use": true,
}

// collectRouteHandlers finds functions registered as HTTP route handlers — a
// function value passed to a call whose method name is a routing verb
// (r.GET("/x", h), mux.HandleFunc(..., h), e.Use(mw), …) — and maps each to the
// register name of its request/context parameter, plus its bound-form parameter
// registers (see formParams).
// collectFuncAliases maps each package-level variable that holds a FUNCTION to
// that function. A package re-exporting another's function as a variable --
// `var Params = macaron.Params`, how grafana's pkg/web surfaces macaron -- turns
// every call through it into an INDIRECT call: SSA loads the global and calls the
// loaded value, so there is no static callee and convertCall leaves the name
// empty. An unnamed callee matches no source, sink or propagator glob, so the
// call is invisible to every rule; grafana CVE-2021-43798 reaches os.Open through
// exactly that alias.
//
// Only a variable with EXACTLY ONE store program-wide is mapped, and only when
// that store's value is a function. A second store means the variable is
// reassigned -- a mock swapped in by a test, a hook rebound at init -- and the
// call site no longer has one answer, so naming either would be a guess. Counting
// every store rather than only the function-valued ones is what makes the guard
// hold: a var later set to nil or to a different function is excluded, not
// silently resolved to its first value.
func collectFuncAliases(allFns map[*ssa.Function]bool) map[*ssa.Global]*ssa.Function {
	type record struct {
		fn     *ssa.Function
		stores int
	}
	seen := map[*ssa.Global]*record{}
	for fn := range allFns {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				st, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				g, ok := st.Addr.(*ssa.Global)
				if !ok {
					continue
				}
				r := seen[g]
				if r == nil {
					r = &record{}
					seen[g] = r
				}
				r.stores++
				if target, ok := st.Val.(*ssa.Function); ok {
					r.fn = target
				}
			}
		}
	}
	out := map[*ssa.Global]*ssa.Function{}
	for g, r := range seen {
		if r.stores == 1 && r.fn != nil {
			out[g] = r.fn
		}
	}
	return out
}

// aliasedFunc returns the function an indirect call's callee value resolves to
// when that value is a load of a function-holding package-level variable, or nil.
// A load is UnOp(MUL) over the global.
func (c *Converter) aliasedFunc(v ssa.Value) *ssa.Function {
	load, ok := v.(*ssa.UnOp)
	if !ok || load.Op != token.MUL {
		return nil
	}
	g, ok := load.X.(*ssa.Global)
	if !ok {
		return nil
	}
	return c.funcAliases[g]
}

func collectRouteHandlers(allFns map[*ssa.Function]bool) (map[*ssa.Function]string, map[*ssa.Function][]string) {
	handlers := map[*ssa.Function]string{}
	forms := map[*ssa.Function][]string{}
	for fn := range allFns {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}
				common := call.Common()
				if !routingVerbs[strings.ToLower(routingMethodName(common))] {
					continue
				}
				for _, arg := range common.Args {
					h := handlerFuncArg(arg)
					if h == nil {
						continue
					}
					if reg, ok := contextParam(h); ok {
						handlers[h] = reg
					}
					if fps := formParams(h); len(fps) > 0 {
						forms[h] = fps
					}
				}
			}
		}
	}
	return handlers, forms
}

// formParams returns the register names of a route handler's bound-form
// parameters: parameters whose static type is a named struct passed BY VALUE. A
// binding middleware (macaron/martini `binding.Bind`/`bindIgnErr`, …)
// reflectively decodes the request into such a param, so it is request-derived
// and its field reads carry taint. The value-struct shape is the
// low-false-positive signal: a framework context or an injected service is a
// pointer or interface, so those are excluded.
func formParams(h *ssa.Function) []string {
	var out []string
	for _, p := range h.Params {
		if p.Name() == "" {
			continue
		}
		if _, ok := p.Type().(*types.Named); !ok {
			continue // a value struct is a *types.Named whose underlying is a struct
		}
		if _, ok := p.Type().Underlying().(*types.Struct); ok {
			out = append(out, p.Name())
		}
	}
	return out
}

// routingMethodName returns the method name of a call, for both interface
// (invoke) and concrete method calls, or "" for a non-method call.
func routingMethodName(cc *ssa.CallCommon) string {
	if cc.Method != nil {
		return cc.Method.Name()
	}
	if fn, ok := cc.Value.(*ssa.Function); ok && fn.Signature.Recv() != nil {
		return fn.Name()
	}
	return ""
}

// handlerFuncArg returns the underlying *ssa.Function of a call argument that is
// a function value — passed directly or via MakeClosure — or nil.
func handlerFuncArg(arg ssa.Value) *ssa.Function {
	switch v := arg.(type) {
	case *ssa.Function:
		return v
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
			return fn
		}
	}
	return nil
}

// contextParam returns the register name of a handler's request/context
// parameter: the first parameter that is a pointer to a named type or a named
// interface (e.g. *http.Request, *gin.Context, echo.Context, *fiber.Ctx),
// excluding http.ResponseWriter.
func contextParam(h *ssa.Function) (string, bool) {
	for _, p := range h.Params {
		t := p.Type()
		if isNamedType(t, "net/http", "ResponseWriter") {
			continue
		}
		if isRequestLikeType(t) && p.Name() != "" {
			return p.Name(), true
		}
	}
	return "", false
}

// isRequestLikeType reports whether t is a value we can call accessor methods on
// — a pointer to a named type, or a named interface type.
func isRequestLikeType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		_, ok := ptr.Elem().(*types.Named)
		return ok
	}
	if named, ok := t.(*types.Named); ok {
		_, isIface := named.Underlying().(*types.Interface)
		return isIface
	}
	return false
}

func (c *Converter) convertBlock(b *ssa.BasicBlock) *ir.BasicBlock {
	irBlock := &ir.BasicBlock{
		Index:   int32(b.Index),
		Comment: b.Comment,
	}

	if n := len(b.Preds); n > 0 {
		irBlock.Preds = make([]int32, n)
		for i, p := range b.Preds {
			irBlock.Preds[i] = int32(p.Index)
		}
	}
	if n := len(b.Succs); n > 0 {
		irBlock.Succs = make([]int32, n)
		for i, s := range b.Succs {
			irBlock.Succs[i] = int32(s.Index)
		}
	}

	// Slab-allocate the block's instructions AND their positions: one exact-sized
	// backing array each instead of a heap object per instruction — the
	// converter's dominant allocation. The slabs must never be appended to or
	// copied after pointers are taken, so the pointers stay stable.
	slab := make([]ir.Instruction, len(b.Instrs))
	posSlab := make([]ir.Position, len(b.Instrs))
	irBlock.Instrs = make([]*ir.Instruction, len(b.Instrs))
	for i, inst := range b.Instrs {
		c.convertInstructionInto(&slab[i], &posSlab[i], inst)
		irBlock.Instrs[i] = &slab[i]
	}

	return irBlock
}

// goFormatCallees are the exact canonical FQNs of the stdlib string-returning
// fmt formatters that carry the builtin.format marker (the literal template — or
// first value — is the call's Args[0]; see internal/analysis/ssrf.go).
var goFormatCallees = map[string]bool{
	"go:fmt.Sprintf":  true,
	"go:fmt.Sprint":   true,
	"go:fmt.Sprintln": true,
}

// convertInstructionInto lowers one SSA instruction into irInst (caller-provided
// storage, see the slabs in convertBlock). irInst and pos must be zero-valued;
// pos is linked as irInst.Pos only when the instruction has a valid source
// position, so an invalid position leaves Pos nil.
func (c *Converter) convertInstructionInto(irInst *ir.Instruction, pos *ir.Position, inst ssa.Instruction) {
	if p := inst.Pos(); p.IsValid() {
		fp := c.fset.Position(p)
		pos.Filename = fp.Filename
		pos.Line = int32(fp.Line)
		pos.Column = int32(fp.Column)
		irInst.Pos = pos
	}

	if val, ok := inst.(ssa.Value); ok {
		irInst.Name = val.Name()
		irInst.Type = c.convertType(val.Type())
	}

	switch i := inst.(type) {
	// --- Core opcodes ---
	case *ssa.Alloc:
		irInst.Op = ir.OpCode_OP_CODE_ALLOC
		irInst.Heap = i.Heap
	case *ssa.BinOp:
		// A comparison's result is a bool -- influence, not content -- so it lowers
		// to the inert builtin.compare intrinsic instead of a propagating BIN_OP,
		// which stops `fmt.Sprint(user == "admin")` reading as an injection.
		if isComparisonToken(i.Op) {
			irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
			irInst.Intrinsic = "builtin.compare"
		} else {
			irInst.Op = ir.OpCode_OP_CODE_BIN_OP
			irInst.BinOp = c.convertBinOp(i.Op)
		}
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X), c.convertValue(i.Y))
	case *ssa.UnOp:
		irInst.Op = ir.OpCode_OP_CODE_UN_OP
		irInst.UnOp = c.convertUnOp(i.Op)
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Call:
		if i.Call.IsInvoke() {
			irInst.Op = ir.OpCode_OP_CODE_INVOKE
		} else {
			irInst.Op = ir.OpCode_OP_CODE_CALL
		}
		irInst.Call = c.convertCall(i.Call)
		// Tag a printf-style formatter with the language-neutral builtin.format
		// marker so the engine's SSRF host reconstruction reads the marker, not a Go
		// callee-name shape. The match is on exact FQNs: a name-shape heuristic would
		// let a user function merely named like a formatter (MySprintf) claim
		// "Args[0] is the template" and wrongly prove a fixed host, suppressing a
		// real SSRF finding.
		if goFormatCallees[irInst.Call.GetCallee()] {
			irInst.Intrinsic = "builtin.format"
		}
	case *ssa.Return:
		irInst.Op = ir.OpCode_OP_CODE_RET
		for _, r := range i.Results {
			irInst.Operands = append(irInst.Operands, c.convertValue(r))
		}
	case *ssa.If:
		irInst.Op = ir.OpCode_OP_CODE_IF
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Cond))
		irInst.TrueBlock = blockName(i.Block().Succs[0])
		irInst.FalseBlock = blockName(i.Block().Succs[1])
	case *ssa.Jump:
		irInst.Op = ir.OpCode_OP_CODE_JUMP
		irInst.JumpBlock = blockName(i.Block().Succs[0])
	case *ssa.Store:
		irInst.Op = ir.OpCode_OP_CODE_STORE
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Addr), c.convertValue(i.Val))
	case *ssa.Phi:
		irInst.Op = ir.OpCode_OP_CODE_PHI
		for idx, edge := range i.Edges {
			irInst.Operands = append(irInst.Operands, c.convertValue(edge))
			irInst.Blocks = append(irInst.Blocks, blockName(i.Block().Preds[idx]))
		}
	case *ssa.Index:
		irInst.Op = ir.OpCode_OP_CODE_INDEX
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X), c.convertValue(i.Index))
	case *ssa.IndexAddr:
		irInst.Op = ir.OpCode_OP_CODE_INDEX_ADDR
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X), c.convertValue(i.Index))
	case *ssa.Field:
		irInst.Op = ir.OpCode_OP_CODE_FIELD
		irInst.FieldIndex = int32(i.Field)
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.FieldAddr:
		irInst.Op = ir.OpCode_OP_CODE_FIELD_ADDR
		irInst.FieldIndex = int32(i.Field)
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.MakeInterface:
		irInst.Op = ir.OpCode_OP_CODE_MAKE_INTERFACE
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.ChangeType:
		c.lowerConversion(irInst, i.Type(), i.X)
	case *ssa.ChangeInterface:
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Convert:
		c.lowerConversion(irInst, i.Type(), i.X)
	case *ssa.TypeAssert:
		irInst.Op = ir.OpCode_OP_CODE_TYPE_ASSERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Extract:
		irInst.Op = ir.OpCode_OP_CODE_EXTRACT
		irInst.FieldIndex = int32(i.Index)
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Tuple))
	case *ssa.Panic:
		irInst.Op = ir.OpCode_OP_CODE_PANIC
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))

	// --- Intrinsics (language-specific escape hatch) ---
	case *ssa.RunDefers:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.rundefers"
	case *ssa.Go:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.goroutine"
		irInst.Call = c.convertCall(i.Call)
	case *ssa.Defer:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.defer"
		irInst.Call = c.convertCall(i.Call)
	case *ssa.Send:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.chan.send"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Chan), c.convertValue(i.X))
	case *ssa.Select:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.select"
		for _, state := range i.States {
			irInst.Operands = append(irInst.Operands, c.convertValue(state.Chan), c.convertValue(state.Send))
		}
	case *ssa.Range:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.range"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Next:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.next"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Iter))
	case *ssa.Lookup:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.map.lookup"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X), c.convertValue(i.Index))
	case *ssa.MapUpdate:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.map.update"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Map), c.convertValue(i.Key), c.convertValue(i.Value))
	case *ssa.MakeMap:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.make.map"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Reserve))
	case *ssa.MakeChan:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.make.chan"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Size))
	case *ssa.MakeSlice:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.make.slice"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Len), c.convertValue(i.Cap))
	case *ssa.MakeClosure:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "builtin.make_closure"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.Fn))
		for _, v := range i.Bindings {
			irInst.Operands = append(irInst.Operands, c.convertValue(v))
		}
	case *ssa.Slice:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "builtin.slice"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X), c.convertValue(i.Low), c.convertValue(i.High), c.convertValue(i.Max))
	case *ssa.SliceToArrayPointer:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "builtin.slice_to_array_ptr"
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.DebugRef:
		irInst.Op = ir.OpCode_OP_CODE_INTRINSIC
		irInst.Intrinsic = "go.debugref"

	default:
		irInst.Comment = fmt.Sprintf("unsupported instruction: %T", inst)
	}
}

// blockName is the gIR label for an SSA basic block ("b<index>"), used by
// IF/JUMP/PHI to name their target and predecessor blocks.
func blockName(b *ssa.BasicBlock) string {
	return "b" + strconv.Itoa(b.Index)
}

func (c *Converter) convertValue(v ssa.Value) *ir.Value {
	if v == nil {
		return nil
	}
	// Interning is sound only because the emitted wrappers are never mutated
	// downstream; the cache is per function (cleared by convertFunction).
	if cached, ok := c.valueCache[v]; ok {
		return cached
	}
	var out *ir.Value
	switch val := v.(type) {
	case *ssa.Const:
		out = &ir.Value{Kind: &ir.Value_Constant{Constant: c.convertConstant(val)}}
	case *ssa.Global:
		out = &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: val.Name()}}
	case *ssa.Function:
		out = &ir.Value{Kind: &ir.Value_FuncName{FuncName: c.canonicalFunc(val)}}
	case *ssa.Builtin:
		out = &ir.Value{Kind: &ir.Value_FuncName{FuncName: "builtin." + val.Name()}}
	default:
		out = &ir.Value{Kind: &ir.Value_RegName{RegName: val.Name()}}
	}
	c.valueCache[v] = out
	return out
}

func (c *Converter) convertConstant(con *ssa.Const) *ir.Constant {
	res := &ir.Constant{
		Type: c.convertType(con.Type()),
	}
	if con.Value == nil {
		res.IsNil = true
		return res
	}
	// Model every constant by its string form: it feeds the secrets scanner and
	// stays untainted (a compile-time constant is never attacker-controlled).
	res.Value = &ir.Constant_StringVal{StringVal: constantText(con.Value)}
	return res
}

// constantText renders a Go constant for the IR. A string must come back
// VERBATIM: constant.Value.String() is a display form that quotes it and
// truncates past ~72 chars, hiding every long secret (JWTs, PEM bodies) from the
// secrets scanner. Numeric and bool constants keep that display form —
// ExactString would render 3.14 as the rational 157/50.
func constantText(v constant.Value) string {
	if v.Kind() == constant.String {
		return constant.StringVal(v)
	}
	return v.String()
}

func (c *Converter) convertCall(call ssa.CallCommon) *ir.CallCommon {
	cc := &ir.CallCommon{
		Value:    c.convertValue(call.Value),
		IsInvoke: call.IsInvoke(),
	}
	if call.Method != nil {
		cc.MethodName = call.Method.Name()
		cc.Callee = "go:" + call.Method.FullName()
	} else if fn, ok := call.Value.(*ssa.Function); ok {
		cc.Callee = c.canonicalFunc(fn)
		// A statically resolved method call passes its receiver as Args[0]. Record
		// the method name so the engine strips the receiver from the logical
		// argument list without parsing the callee-name shape.
		if sig := fn.Signature; sig != nil && sig.Recv() != nil {
			cc.MethodName = fn.Name()
		}
	} else if b, ok := call.Value.(*ssa.Builtin); ok {
		cc.Callee = "builtin." + b.Name()
	} else if fn := c.aliasedFunc(call.Value); fn != nil {
		// A call through a function-holding package-level variable. Named with the
		// function it resolves to rather than the variable, because that is the Go
		// frontend's convention throughout -- callees are semantic FQNs from SSA,
		// never the syntax at the call site. See collectFuncAliases.
		cc.Callee = c.canonicalFunc(fn)
		if sig := fn.Signature; sig != nil && sig.Recv() != nil {
			cc.MethodName = fn.Name()
		}
	}
	if n := len(call.Args); n > 0 {
		cc.Args = make([]*ir.Value, n)
		for i, arg := range call.Args {
			cc.Args[i] = c.convertValue(arg)
		}
	}
	return cc
}

// canonicalFunc returns a language-prefixed, cross-language-comparable name
// for a Go function, e.g. "go:net/http.(*Request).FormValue".
func (c *Converter) canonicalFunc(f *ssa.Function) string {
	return "go:" + c.fnString(f)
}

func (c *Converter) convertType(t types.Type) *ir.Type {
	if cached, ok := c.typeCache[t]; ok {
		return cached
	}
	if cached, ok := c.baseTypes[t]; ok {
		return cached
	}

	irType := &ir.Type{}
	c.typeCache[t] = irType // Handle recursion

	switch typ := t.(type) {
	case *types.Basic:
		irType.Kind = ir.TypeKind_TYPE_KIND_BASIC
		irType.BasicKind = c.convertBasicKind(typ.Kind())
	case *types.Pointer:
		irType.Kind = ir.TypeKind_TYPE_KIND_POINTER
		irType.ElemType = c.convertType(typ.Elem())
	case *types.Struct:
		irType.Kind = ir.TypeKind_TYPE_KIND_STRUCT
		for i := range typ.NumFields() {
			f := typ.Field(i)
			irType.Fields = append(irType.Fields, &ir.Field{
				Name: f.Name(),
				Type: c.convertType(f.Type()),
			})
		}
	case *types.Slice:
		irType.Kind = ir.TypeKind_TYPE_KIND_SLICE
		irType.ElemType = c.convertType(typ.Elem())
	case *types.Array:
		irType.Kind = ir.TypeKind_TYPE_KIND_ARRAY
		irType.ElemType = c.convertType(typ.Elem())
		irType.ArrayLen = typ.Len()
	case *types.Map:
		irType.Kind = ir.TypeKind_TYPE_KIND_MAP
		irType.KeyType = c.convertType(typ.Key())
		irType.ElemType = c.convertType(typ.Elem())
	case *types.Chan:
		irType.Kind = ir.TypeKind_TYPE_KIND_CHAN
		irType.ElemType = c.convertType(typ.Elem())
	case *types.Interface:
		irType.Kind = ir.TypeKind_TYPE_KIND_INTERFACE
		for i := range typ.NumMethods() {
			m := typ.Method(i)
			irType.Methods = append(irType.Methods, &ir.Method{
				Name:      m.Name(),
				Signature: c.convertType(m.Type()),
			})
		}
	case *types.Tuple:
		irType.Kind = ir.TypeKind_TYPE_KIND_TUPLE
		for i := range typ.Len() {
			irType.Fields = append(irType.Fields, &ir.Field{
				Type: c.convertType(typ.At(i).Type()),
			})
		}
	case *types.Named:
		irType.Kind = ir.TypeKind_TYPE_KIND_NAMED
		irType.Name = typ.Obj().Name()
		irType.UnderlyingType = c.convertType(typ.Underlying())
	// Handle more...
	default:
		irType.Kind = ir.TypeKind_TYPE_KIND_UNSPECIFIED
	}

	return irType
}

func (c *Converter) convertSignature(sig *types.Signature) *ir.Signature {
	irSig := &ir.Signature{
		Variadic: sig.Variadic(),
	}
	if sig.Recv() != nil {
		irSig.Recv = c.convertType(sig.Recv().Type())
	}
	params := sig.Params()
	for i := range params.Len() {
		irSig.Params = append(irSig.Params, c.convertType(params.At(i).Type()))
	}
	results := sig.Results()
	for i := range results.Len() {
		irSig.Results = append(irSig.Results, c.convertType(results.At(i).Type()))
	}
	return irSig
}

func (c *Converter) convertPos(pos token.Pos) *ir.Position {
	if !pos.IsValid() {
		return nil
	}
	p := c.fset.Position(pos)
	return &ir.Position{
		Filename: p.Filename,
		Line:     int32(p.Line),
		Column:   int32(p.Column),
	}
}

func (c *Converter) convertBasicKind(k types.BasicKind) ir.BasicTypeKind {
	switch k {
	case types.Bool:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_BOOL
	case types.Int:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_INT
	case types.Int8:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_INT8
	case types.Int16:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_INT16
	case types.Int32:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_INT32
	case types.Int64:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_INT64
	case types.Uint:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINT
	case types.Uint8:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINT8
	case types.Uint16:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINT16
	case types.Uint32:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINT32
	case types.Uint64:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINT64
	case types.Uintptr:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UINTPTR
	case types.Float32:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_FLOAT32
	case types.Float64:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_FLOAT64
	case types.Complex64:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_COMPLEX64
	case types.Complex128:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_COMPLEX128
	case types.String:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_STRING
	case types.UnsafePointer:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNSAFE_POINTER
	case types.UntypedBool:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_BOOL
	case types.UntypedInt:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_INT
	case types.UntypedRune:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_RUNE
	case types.UntypedFloat:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_FLOAT
	case types.UntypedComplex:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_COMPLEX
	case types.UntypedString:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_STRING
	case types.UntypedNil:
		return ir.BasicTypeKind_BASIC_TYPE_KIND_UNTYPED_NIL
	}
	return ir.BasicTypeKind_BASIC_TYPE_KIND_UNSPECIFIED
}

func (c *Converter) convertBinOp(op token.Token) ir.BinOpKind {
	switch op {
	case token.ADD:
		return ir.BinOpKind_BIN_OP_ADD
	case token.SUB:
		return ir.BinOpKind_BIN_OP_SUB
	case token.MUL:
		return ir.BinOpKind_BIN_OP_MUL
	case token.QUO:
		return ir.BinOpKind_BIN_OP_QUO
	case token.REM:
		return ir.BinOpKind_BIN_OP_REM
	case token.AND:
		return ir.BinOpKind_BIN_OP_AND
	case token.OR:
		return ir.BinOpKind_BIN_OP_OR
	case token.XOR:
		return ir.BinOpKind_BIN_OP_XOR
	case token.SHL:
		return ir.BinOpKind_BIN_OP_SHL
	case token.SHR:
		return ir.BinOpKind_BIN_OP_SHR
	case token.AND_NOT:
		return ir.BinOpKind_BIN_OP_AND_NOT
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
}

// isComparisonToken reports whether op yields a bool. Those lower to the
// builtin.compare intrinsic, so they never reach convertBinOp.
func isComparisonToken(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}

func (c *Converter) convertUnOp(op token.Token) ir.UnOpKind {
	switch op {
	case token.NOT:
		return ir.UnOpKind_UN_OP_NOT
	case token.XOR:
		return ir.UnOpKind_UN_OP_BIT_NOT
	case token.SUB:
		return ir.UnOpKind_UN_OP_NEG
	case token.ADD:
		return ir.UnOpKind_UN_OP_POS
	case token.MUL:
		return ir.UnOpKind_UN_OP_DEREF
	case token.AND:
		return ir.UnOpKind_UN_OP_ADDR
	case token.ARROW:
		return ir.UnOpKind_UN_OP_ARROW
	}
	return ir.UnOpKind_UN_OP_UNSPECIFIED
}

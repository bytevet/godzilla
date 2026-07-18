package go_converter

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	ir "godzilla/pkg/ir/v1"
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

	// fnNames lazily memoizes ssa.Function.String() — rendering it re-runs
	// RelString/TypeString every time, and the same name is consulted by sort
	// comparisons and per callee reference. Per-converter and private, exactly
	// like typeCache.
	fnNames map[*ssa.Function]string

	// valueCache interns the *ir.Value operand wrappers per function (cleared at
	// the top of convertFunction): the same ssa.Value is typically referenced by
	// many instructions, and the wrappers are immutable once emitted, so reusing
	// one object per value halves the converter's smallest-object churn.
	valueCache map[ssa.Value]*ir.Value

	// routeHandlers maps a function registered as an HTTP route handler
	// (passed to a router's GET/POST/Handle/Use/... call) to the register name
	// of its request/context parameter, so addHTTPRequestSource can taint the
	// request object even for a framework whose context type we have no rules
	// for. Populated by collectRouteHandlers.
	routeHandlers map[*ssa.Function]string

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

// fnString returns f.String(), memoized per converter.
func (c *Converter) fnString(f *ssa.Function) string {
	if s, ok := c.fnNames[f]; ok {
		return s
	}
	s := f.String()
	c.fnNames[f] = s
	return s
}

// ConvertFile lowers the Go package(s) at path into gIR. path may be either a
// single .go file (its containing package is loaded) or a directory (all
// packages under it are loaded recursively). Package load errors are reported
// as warnings and conversion continues, so partial/vulnerable code still
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
	// AllFunctions is a full-program traversal (now covering the whole lowered
	// dependency closure); compute it once and share it between route-handler
	// detection and the per-package function grouping below.
	allFns := ssautil.AllFunctions(prog)
	c.routeHandlers = collectRouteHandlers(allFns)

	// pkg.Members only exposes package-level funcs, not methods or anonymous
	// function literals (closures) — and vulnerable code frequently lives inside
	// closures (e.g. http.HandleFunc handlers). AllFunctions enumerates every
	// function/method/closure; group them by their defining package.
	funcsByPkg := make(map[*ssa.Package][]*ssa.Function)
	for fn := range allFns {
		if fn.Pkg != nil {
			funcsByPkg[fn.Pkg] = append(funcsByPkg[fn.Pkg], fn)
		}
	}

	return c.lowerModules(funcsByPkg, stdlibPkgs), nil
}

// classifyPackages is Phase A of the two-phase load: a metadata-only `go list`
// (no parsing, no typechecking) that discovers the dependency closure and
// classifies every package by MODULE (go/packages NeedModule):
//   - stdlib (nil Module) is NOT lowered — modeled by rules. Its bodies are
//     never read downstream, so loading its source and building its SSA
//     (which LoadAllSyntax did) was pure overhead;
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
// is what keeps its Syntax+TypesInfo complete without NeedDeps; source roots
// resolve each other in-memory, exactly as before.
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
	// Some packages failed to load cleanly (type/parse errors). PrintErrors
	// dumps the specifics to stderr; conversion continues on whatever built so
	// partial/vulnerable code still converts. Route our summary line to stderr
	// too — a stdout write would corrupt machine-readable output when the user
	// pipes findings (e.g. `godzilla scan > out.txt`).
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
	// This replaces ssautil.AllPackages, which only visits the go/packages
	// graph — and without NeedDeps that graph is truncated at the roots' direct
	// imports. Export data can reference packages BEYOND that frontier (e.g. a
	// type alias into a transitive stdlib package), and the SSA builder panics
	// on any referenced-but-uncreated package, so we additionally create the
	// full transitive types.Package closure (types-only) of every import.
	prog := ssa.NewProgram(initial[0].Fset, ssa.InstantiateGenerics)
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
// (third-party bodies, so taint flows through them). We do NOT tree-shake
// before lowering: with demand-driven analysis (the engine analyzes a
// dependency function only when taint reaches it — see Engine.ScopeSeed), the
// analysis cost no longer scales with the lowered set, so a reachability
// pre-pass (RTA) only added overhead. The remaining cost is the lowering
// itself, which is parallelized here. The stdlib is skipped (modeled by rules).
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
	irProg := &ir.Program{Mode: "ssa"}
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
	// lowered. Each worker uses its OWN Converter (own typeCache): the cache is
	// pure memoization, so per-worker copies need no lock and cannot race, while
	// the read-only fset/routeHandlers are shared. Output is
	// deterministic: functions are pre-sorted and written to fixed slice indices.
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
// setup (fset, route handlers) but has its own typeCache, so it can
// lower functions concurrently without locking or racing on the shared cache.
// targetPkgs is intentionally NOT copied: it is read only via TargetPackages()
// on the top-level converter, never on the worker path.
func (c *Converter) worker() *Converter {
	return &Converter{
		fset:          c.fset,
		typeCache:     make(map[types.Type]*ir.Type),
		baseTypes:     c.typeCache,
		fnNames:       make(map[*ssa.Function]string),
		valueCache:    make(map[ssa.Value]*ir.Value),
		routeHandlers: c.routeHandlers,
	}
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
	// dispatch without parsing the canonical name. A method is type-resolved
	// (the receiver has a static type), so the call site is left with
	// untyped_dispatch=false and the engine fans out to every implementer.
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
	// Append captured free variables as trailing parameters (after the real
	// params) so the analysis can flow taint from a `builtin.make_closure`
	// binding into the closure's use of that captured variable — e.g. a request
	// value captured by a `go func(){ db.Query(id) }()` goroutine. The engine
	// maps the K make_closure bindings to the last K params.
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

// httpRequestSourceCallee is the canonical name of the synthetic source the
// frontend injects for an HTTP handler's *http.Request parameter (see
// addHTTPRequestSource). It is listed as a source in the Go rule packs, so every
// read off the request object carries taint — including field reads like
// r.URL.Path / r.Form / r.Body that no method-call rule can match (the
// documented "Go field-access sources aren't matchable" gap).
const httpRequestSourceCallee = "go:@net/http.Request"

// addHTTPRequestSource injects a synthetic request-object source at the entry of
// an HTTP handler so its *http.Request parameter is tainted. It mirrors the
// parameter-source synthesis the Rust (axum typed params) and Java (@RequestParam)
// frontends already do: the register defined by the synthetic source CALL is the
// parameter's own name, so the engine (which seeds taint by register name) marks
// the request tainted at function entry and whole-object taint flows to every
// field read off it.
//
// A handler is either (a) a function taking BOTH an http.ResponseWriter and an
// *http.Request (net/http, chi, gorilla/mux, and any router built on them), or
// (b) a function registered at a router's GET/POST/Handle/Use/... call
// (collectRouteHandlers) — which covers a framework context value like
// *gin.Context / echo.Context / *fiber.Ctx, and any framework we have no rules
// for. Case (a)'s ResponseWriter requirement keeps this from tainting helpers
// that merely pass an *http.Request around or build an OUTBOUND request
// (http.NewRequest), which are not attacker-controlled.
func (c *Converter) addHTTPRequestSource(f *ssa.Function, irFunc *ir.Function) {
	reqName, ok := handlerRequestParam(f)
	if !ok {
		reqName, ok = c.routeHandlers[f]
	}
	if !ok || reqName == "" || len(irFunc.Blocks) == 0 {
		return
	}
	src := &ir.Instruction{
		Name:    reqName,
		Op:      ir.OpCode_OP_CODE_CALL,
		Pos:     irFunc.Pos,
		Comment: "http-request-source",
		Call: &ir.CallCommon{
			Callee: httpRequestSourceCallee,
			Value:  &ir.Value{Kind: &ir.Value_FuncName{FuncName: httpRequestSourceCallee}},
		},
	}
	entry := irFunc.Blocks[0]
	entry.Instrs = append([]*ir.Instruction{src}, entry.Instrs...)
}

// handlerRequestParam returns the register name of an HTTP handler's
// *net/http.Request parameter, if the function looks like a handler — i.e. it
// also takes an http.ResponseWriter.
func handlerRequestParam(f *ssa.Function) (string, bool) {
	var reqName string
	var hasWriter, hasRequest bool
	for _, p := range f.Params {
		switch {
		case isNamedTypePtr(p.Type(), "net/http", "Request"):
			hasRequest = true
			reqName = p.Name()
		case isNamedType(p.Type(), "net/http", "ResponseWriter"):
			hasWriter = true
		}
	}
	return reqName, hasWriter && hasRequest
}

// isNamedTypePtr reports whether t is a pointer to the named type pkgPath.name.
func isNamedTypePtr(t types.Type, pkgPath, name string) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	return isNamedType(ptr.Elem(), pkgPath, name)
}

// isNamedType reports whether t is the named (defined) type pkgPath.name.
func isNamedType(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath && obj.Name() == name
}

// templateTrustedTypes are the html/template string types whose conversion
// marks a value as ALREADY-SAFE and BYPASSES the package's context-aware auto
// -escaping. Converting attacker-controlled data to one is the canonical Go XSS
// pattern (what gosec flags as G203). A conversion is not a call, so it carries
// no callee for a sink rule to match — the frontend synthesizes one (see
// emitTemplateTrustedConv).
var templateTrustedTypes = map[string]bool{
	"HTML": true, "HTMLAttr": true, "JS": true, "JSStr": true,
	"URL": true, "CSS": true, "Srcset": true,
}

// emitTemplateTrustedConv, when t is an html/template trusted-string type,
// lowers the conversion as a synthetic CALL `go:html/template.<Type>` (arg 0 =
// the converted value) instead of an opaque OP_CODE_CONVERT, so the rule engine
// can treat it as an XSS sink. It also stays a default propagator (see
// internal/rules/propagators.go), so for every non-XSS rule the result still
// carries taint exactly as the plain conversion did. Returns false (caller
// emits the normal CONVERT) when t is not a trusted type.
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

// routingVerbs are the method names (lowercased) that register an HTTP handler
// across the common Go routers — the near-universal REST verbs plus stdlib
// Handle/HandleFunc and middleware Use/Any/All. A call to a method with one of
// these names that is passed a function value is treated as a route
// registration, which is how the frontend recognizes a handler for a framework
// context type it has no other knowledge of.
var routingVerbs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "options": true, "connect": true, "trace": true,
	"any": true, "all": true, "handle": true, "handlefunc": true, "use": true,
}

// collectRouteHandlers finds functions registered as HTTP route handlers and
// maps each to the register name of its request/context parameter. A handler is
// a function value passed to a call whose method name is a routing verb
// (r.GET("/x", h), app.Post(..., h), mux.HandleFunc(..., h), e.Use(mw), …).
func collectRouteHandlers(allFns map[*ssa.Function]bool) map[*ssa.Function]string {
	handlers := map[*ssa.Function]string{}
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
				}
			}
		}
	}
	return handlers
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
// a function value — a named/anonymous function passed directly, or a closure
// (MakeClosure) over one — or nil if the argument is not a function value.
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

	// Slab-allocate the block's instructions AND their positions: one
	// exact-sized backing array each instead of one heap object per
	// instruction — the converter's dominant allocations (every SSA instruction
	// of every lowered function carries a Position). The slabs are never
	// appended to or copied after pointers are taken, so the pointers stay
	// stable; output is value-identical to individual allocations.
	slab := make([]ir.Instruction, len(b.Instrs))
	posSlab := make([]ir.Position, len(b.Instrs))
	irBlock.Instrs = make([]*ir.Instruction, len(b.Instrs))
	for i, inst := range b.Instrs {
		c.convertInstructionInto(&slab[i], &posSlab[i], inst)
		irBlock.Instrs[i] = &slab[i]
	}

	return irBlock
}

// convertInstructionInto lowers one SSA instruction into irInst
// (caller-provided storage, see the slabs in convertBlock). irInst and pos must
// be zero-valued; pos is used (and linked as irInst.Pos) only when the
// instruction has a valid source position, so an invalid position stays nil
// exactly as before.
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
		irInst.Op = ir.OpCode_OP_CODE_BIN_OP
		irInst.BinOp = c.convertBinOp(i.Op)
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
		if !c.emitTemplateTrustedConv(irInst, i.Type(), i.X) {
			irInst.Op = ir.OpCode_OP_CODE_CONVERT
			irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
		}
	case *ssa.ChangeInterface:
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Convert:
		if !c.emitTemplateTrustedConv(irInst, i.Type(), i.X) {
			irInst.Op = ir.OpCode_OP_CODE_CONVERT
			irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
		}
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

// blockName is the gIR label for an SSA basic block ("b<index>"); the
// control-flow instructions (IF/JUMP/PHI) use it to name their target and
// predecessor blocks.
func blockName(b *ssa.BasicBlock) string {
	return fmt.Sprintf("b%d", b.Index)
}

func (c *Converter) convertValue(v ssa.Value) *ir.Value {
	if v == nil {
		return nil
	}
	// Intern the wrapper per function (valueCache is cleared by
	// convertFunction): the same ssa.Value is referenced by many instructions,
	// and the emitted wrappers are never mutated downstream, so one object per
	// value is observably identical to a fresh allocation per reference.
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
	res.Value = &ir.Constant_StringVal{StringVal: con.Value.String()}
	return res
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
	} else if b, ok := call.Value.(*ssa.Builtin); ok {
		cc.Callee = "builtin." + b.Name()
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
	case token.EQL:
		return ir.BinOpKind_BIN_OP_EQL
	case token.NEQ:
		return ir.BinOpKind_BIN_OP_NEQ
	case token.LSS:
		return ir.BinOpKind_BIN_OP_LSS
	case token.LEQ:
		return ir.BinOpKind_BIN_OP_LEQ
	case token.GTR:
		return ir.BinOpKind_BIN_OP_GTR
	case token.GEQ:
		return ir.BinOpKind_BIN_OP_GEQ
	}
	return ir.BinOpKind_BIN_OP_UNSPECIFIED
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

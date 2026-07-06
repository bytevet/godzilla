package go_converter

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ir "godzilla/pkg/ir/v1"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type Converter struct {
	program *ssa.Program
	fset    *token.FileSet

	typeCache map[types.Type]*ir.Type

	// routeHandlers maps a function registered as an HTTP route handler
	// (passed to a router's GET/POST/Handle/Use/... call) to the register name
	// of its request/context parameter, so addHTTPRequestSource can taint the
	// request object even for a framework whose context type we have no rules
	// for. Populated by collectRouteHandlers.
	routeHandlers map[*ssa.Function]string
}

func NewConverter() *Converter {
	return &Converter{
		typeCache: make(map[types.Type]*ir.Type),
	}
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

	cfg := &packages.Config{
		// LoadSyntax (not LoadAllSyntax): load full syntax + types for the TARGET
		// packages, and only type information (from export data) for their
		// dependencies. The taint engine never analyzes inside stdlib/third-party
		// code — library behavior is modeled by rules (sources/sinks/propagators) —
		// so parsing and SSA-building the whole dependency closure is pure waste.
		// This, together with ssautil.Packages below (which builds SSA bodies only
		// for the target packages), is what keeps a scan's cost proportional to the
		// scanned code rather than to its dependency tree.
		Mode:  packages.LoadSyntax,
		Tests: false,
		Dir:   dir,
	}
	initial, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, err
	}
	if len(initial) == 0 {
		return nil, fmt.Errorf("no Go packages found under %s", dir)
	}
	// Some packages failed to load cleanly (type/parse errors). PrintErrors
	// dumps the specifics to stderr; conversion continues on whatever built so
	// partial/vulnerable code still converts. Route our summary line to stderr
	// too — a stdout write would corrupt machine-readable output when the user
	// pipes findings (e.g. `godzilla scan > out.txt`).
	if packages.PrintErrors(initial) > 0 {
		fmt.Fprintln(os.Stderr, "warning: some Go packages failed to load cleanly; findings from those packages may be incomplete")
	}

	// ssautil.Packages (not AllPackages): create SSA for the TARGET packages
	// only; dependencies contribute types but no function bodies. prog.Build()
	// then builds just the target packages, so cost scales with the scanned code,
	// not the dependency closure. Findings are unaffected: calls into libraries
	// are matched by their canonical names in rules, not by analyzing their bodies.
	prog, pkgs := ssautil.Packages(initial, ssa.InstantiateGenerics)
	prog.Build()
	c.program = prog
	c.fset = initial[0].Fset
	c.routeHandlers = collectRouteHandlers(prog)

	// pkg.Members only exposes package-level funcs, not methods or anonymous
	// function literals (closures) — and vulnerable code frequently lives inside
	// closures (e.g. http.HandleFunc handlers). AllFunctions enumerates every
	// function/method/closure; group them by their defining package.
	funcsByPkg := make(map[*ssa.Package][]*ssa.Function)
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Pkg != nil {
			funcsByPkg[fn.Pkg] = append(funcsByPkg[fn.Pkg], fn)
		}
	}

	irProg := &ir.Program{
		Mode: "ssa",
	}

	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		irMod := c.convertPackage(pkg, funcsByPkg[pkg])
		irProg.Modules = append(irProg.Modules, irMod)
	}

	return irProg, nil
}

func (c *Converter) convertPackage(pkg *ssa.Package, funcs []*ssa.Function) *ir.Module {
	mod := &ir.Module{
		Name:     pkg.Pkg.Path(),
		Language: "go",
	}

	// Deterministic output: functions come from a map, so sort them.
	sort.Slice(funcs, func(i, j int) bool { return funcs[i].String() < funcs[j].String() })
	for _, fn := range funcs {
		mod.Functions = append(mod.Functions, c.convertFunction(fn))
	}

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

	return mod
}

func (c *Converter) convertFunction(f *ssa.Function) *ir.Function {
	irFunc := &ir.Function{
		Name:          f.String(),
		ObjectName:    f.Name(),
		PackageName:   f.Pkg.Pkg.Path(),
		Pos:           c.convertPos(f.Pos()),
		Synthetic:     f.Synthetic != "",
		CanonicalName: c.canonicalFunc(f),
	}

	if f.Signature != nil {
		irFunc.Signature = c.convertSignature(f.Signature)
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
func collectRouteHandlers(prog *ssa.Program) map[*ssa.Function]string {
	handlers := map[*ssa.Function]string{}
	for fn := range ssautil.AllFunctions(prog) {
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

	for _, p := range b.Preds {
		irBlock.Preds = append(irBlock.Preds, int32(p.Index))
	}
	for _, s := range b.Succs {
		irBlock.Succs = append(irBlock.Succs, int32(s.Index))
	}

	for _, inst := range b.Instrs {
		irBlock.Instrs = append(irBlock.Instrs, c.convertInstruction(inst))
	}

	return irBlock
}

func (c *Converter) convertInstruction(inst ssa.Instruction) *ir.Instruction {
	irInst := &ir.Instruction{
		Pos: c.convertPos(inst.Pos()),
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
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.ChangeInterface:
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
	case *ssa.Convert:
		irInst.Op = ir.OpCode_OP_CODE_CONVERT
		irInst.Operands = append(irInst.Operands, c.convertValue(i.X))
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

	return irInst
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
	switch val := v.(type) {
	case *ssa.Const:
		return &ir.Value{Kind: &ir.Value_Constant{Constant: c.convertConstant(val)}}
	case *ssa.Global:
		return &ir.Value{Kind: &ir.Value_GlobalName{GlobalName: val.Name()}}
	case *ssa.Function:
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: c.canonicalFunc(val)}}
	case *ssa.Builtin:
		return &ir.Value{Kind: &ir.Value_FuncName{FuncName: "builtin." + val.Name()}}
	default:
		return &ir.Value{Kind: &ir.Value_RegName{RegName: val.Name()}}
	}
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
	for _, arg := range call.Args {
		cc.Args = append(cc.Args, c.convertValue(arg))
	}
	return cc
}

// canonicalFunc returns a language-prefixed, cross-language-comparable name
// for a Go function, e.g. "go:net/http.(*Request).FormValue".
func (c *Converter) canonicalFunc(f *ssa.Function) string {
	return "go:" + f.String()
}

func (c *Converter) convertType(t types.Type) *ir.Type {
	if cached, ok := c.typeCache[t]; ok {
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
		for i := 0; i < typ.NumFields(); i++ {
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
		for i := 0; i < typ.NumMethods(); i++ {
			m := typ.Method(i)
			irType.Methods = append(irType.Methods, &ir.Method{
				Name:      m.Name(),
				Signature: c.convertType(m.Type()),
			})
		}
	case *types.Tuple:
		irType.Kind = ir.TypeKind_TYPE_KIND_TUPLE
		for i := 0; i < typ.Len(); i++ {
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
	for i := 0; i < params.Len(); i++ {
		irSig.Params = append(irSig.Params, c.convertType(params.At(i).Type()))
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
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

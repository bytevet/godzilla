package playground

import (
	"strconv"
	"strings"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// The JSON below is a VIEW of gIR, not gIR itself. protojson would be a smaller
// amount of code but a worse contract: types are a recursive tree that has to
// become a string to be readable, enums arrive as bare numbers, and every
// oneof/optional field would have to be re-derived in the browser. Pre-formatting
// here keeps the client a renderer — the same split internal/report makes when it
// builds reportData so its template stays logic-free.

type position struct {
	Line   int32 `json:"line"`
	Column int32 `json:"column"`
}

type constantView struct {
	Type      string `json:"type"`
	StringVal string `json:"string_val"`
}

type valueView struct {
	RegName    string        `json:"reg_name,omitempty"`
	GlobalName string        `json:"global_name,omitempty"`
	FuncName   string        `json:"func_name,omitempty"`
	Constant   *constantView `json:"constant,omitempty"`
	// Name is the keyword this argument was passed under, recovered from a
	// builtin.kwarg marker. gIR carries positional arguments only.
	Name string `json:"name,omitempty"`
}

type callView struct {
	Value           *valueView  `json:"value,omitempty"`
	Args            []valueView `json:"args"`
	IsInvoke        bool        `json:"is_invoke"`
	MethodName      string      `json:"method_name,omitempty"`
	Callee          string      `json:"callee,omitempty"`
	UntypedDispatch bool        `json:"untyped_dispatch,omitempty"`
}

// flagView is the loaded rulepacks' verdict on a call, computed server-side so
// the browser never re-implements matching.
type flagView struct {
	Kind    string `json:"kind"` // "sink" | "source"
	Rule    string `json:"rule"`
	CWE     string `json:"cwe,omitempty"`
	Pattern string `json:"pattern"`
	// Idx is the pinned logical injection point; nil means every argument.
	Idx *int32 `json:"idx,omitempty"`
}

type instrView struct {
	// Ord is this instruction's index in the file's emission order. It is how
	// /api/match points back at an instruction without shipping a second
	// identity scheme.
	Ord        int         `json:"ord"`
	Name       string      `json:"name,omitempty"`
	Op         string      `json:"op"`
	Type       string      `json:"type,omitempty"`
	Pos        *position   `json:"pos"`
	Comment    string      `json:"comment,omitempty"`
	Intrinsic  string      `json:"intrinsic,omitempty"`
	Operands   []valueView `json:"operands,omitempty"`
	BinOp      string      `json:"bin_op,omitempty"`
	UnOp       string      `json:"un_op,omitempty"`
	FieldIndex *int32      `json:"field_index,omitempty"`
	Heap       bool        `json:"heap,omitempty"`
	Call       *callView   `json:"call,omitempty"`
	TrueBlock  string      `json:"true_block,omitempty"`
	FalseBlock string      `json:"false_block,omitempty"`
	JumpBlock  string      `json:"jump_block,omitempty"`
	Flag       *flagView   `json:"flag,omitempty"`
}

type blockView struct {
	Index   int32       `json:"index"`
	Comment string      `json:"comment"`
	Preds   []int32     `json:"preds"`
	Succs   []int32     `json:"succs"`
	Instrs  []instrView `json:"instrs"`
}

type namedView struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
}

type sigView struct {
	Params  []string `json:"params"`
	Results []string `json:"results"`
	Recv    string   `json:"recv,omitempty"`
}

type funcView struct {
	Name          string      `json:"name"`
	ObjectName    string      `json:"object_name"`
	MethodName    string      `json:"method_name,omitempty"`
	PackageName   string      `json:"package_name"`
	Parent        string      `json:"parent,omitempty"`
	CanonicalName string      `json:"canonical_name"`
	Synthetic     bool        `json:"synthetic"`
	Pos           *position   `json:"pos"`
	Signature     sigView     `json:"signature"`
	Params        []namedView `json:"params"`
	FreeVars      []namedView `json:"free_vars"`
	Locals        []namedView `json:"locals"`
	Blocks        []blockView `json:"blocks"`
}

type globalView struct {
	Name string    `json:"name"`
	Type string    `json:"type"`
	Pos  *position `json:"pos"`
}

type typeView struct {
	Name       string      `json:"name"`
	Kind       string      `json:"kind"`
	Underlying string      `json:"underlying"`
	Pos        *position   `json:"pos"`
	Fields     []namedView `json:"fields"`
}

type moduleView struct {
	Name      string       `json:"name"`
	Language  string       `json:"language"`
	Imports   []string     `json:"imports"`
	Globals   []globalView `json:"globals"`
	Types     []typeView   `json:"types"`
	Functions []funcView   `json:"functions"`
}

// posView renders a Position, or nil when the frontend genuinely recorded none —
// varargs packing and synthetic wrappers do. The UI dims and tags those rather
// than hiding them, so a rule author can see the lowering has steps the source
// does not.
func posView(p *ir.Position) *position {
	if p == nil {
		return nil
	}
	return &position{Line: p.GetLine(), Column: p.GetColumn()}
}

func constView(c *ir.Constant) *constantView {
	if c == nil {
		return nil
	}
	switch v := c.GetValue().(type) {
	case *ir.Constant_StringVal:
		return &constantView{Type: "string", StringVal: v.StringVal}
	case *ir.Constant_IntVal:
		return &constantView{Type: "int", StringVal: strconv.FormatInt(v.IntVal, 10)}
	case *ir.Constant_BoolVal:
		return &constantView{Type: "bool", StringVal: strconv.FormatBool(v.BoolVal)}
	case *ir.Constant_FloatVal:
		return &constantView{Type: "float", StringVal: strconv.FormatFloat(v.FloatVal, 'g', -1, 64)}
	}
	if c.GetIsNil() {
		return &constantView{Type: "nil", StringVal: "nil"}
	}
	return &constantView{Type: typeString(c.GetType()), StringVal: ""}
}

func valView(v *ir.Value) valueView {
	if v == nil {
		return valueView{}
	}
	switch k := v.GetKind().(type) {
	case *ir.Value_RegName:
		return valueView{RegName: k.RegName}
	case *ir.Value_GlobalName:
		return valueView{GlobalName: k.GlobalName}
	case *ir.Value_FuncName:
		return valueView{FuncName: k.FuncName}
	case *ir.Value_Constant:
		return valueView{Constant: constView(k.Constant)}
	}
	return valueView{}
}

func valViews(vs []*ir.Value) []valueView {
	out := make([]valueView, 0, len(vs))
	for _, v := range vs {
		out = append(out, valView(v))
	}
	return out
}

// kwargOf resolves an argument through a builtin.kwarg marker, returning the
// keyword name and the value it wraps. Mirrors internal/analysis's unwrapKwarg;
// without it every Python keyword argument renders as an opaque register.
func kwargOf(v *ir.Value, defs map[string]*ir.Instruction) (string, *ir.Value) {
	if v == nil || defs == nil {
		return "", v
	}
	def, ok := defs[v.GetRegName()]
	if !ok || def.GetIntrinsic() != "builtin.kwarg" || def.Call == nil {
		return "", v
	}
	args := def.Call.GetArgs()
	if len(args) != 2 {
		return "", v
	}
	name, ok := args[0].GetConstant().GetValue().(*ir.Constant_StringVal)
	if !ok {
		return "", v
	}
	return name.StringVal, args[1]
}

func callViewOf(cc *ir.CallCommon, defs map[string]*ir.Instruction) *callView {
	if cc == nil {
		return nil
	}
	cv := &callView{
		Args:            make([]valueView, 0, len(cc.GetArgs())),
		IsInvoke:        cc.GetIsInvoke(),
		MethodName:      cc.GetMethodName(),
		Callee:          cc.GetCallee(),
		UntypedDispatch: cc.GetUntypedDispatch(),
	}
	if cc.Value != nil {
		v := valView(cc.Value)
		cv.Value = &v
	}
	for _, a := range cc.GetArgs() {
		name, inner := kwargOf(a, defs)
		av := valView(inner)
		av.Name = name
		cv.Args = append(cv.Args, av)
	}
	return cv
}

// defsOf indexes a function's SSA registers to their defining instruction, so
// kwargOf can see through a marker.
func defsOf(fn *ir.Function) map[string]*ir.Instruction {
	defs := map[string]*ir.Instruction{}
	for _, b := range fn.GetBlocks() {
		if b == nil {
			continue
		}
		for _, in := range b.GetInstrs() {
			if in != nil && in.GetName() != "" {
				defs[in.GetName()] = in
			}
		}
	}
	return defs
}

func instrViewOf(in *ir.Instruction, ord int, defs map[string]*ir.Instruction) instrView {
	iv := instrView{
		Ord:        ord,
		Name:       in.GetName(),
		Op:         in.GetOp().String(),
		Type:       typeString(in.GetType()),
		Pos:        posView(in.GetPos()),
		Comment:    in.GetComment(),
		Intrinsic:  in.GetIntrinsic(),
		Operands:   valViews(in.GetOperands()),
		Heap:       in.GetHeap(),
		Call:       callViewOf(in.Call, defs),
		TrueBlock:  in.GetTrueBlock(),
		FalseBlock: in.GetFalseBlock(),
		JumpBlock:  in.GetJumpBlock(),
	}
	switch in.GetOp() {
	case ir.OpCode_OP_CODE_BIN_OP:
		iv.BinOp = in.GetBinOp().String()
	case ir.OpCode_OP_CODE_UN_OP:
		iv.UnOp = in.GetUnOp().String()
	case ir.OpCode_OP_CODE_FIELD, ir.OpCode_OP_CODE_FIELD_ADDR, ir.OpCode_OP_CODE_EXTRACT:
		// Carried as a pointer so index 0 survives: omitempty on a bare int32
		// would drop the commonest field index and render "[undefined]".
		idx := in.GetFieldIndex()
		iv.FieldIndex = &idx
	}
	return iv
}

// namedViews pairs each parameter/local register with its declared type. gIR's
// Function.Params are Values (registers), and the types live in the Signature —
// which excludes the receiver, so a method's params run one ahead of it.
func namedViews(vals []*ir.Value, types []*ir.Type, recv *ir.Type) []namedView {
	out := make([]namedView, 0, len(vals))
	shift := 0
	if recv != nil && len(vals) == len(types)+1 {
		shift = 1
	}
	for i, v := range vals {
		nv := namedView{Name: v.GetRegName()}
		switch {
		case shift == 1 && i == 0:
			nv.Type = typeString(recv)
		case i-shift >= 0 && i-shift < len(types):
			nv.Type = typeString(types[i-shift])
		}
		out = append(out, nv)
	}
	return out
}

func typeStrings(ts []*ir.Type) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, typeString(t))
	}
	return out
}

func funcViewOf(fn *ir.Function, ord *int, flagFor func(*ir.Instruction) *flagView) funcView {
	sig := fn.GetSignature()
	defs := defsOf(fn)
	fv := funcView{
		Name:          fn.GetName(),
		ObjectName:    fn.GetObjectName(),
		MethodName:    fn.GetMethodName(),
		PackageName:   fn.GetPackageName(),
		Parent:        typeString(fn.GetParent()),
		CanonicalName: fn.GetCanonicalName(),
		Synthetic:     fn.GetSynthetic(),
		Pos:           posView(fn.GetPos()),
		Signature: sigView{
			Params:  typeStrings(sig.GetParams()),
			Results: typeStrings(sig.GetResults()),
			Recv:    typeString(sig.GetRecv()),
		},
		Params:   namedViews(fn.GetParams(), sig.GetParams(), sig.GetRecv()),
		FreeVars: namedViews(fn.GetFreeVars(), nil, nil),
		Locals:   namedViews(fn.GetLocals(), nil, nil),
		Blocks:   make([]blockView, 0, len(fn.GetBlocks())),
	}
	for _, b := range fn.GetBlocks() {
		if b == nil {
			continue
		}
		bv := blockView{
			Index:   b.GetIndex(),
			Comment: b.GetComment(),
			Preds:   append([]int32{}, b.GetPreds()...),
			Succs:   append([]int32{}, b.GetSuccs()...),
			Instrs:  make([]instrView, 0, len(b.GetInstrs())),
		}
		for _, in := range b.GetInstrs() {
			if in == nil {
				continue
			}
			iv := instrViewOf(in, *ord, defs)
			*ord++
			if flagFor != nil {
				iv.Flag = flagFor(in)
			}
			bv.Instrs = append(bv.Instrs, iv)
		}
		fv.Blocks = append(fv.Blocks, bv)
	}
	return fv
}

func globalViewOf(g *ir.Global) globalView {
	return globalView{Name: g.GetName(), Type: typeString(g.GetType()), Pos: posView(g.GetPos())}
}

func typeViewOf(t *ir.Type) typeView {
	tv := typeView{
		Name:       t.GetName(),
		Kind:       t.GetKind().String(),
		Underlying: t.GetUnderlyingType().GetKind().String(),
		Pos:        posView(t.GetPos()),
		Fields:     []namedView{},
	}
	for _, f := range t.GetUnderlyingType().GetFields() {
		tv.Fields = append(tv.Fields, namedView{Name: f.GetName(), Type: typeString(f.GetType()), Tag: f.GetTag()})
	}
	return tv
}

// typeString renders a gIR type tree as source-like text. gIR has no type table
// and no printer, so this is the one place a Type becomes readable; it is a view
// concern, which is why it lives here rather than beside the schema.
func typeString(t *ir.Type) string { return typeStr(t, 0) }

func typeStr(t *ir.Type, depth int) string {
	// A malformed or self-referential type must not take the server down with it.
	if t == nil || depth > 12 {
		return ""
	}
	switch t.GetKind() {
	case ir.TypeKind_TYPE_KIND_BASIC:
		return strings.ToLower(strings.TrimPrefix(t.GetBasicKind().String(), "BASIC_TYPE_KIND_"))
	case ir.TypeKind_TYPE_KIND_POINTER:
		return "*" + typeStr(t.GetElemType(), depth+1)
	case ir.TypeKind_TYPE_KIND_SLICE:
		return "[]" + typeStr(t.GetElemType(), depth+1)
	case ir.TypeKind_TYPE_KIND_ARRAY:
		return "[" + strconv.FormatInt(t.GetArrayLen(), 10) + "]" + typeStr(t.GetElemType(), depth+1)
	case ir.TypeKind_TYPE_KIND_MAP:
		return "map[" + typeStr(t.GetKeyType(), depth+1) + "]" + typeStr(t.GetElemType(), depth+1)
	case ir.TypeKind_TYPE_KIND_CHAN:
		return "chan " + typeStr(t.GetElemType(), depth+1)
	case ir.TypeKind_TYPE_KIND_NAMED:
		if n := t.GetName(); n != "" {
			return n
		}
		return typeStr(t.GetUnderlyingType(), depth+1)
	case ir.TypeKind_TYPE_KIND_INTERFACE:
		if len(t.GetMethods()) == 0 {
			return "any"
		}
		return "interface"
	case ir.TypeKind_TYPE_KIND_STRUCT:
		return "struct"
	case ir.TypeKind_TYPE_KIND_FUNC:
		sig := t.GetSignature()
		return "func(" + strings.Join(typeStrings(sig.GetParams()), ", ") + ")" +
			resultSuffix(typeStrings(sig.GetResults()))
	case ir.TypeKind_TYPE_KIND_TUPLE:
		// A tuple's elements ride in Fields with only Type set (see the Go
		// converter's *types.Tuple case).
		elems := make([]string, 0, len(t.GetFields()))
		for _, f := range t.GetFields() {
			elems = append(elems, typeStr(f.GetType(), depth+1))
		}
		return "(" + strings.Join(elems, ", ") + ")"
	}
	if n := t.GetName(); n != "" {
		return n
	}
	return ""
}

func resultSuffix(res []string) string {
	switch len(res) {
	case 0:
		return ""
	case 1:
		return " " + res[0]
	default:
		return " (" + strings.Join(res, ", ") + ")"
	}
}

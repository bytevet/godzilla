package playground

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/scan"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// The fixtures below are hand-built gIR rather than a real scan: the properties
// under test (which file a function lands under, what a #<n> pin resolves to)
// are about the indexing, and a real scan would make them hostage to a
// toolchain. converters/* own frontend fidelity; test/corpus owns end-to-end.

func reg(n string) *ir.Value  { return &ir.Value{Kind: &ir.Value_RegName{RegName: n}} }
func fref(n string) *ir.Value { return &ir.Value{Kind: &ir.Value_FuncName{FuncName: n}} }
func str(s string) *ir.Value {
	return &ir.Value{Kind: &ir.Value_Constant{
		Constant: &ir.Constant{Value: &ir.Constant_StringVal{StringVal: s}},
	}}
}
func pos(file string, line int32) *ir.Position {
	return &ir.Position{Filename: file, Line: line, Column: 1}
}

// methodCall is a statically-resolved method call: the receiver rides in
// args[0] and method_name is set, so logical #0 is args[1].
func methodCall(name, callee, method string, p *ir.Position, args ...*ir.Value) *ir.Instruction {
	return &ir.Instruction{
		Name: name, Op: ir.OpCode_OP_CODE_CALL, Pos: p,
		Call: &ir.CallCommon{Value: fref(callee), Callee: callee, MethodName: method, Args: args},
	}
}

const (
	sourceCallee = "go:(*net/http.Request).FormValue"
	sinkCallee   = "go:(*database/sql.DB).Query"
)

// fixture writes a small tree and returns it with a program lowered "from" it.
func fixture(t *testing.T) (root string, res scan.Result) {
	t.Helper()
	root = t.TempDir()
	for name, body := range map[string]string{
		"main.go":   "package app\n\nfunc handler() {}\n",
		"models.go": "package app\n\nvar db *sql.DB\n",
		"broken.go": "package app\n\n// never lowered\n",
		"notes.txt": "not source\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mainGo := filepath.Join(root, "main.go")

	handler := &ir.Function{
		Name: "app.handler", ObjectName: "handler", PackageName: "app",
		CanonicalName: "go:app.handler", Pos: pos(mainGo, 3),
		Signature: &ir.Signature{},
		Params:    []*ir.Value{reg("r")},
		Blocks: []*ir.BasicBlock{{
			Index: 0, Comment: "entry",
			Instrs: []*ir.Instruction{
				methodCall("t0", sourceCallee, "FormValue", pos(mainGo, 4), reg("r"), str("id")),
				methodCall("t1", sinkCallee, "Query", pos(mainGo, 5), reg("db"), reg("t0")),
			},
		}},
	}
	// A lowered dependency body: inside the program, outside the scan root.
	dep := &ir.Function{
		Name: "dep.Helper", ObjectName: "Helper", CanonicalName: "go:dep.Helper",
		Pos: pos(filepath.Join(t.TempDir(), "vendored.go"), 9), Signature: &ir.Signature{},
	}

	mod := &ir.Module{
		Name: "app", Language: "go", Imports: []string{"database/sql"},
		Functions: []*ir.Function{handler, dep},
		Globals: []*ir.Global{{
			Name: "db", Pos: pos(filepath.Join(root, "models.go"), 3),
			Type: &ir.Type{Kind: ir.TypeKind_TYPE_KIND_POINTER, ElemType: &ir.Type{
				Kind: ir.TypeKind_TYPE_KIND_NAMED, Name: "DB",
			}},
		}},
	}
	res = scan.Result{
		Program:  &ir.Program{Modules: []*ir.Module{mod}},
		Findings: []analysis.Finding{{RuleID: "go-sqli", SinkPos: pos(mainGo, 5)}},
		Coverage: []scan.LangCoverage{{Language: "go", Detected: true, Converted: true, Files: 3, Skipped: 1}},
	}
	return root, res
}

func testRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	return testsupport.OneRuleSet(t, "go-sqli", "go", "CWE-89",
		[]string{"go:*net/http.Request*.FormValue"},
		[]string{"go:*database/sql*.DB*.Query#0"})
}

func newTestIndex(t *testing.T) (*Index, string) {
	t.Helper()
	root, res := fixture(t)
	return NewIndex(res, root, "test", testRules(t)), root
}

func TestIndexAttributesGIRToItsSourceFile(t *testing.T) {
	idx, _ := newTestIndex(t)

	got := map[string]*fileEntry{}
	for _, e := range idx.Files() {
		got[e.ID] = e
	}
	if _, ok := got["notes.txt"]; ok {
		t.Error("a non-source file was listed; only files a frontend claims belong in the tree")
	}
	for id := range got {
		if strings.Contains(id, "vendored.go") || strings.HasPrefix(id, "..") {
			t.Errorf("file outside the scan root leaked into the tree: %q", id)
		}
	}

	main, ok := got["main.go"]
	if !ok {
		t.Fatalf("main.go missing from the tree; got %v", keys(got))
	}
	if len(main.fns) != 1 || main.fns[0].GetObjectName() != "handler" {
		t.Errorf("main.go should own exactly the handler function, got %d", len(main.fns))
	}
	if main.State != "" {
		t.Errorf("main.go lowered, so it should carry no empty state; got %q", main.State)
	}
	if main.Findings != 1 {
		t.Errorf("main.go findings = %d, want 1 (the finding's sink is on line 5)", main.Findings)
	}

	// A file that lowered but declares nothing callable is a milder story than a
	// failure, and the UI tells them apart.
	if s := got["models.go"].State; s != stateNoFunc {
		t.Errorf("models.go state = %q, want %q", s, stateNoFunc)
	}
	// A file the walk found and no gIR came back for is invisible to every rule.
	broken, ok := got["broken.go"]
	if !ok {
		t.Fatal("broken.go produced no gIR and must still be listed")
	}
	if broken.State != stateFailed {
		t.Errorf("broken.go state = %q, want %q", broken.State, stateFailed)
	}
	if broken.StateDetail == "" {
		t.Error("a failed file must say why, or it reads as clean")
	}
}

// A file that produced no gIR still serves its source. That file is the one
// whose contents most need reading — something in it is why the frontend came
// back empty — so blanking it would hide the evidence.
func TestViewOfAFileWithNoGIRStillCarriesItsSource(t *testing.T) {
	idx, _ := newTestIndex(t)

	fv := idx.View("broken.go")
	if fv == nil {
		t.Fatal("a file with no gIR must still have a view")
	}
	if fv.State != stateFailed {
		t.Errorf("state = %q, want %q", fv.State, stateFailed)
	}
	if fv.StateDetail == "" {
		t.Error("the view must carry the reason, or the UI has nothing to show")
	}
	if len(fv.Src) == 0 {
		t.Fatal("source is missing; the whole point is that it is still readable")
	}
	if len(fv.Module.Functions) != 0 {
		t.Errorf("functions = %d, want 0", len(fv.Module.Functions))
	}

	// It must not, however, look like something a pattern can be tested against.
	if got := idx.Match("broken.go", "go:*"); got.Error == "" {
		t.Error("matching a file with no gIR must say so, not report zero matches")
	}
	// An unknown id is still a 404, which is a different thing entirely.
	if idx.View("nope.go") != nil {
		t.Error("an unknown id must have no view")
	}
}

func TestViewFlagsSinksAndSourcesFromTheLoadedRules(t *testing.T) {
	idx, _ := newTestIndex(t)
	fv := idx.View("main.go")
	if fv == nil {
		t.Fatal("no view for main.go")
	}
	if len(fv.Module.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(fv.Module.Functions))
	}
	instrs := fv.Module.Functions[0].Blocks[0].Instrs
	if len(instrs) != 2 {
		t.Fatalf("instrs = %d, want 2", len(instrs))
	}
	if got := instrs[0].Ord; got != 0 {
		t.Errorf("first ordinal = %d, want 0", got)
	}

	src := instrs[0].Flag
	if src == nil || src.Kind != "source" {
		t.Fatalf("FormValue should be flagged a source, got %+v", src)
	}
	sink := instrs[1].Flag
	if sink == nil || sink.Kind != "sink" {
		t.Fatalf("Query should be flagged a sink, got %+v", sink)
	}
	if sink.Idx == nil || *sink.Idx != 0 {
		t.Errorf("sink pin = %v, want 0 (the rule pins #0)", sink.Idx)
	}
	if sink.Rule != "go-sqli" || sink.CWE != "CWE-89" {
		t.Errorf("sink flag should name its rule, got %+v", sink)
	}
}

// The receiver shift is the whole reason this tool exists: a static method call
// passes its receiver as args[0], so the argument a rule pins with #0 is args[1].
// If this ever reports the receiver, the UI is teaching the off-by-one it exists
// to remove.
func TestMatchResolvesPinnedArgumentPastTheReceiver(t *testing.T) {
	idx, _ := newTestIndex(t)
	r := idx.Match("main.go", "go:*database/sql*.DB*.Query#0")
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if r.Count != 1 {
		t.Fatalf("count = %d, want 1", r.Count)
	}
	if len(r.Pinned) != 1 || r.Pinned[0] != 0 {
		t.Errorf("pinned = %v, want [0]", r.Pinned)
	}
	if len(r.Matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(r.Matches))
	}
	if got := r.Matches[0].Pinned; got != "t0" {
		t.Errorf("pinned argument = %q, want %q (args[1]; args[0] is the receiver `db`)", got, "t0")
	}
	if r.Matches[0].Ord != 1 {
		t.Errorf("ord = %d, want 1", r.Matches[0].Ord)
	}
}

func TestMatchBarePatternPinsNothing(t *testing.T) {
	idx, _ := newTestIndex(t)
	r := idx.Match("main.go", "go:*database/sql*.DB*.Query")
	if r.Count != 1 {
		t.Fatalf("count = %d, want 1", r.Count)
	}
	if len(r.Pinned) != 0 {
		t.Errorf("a bare pattern makes every argument an injection point, got pinned %v", r.Pinned)
	}
}

// The loader rejects a "#" spec that names no valid index, because it parses
// leniently to zero indices and silently widens the sink to every argument.
func TestMatchRejectsAnInvalidPinSpec(t *testing.T) {
	idx, _ := newTestIndex(t)
	for _, p := range []string{"go:*.Query#", "go:*.Query#x", "go:*.Query#-1"} {
		if got := idx.Match("main.go", p); got.Error == "" {
			t.Errorf("%q is a spec the loader would reject; the tester must say so", p)
		}
	}
}

func TestMatchReportsALanguageMismatch(t *testing.T) {
	idx, _ := newTestIndex(t)
	r := idx.Match("main.go", "py:sqlite3.Cursor.execute#0")
	if r.Count != 0 {
		t.Errorf("count = %d, want 0", r.Count)
	}
	if r.PatternLang != "py" || r.ModuleLang != "go" {
		t.Errorf("langs = %q/%q, want py/go", r.PatternLang, r.ModuleLang)
	}
}

func TestTypeString(t *testing.T) {
	basic := func(k ir.BasicTypeKind) *ir.Type {
		return &ir.Type{Kind: ir.TypeKind_TYPE_KIND_BASIC, BasicKind: k}
	}
	strT := basic(ir.BasicTypeKind_BASIC_TYPE_KIND_STRING)
	named := &ir.Type{Kind: ir.TypeKind_TYPE_KIND_NAMED, Name: "DB"}

	for _, tc := range []struct {
		name string
		in   *ir.Type
		want string
	}{
		{"nil", nil, ""},
		{"basic", strT, "string"},
		{"pointer", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_POINTER, ElemType: named}, "*DB"},
		{"slice", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_SLICE, ElemType: strT}, "[]string"},
		{"array", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_ARRAY, ArrayLen: 2, ElemType: strT}, "[2]string"},
		{"map", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_MAP, KeyType: strT, ElemType: named}, "map[string]DB"},
		{"chan", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_CHAN, ElemType: strT}, "chan string"},
		{"empty interface", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_INTERFACE}, "any"},
		{"tuple", &ir.Type{Kind: ir.TypeKind_TYPE_KIND_TUPLE, Fields: []*ir.Field{
			{Type: named}, {Type: strT},
		}}, "(DB, string)"},
	} {
		if got := typeString(tc.in); got != tc.want {
			t.Errorf("%s: typeString = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A self-referential type must not take the server down with it.
func TestTypeStringTerminatesOnACycle(t *testing.T) {
	cyc := &ir.Type{Kind: ir.TypeKind_TYPE_KIND_POINTER}
	cyc.ElemType = cyc
	_ = typeString(cyc)
}

func TestKeywordArgumentKeepsItsName(t *testing.T) {
	marker := &ir.Instruction{
		Name: "k0", Op: ir.OpCode_OP_CODE_INTRINSIC, Intrinsic: "builtin.kwarg",
		Call: &ir.CallCommon{Args: []*ir.Value{str("shell"), str("True")}},
	}
	call := &ir.Instruction{
		Name: "t1", Op: ir.OpCode_OP_CODE_CALL,
		Call: &ir.CallCommon{Callee: "py:subprocess.run", Args: []*ir.Value{str("cmd"), reg("k0")}},
	}
	fn := &ir.Function{Signature: &ir.Signature{}, Blocks: []*ir.BasicBlock{{
		Instrs: []*ir.Instruction{marker, call},
	}}}
	fv, _ := funcViewOf(fn, 0, nil)
	args := fv.Blocks[0].Instrs[1].Call.Args
	if len(args) != 2 {
		t.Fatalf("args = %d, want 2", len(args))
	}
	// gIR carries positional arguments only; without unwrapping the marker this
	// renders as an opaque register and a guard's `kwargs.shell` looks unfounded.
	if args[1].Name != "shell" {
		t.Errorf("keyword name = %q, want %q", args[1].Name, "shell")
	}
	if args[1].Constant == nil || args[1].Constant.StringVal != "True" {
		t.Errorf("keyword value not unwrapped: %+v", args[1].Constant)
	}
}

func TestHTTPEndpoints(t *testing.T) {
	idx, _ := newTestIndex(t)
	srv := httptest.NewServer(idx.Handler())
	defer srv.Close()

	get := func(path string) *http.Response {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	index := get("/")
	if index.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", index.StatusCode)
	}
	// The UI is served over HTTP, so the CSP is a real header rather than the
	// <meta> the single-file HTML report has to use.
	if csp := index.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("missing or weak CSP: %q", csp)
	}

	tree := get("/api/tree")
	var got struct {
		Files []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"files"`
		Presets presetView `json:"presets"`
	}
	if err := json.NewDecoder(tree.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Files) == 0 {
		t.Fatal("empty tree")
	}

	file := get("/api/file?p=main.go")
	if file.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/file = %d", file.StatusCode)
	}
	var fv fileView
	if err := json.NewDecoder(file.Body).Decode(&fv); err != nil {
		t.Fatal(err)
	}
	if len(fv.Src) == 0 {
		t.Error("file view carries no source lines")
	}

	missing := get("/api/file?p=nope.go")
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("unknown file = %d, want 404", missing.StatusCode)
	}

	body := strings.NewReader(`{"file":"main.go","pattern":"go:*database/sql*.DB*.Query#0"}`)
	match, err := http.Post(srv.URL+"/api/match", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = match.Body.Close() })
	var mr matchResult
	if err := json.NewDecoder(match.Body).Decode(&mr); err != nil {
		t.Fatal(err)
	}
	if mr.Count != 1 || len(mr.Matches) != 1 || mr.Matches[0].Pinned != "t0" {
		t.Errorf("match over HTTP disagrees with the direct call: %+v", mr)
	}
}

// A page on another origin must not be able to read the user's source by
// pointing a DNS name at 127.0.0.1.
func TestRejectsNonLoopbackHost(t *testing.T) {
	idx, _ := newTestIndex(t)
	req := httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	req.Host = "evil.example.com"
	rec := httptest.NewRecorder()
	idx.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-loopback Host = %d, want 403", rec.Code)
	}
}

func keys(m map[string]*fileEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

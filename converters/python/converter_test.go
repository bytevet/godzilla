package py_converter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/converters/ssabuild"
	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// requirePython3 skips the test if python3 is not on PATH, since ConvertFile
// shells out to it (there is no pure-Go fallback yet).
func requirePython3(t *testing.T) { testsupport.RequireTool(t, "python3") }

func TestConvertFile_SQLInjectionSample(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/sql_injection/app.py")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}
	if prog == nil {
		t.Fatal("program is nil")
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(prog.Modules))
	}

	mod := prog.Modules[0]
	if mod.Language != "python" {
		t.Errorf("expected language %q, got %q", "python", mod.Language)
	}

	var foundHandler bool
	var foundSourceCall, foundSinkCall bool
	for _, f := range mod.Functions {
		t.Logf("function: %s (canonical: %s, synthetic: %v)", f.Name, f.CanonicalName, f.Synthetic)
		if f.ObjectName == "get_user" {
			foundHandler = true
		}
		for _, b := range f.Blocks {
			for _, inst := range b.Instrs {
				if inst.Op == ir.OpCode_OP_CODE_INTRINSIC && inst.Intrinsic == "py.unsupported" {
					t.Errorf("unsupported python construct in function %s: %s", f.Name, inst.Comment)
				}
				// An object-method sink like `cursor.execute(...)` is an INVOKE (CHA
				// dispatch) while a resolved module accessor stays a CALL, so accept
				// either op and match on Callee.
				if (inst.Op == ir.OpCode_OP_CODE_CALL || inst.Op == ir.OpCode_OP_CODE_INVOKE) && inst.Call != nil {
					// `from flask import request` makes alias resolution qualify the
					// callee to py:flask.request.args.get; match by suffix.
					if strings.HasSuffix(inst.Call.Callee, "request.args.get") {
						foundSourceCall = true
					}
					if inst.Call.Callee == "py:cursor.execute" {
						foundSinkCall = true
					}
				}
			}
		}
	}
	if !foundHandler {
		t.Error("could not find get_user handler function in converted IR")
	}
	if !foundSourceCall {
		t.Error("expected a py:request.args.get call in the IR")
	}
	if !foundSinkCall {
		t.Error("expected a py:cursor.execute call in the IR")
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-SQLI-TEST",
		Languages: []string{"python"},
		Severity:  rules.SeverityHigh,
		CWE:       "CWE-89",
		Message:   "untrusted input reaches a SQL execute call",
		Sources:   []string{"py:*request.args.get"},
		Sinks:     rules.SinksOf("py:*.execute"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got 0")
	}

	var found *analysis.Finding
	for i := range findings {
		if findings[i].RuleID == "PY-SQLI-TEST" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a PY-SQLI-TEST finding, got: %v", findings)
	}
	if found.SourcePos == nil {
		t.Error("expected non-nil SourcePos")
	}
	if found.SinkPos == nil {
		t.Error("expected non-nil SinkPos")
	}
	t.Logf("finding: %s", found.String())
}

func TestConvertFile_CommandInjectionSample(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/command_injection/app.py")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}
	if prog == nil {
		t.Fatal("program is nil")
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-CMDI-TEST",
		Languages: []string{"python"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os.system",
		Sources:   []string{"py:*request.args.get"},
		Sinks:     rules.SinksOf("py:os.system"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got 0")
	}

	var found *analysis.Finding
	for i := range findings {
		if findings[i].RuleID == "PY-CMDI-TEST" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a PY-CMDI-TEST finding, got: %v", findings)
	}
	if found.SourcePos == nil {
		t.Error("expected non-nil SourcePos")
	}
	if found.SinkPos == nil {
		t.Error("expected non-nil SinkPos")
	}
	t.Logf("finding: %s", found.String())
}

// TestConvertFile_BranchMergeDefault pins that the "default if empty" pattern
// (`if not host: host = "localhost"`) keeps taint: the merge PHI must carry the
// pre-branch tainted value through to the os.system sink.
func TestConvertFile_BranchMergeDefault(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/branch_merge_default/app.py")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-CMDI-BRANCH",
		Languages: []string{"python"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os.system after a default-if-empty branch",
		Sources:   []string{"py:*request.args.get"},
		Sinks:     rules.SinksOf("py:os.system"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	var found bool
	for i := range findings {
		if findings[i].RuleID == "PY-CMDI-BRANCH" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected taint to survive the default-if-empty branch, got: %v", findings)
	}
}

func TestConvertFile_Directory(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python")
	if err != nil {
		t.Fatalf("failed to convert directory: %v", err)
	}
	if len(prog.Modules) < 2 {
		t.Fatalf("expected at least 2 modules when converting a directory, got %d", len(prog.Modules))
	}
}

// TestConvertFile_SubscriptSourceSample pins that the bracket-subscript form
// `request.args["cmd"]` lowers to a synthetic "py:request.args.__getitem__"
// source CALL rather than a plain OP_CODE_INDEX, which is what makes the
// "py:*request.args.__getitem__" glob in py-command-injection.yaml fire.
func TestConvertFile_SubscriptSourceSample(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/command_injection_subscript/app.py")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	var foundSubscriptSource bool
	for _, mod := range prog.Modules {
		for _, f := range mod.Functions {
			for _, b := range f.Blocks {
				for _, inst := range b.Instrs {
					if inst.Op == ir.OpCode_OP_CODE_INTRINSIC && inst.Intrinsic == "py.unsupported" {
						t.Errorf("unsupported python construct in function %s: %s", f.Name, inst.Comment)
					}
					if inst.Op == ir.OpCode_OP_CODE_CALL && inst.Call != nil && inst.Call.Callee == "py:request.args.__getitem__" {
						foundSubscriptSource = true
					}
				}
			}
		}
	}
	if !foundSubscriptSource {
		t.Fatal("expected a py:request.args.__getitem__ synthetic source call in the IR")
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-CMDI-SUBSCRIPT-TEST",
		Languages: []string{"python"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input (subscript form) reaches os.system",
		Sources:   []string{"py:*request.args.__getitem__"},
		Sinks:     rules.SinksOf("py:os.system"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got 0")
	}
}

// TestSubscript_OpaqueBaseDiscrimination is a whitebox test (no python3
// dependency: it builds pyast.py-shaped astNode trees directly) covering the
// three roots lowerSubscript must discriminate: an unbound module global/import,
// the function's own parameter, and a local holding a locally-computed value.
// Only the first two are opaque and lower to a synthetic source CALL; the local
// must stay OP_CODE_INDEX or taint through `local_list[i]` regresses.
func TestSubscript_OpaqueBaseDiscrimination(t *testing.T) {
	nameNode := func(id string) map[string]any {
		return map[string]any{"kind": "Name", "id": id}
	}
	attrNode := func(base map[string]any, attr string) map[string]any {
		return map[string]any{"kind": "Attribute", "value": base, "attr": attr}
	}
	strConst := func(s string) map[string]any {
		return map[string]any{"kind": "Constant", "value_type": "str", "value": s}
	}
	subscriptNode := func(base, slice map[string]any) astNode {
		return astNode{"kind": "Subscript", "value": base, "slice": slice}
	}

	// curInstrs materializes the (single, branch-free) block the whitebox lowering
	// produced and returns its instruction stream. Finish() emits PHIs, then body
	// instructions, then any terminator; these cases have neither PHIs nor a
	// terminator, so this is exactly the emitted body in order.
	curInstrs := func(fs *funcState) []*ir.Instruction {
		blocks := fs.b.Finish()
		if len(blocks) != 1 {
			t.Fatalf("expected exactly 1 block, got %d", len(blocks))
		}
		return blocks[0].Instrs
	}

	t.Run("global root is opaque", func(t *testing.T) {
		fs := newFuncState("test.py")
		// request.args["cmd"], where `request` is never bound locally (an
		// unbound module-level import, per the Name fallback in lookupName).
		sub := subscriptNode(attrNode(nameNode("request"), "args"), strConst("cmd"))

		val := fs.lowerExpr(sub)

		instrs := curInstrs(fs)
		if len(instrs) != 1 {
			t.Fatalf("expected exactly 1 emitted instruction, got %d: %+v", len(instrs), instrs)
		}
		inst := instrs[0]
		if inst.Op != ir.OpCode_OP_CODE_CALL {
			t.Fatalf("Op = %v, want OP_CODE_CALL", inst.Op)
		}
		wantCallee := "py:request.args.__getitem__"
		if inst.Call == nil || inst.Call.Callee != wantCallee {
			t.Fatalf("callee = %v, want %q", inst.Call, wantCallee)
		}
		if len(inst.Call.Args) != 2 {
			t.Fatalf("expected 2 call args (base, key), got %d", len(inst.Call.Args))
		}
		if val.GetRegName() != inst.Name {
			t.Fatalf("lowerExpr result should reference the synthetic call's result register")
		}
	})

	t.Run("function parameter root is opaque", func(t *testing.T) {
		fs := newFuncState("test.py")
		fs.write("req", ssabuild.Reg("req"))
		fs.paramRegs["req"] = true
		// req.args["cmd"], where `req` is this function's own parameter.
		sub := subscriptNode(attrNode(nameNode("req"), "args"), strConst("cmd"))

		fs.lowerExpr(sub)

		instrs := curInstrs(fs)
		if len(instrs) != 1 || instrs[0].Op != ir.OpCode_OP_CODE_CALL {
			t.Fatalf("expected a single OP_CODE_CALL instruction, got %+v", instrs)
		}
		wantCallee := "py:req.args.__getitem__"
		if instrs[0].Call == nil || instrs[0].Call.Callee != wantCallee {
			t.Fatalf("callee = %v, want %q", instrs[0].Call, wantCallee)
		}
		// A parameter-rooted read must ALSO carry the parameter register in
		// Call.Value and be tagged builtin.member_read, or incoming
		// inter-procedural taint on `req` drops at the synthetic source call.
		if got := instrs[0].Call.GetValue().GetRegName(); got != "req" {
			t.Fatalf("Call.Value = %v, want the req parameter register", instrs[0].Call.GetValue())
		}
		if instrs[0].Intrinsic != "builtin.member_read" {
			t.Fatalf("Intrinsic = %q, want builtin.member_read", instrs[0].Intrinsic)
		}
	})

	t.Run("direct parameter subscript is a member_read call", func(t *testing.T) {
		fs := newFuncState("test.py")
		fs.write("details", ssabuild.Reg("details"))
		fs.paramRegs["details"] = true
		// details["path"] where `details` is a parameter (CVE-2025-47782): one
		// synthetic CALL, base in Call.Value, tagged builtin.member_read.
		sub := subscriptNode(nameNode("details"), strConst("path"))

		fs.lowerExpr(sub)

		instrs := curInstrs(fs)
		if len(instrs) != 1 || instrs[0].Op != ir.OpCode_OP_CODE_CALL {
			t.Fatalf("expected a single OP_CODE_CALL instruction, got %+v", instrs)
		}
		if got := instrs[0].Call.GetCallee(); got != "py:details.__getitem__" {
			t.Fatalf("callee = %q, want py:details.__getitem__", got)
		}
		if got := instrs[0].Call.GetValue().GetRegName(); got != "details" {
			t.Fatalf("Call.Value = %v, want the details parameter register", instrs[0].Call.GetValue())
		}
		if instrs[0].Intrinsic != "builtin.member_read" {
			t.Fatalf("Intrinsic = %q, want builtin.member_read", instrs[0].Intrinsic)
		}
	})

	t.Run("global root keeps the plain FuncName form", func(t *testing.T) {
		fs := newFuncState("test.py")
		// request.args["cmd"] rooted at an unbound global: there is no
		// register whose taint could be carried, so no member_read tag.
		sub := subscriptNode(attrNode(nameNode("request"), "args"), strConst("cmd"))

		fs.lowerExpr(sub)

		instrs := curInstrs(fs)
		if len(instrs) != 1 || instrs[0].Op != ir.OpCode_OP_CODE_CALL {
			t.Fatalf("expected a single OP_CODE_CALL instruction, got %+v", instrs)
		}
		if instrs[0].Intrinsic != "" {
			t.Fatalf("Intrinsic = %q, want none for a global-rooted read", instrs[0].Intrinsic)
		}
		if got := instrs[0].Call.GetValue().GetFuncName(); got != "py:request.args.__getitem__" {
			t.Fatalf("Call.Value = %v, want the callee FuncName", instrs[0].Call.GetValue())
		}
	})

	t.Run("local variable root stays OP_CODE_INDEX", func(t *testing.T) {
		fs := newFuncState("test.py")
		// items = get_items(); items[0] -- `items` is bound to a
		// locally-computed register (not a param, not unbound), so it must
		// NOT be treated as an opaque source.
		fs.write("items", ssabuild.Reg("t0"))
		sub := subscriptNode(nameNode("items"), strConst("0"))

		fs.lowerExpr(sub)

		instrs := curInstrs(fs)
		if len(instrs) != 1 {
			t.Fatalf("expected exactly 1 emitted instruction, got %d: %+v", len(instrs), instrs)
		}
		if instrs[0].Op != ir.OpCode_OP_CODE_INDEX {
			t.Fatalf("Op = %v, want OP_CODE_INDEX for a local-variable base", instrs[0].Op)
		}
	})
}

// TestSubscript_TaintedParamMemberRead pins the flow the builtin.member_read tag
// exists for: a helper's PARAMETER arrives tainted from its caller and the helper
// reads a member chain off it with a subscript (`d.args["k"]` — param.attr[key],
// not a plain param[key]). The synthetic __getitem__ source only INTRODUCES taint
// when its dotted name matches a source glob, so without the tag this drops.
func TestSubscript_TaintedParamMemberRead(t *testing.T) {
	requirePython3(t)

	dir := t.TempDir()
	src := `from flask import Flask, request
import os

app = Flask(__name__)

def helper(d):
    os.system(d.args["k"])

@app.route("/run")
def handler():
    helper(request.args.get("x"))
    return "ok"
`
	path := filepath.Join(dir, "app.py")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := NewConverter().ConvertFile(path)
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-MEMBER-READ-TEST",
		Languages: []string{"python"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "tainted parameter member read reaches os.system",
		Sources:   []string{"py:*request.args.get"},
		Sinks:     rules.SinksOf("py:os.system"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	if len(findings) < 1 {
		t.Fatal("expected the tainted-param member read to reach os.system, got 0 findings")
	}
}

// TestConvertFile_DirectorySkipsUnparseableFile pins that a directory conversion
// tolerates one unparseable .py file: test/python/resilience holds both
// broken.py (a syntax error) and a valid, vulnerable app.py, and the batch must
// still succeed, yield only app.py's module, and still find its vulnerability.
func TestConvertFile_DirectorySkipsUnparseableFile(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/resilience")
	if err != nil {
		t.Fatalf("ConvertFile: expected the batch to tolerate one broken .py file, got error: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("expected exactly 1 module (broken.py skipped), got %d", len(prog.Modules))
	}
	if prog.Modules[0].Name != "app" {
		t.Errorf("Modules[0].Name = %q, want %q", prog.Modules[0].Name, "app")
	}

	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "PY-RESILIENCE-TEST",
		Languages: []string{"python"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "untrusted input reaches os.system",
		Sources:   []string{"py:*request.args.get"},
		Sinks:     rules.SinksOf("py:os.system"),
	}}}

	findings := analysis.NewEngine(rs).Analyze(prog)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding from app.py despite the broken sibling, got 0")
	}
}

// TestConvertFile_SingleUnparseableFileErrors proves that a single-file path
// (as opposed to a directory) still surfaces a parse failure as an error, per
// ConvertFile's contract: only a directory batch tolerates a broken sibling
// file.
func TestConvertFile_SingleUnparseableFileErrors(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	_, err := conv.ConvertFile("../../test/python/resilience/broken.py")
	if err == nil {
		t.Fatal("ConvertFile on a single unparseable file: expected an error, got nil")
	}
}

// TestConvertFile_ModuleConstantBecomesGlobal pins that a module-level constant
// binding surfaces as a gIR Global with its string init value; otherwise the
// literal is invisible to the hardcoded-secret scanner.
func TestConvertFile_ModuleConstantBecomesGlobal(t *testing.T) {
	requirePython3(t)

	conv := NewConverter()
	prog, err := conv.ConvertFile("../../test/python/secrets/app.py")
	if err != nil {
		t.Fatalf("failed to convert file: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(prog.Modules))
	}

	const want = "AKIAIOSFODNN7EXAMPLE"
	var found bool
	for _, g := range prog.Modules[0].Globals {
		if g.GetName() == "AWS_ACCESS_KEY_ID" && g.GetInitValue().GetStringVal() == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a global AWS_ACCESS_KEY_ID with init value %q; globals = %v", want, prog.Modules[0].Globals)
	}
}

// TestResolveDotted covers import-alias resolution of a callee's root: module
// aliases (import x as y) and from-imports (from m import n).
func TestResolveDotted(t *testing.T) {
	fs := &funcState{aliases: map[string]string{
		"sp":     "subprocess",    // import subprocess as sp
		"system": "os.system",     // from os import system
		"req":    "flask.request", // import flask.request as req
	}}
	cases := []struct{ in, want string }{
		{"sp.call", "subprocess.call"},
		{"sp", "subprocess"},
		{"system", "os.system"},
		{"req.args.get", "flask.request.args.get"},
		{"os.system", "os.system"}, // unaliased root passes through
		{"cursor.execute", "cursor.execute"},
	}
	for _, c := range cases {
		if got := fs.resolveDotted(c.in); got != c.want {
			t.Errorf("resolveDotted(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// No alias table: identity.
	empty := &funcState{}
	if got := empty.resolveDotted("sp.call"); got != "sp.call" {
		t.Errorf("no aliases should be identity, got %q", got)
	}
}

// TestCollectImportAliases covers building the alias table from import statements.
func TestCollectImportAliases(t *testing.T) {
	// astNode is map[string]any; a list() child is []any of map[string]any.
	body := []astNode{
		{"kind": "Import", "names": []any{
			map[string]any{"name": "subprocess", "asname": "sp"},
			map[string]any{"name": "os", "asname": nil}, // no asname -> no alias
		}},
		{"kind": "ImportFrom", "module": "os", "names": []any{
			map[string]any{"name": "system", "asname": nil},
		}},
		{"kind": "ImportFrom", "module": nil, "names": []any{
			map[string]any{"name": "x", "asname": nil}, // relative -> skipped
		}},
	}
	got := collectImportAliases(body)
	if got["sp"] != "subprocess" {
		t.Errorf("sp -> %q, want subprocess", got["sp"])
	}
	if got["system"] != "os.system" {
		t.Errorf("system -> %q, want os.system", got["system"])
	}
	if _, ok := got["os"]; ok {
		t.Errorf("plain `import os` should not create an alias")
	}
	if _, ok := got["x"]; ok {
		t.Errorf("relative import should be skipped")
	}
}

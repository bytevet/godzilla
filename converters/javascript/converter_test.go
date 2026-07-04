package js_converter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// xssRuleSet mirrors internal/rules/loader/builtin/js-xss.yaml.
func xssRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-xss",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityHigh,
				CWE:       "CWE-79",
				Message:   "reflected XSS",
				Sources: []string{
					"js:*req.query*",
					"js:*req.params*",
					"js:*req.body*",
				},
				Sinks: []string{
					"js:*res.send",
					"js:*res.write",
					"js:*res.end",
				},
			},
		},
	}
}

// commandInjectionRuleSet mirrors
// internal/rules/loader/builtin/js-command-injection.yaml.
func commandInjectionRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-command-injection",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityCritical,
				CWE:       "CWE-78",
				Message:   "OS command injection",
				Sources: []string{
					"js:*req.query*",
					"js:*req.params*",
					"js:*req.body*",
				},
				Sinks: []string{
					"js:*child_process.exec*",
					"js:*.exec",
					"js:*.execSync",
					"js:*.spawn",
				},
			},
		},
	}
}

// sqliRuleSet mirrors internal/rules/loader/builtin/js-sqli.yaml.
func sqliRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-sqli",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityHigh,
				CWE:       "CWE-89",
				Message:   "SQL injection",
				Sources: []string{
					"js:*req.query*",
					"js:*req.params*",
					"js:*req.body*",
				},
				Sinks: []string{
					"js:*.query",
					"js:*.execute",
				},
			},
		},
	}
}

// ssrfRuleSet mirrors internal/rules/loader/builtin/js-ssrf.yaml.
func ssrfRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-ssrf",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityHigh,
				CWE:       "CWE-918",
				Message:   "server-side request forgery",
				Sources: []string{
					"js:*req.query*",
					"js:*req.params*",
					"js:*req.body*",
				},
				Sinks: []string{
					"js:*http.get",
					"js:*https.get",
					"js:*axios*",
					"js:*fetch",
				},
			},
		},
	}
}

// pathTraversalRuleSet mirrors
// internal/rules/loader/builtin/js-path-traversal.yaml.
func pathTraversalRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-path-traversal",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityHigh,
				CWE:       "CWE-22",
				Message:   "path traversal",
				Sources: []string{
					"js:*req.query*",
					"js:*req.params*",
					"js:*req.body*",
				},
				Sinks: []string{
					"js:*fs.readFile*",
					"js:*fs.createReadStream",
					"js:*.sendFile",
				},
			},
		},
	}
}

func mustConvert(t *testing.T, path string) *ir.Program {
	t.Helper()
	conv := NewConverter()
	prog, err := conv.ConvertFile(path)
	if err != nil {
		t.Fatalf("ConvertFile(%q) error: %v", path, err)
	}
	if prog == nil {
		t.Fatalf("ConvertFile(%q) returned a nil program", path)
	}
	return prog
}

// requireFinding asserts that findings contains at least one entry for
// ruleID with non-nil source/sink positions, returning it.
func requireFinding(t *testing.T, findings []analysis.Finding, ruleID string) analysis.Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID != ruleID {
			continue
		}
		if f.SourcePos == nil {
			t.Errorf("finding %s has a nil SourcePos: %+v", ruleID, f)
		}
		if f.SinkPos == nil {
			t.Errorf("finding %s has a nil SinkPos: %+v", ruleID, f)
		}
		return f
	}
	t.Fatalf("expected at least one %s finding, got %d finding(s): %v", ruleID, len(findings), findings)
	return analysis.Finding{}
}

func TestConvertXSSSample(t *testing.T) {
	prog := mustConvert(t, "../../test/js/xss/app.js")

	if len(prog.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(prog.Modules))
	}
	mod := prog.Modules[0]
	if mod.Language != "javascript" {
		t.Errorf("Language = %q, want javascript", mod.Language)
	}

	var handler *ir.Function
	for _, fn := range mod.Functions {
		if fn.ObjectName == "handleName" {
			handler = fn
		}
	}
	if handler == nil {
		t.Fatalf("expected a handleName function, got: %v", functionNames(mod))
	}
	if handler.CanonicalName != "js:app.handleName" {
		t.Errorf("CanonicalName = %q, want js:app.handleName", handler.CanonicalName)
	}

	engine := analysis.NewEngine(xssRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-xss")
}

func TestConvertCommandInjectionSample(t *testing.T) {
	prog := mustConvert(t, "../../test/js/command_injection/app.js")

	engine := analysis.NewEngine(commandInjectionRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-command-injection")
}

func TestConvertSQLInjectionSample(t *testing.T) {
	prog := mustConvert(t, "../../test/js/sql_injection/app.js")

	engine := analysis.NewEngine(sqliRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-sqli")
}

func TestConvertSSRFSample(t *testing.T) {
	prog := mustConvert(t, "../../test/js/ssrf/app.js")

	engine := analysis.NewEngine(ssrfRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-ssrf")
}

// TestConvertChainedAxiosCallSSRF is a regression test for the
// chained-call lowering bug: a CallExpression that appears inside another
// call's *callee* (e.g. the `axios.get(url)` inside
// `axios.get(url).then(cb)`) must still be lowered to its own OP_CODE_CALL
// -- with its own real arguments -- even though it is never assigned to an
// intermediate variable first. Before the fix, lowerCall built the outer
// call's callee purely syntactically (via syntacticCallee) and never ran
// lowerExpr on it, so the inner axios.get(...) call (and the taint flowing
// through its argument) was silently dropped and never matched the SSRF
// sink glob.
func TestConvertChainedAxiosCallSSRF(t *testing.T) {
	src := `
var express = require("express");
var axios = require("axios");
var app = express();

function handleProxy(req, res) {
  axios.get(req.query.url).then(function (response) {
    res.send(response.data);
  });
}

app.get("/proxy", handleProxy);
module.exports = app;
`
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	prog := mustConvert(t, path)

	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID:        "js-ssrf-chained",
				Languages: []string{"javascript"},
				Severity:  rules.SeverityHigh,
				CWE:       "CWE-918",
				Message:   "server-side request forgery via a chained call",
				Sources: []string{
					"js:*req.query*",
				},
				Sinks: []string{
					"js:*axios*",
				},
			},
		},
	}

	engine := analysis.NewEngine(rs)
	findings := engine.Analyze(prog)
	f := requireFinding(t, findings, "js-ssrf-chained")
	if f.SinkCallee != "js:axios.get" {
		t.Errorf("SinkCallee = %q, want %q", f.SinkCallee, "js:axios.get")
	}
}

func TestConvertPathTraversalSample(t *testing.T) {
	prog := mustConvert(t, "../../test/js/path_traversal/app.js")

	engine := analysis.NewEngine(pathTraversalRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-path-traversal")
}

// TestNewRulePacksDoNotCrossFire proves that the three new rule packs
// (js-sqli, js-ssrf, js-path-traversal) do not spuriously fire on the
// pre-existing xss/command-injection samples, and that js-xss/
// js-command-injection do not spuriously fire on the three new samples --
// i.e. the broad `js:*.<method>` sink globs stay isolated to their own
// vulnerability class.
func TestNewRulePacksDoNotCrossFire(t *testing.T) {
	allRules := &rules.RuleSet{}
	for _, rs := range []*rules.RuleSet{xssRuleSet(), commandInjectionRuleSet(), sqliRuleSet(), ssrfRuleSet(), pathTraversalRuleSet()} {
		allRules.Rules = append(allRules.Rules, rs.Rules...)
	}
	engine := analysis.NewEngine(allRules)

	cases := []struct {
		path string
		want string
	}{
		{"../../test/js/xss/app.js", "js-xss"},
		{"../../test/js/command_injection/app.js", "js-command-injection"},
		{"../../test/js/sql_injection/app.js", "js-sqli"},
		{"../../test/js/ssrf/app.js", "js-ssrf"},
		{"../../test/js/path_traversal/app.js", "js-path-traversal"},
	}
	for _, tc := range cases {
		prog := mustConvert(t, tc.path)
		findings := engine.Analyze(prog)
		for _, f := range findings {
			if f.RuleID != tc.want {
				t.Errorf("%s: unexpected cross-fire from rule %s (want only %s): %+v", tc.path, f.RuleID, tc.want, f)
			}
		}
		requireFinding(t, findings, tc.want)
	}
}

// TestConvertDirectory exercises the directory-walk path of ConvertFile
// (both sample directories share a common parent, test/js).
func TestConvertDirectory(t *testing.T) {
	prog := mustConvert(t, "../../test/js")
	if len(prog.Modules) < 2 {
		t.Fatalf("expected at least 2 modules from directory conversion, got %d", len(prog.Modules))
	}
}

// TestConvertDirectorySkipsUnparseableFile proves that a directory
// conversion tolerates one unparseable .js file: test/js/resilience contains
// both broken.js (a syntax error) and a valid, vulnerable app.js. The batch
// must still succeed, must still yield app.js's module (and only that one --
// broken.js contributes none), and the taint engine must still find
// app.js's vulnerability.
func TestConvertDirectorySkipsUnparseableFile(t *testing.T) {
	prog := mustConvert(t, "../../test/js/resilience")

	if len(prog.Modules) != 1 {
		t.Fatalf("expected exactly 1 module (broken.js skipped), got %d: %v", len(prog.Modules), functionNamesForModules(prog))
	}
	if prog.Modules[0].Name != "app" {
		t.Errorf("Modules[0].Name = %q, want %q", prog.Modules[0].Name, "app")
	}

	engine := analysis.NewEngine(xssRuleSet())
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-xss")
}

// TestConvertSingleUnparseableFileErrors proves that a single-file path
// (as opposed to a directory) still surfaces a parse failure as an error,
// per ConvertFile's contract: only a directory batch tolerates a broken
// sibling file.
func TestConvertSingleUnparseableFileErrors(t *testing.T) {
	conv := NewConverter()
	_, err := conv.ConvertFile("../../test/js/resilience/broken.js")
	if err == nil {
		t.Fatalf("ConvertFile on a single unparseable file: expected an error, got nil")
	}
}

func functionNamesForModules(prog *ir.Program) []string {
	var names []string
	for _, mod := range prog.Modules {
		names = append(names, functionNames(mod)...)
	}
	return names
}

// TestNoUnsupportedInstructions guards against silent regressions: every
// instruction in the converted samples should have a real OpCode, not the
// generic "js.unsupported" intrinsic fallback, mirroring
// converters/go's TestConvertComplexFile absence-of-fallback-comments check.
func TestNoUnsupportedInstructions(t *testing.T) {
	for _, path := range []string{
		"../../test/js/xss/app.js",
		"../../test/js/command_injection/app.js",
		"../../test/js/sql_injection/app.js",
		"../../test/js/ssrf/app.js",
		"../../test/js/path_traversal/app.js",
		"../../test/js/resilience/app.js",
	} {
		prog := mustConvert(t, path)
		for _, mod := range prog.Modules {
			for _, fn := range mod.Functions {
				for _, blk := range fn.Blocks {
					for _, inst := range blk.Instrs {
						if inst.Op == ir.OpCode_OP_CODE_INTRINSIC && inst.Intrinsic == "js.unsupported" {
							t.Errorf("%s: unsupported instruction in %s: %s", path, fn.CanonicalName, inst.Comment)
						}
					}
				}
			}
		}
	}
}

// TestLogXSSSampleInstructions is a diagnostic test: it converts the XSS
// sample and logs every instruction in the handleName function, so the
// lowering shape (registers, opcodes, callees, positions) is visible in test
// output, mirroring internal/analysis's TestLogSQLInjectionCallees.
func TestLogXSSSampleInstructions(t *testing.T) {
	prog := mustConvert(t, "../../test/js/xss/app.js")
	for _, mod := range prog.Modules {
		for _, fn := range mod.Functions {
			t.Logf("function %s (canonical=%s, synthetic=%v)", fn.Name, fn.CanonicalName, fn.Synthetic)
			for _, blk := range fn.Blocks {
				for _, inst := range blk.Instrs {
					pos := "<nil>"
					if inst.Pos != nil {
						pos = fmt.Sprintf("%s:%d:%d", inst.Pos.GetFilename(), inst.Pos.GetLine(), inst.Pos.GetColumn())
					}
					callee := ""
					if inst.Call != nil {
						callee = inst.Call.Callee
					}
					t.Logf("  name=%-4s op=%-24s callee=%-20s comment=%-20q pos=%s", inst.Name, inst.Op, callee, inst.Comment, pos)
				}
			}
		}
	}
}

func functionNames(mod *ir.Module) []string {
	var names []string
	for _, fn := range mod.Functions {
		names = append(names, fn.CanonicalName)
	}
	return names
}

// TestCollectRequireAliases covers FE-2's require-alias table: plain, aliased,
// destructured, and require().member bindings.
func TestCollectRequireAliases(t *testing.T) {
	src := `var cp = require("child_process");
var { exec, spawn } = require("child_process");
var ex = require("child_process").execSync;
var express = require("express");
var local = require("./util");
`
	fset := &file.FileSet{}
	prog, err := parser.ParseFile(fset, "a.js", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	a := collectRequireAliases(prog.Body)
	want := map[string]string{
		"cp":      "child_process",
		"exec":    "child_process.exec",
		"spawn":   "child_process.spawn",
		"ex":      "child_process.execSync",
		"express": "express",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("alias %q = %q, want %q", k, a[k], v)
		}
	}
	// A relative require (./util) is a local module and must NOT be aliased, so
	// cross-file resolution (a caller's util.fn -> js:util.fn) is preserved.
	if _, ok := a["local"]; ok {
		t.Errorf("relative require ./util should not create an alias, got %q", a["local"])
	}
}

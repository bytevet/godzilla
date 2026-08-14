package js_converter

import (
	"os"
	"path/filepath"
	"testing"

	jsast "github.com/bytevet/esbuild-jsast"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/irwalk"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/testsupport"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// reqSources is the untrusted-HTTP-request source glob set shared by every
// builtin JS rulepack these tests mirror.
var reqSources = []string{"js:*req.query*", "js:*req.params*", "js:*req.body*"}

// jsRuleSet builds a one-rule RuleSet over reqSources, mirroring one of the
// builtin internal/rules/loader/builtin/js-*.yaml packs.
func jsRuleSet(t testing.TB, id, cwe, msg string, sev rules.Severity, sinks ...string) *rules.RuleSet {
	return testsupport.OneRuleSet(t, id, "javascript", cwe, reqSources, sinks,
		testsupport.Severity(sev), testsupport.Message(msg))
}

func xssRuleSet(t testing.TB) *rules.RuleSet {
	return jsRuleSet(t, "js-xss", "CWE-79", "reflected XSS", rules.SeverityHigh,
		"js:*res.send", "js:*res.write", "js:*res.end")
}

func commandInjectionRuleSet(t testing.TB) *rules.RuleSet {
	return jsRuleSet(t, "js-command-injection", "CWE-78", "OS command injection", rules.SeverityCritical,
		"js:*child_process.exec*", "js:*.exec", "js:*.execSync", "js:*.spawn")
}

func sqliRuleSet(t testing.TB) *rules.RuleSet {
	return jsRuleSet(t, "js-sqli", "CWE-89", "SQL injection", rules.SeverityHigh,
		"js:*.query", "js:*.execute")
}

func ssrfRuleSet(t testing.TB) *rules.RuleSet {
	return jsRuleSet(t, "js-ssrf", "CWE-918", "server-side request forgery", rules.SeverityHigh,
		"js:*http.get", "js:*https.get", "js:*axios*", "js:*fetch")
}

func pathTraversalRuleSet(t testing.TB) *rules.RuleSet {
	return jsRuleSet(t, "js-path-traversal", "CWE-22", "path traversal", rules.SeverityHigh,
		"js:*fs.readFile*", "js:*fs.createReadStream", "js:*.sendFile")
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

	engine := analysis.NewEngine(xssRuleSet(t))
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-xss")
}

// TestConvertBranchMergeDefault pins the statement-level "default if empty"
// pattern (`if (!host) host = "localhost"`, FE-5): without the merge PHI the
// reassignment inside the `if` kills the tainted binding on the merge path and
// the execSync sink reads clean (a false negative).
func TestConvertBranchMergeDefault(t *testing.T) {
	prog := mustConvert(t, "../../test/js/branch_merge_default/app.js")

	engine := analysis.NewEngine(commandInjectionRuleSet(t))
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-command-injection")
}

// TestConvertChainedAxiosCallSSRF pins the chained-call lowering: a
// CallExpression inside another call's *callee* (the `axios.get(url)` in
// `axios.get(url).then(cb)`) must get its own OP_CODE_CALL with its own real
// arguments, even though it is never assigned to an intermediate variable.
// Building the outer callee purely syntactically without also lowering it drops
// the inner call — and the taint through its argument — so the SSRF sink glob
// never matches.
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
				Sinks: rules.SinksOf("js:*axios*"),
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

// TestNewRulePacksDoNotCrossFire pins that the broad `js:*.<method>` sink globs
// stay isolated to their own vulnerability class: no pack fires on another
// pack's sample.
func TestNewRulePacksDoNotCrossFire(t *testing.T) {
	sets := []*rules.RuleSet{xssRuleSet(t), commandInjectionRuleSet(t), sqliRuleSet(t), ssrfRuleSet(t), pathTraversalRuleSet(t)}
	var all []rules.Rule
	for _, rs := range sets {
		all = append(all, rs.Rules...)
	}
	// WithRules keeps the set-wide DefaultPropagators the component sets carry.
	engine := analysis.NewEngine(sets[0].WithRules(all))

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

// TestConvertDirectorySkipsUnparseableFile pins that a directory conversion
// tolerates one unparseable .js file: the batch still succeeds, yields only
// app.js's module, and the engine still finds app.js's vulnerability.
func TestConvertDirectorySkipsUnparseableFile(t *testing.T) {
	prog := mustConvert(t, "../../test/js/resilience")

	if len(prog.Modules) != 1 {
		t.Fatalf("expected exactly 1 module (broken.js skipped), got %d: %v", len(prog.Modules), functionNamesForModules(prog))
	}
	if prog.Modules[0].Name != "app" {
		t.Errorf("Modules[0].Name = %q, want %q", prog.Modules[0].Name, "app")
	}

	engine := analysis.NewEngine(xssRuleSet(t))
	findings := engine.Analyze(prog)
	requireFinding(t, findings, "js-xss")
}

// TestConvertSingleUnparseableFileErrors pins the other half of ConvertFile's
// contract: only a directory batch tolerates a broken file; a single-file path
// surfaces the parse failure as an error.
func TestConvertSingleUnparseableFileErrors(t *testing.T) {
	conv := NewConverter()
	_, err := conv.ConvertFile("../../test/js/resilience/broken.js")
	if err == nil {
		t.Fatalf("ConvertFile on a single unparseable file: expected an error, got nil")
	}
}

func functionNamesForModules(prog *ir.Program) []string {
	var names []string
	for _, fn := range irwalk.Funcs(prog) {
		names = append(names, fn.CanonicalName)
	}
	return names
}

// TestCollectsParamDefaultLiteral pins the half of collector coverage no
// intrinsic reports: nothing lowers a parameter default, so a literal the
// collector misses there is silently absent rather than flagged.
func TestCollectsParamDefaultLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pdef.js")
	if err := os.WriteFile(path, []byte("function f(cb = (c) => eval(c)) { cb(1); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mod, _, err := NewConverter().convertJSFile(path, "pdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range mod.Functions {
		for inst := range irwalk.Instrs(fn) {
			if inst.GetCall().GetCallee() == "js:eval" {
				return
			}
		}
	}
	t.Error("no js:eval call lowered — the default's literal was never collected")
}

func functionNames(mod *ir.Module) []string {
	var names []string
	for _, fn := range mod.Functions {
		names = append(names, fn.CanonicalName)
	}
	return names
}

// mustParse parses src as plain JavaScript for the alias tests, which assert on
// the module-level tables rather than on a lowered module.
func mustParse(t *testing.T, src string) *jsast.File {
	t.Helper()
	f, errs := jsast.Parse(src, jsast.Options{})
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", src, errs)
	}
	return f
}

// TestCollectRequireAliases covers FE-2's require-alias table: plain, aliased,
// destructured, and require().member bindings.
func TestCollectRequireAliases(t *testing.T) {
	f := mustParse(t, `var cp = require("child_process");
var { exec, spawn } = require("child_process");
var ex = require("child_process").execSync;
var express = require("express");
var local = require("./util");
`)
	a := collectRequireAliases(f)
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

// TestCollectImportAliases is the ESM half of FE-2. It is new surface: until the
// frontend parsed modules directly, every import arrived already rewritten as a
// require call, so none of these forms had their own path.
func TestCollectImportAliases(t *testing.T) {
	f := mustParse(t, `import cp from "child_process";
import * as pathns from "path";
import { exec, spawn as sp } from "child_process";
import { default as fsd } from "fs";
import "side-effect-only";
import local from "./util";
`)
	a := map[string]string{}
	collectImportAliases(f, a)
	want := map[string]string{
		"cp":     "child_process",
		"pathns": "path",
		"exec":   "child_process.exec",
		"sp":     "child_process.spawn",
		// `{default as X}` is the module's own value, not a member of it: a rule
		// keyed on "js:fs*" matches "fs", never "fs.default".
		"fsd": "fs",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("alias %q = %q, want %q", k, a[k], v)
		}
	}
	// A relative import names a project module; collectRelativeDefaults owns it.
	if _, ok := a["local"]; ok {
		t.Errorf("relative import ./util should not create an alias, got %q", a["local"])
	}
	if len(a) != len(want) {
		t.Errorf("unexpected extra aliases: %v", a)
	}
}

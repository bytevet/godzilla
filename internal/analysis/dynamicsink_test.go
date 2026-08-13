package analysis

import (
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/rules"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// TestArgVals checks the IR->Arg skeleton bridge a dynamic guard evaluates over:
// a concatenation reconstructs to "prefix<DYN>", a literal is fully constant, and
// a register is fully dynamic ("<DYN>").
func TestArgVals(t *testing.T) {
	concat := binOp("c", ir.BinOpKind_BIN_OP_ADD, cstV("cmd:"), regV("t0")) // "cmd:" + t0
	defs := defsOf(concat)

	partial := argVals(callInst("s1", "x:sink", regV("c")).Call, defs, nil, true)[0]
	if partial.String != "cmd:"+rules.DynMarker || partial.Complete {
		t.Errorf("partial = %+v, want {String:cmd:<DYN> Complete:false}", partial)
	}
	full := argVals(callInst("s2", "x:sink", cstV("AES/ECB/PKCS5Padding")).Call, defs, nil, true)[0]
	if !full.Complete || full.String != "AES/ECB/PKCS5Padding" || full.Type != "string" {
		t.Errorf("full = %+v, want a complete string constant", full)
	}
	dyn := argVals(callInst("s3", "x:sink", regV("t0")).Call, defs, nil, true)[0]
	if dyn.Complete || dyn.String != rules.DynMarker {
		t.Errorf("dynamic = %+v, want {String:<DYN> Complete:false}", dyn)
	}
}

// TestArgValsScalarConstants checks that a NON-string constant reaches a guard as
// its literal text. constSkeleton reconstructs string text only, so without the
// constScalar fallback a bool argument arrives empty and incomplete and a rule
// could not tell `shell=True` (injectable) from `shell=False` (safe argv form) --
// the distinction the command-injection guards depend on.
func TestArgValsScalarConstants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		val      *ir.Value
		wantStr  string
		wantType string
	}{
		{"true", boolV(true), "true", "bool"},
		{"false", boolV(false), "false", "bool"},
		{"int", intV(8080), "8080", "int"},
	} {
		got := argVals(callInst("s", "x:sink", tc.val).Call, nil, nil, true)[0]
		if got.String != tc.wantStr || !got.Complete || got.Type != tc.wantType {
			t.Errorf("%s: argVals = %+v, want {String:%s Complete:true Type:%s}", tc.name, got, tc.wantStr, tc.wantType)
		}
	}
}

// TestConstSkeletonIgnoresScalars pins the deliberate SCOPE of the constScalar
// fallback: it lives in the guard path (argVals) and must NOT leak into
// constSkeleton, which also backs the SSRF host reconstruction. There a
// non-string operand is not part of the URL text, and rendering one "complete"
// could wrongly prove a fixed host and suppress a real CWE-918 finding.
func TestConstSkeletonIgnoresScalars(t *testing.T) {
	s, complete := constSkeleton(boolV(true), nil, map[string]bool{})
	if complete || s != rules.DynMarker {
		t.Errorf("constSkeleton(bool) = (%q, %v), want (%q, false) — scalars must stay guard-only", s, complete, rules.DynMarker)
	}
}

// TestDynamicSinkGuard is the end-to-end taint-sink guard: a `when:` on a sink
// fires only when the guard confirms against the call's argument values. The
// same tainted exec sink fires with a "cmd:" prefix, and is suppressed with a
// wrong prefix or a fully dynamic argument (required-confirmation).
func TestDynamicSinkGuard(t *testing.T) {
	const src = `
package main

import (
	"net/http"
	"os/exec"
)

func fireCmd(w http.ResponseWriter, r *http.Request) {
	x := r.URL.Query().Get("x")
	_ = exec.Command("cmd:" + x) // prefix confirmed -> fires
}

func wrongPrefix(w http.ResponseWriter, r *http.Request) {
	x := r.URL.Query().Get("x")
	_ = exec.Command("log:" + x) // wrong prefix -> suppressed
}

func dynamicArg(w http.ResponseWriter, r *http.Request) {
	x := r.URL.Query().Get("x")
	_ = exec.Command(x) // fully dynamic -> suppressed
}

func main() {
	http.HandleFunc("/a", fireCmd)
	http.HandleFunc("/b", wrongPrefix)
	http.HandleFunc("/c", dynamicArg)
	_ = http.ListenAndServe(":0", nil)
}
`
	rs := &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-DYN",
		Languages: []string{"go"},
		Severity:  rules.SeverityHigh,
		CWE:       "CWE-78",
		Message:   "guarded exec sink",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     []rules.Sink{{Pattern: "go:*os/exec.Command*#0", When: "arg[0].String startsWith 'cmd:'"}},
	}}}

	fired := map[string]bool{}
	for _, f := range scanSource(t, src, rs) {
		if f.RuleID == "GO-DYN" {
			fired[f.Function] = true
		}
	}
	firedIn := func(fn string) bool {
		for f := range fired {
			if strings.Contains(f, fn) {
				return true
			}
		}
		return false
	}
	if !firedIn("fireCmd") {
		t.Errorf("the confirmed 'cmd:' prefix should fire; fired=%v", fired)
	}
	if firedIn("wrongPrefix") {
		t.Error("a wrong prefix ('log:') must be suppressed")
	}
	if firedIn("dynamicArg") {
		t.Error("a fully dynamic argument must be suppressed (cannot confirm)")
	}
}

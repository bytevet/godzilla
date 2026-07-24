package analysis

import (
	"strings"
	"testing"

	"godzilla/internal/rules"
	ir "godzilla/pkg/ir/v1"
)

// TestArgVals checks the IR->Arg skeleton bridge a dynamic guard evaluates over:
// a concatenation reconstructs to "prefix<DYN>", a literal is fully constant, and
// a register is fully dynamic ("<DYN>").
func TestArgVals(t *testing.T) {
	concat := binOp("c", ir.BinOpKind_BIN_OP_ADD, cstV("cmd:"), regV("t0")) // "cmd:" + t0
	defs := defsOf(concat)

	partial := argVals(callInst("s1", "x:sink", regV("c")).Call, defs)[0]
	if partial.String != "cmd:"+rules.DynMarker || partial.Complete {
		t.Errorf("partial = %+v, want {String:cmd:<DYN> Complete:false}", partial)
	}
	full := argVals(callInst("s2", "x:sink", cstV("AES/ECB/PKCS5Padding")).Call, defs)[0]
	if !full.Complete || full.String != "AES/ECB/PKCS5Padding" || full.Type != "string" {
		t.Errorf("full = %+v, want a complete string constant", full)
	}
	dyn := argVals(callInst("s3", "x:sink", regV("t0")).Call, defs)[0]
	if dyn.Complete || dyn.String != rules.DynMarker {
		t.Errorf("dynamic = %+v, want {String:<DYN> Complete:false}", dyn)
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

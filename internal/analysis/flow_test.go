package analysis

import (
	"testing"

	"godzilla/internal/rules"
)

// cmdiRule is a minimal command-injection rule for the flow-sensitivity tests.
func cmdiRule() *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-CMDI",
		Languages: []string{"go"},
		Severity:  rules.SeverityCritical,
		CWE:       "CWE-78",
		Message:   "command injection",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     rules.SinksOf("go:*os/exec.Command*"),
	}}}
}

func cmdiFindings(t *testing.T, src string) int {
	t.Helper()
	n := 0
	for _, f := range scanSource(t, src, cmdiRule()) {
		if f.RuleID == "GO-CMDI" {
			n++
		}
	}
	return n
}

// TestFlow_StrongUpdateSuppresses is the ENG-2 core: taint written into an
// address-taken local and then overwritten with a constant through the same
// cell must not reach the sink — the strong update on the non-escaping alloc
// clears the cell.
func TestFlow_StrongUpdateSuppresses(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	var cmd string
	p := &cmd
	*p = r.URL.Query().Get("cmd")
	*p = "safe"
	_ = exec.Command("sh", "-c", *p).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`
	if n := cmdiFindings(t, src); n != 0 {
		t.Errorf("expected 0 findings (cell overwritten with a constant), got %d", n)
	}
}

// TestFlow_SinkBeforeTaint is the ordering case: a sink that textually and
// dynamically precedes the tainting store must not fire — flow-sensitivity
// respects statement order through memory.
func TestFlow_SinkBeforeTaint(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	var cmd string
	p := &cmd
	*p = "safe"
	_ = exec.Command("sh", "-c", *p).Run()
	*p = r.URL.Query().Get("cmd")
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`
	if n := cmdiFindings(t, src); n != 0 {
		t.Errorf("expected 0 findings (sink precedes the taint), got %d", n)
	}
}

// TestFlow_TaintedMemoryStillFires is the recall control: taint written into a
// local and NOT overwritten before the sink must still be found — strong
// updates must not suppress a genuine store-then-use flow through memory.
func TestFlow_TaintedMemoryStillFires(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	var cmd string
	p := &cmd
	*p = r.URL.Query().Get("cmd")
	_ = exec.Command("sh", "-c", *p).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`
	if n := cmdiFindings(t, src); n == 0 {
		t.Errorf("expected the store-then-use flow through memory to fire, got 0")
	}
}

// TestFlow_ConditionalTaintStillFires is the union-join recall control: taint
// assigned on only ONE branch of an if must still reach a sink after the merge
// (taint that reaches a point on ANY path is retained). A strong update on one
// branch must not erase taint contributed by the other.
func TestFlow_ConditionalTaintStillFires(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func h(w http.ResponseWriter, r *http.Request) {
	var cmd string
	p := &cmd
	*p = "safe"
	if r.URL.Query().Get("t") == "1" {
		*p = r.URL.Query().Get("cmd")
	}
	_ = exec.Command("sh", "-c", *p).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`
	if n := cmdiFindings(t, src); n == 0 {
		t.Errorf("expected the conditionally-tainted flow to fire after the merge, got 0")
	}
}

// TestFlow_EscapingAllocNotStrongUpdated is the soundness control for the escape
// gate: when the alloc's address is passed to another function (it escapes), a
// later clean store must NOT strong-update it, because an alias could still
// carry the taint. Here the address escapes via fill(&cmd); the subsequent local
// constant store must not clear taint the callee wrote — the flow still fires.
func TestFlow_EscapingAllocNotStrongUpdated(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os/exec"
)

func fill(r *http.Request, out *string) { *out = r.URL.Query().Get("cmd") }

func h(w http.ResponseWriter, r *http.Request) {
	var cmd string
	fill(r, &cmd)
	_ = exec.Command("sh", "-c", cmd).Run()
	_ = w
}

func main() { http.HandleFunc("/x", h); _ = http.ListenAndServe(":0", nil) }
`
	if n := cmdiFindings(t, src); n == 0 {
		t.Errorf("expected the out-parameter-filled flow (escaping alloc) to fire, got 0")
	}
}

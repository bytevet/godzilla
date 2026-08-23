package go_converter

import (
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// selectRoots' priority order is not directly observable (both results come back
// sorted by path so Phase B's roots are deterministic), so it is pinned through
// the cut: a budget that admits exactly N candidates must admit the N highest
// priority ones.
func TestSelectRootsPriorityOrder(t *testing.T) {
	// Priority: depth 0 before depth 1; within a depth, smaller first; equal
	// depth AND size fall back to the path.
	cands := []rootCost{
		{path: "far/small", bytes: 10, depth: 1},
		{path: "near/big", bytes: 100, depth: 0},
		{path: "near/small", bytes: 10, depth: 0},
		{path: "near/tie-b", bytes: 10, depth: 0},
		{path: "near/tie-a", bytes: 10, depth: 0},
	}
	tests := []struct {
		limit int64
		keep  []string
	}{
		{limit: 10, keep: []string{"near/small"}},
		{limit: 20, keep: []string{"near/small", "near/tie-a"}},
		{limit: 30, keep: []string{"near/small", "near/tie-a", "near/tie-b"}},
		{limit: 130, keep: []string{"near/big", "near/small", "near/tie-a", "near/tie-b"}},
		{limit: 140, keep: []string{"far/small", "near/big", "near/small", "near/tie-a", "near/tie-b"}},
	}
	for _, tc := range tests {
		keep, dropped := selectRoots(cands, tc.limit)
		if !reflect.DeepEqual(keep, tc.keep) {
			t.Errorf("limit %d: keep = %v, want %v", tc.limit, keep, tc.keep)
		}
		if len(keep)+len(dropped) != len(cands) {
			t.Errorf("limit %d: %d kept + %d dropped != %d candidates", tc.limit, len(keep), len(dropped), len(cands))
		}
	}
}

// A candidate that brings the running total to EXACTLY the limit fits; the next
// one does not. An off-by-one here silently changes which packages a scan loads.
func TestSelectRootsAtLimitBoundary(t *testing.T) {
	cands := []rootCost{
		{path: "a", bytes: 60, depth: 0},
		{path: "b", bytes: 40, depth: 0},
		{path: "c", bytes: 1, depth: 1},
	}
	keep, dropped := selectRoots(cands, 100)
	if !reflect.DeepEqual(keep, []string{"a", "b"}) {
		t.Errorf("keep = %v, want [a b] (the pair summing to exactly the limit)", keep)
	}
	if !reflect.DeepEqual(dropped, []string{"c"}) {
		t.Errorf("dropped = %v, want [c]", dropped)
	}
}

func TestSelectRootsUnlimitedAndZero(t *testing.T) {
	cands := []rootCost{
		{path: "a", bytes: 5, depth: 0},
		{path: "b", bytes: 0, depth: 0}, // unmeasurable: must not survive a zero budget
	}
	keep, dropped := selectRoots(cands, -1)
	if !reflect.DeepEqual(keep, []string{"a", "b"}) || dropped != nil {
		t.Errorf("limit -1: keep = %v, dropped = %v, want all kept and nothing dropped", keep, dropped)
	}
	keep, dropped = selectRoots(cands, 0)
	if keep != nil || !reflect.DeepEqual(dropped, []string{"a", "b"}) {
		t.Errorf("limit 0: keep = %v, dropped = %v, want nothing kept", keep, dropped)
	}
}

// The scan must be byte-identical across runs, so the selection may not depend on
// map/slice arrival order.
func TestSelectRootsDeterministic(t *testing.T) {
	cands := make([]rootCost, 0, 40)
	for i := range 40 {
		cands = append(cands, rootCost{
			path:  string(rune('a'+i%7)) + "/pkg" + string(rune('0'+i%10)),
			bytes: int64(10 * (i % 5)),
			depth: i % 3,
		})
	}
	wantKeep, wantDropped := selectRoots(cands, 300)
	rng := rand.New(rand.NewSource(1))
	for range 20 {
		shuffled := make([]rootCost, len(cands))
		copy(shuffled, cands)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		keep, dropped := selectRoots(shuffled, 300)
		if !reflect.DeepEqual(keep, wantKeep) || !reflect.DeepEqual(dropped, wantDropped) {
			t.Fatalf("shuffled input changed the selection:\n keep %v\n want %v\n dropped %v\n want %v",
				keep, wantKeep, dropped, wantDropped)
		}
	}
}

// End to end: a zero budget must degrade, not fail. The dependency's bodies are
// gone from the lowered program, but the user code that calls it still lowers
// with the callee NAMED — export data still resolves types and method sets, so
// rules that model a third-party sink by FQN keep matching.
func TestConvertFile_DepBudgetDegrades(t *testing.T) {
	const dep = "example.com/util"

	lowered := func(budget int64) (*ir.Program, *Converter) {
		t.Helper()
		conv := NewConverter().SetDepBudget(budget)
		prog, err := conv.ConvertFile("../../test/go/dep_transit")
		if err != nil {
			t.Fatalf("budget %d: ConvertFile failed: %v", budget, err)
		}
		return prog, conv
	}
	hasModule := func(prog *ir.Program, name string) bool {
		for _, m := range prog.Modules {
			if m.Name == name {
				return true
			}
		}
		return false
	}
	callsDep := func(prog *ir.Program) bool {
		for _, m := range prog.Modules {
			for _, f := range m.Functions {
				for _, b := range f.Blocks {
					for _, inst := range b.Instrs {
						if inst.Call != nil && strings.Contains(inst.Call.Callee, dep+".Transform") {
							return true
						}
					}
				}
			}
		}
		return false
	}

	full, conv := lowered(-1)
	if deg, note := conv.Degraded(); deg {
		t.Errorf("unlimited budget reported degraded with note %q", note)
	}
	if !hasModule(full, dep) {
		t.Fatalf("unlimited budget did not lower the dependency %s; the test sample no longer exercises the budget", dep)
	}

	cut, conv := lowered(0)
	deg, note := conv.Degraded()
	if !deg || note == "" {
		t.Errorf("zero budget: Degraded() = %v, %q; want true and a note", deg, note)
	}
	if hasModule(cut, dep) {
		t.Errorf("zero budget still lowered %s; it was not dropped from the Phase-B roots", dep)
	}
	if !callsDep(cut) {
		t.Error("zero budget lost the callee name at the call into the dropped dependency")
	}
}

// A dropped package that imports a KEPT one is the case the two-module sample
// cannot produce, and it is the one that crashed: go/packages must load such a
// package from source (its dependency needs source), but type-checks it with
// IgnoreFuncBodies because it is not a root — so its syntax is present and its
// TypesInfo has nothing for anything inside a body. Handing that pair to the SSA
// builder panics in objectOf, or dereferences a nil types.Object in
// packageLevelMember. The fixture is a temp module tree because it takes three
// modules to arrange, and test/go samples are asserted scan cases.
func TestConvertFile_DepBudgetDropsPackageImportingAKeptRoot(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module tmpmod\n\ngo 1.21\n\nrequire (\n\texample.com/small v0.0.0\n\texample.com/heavy v0.0.0\n)\n\nreplace example.com/small => ./small\n\nreplace example.com/heavy => ./heavy\n")
	writeFile("main.go", `package main

import (
	"net/http"
	"os/exec"

	"example.com/heavy"
	"example.com/small"
)

func handler(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", heavy.Do(small.Tag(r.FormValue("cmd")))).Run()
}

func main() { http.HandleFunc("/", handler) }
`)
	writeFile("small/go.mod", "module example.com/small\n\ngo 1.21\n")
	writeFile("small/small.go", "package small\n\nfunc Tag(s string) string { return s + \"!\" }\n")
	writeFile("heavy/go.mod", "module example.com/heavy\n\ngo 1.21\n\nrequire example.com/small v0.0.0\n\nreplace example.com/small => ../small\n")
	// heavy imports the KEPT package, and its body reads a package-level var and
	// defines a local — the two idents the builder resolves through TypesInfo.
	// The padding only has to make heavy the larger of the two candidates.
	writeFile("heavy/heavy.go", `package heavy

import "example.com/small"

var prefix = "run "

func Do(s string) string {
	out := prefix + small.Tag(s)
	return out
}

`+"// "+strings.Repeat("pad ", 2000)+"\n")

	conv := NewConverter().SetDepBudget(4096) // fits small (~60B), not heavy (~8KB)
	prog, err := conv.ConvertFile(dir)
	if err != nil {
		t.Fatalf("ConvertFile failed: %v", err)
	}
	deg, note := conv.Degraded()
	if !deg {
		t.Fatalf("nothing was dropped (note %q); the fixture no longer separates the two dependencies", note)
	}

	var haveSmall, haveHeavy, smallHasBody bool
	for _, m := range prog.Modules {
		switch m.Name {
		case "example.com/small":
			haveSmall = true
			for _, f := range m.Functions {
				if f.GetObjectName() == "Tag" && len(f.Blocks) > 0 {
					smallHasBody = true
				}
			}
		case "example.com/heavy":
			haveHeavy = true
		}
	}
	if !haveSmall || !smallHasBody {
		t.Errorf("the kept dependency lost its body (present=%v, body=%v); a package the walk reached first was created bodyless", haveSmall, smallHasBody)
	}
	if haveHeavy {
		t.Error("the dropped dependency was still lowered")
	}
}

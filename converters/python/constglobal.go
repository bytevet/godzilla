package py_converter

import (
	"strings"

	ir "godzilla/pkg/ir/v1"
)

// Module-level string constants are INLINED at their use sites (see
// funcState.lookupName), rather than lowered as a GlobalName the engine cannot
// read.
//
// The motivating shape is the commonest URL idiom in Python:
//
//	BASE = "https://api.internal.example.com"
//	requests.get(BASE + "/" + user_input)
//
// The engine's SSRF host check (internal/analysis/ssrf.go) proves a host is
// FIXED by reconstructing the URL's constant prefix. A GlobalName operand has no
// readable text, so the prefix came back empty, the host read as attacker-
// controllable, and every such call reported CWE-918. Inlining the literal makes
// the prefix visible and the finding correctly suppressed — and it does so for
// every constant consumer at once (format templates, dangerous-call guards),
// with no engine change.
//
// # Why this is allowed to be wrong only in one direction
//
// Folding a value that is NOT actually constant would suppress a REAL finding —
// a false negative on an exploitable SSRF, which is the one outcome ssrf.go's
// contract forbids. So constStringGlobals proves immutability for the whole
// module before folding anything, and gives up entirely the moment it might be
// looking at an incomplete picture:
//
//   - the name must be bound EXACTLY ONCE across the module, by a top-level
//     assignment whose value is a string literal;
//   - a module containing any construct that can rebind or unbind a name
//     WITHOUT the walker seeing it folds nothing at all (see unseenBindingKind).
//
// Both directions of failure are safe: a missed fold leaves the finding firing,
// exactly as before this file existed.

// pyastKinds is every node kind pyast.py emits structurally. A kind outside this
// set is a statement pyast.py did not lower (conv_stmt falls back to a bare
// {"kind": <PythonClassName>}), so its children — including any name it binds —
// are invisible here.
var pyastKinds = map[string]bool{
	"Module": true, "FunctionDef": true, "ClassDef": true, "Assign": true,
	"AugAssign": true, "ExprStmt": true, "Return": true, "If": true, "For": true,
	"While": true, "With": true, "Try": true, "Import": true, "ImportFrom": true,
	"Constant": true, "Name": true, "Attribute": true, "Subscript": true,
	"Call": true, "BinOp": true, "UnaryOp": true, "BoolOp": true, "Compare": true,
	"IfExp": true, "NamedExpr": true, "Comprehension": true, "JoinedStr": true,
	"FormattedValue": true, "Await": true, "Sequence": true, "Starred": true,
}

// "Unknown" is deliberately ABSENT above. pyast.py emits it for any node it does
// not lower, carrying only kind/pos/note -- the children, and therefore any name
// bound inside, are gone. A module containing one (a lambda, a `match`) folds
// nothing rather than risk folding a name that construct rebinds.

// inertUnloweredKinds are unlowered statements that cannot bind, rebind or
// delete a name, so their presence does not compromise the walk. Everything else
// outside pyastKinds does — `global`/`nonlocal` (declares intent to write),
// AnnAssign (`X: str = …`), Delete (`del X`) and Match (pattern bindings) all
// arrive as kind-only nodes whose targets cannot be inspected.
//
// Listing the SAFE kinds rather than the dangerous ones is deliberate: if
// pyast.py later emits a new binding form, it lands outside both sets and
// folding switches itself off, instead of silently mis-folding.
var inertUnloweredKinds = map[string]bool{
	"Pass": true, "Break": true, "Continue": true, "Raise": true, "Assert": true,
}

// constStringGlobals returns the module-level names that are provably bound
// exactly once, to a string literal, mapped to that literal. Returns nil if the
// module contains anything that could hide a rebinding.
func constStringGlobals(root astNode) map[string]*ir.Constant {
	cand := map[string]*ir.Constant{}
	for _, s := range root.list("body") {
		if s.kind() != "Assign" {
			continue
		}
		val := s.node("value")
		if val.kind() != "Constant" || val.str("value_type") != "str" {
			continue
		}
		c := constantValue(val).GetConstant()
		if c == nil {
			continue
		}
		for _, t := range s.list("targets") {
			if t.kind() == "Name" {
				cand[t.str("id")] = c
			}
		}
	}
	if len(cand) == 0 {
		return nil
	}
	binds := map[string]int{}
	if !countBindings(root, binds) {
		return nil // an unseen binding construct: fold nothing in this module
	}
	for name := range cand {
		if binds[name] != 1 {
			delete(cand, name) // rebound, shadowed, or bound by an unclear form
		}
	}
	if len(cand) == 0 {
		return nil
	}
	return cand
}

// countBindings walks the whole module tallying every name-binding occurrence,
// returning false if it meets a kind whose bindings it cannot see.
func countBindings(n astNode, binds map[string]int) bool {
	if n == nil {
		return true
	}
	kind := n.kind()
	// pyast.py also emits keyless STRUCTURAL dicts -- a `with` item, a `try`
	// handler, a comprehension generator clause. They carry no kind because they
	// are containers, not nodes; recurse without the kind check (their bindings
	// are picked up by the owning statement's case below).
	if kind == "" {
		return walkChildren(n, binds)
	}
	if !pyastKinds[kind] {
		return inertUnloweredKinds[kind] // unlowered: safe only if it cannot bind
	}
	switch kind {
	case "Assign":
		for _, t := range n.list("targets") {
			bindTarget(t, binds)
		}
	case "AugAssign", "For", "NamedExpr":
		bindTarget(n.node("target"), binds)
	case "FunctionDef", "ClassDef":
		binds[n.str("name")]++
		for _, p := range n.strList("params") {
			binds[p]++
		}
	case "Import", "ImportFrom":
		// names are {"name","asname"} objects; the bound name is the asname when
		// present, else the first dotted component (`import a.b` binds `a`).
		for _, a := range n.list("names") {
			if as := a.str("asname"); as != "" {
				binds[as]++
				continue
			}
			name := a.str("name")
			if i := strings.Index(name, "."); i >= 0 {
				name = name[:i]
			}
			binds[name]++
		}
	case "With":
		for _, it := range n.list("items") {
			bindTarget(it.node("vars"), binds)
		}
	case "Try":
		for _, h := range n.list("handlers") {
			if name := h.str("name"); name != "" {
				binds[name]++ // `except E as name`
			}
		}
	case "Comprehension":
		for _, g := range n.list("generators") {
			bindTarget(g.node("target"), binds)
		}
	}
	return walkChildren(n, binds)
}

// bindTarget records the names an assignment target binds, following tuple /
// list destructuring and starred elements. An Attribute or Subscript target
// (`obj.f = …`, `d[k] = …`) rebinds no NAME, so it contributes nothing.
func bindTarget(t astNode, binds map[string]int) {
	if t == nil {
		return
	}
	switch t.kind() {
	case "Name":
		binds[t.str("id")]++
	case "Sequence":
		for _, e := range t.list("elts") {
			bindTarget(e, binds)
		}
	case "Starred":
		bindTarget(t.node("value"), binds)
	}
}

// walkChildren recurses into every nested node, whatever key holds it, so a
// construct this file does not name explicitly is still traversed (and its own
// kind checked) rather than skipped.
func walkChildren(n astNode, binds map[string]int) bool {
	for k, v := range n {
		// "pos" is a coordinate object on EVERY node -- by far the most numerous
		// map in the tree and never a container for a binding. Skipping it by name
		// is what keeps this whole-module walk off the scan's critical path.
		if k == "pos" || k == "kind" {
			continue
		}
		if !walkAny(v, binds) {
			return false
		}
	}
	return true
}

func walkAny(v any, binds map[string]int) bool {
	switch t := v.(type) {
	case map[string]any:
		return countBindings(astNode(t), binds)
	case []any:
		for _, e := range t {
			if !walkAny(e, binds) {
				return false
			}
		}
	}
	return true
}

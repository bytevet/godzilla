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
//     WITHOUT the walker seeing it folds nothing at all (see bindingSafeKinds).
//
// Both directions of failure are safe: a missed fold leaves the finding firing,
// exactly as before this file existed.
//
// The PROOF has to live here because Python's rebinding forms (`global`, `del`,
// `match`, lambda) leave no trace in gIR at all, so the engine cannot answer the
// question. The GAP it closes is not Python's, though: a constant-valued global
// is unreadable to every constant-consuming analysis in every language (Go
// package `var`, Java `static final`, JS module `const`). A second language
// wanting this should lift the CONTRACT -- frontend proves const, engine
// resolves a GlobalName through Module.Globals -- rather than copy this file.

// bindingSafeKinds is every node kind this walker can traverse without risking a
// missed binding. Two groups, one rule:
//
//   - the kinds pyast.py emits STRUCTURALLY, whose children are all present, so
//     recursing into them sees every name they bind;
//   - the unlowered statements that cannot bind, rebind or delete a name at all
//     (Pass/Break/Continue/Raise/Assert). pyast.py's conv_stmt renders these as a
//     bare {"kind": <PythonClassName>, "pos": p}, so there is nothing to recurse
//     into and nothing to miss.
//
// Anything else -- `global`, `nonlocal`, AnnAssign, Delete, Match, and the
// catch-all "Unknown" -- arrives as a kind-only node whose targets cannot be
// inspected, and aborts the walk.
//
// Listing the SAFE kinds rather than the dangerous ones is deliberate: if
// pyast.py later emits a new binding form, it lands outside this set and folding
// switches itself off, instead of silently mis-folding. The cost is that this is
// a second copy of pyast.py's emitted-kind vocabulary living in Go; it fails
// closed, so drift makes it conservative rather than wrong.
var bindingSafeKinds = map[string]bool{
	// structural
	"Module": true, "FunctionDef": true, "ClassDef": true, "Assign": true,
	"AugAssign": true, "ExprStmt": true, "Return": true, "If": true, "For": true,
	"While": true, "With": true, "Try": true, "Import": true, "ImportFrom": true,
	"Constant": true, "Name": true, "Attribute": true, "Subscript": true,
	"Call": true, "BinOp": true, "UnaryOp": true, "BoolOp": true, "Compare": true,
	"IfExp": true, "NamedExpr": true, "Comprehension": true, "JoinedStr": true,
	"FormattedValue": true, "Await": true, "Sequence": true, "Starred": true,
	// unlowered but inert
	"Pass": true, "Break": true, "Continue": true, "Raise": true, "Assert": true,
}

// eachModuleConstAssign calls fn for every top-level `NAME = <literal>` binding,
// with the bound name, the constant, and the value node (for its position).
//
// Two passes want this same shape and must not drift: convertModule turns them
// into gIR Globals so the secret scanner can see a hardcoded literal, and
// constStringGlobals takes the string-valued ones as fold candidates. The
// filtering differs -- Globals wants every constant type, folding only strings --
// so the predicate stays with each caller and only the traversal is shared.
func eachModuleConstAssign(root astNode, fn func(name string, c *ir.Constant, val astNode)) {
	for _, s := range root.list("body") {
		if s.kind() != "Assign" {
			continue
		}
		val := s.node("value")
		if val.kind() != "Constant" {
			continue
		}
		c := constantValue(val).GetConstant()
		if c == nil {
			continue
		}
		for _, t := range s.list("targets") {
			if t.kind() == "Name" {
				fn(t.str("id"), c, val)
			}
		}
	}
}

// constStringGlobals returns the module-level names that are provably bound
// exactly once, to a string literal, mapped to that literal. Returns nil if the
// module contains anything that could hide a rebinding.
func constStringGlobals(root astNode) map[string]*ir.Constant {
	cand := map[string]*ir.Constant{}
	eachModuleConstAssign(root, func(name string, c *ir.Constant, val astNode) {
		if val.str("value_type") == "str" {
			cand[name] = c
		}
	})
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
	if !bindingSafeKinds[kind] {
		return false // a kind whose bindings are invisible: abort the whole walk
	}
	// Constant and Name are the most numerous nodes in any AST and carry no child
	// node maps, so returning before walkChildren's range+type-switch is worth a
	// measured ~28% off this walk.
	if kind == "Constant" || kind == "Name" {
		return true
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

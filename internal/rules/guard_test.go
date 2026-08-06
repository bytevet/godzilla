package rules

import "testing"

func TestCompileGuardValid(t *testing.T) {
	for _, src := range []string{
		"arg[0].String startsWith 'cmd:'",
		"arg[0].String endsWith '.sh'",
		"arg[0].String contains '/ECB/'",
		"arg[0].Complete && arg[0].String == 'MD5'",
		"arg[0].String matches '(?i)^md5$'",
		"arg[0].String in ['DES', 'RC4']",
		"hasPrefix(arg[0].String, 'cmd:')",
		"arg[0].String startsWith 'cmd:' && arg[1].String contains 'x'",
		"arg[0].Type == 'string'",
	} {
		if g, err := CompileGuard(src); err != nil || g == nil {
			t.Errorf("CompileGuard(%q): err=%v guard=%v, want ok", src, err, g)
		}
	}
	if g, err := CompileGuard("  "); err != nil || g != nil {
		t.Errorf("CompileGuard(empty): want (nil,nil), got (%v,%v)", g, err)
	}
}

func TestCompileGuardInvalid(t *testing.T) {
	for name, src := range map[string]string{
		"syntax":     "arg[0].String startsWith",
		"unknown":    "nope(arg[0])",
		"non-bool":   "arg[0].String",
		"bad-regexp": "arg[0].String matches '('",
		"bad-field":  "arg[0].Nope == 'x'",
	} {
		if _, err := CompileGuard(src); err == nil {
			t.Errorf("CompileGuard(%s=%q): want error, got nil", name, src)
		}
	}
}

func TestGuardEval(t *testing.T) {
	partial := Arg{String: "cmd:" + DynMarker, Type: "string"}                  // "cmd:" + tainted
	full := Arg{String: "AES/ECB/PKCS5Padding", Complete: true, Type: "string"} // full constant
	dynamic := Arg{String: DynMarker}                                           // fully dynamic

	cases := []struct {
		src  string
		args []Arg
		want bool
	}{
		{"arg[0].String startsWith 'cmd:'", []Arg{partial}, true},                    // prefix confirmed on a partial constant
		{"arg[0].String startsWith 'log:'", []Arg{partial}, false},                   // wrong prefix
		{"arg[0].String startsWith 'cmd:'", []Arg{dynamic}, false},                   // dynamic -> suppress
		{"arg[0].String contains '/ECB/'", []Arg{full}, true},                        // full constant contains
		{"arg[0].String contains '/GCM/'", []Arg{full}, false},                       //
		{"arg[0].String == 'cmd:'", []Arg{partial}, false},                           // partial (has DynMarker) != the exact constant
		{"arg[0].String == 'AES/ECB/PKCS5Padding'", []Arg{full}, true},               //
		{"arg[0].Complete && arg[0].String contains '/ECB/'", []Arg{partial}, false}, // .Complete gates a partial
		{"arg[0].String matches '(?i)/ecb/'", []Arg{full}, true},                     //
		{"arg[0].String in ['DES', 'AES/ECB/PKCS5Padding']", []Arg{full}, true},      //
		{"arg[0].String startsWith 'cmd:'", []Arg{}, false},                          // out-of-range index -> suppress
	}
	for _, c := range cases {
		g, err := CompileGuard(c.src)
		if err != nil {
			t.Fatalf("CompileGuard(%q): %v", c.src, err)
		}
		if got := g.Eval(c.args); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.src, got, c.want)
		}
	}
	if !(*Guard)(nil).Eval(nil) {
		t.Error("nil guard should always fire")
	}
	if DenyGuard.Eval([]Arg{full}) {
		t.Error("DenyGuard must never fire")
	}
}

// TestGuardFailsClosed pins the safety property: a rule whose `when:` does not
// compile must SUPPRESS its entry, never degrade to an unguarded one that fires
// on everything. Compile reports the error and installs DenyGuard, so a RuleSet
// built in Go (bypassing the loader) is safe too.
func TestGuardFailsClosed(t *testing.T) {
	r := &Rule{
		ID:       "bad",
		Severity: SeverityHigh,
		Sinks:    []Sink{{Pattern: "go:*Sink", When: "nope(arg[0])"}},
	}
	err := r.Compile()
	if err == nil {
		t.Fatal("Compile() with an uncompilable guard: want error, got nil")
	}
	_, guard, ok := r.MatchSink("go:aSink")
	if !ok {
		t.Fatal("sink should still match structurally")
	}
	if guard.Eval([]Arg{{String: "anything", Complete: true}}) {
		t.Error("a guard that failed to compile must suppress, not fire")
	}

	// Without an explicit Compile the guard is compiled lazily on first match:
	// the same real guard, the same verdicts.
	u := &Rule{Sinks: []Sink{{Pattern: "go:*Sink", When: "arg[0].String startsWith 'x'"}}}
	if _, g, ok := u.MatchSink("go:aSink"); !ok || g == nil ||
		!g.Eval([]Arg{{String: "xyz", Complete: true}}) || g.Eval([]Arg{{String: "abc", Complete: true}}) {
		t.Error("lazily-compiled guarded sink must evaluate its real guard")
	}
}

// TestArgHostFixed pins the host-fixedness reading that SSRF and open-redirect
// rules suppress on. It moved here with the regex when the check left the engine:
// the prefix is the skeleton text before the first DynMarker, so a constant
// scheme://host followed by a separator confines any later taint to the
// path/query, while a bare scheme, a host that taint could still EXTEND, or a
// wholly dynamic value must all stay controllable.
func TestArgHostFixed(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"https://example.com/" + DynMarker, true},
		{"http://h:8080?" + DynMarker, true},
		{"https://example.com#" + DynMarker, true},
		{"https://" + DynMarker, false},            // no host yet
		{"https://example.com" + DynMarker, false}, // taint could extend the host
		{"//host/" + DynMarker, false},             // no scheme
		{DynMarker, false},                         // wholly dynamic / unrecoverable
		{"", false},
		{"https://example.com/static", true}, // fully constant
	} {
		if got := ArgHostFixed(Arg{String: c.in}); got != c.want {
			t.Errorf("ArgHostFixed(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// el builds a constant string Arg, and argvOf the in-place container a safe
// argv lowers to: a fixed program, then flags, then the untrusted element.
func el(s string) Arg { return Arg{String: s, Complete: true, Type: "string"} }

func argvOf(parts ...string) Arg {
	a := Arg{Type: "aggregate", Tainted: true, String: DynMarker, TaintInChildren: true}
	for _, p := range parts {
		a.Elems = append(a.Elems, el(p))
	}
	a.Elems = append(a.Elems, Arg{String: DynMarker, Tainted: true})
	return a
}

// shippedArgvPolicy is rulepacks/py-command-injection.yaml's `when:`. Both tests
// below evaluate THIS, so neither can drift from the other — an earlier copy in
// each had already diverged from the pack and from itself, and one of them
// documented the `!= "true"` polarity the shipped rule rejects as correct.
//
// Two clauses are load-bearing and are why it is not written the obvious way:
// `shell` is cleared by evidence of ABSENCE, never by `!= "true"` (a
// non-constant `shell=flag` reconstructs to neither, so the lazy form clears it
// and drops a real finding); and a non-tainted argument must carry a keyword we
// can NAME, because `shell=flag` records no name at all.
const shippedArgvPolicy = `not ((kwargs.shell.String == "" or kwargs.shell.String == "false") ` +
	`and all(filter(arg, not .Tainted), .Name != "") ` +
	`and any(arg, .Tainted) ` +
	`and all(filter(arg, .Tainted), ` +
	`len(.Elems) > 0 and .TaintInChildren and .Elems[0].Complete ` +
	`and not (.Elems[0].String matches "(^|/)(sh|bash|dash|zsh|ksh|csh|tcsh|fish|ash|busybox|env|xargs)$")))`

// TestGuardKWArgsAndTainted covers the two primitives a rule needs to express an
// argv-vs-shell policy in YAML instead of the engine deciding for it: `kwargs`
// (arguments indexed by the keyword they were passed under) and Arg.Tainted.
//
// The important case is a MISSING keyword. `kwargs.shell` on a call with no
// `shell=` must read as the zero Arg, NOT raise — a run error would suppress the
// entry (Eval returns false on error), turning an absent keyword into a silent
// false negative. This pins expr's map semantics so a dependency bump that
// changed them would fail here rather than quietly weakening the rule.
func TestGuardKWArgsAndTainted(t *testing.T) {
	argv := argvOf("ls")
	shellOn := []Arg{argv, {String: "true", Complete: true, Type: "bool", Name: "shell"}}
	shellOff := []Arg{argv}
	// `shell=flag` — non-constant, so it reconstructs to neither "" nor "false"
	// and the sink must keep firing.
	shellDyn := []Arg{argv, {String: DynMarker, Type: "bool", Name: "shell"}}
	// An extra positional argument we cannot name; it must keep the sink armed.
	unnamedExtra := []Arg{argv, {String: DynMarker, Type: "bool"}}
	// A tainted plain string, not a container: no argv structure to clear on.
	taintedStr := []Arg{{String: DynMarker, Tainted: true, Type: "string"}}
	cases := []struct {
		name string
		src  string
		args []Arg
		want bool
	}{
		{"missing keyword reads as zero Arg", `kwargs.shell.String == "true"`, shellOff, false},
		{"present keyword is readable", `kwargs.shell.String == "true"`, shellOn, true},
		{"membership on a missing keyword", `"shell" in kwargs`, shellOff, false},
		{"positional args are not indexed", `"" in kwargs`, taintedStr, false},
		{"argv policy: safe list suppresses", shippedArgvPolicy, shellOff, false},
		{"argv policy: shell=True re-arms", shippedArgvPolicy, shellOn, true},
		{"argv policy: tainted string fires", shippedArgvPolicy, taintedStr, true},
		{"argv policy: no taint at all fires", shippedArgvPolicy, []Arg{{String: "ls", Complete: true}}, true},
		{"argv policy: non-constant shell= re-arms", shippedArgvPolicy, shellDyn, true},
		{"argv policy: unnameable extra arg re-arms", shippedArgvPolicy, unnamedExtra, true},
	}
	for _, tc := range cases {
		g, err := CompileGuard(tc.src)
		if err != nil {
			t.Fatalf("%s: CompileGuard(%q): %v", tc.name, tc.src, err)
		}
		if got := g.Eval(tc.args); got != tc.want {
			t.Errorf("%s: Eval(%q) = %v, want %v", tc.name, tc.src, got, tc.want)
		}
	}
}

// TestGuardArgStructure covers the container structure a guard reads back:
// Elems for an ordered container, Entries for a keyed one, and — the case that
// matters most — what happens when the structure is ABSENT because the engine
// declined to reconstruct it (too deep, too wide, or an untrustworthy shape).
//
// Absent structure must FAIL OPEN. A rule suppresses only on positive evidence,
// so an unreconstructed container reads as "unknown" and the finding still
// fires; the alternative would turn a depth limit into a silent false negative.
func TestGuardArgStructure(t *testing.T) {
	safeArgv := argvOf("ls", "-la")
	shellArgv := argvOf("sh", "-c")
	absArgv := argvOf("/bin/bash", "-c")
	// A container the engine did not reconstruct: correct Type, no Elems.
	opaque := Arg{Type: "aggregate", Tainted: true, String: DynMarker}
	keyed := Arg{Type: "map", Tainted: true, String: DynMarker,
		Entries: map[string]Arg{"mode": el("raw")}}

	cases := []struct {
		name string
		src  string
		args []Arg
		want bool
	}{
		{"elements are addressable", `arg[0].Elems[1].String == "-la"`, []Arg{safeArgv}, true},
		{"entries are addressable by key", `arg[0].Entries.mode.String == "raw"`, []Arg{keyed}, true},
		{"missing entry reads as zero Arg", `arg[0].Entries.nope.String == "raw"`, []Arg{keyed}, false},
		{"policy: safe argv suppresses", shippedArgvPolicy, []Arg{safeArgv}, false},
		{"policy: shell argv[0] fires", shippedArgvPolicy, []Arg{shellArgv}, true},
		{"policy: absolute shell path fires", shippedArgvPolicy, []Arg{absArgv}, true},
		{"policy: unreconstructed container fires", shippedArgvPolicy, []Arg{opaque}, true},
		{"policy: keyed container is not argv, fires", shippedArgvPolicy, []Arg{keyed}, true},
	}
	for _, tc := range cases {
		g, err := CompileGuard(tc.src)
		if err != nil {
			t.Fatalf("%s: CompileGuard(%q): %v", tc.name, tc.src, err)
		}
		if got := g.Eval(tc.args); got != tc.want {
			t.Errorf("%s: Eval = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestGuardTaintInChildren pins the distinction between "this value carries
// taint" and "reading its children will find that taint". They differ whenever
// the taint did not come from a reconstructed element: a container mutated after
// construction, a non-constant key, a value built elsewhere, or a container the
// engine declined to expand.
//
// The polarity is the point. TaintInChildren's zero value is "not accounted
// for", so a rule that reasons element-by-element declines a value it cannot see
// into. Were the field inverted, an Arg built without setting it would read as
// "taint is localized" and let a rule clear a finding silently.
func TestGuardTaintInChildren(t *testing.T) {
	el := func(s string) Arg { return Arg{String: s, Complete: true, Type: "string"} }
	tainted := Arg{String: DynMarker, Tainted: true}

	visible := Arg{Type: "aggregate", Tainted: true, TaintInChildren: true,
		Elems: []Arg{el("ls"), tainted}}
	// Tainted, but the taint is not in any child: `d = {}` then `d[k] = tainted`.
	mutated := Arg{Type: "map", Tainted: true}
	// A container the budget declined to expand: correct Type, no children.
	unexpanded := Arg{Type: "aggregate", Tainted: true}
	// A field nobody populated — the zero value must read as "not accounted for".
	zeroValue := Arg{Type: "aggregate", Tainted: true, Elems: []Arg{el("ls"), tainted}}

	cases := []struct {
		name string
		src  string
		args []Arg
		want bool
	}{
		{"taint reachable through children", `arg[0].TaintInChildren`, []Arg{visible}, true},
		{"tainted but mutated after build", `arg[0].TaintInChildren`, []Arg{mutated}, false},
		{"tainted is still true there", `arg[0].Tainted`, []Arg{mutated}, true},
		{"policy: visible taint suppresses", shippedArgvPolicy, []Arg{visible}, false},
		{"policy: mutated container fires", shippedArgvPolicy, []Arg{mutated}, true},
		{"policy: unexpanded container fires", shippedArgvPolicy, []Arg{unexpanded}, true},
		{"policy: unset field fires (fail open)", shippedArgvPolicy, []Arg{zeroValue}, true},
	}
	for _, tc := range cases {
		g, err := CompileGuard(tc.src)
		if err != nil {
			t.Fatalf("%s: CompileGuard(%q): %v", tc.name, tc.src, err)
		}
		if got := g.Eval(tc.args); got != tc.want {
			t.Errorf("%s: Eval = %v, want %v", tc.name, got, tc.want)
		}
	}
}

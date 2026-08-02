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

	// Same on the uncompiled fallback path (Compile never called).
	u := &Rule{Sinks: []Sink{{Pattern: "go:*Sink", When: "arg[0].String startsWith 'x'"}}}
	if _, g, ok := u.MatchSink("go:aSink"); !ok || g.Eval([]Arg{{String: "xyz", Complete: true}}) {
		t.Error("uncompiled guarded sink must deny, not fire unguarded")
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
	shellOn := []Arg{
		{String: DynMarker, Tainted: true, Type: "aggregate"},
		{String: "true", Complete: true, Type: "bool", Name: "shell"},
	}
	shellOff := []Arg{
		{String: DynMarker, Tainted: true, Type: "aggregate"},
	}
	taintedStr := []Arg{
		{String: DynMarker, Tainted: true, Type: "string"},
	}
	// The real py-command-injection guard: fire unless no shell was requested
	// AND every tainted argument arrived as an in-place container.
	const argvPolicy = `not (kwargs.shell.String != "true" ` +
		`and len(filter(arg, .Tainted)) > 0 ` +
		`and all(filter(arg, .Tainted), .Type == "aggregate"))`

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
		{"argv policy: safe list suppresses", argvPolicy, shellOff, false},
		{"argv policy: shell=True re-arms", argvPolicy, shellOn, true},
		{"argv policy: tainted string fires", argvPolicy, taintedStr, true},
		{"argv policy: no taint at all fires", argvPolicy, []Arg{{String: "ls", Complete: true}}, true},
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

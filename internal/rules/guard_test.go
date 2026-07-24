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
}

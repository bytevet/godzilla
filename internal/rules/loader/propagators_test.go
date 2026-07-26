package loader

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultPropagatorsFragment pins the set-wide propagators end to end: that
// `_default-propagators.yaml` is loaded into RuleSet.DefaultPropagators (rather
// than needing an `extend:` from each pack), and that after Compile EVERY rule
// answers IsPropagator for them on top of its own list. It lives in the loader
// package, not internal/rules, so it exercises the real embedded YAML — a rule
// built by hand in a rules-package test would silently have no defaults at all.
func TestDefaultPropagatorsFragment(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if len(rs.DefaultPropagators) == 0 {
		t.Fatal("no DefaultPropagators loaded from _default-propagators.yaml")
	}
	if err := rs.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	shouldMatch := []string{
		"go:strings.TrimSpace",
		"go:strings.ToLower",
		"go:fmt.Sprintf",
		"go:net/url.QueryEscape",
		"py:request.args.get.strip", // py:*.strip
		"py:x.lower",
		"js:req.query.id.trim",  // js:*.trim
		"js:s.toLowerCase",      // js:*.toLowerCase
		"js:encodeURIComponent", // js:*encodeURIComponent
		"java:java/lang/String.trim",
		"java:java/lang/StringBuilder.append",
		"rust:*String::to_lowercase",
		"rust:str::trim",
		// Go net/http + net/url request accessors (canonical format is pkg-inside
		// parens, e.g. "go:(*net/url.URL).Query" — see rule.go / converter.go).
		// These carry request taint through a lowered framework's stdlib parsing.
		"go:(*net/url.URL).Query",          // *url.URL -> url.Values (the gin path)
		"go:net/url.ParseQuery",            // string -> url.Values
		"go:net/url.Parse",                 // string -> *url.URL (minio CVE-2022-35919)
		"go:net/url.ParseRequestURI",       // string -> *url.URL
		"go:(net/url.Values).Get",          // url.Values -> string
		"go:(*net/http.Request).FormValue", // *http.Request -> string
		"go:(*net/http.Request).Cookie",    // *http.Request -> *http.Cookie
		"go:(net/http.Header).Get",         // http.Header -> string
	}
	shouldNotMatch := []string{
		"go:os/exec.Command",          // a sink, must not propagate by default
		"go:(*database/sql.DB).Query", // a sink — the net/url*.Query glob must not leak onto it
		"py:os.system",                // a sink
		"js:child_process.exec",       // a sink
		"go:strings.Contains",         // returns bool, not a taint carrier we list
	}

	// Assert through an arbitrary rule: the defaults apply to all of them, and a
	// rule's own propagator list must not be what satisfies these.
	r := &rs.Rules[0]
	for _, c := range shouldMatch {
		if !r.IsPropagator(c) {
			t.Errorf("rule %q: expected %q to be a default propagator", r.ID, c)
		}
	}
	for _, c := range shouldNotMatch {
		if r.IsPropagator(c) {
			t.Errorf("rule %q: did not expect %q to be a default propagator", r.ID, c)
		}
	}
}

// TestDefaultPropagatorsUserOverride checks that a user rules directory shipping
// its own _default-propagators.yaml replaces the built-in list rather than being
// ignored or merged — the documented escape hatch for a project whose stdlib
// wrappers differ.
func TestDefaultPropagatorsUserOverride(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("_default-propagators.yaml", "propagators:\n  - \"go:*mycorp.Normalize\"\n")
	write("r.yaml", "rules:\n  - id: r\n    severity: high\n    sinks: [\"go:*Sink\"]\n")

	rs, err := LoadFile(filepath.Join(dir, "r.yaml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := rs.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	r := &rs.Rules[0]
	if !r.IsPropagator("go:mycorp.Normalize") {
		t.Error("user _default-propagators.yaml was not applied")
	}
	if r.IsPropagator("go:strings.TrimSpace") {
		t.Error("user _default-propagators.yaml should REPLACE the built-in list, not extend it")
	}
}

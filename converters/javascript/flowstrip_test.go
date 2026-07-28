package js_converter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripFlowOffsets(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"maybe param", "function f(x: ?string) { return x; }", "function f(x         ) { return x; }"},
		{"indexer", "function f(o: {[string]: mixed}) { return o; }", "function f(o                   ) { return o; }"},
		{"opaque", "opaque type ID = string;", "                        "},
		{"type alias body", "type O = { a?: ?string };", "                        ;"},
		{"return type", "function f(): ?string { return null; }", "function f()          { return null; }"},
		{"const decl", "const a: ?T = g();", "const a     = g();"},
		// value code that MUST survive untouched
		{"ternary", "const a = c ? x : y;", "const a = c ? x : y;"},
		{"object literal", "const o = { a: 1, b: 2 };", "const o = { a: 1, b: 2 };"},
		{"nested ternary in call", "f(c ? 1 : 2, d);", "f(c ? 1 : 2, d);"},
		{"label", "outer: for (;;) { break outer; }", "outer: for (;;) { break outer; }"},
		{"switch case", "switch (x) { case 1: break; }", "switch (x) { case 1: break; }"},
		{"string with colon", "const u = 'http://x';", "const u = 'http://x';"},
		{"template with colon", "const u = `a:${b}`;", "const u = `a:${b}`;"},
		{"object arg in call", "f({ a: 1 });", "f({ a: 1 });"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A refusal returns the source unchanged, which is exactly what the
			// value-only cases below want, so ok is not asserted -- only that the
			// OUTPUT is right. Refusing to strip is always safe; the file then fails
			// to parse and is dropped, as it is today.
			got, _ := stripFlow(tc.in)
			if len(got) != len(tc.in) {
				t.Fatalf("length changed %d -> %d (offsets broken)", len(tc.in), len(got))
			}
			for k := range tc.in {
				if (tc.in[k] == '\n') != (got[k] == '\n') {
					t.Fatalf("newline moved at offset %d (line numbering broken)", k)
				}
			}
			if got != tc.want {
				t.Errorf("\n in:   %q\n got:  %q\n want: %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripFlowPreservesSinkPosition is the load-bearing test for the whole
// approach. Blanking is only correct if a lowered instruction still reports the
// line and column it occupies in the ORIGINAL file: positions are mandatory
// (CLAUDE.md), esbuild's sourcemap resolves against the buffer it was handed, and
// nothing in this repo can compose two maps. If the stripper ever shifted a byte,
// every finding in a Flow file would be reported at the wrong place -- and the
// dialect tests would not notice, since they only assert a module converts.
func TestStripFlowPreservesSinkPosition(t *testing.T) {
	// exec is on line 8, at column 3 (1-based), after two Flow-only annotations
	// on earlier lines that must not move it.
	src := `// @flow
opaque type Id = string;
type Opts = { [string]: mixed };

function run(cmd: ?string, o: Opts): ?string {
  const child = require('child_process');
  // the sink, whose position must survive the strip:
  child.exec(cmd);
  return cmd;
}
module.exports = { run };
`
	dir := t.TempDir()
	path := filepath.Join(dir, "flow_pos.js")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	mod, _, err := NewConverter().convertJSFile(path, "flowpos")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var got []string
	for _, f := range mod.GetFunctions() {
		for _, b := range f.GetBlocks() {
			for _, in := range b.GetInstrs() {
				if c := in.GetCall(); c != nil && strings.Contains(c.GetCallee(), "exec") {
					got = append(got, fmt.Sprintf("%d:%d", in.GetPos().GetLine(), in.GetPos().GetColumn()))
				}
			}
		}
	}
	if len(got) == 0 {
		t.Fatal("no exec call lowered from the Flow source")
	}
	if got[0] != "8:3" {
		t.Errorf("exec lowered at %s, want 8:3 — the strip shifted positions", got[0])
	}
}

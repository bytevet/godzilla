package js_converter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blankAll returns s with every non-newline byte replaced by a space, for the
// cases where a whole declaration is expected to disappear. Spelling those out by
// hand is how a want string ends up one space short of the input.
func blankAll(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c != '\n' && c != '\r' {
			b[i] = ' '
		}
	}
	return string(b)
}

// blankSpan returns s with the first occurrence of sub replaced by spaces, so a
// want string states WHICH span disappears instead of asserting a hand-counted
// run of spaces.
func blankSpans(s string, subs ...string) string {
	for _, sub := range subs {
		s = blankSpan(s, sub)
	}
	return s
}

func blankSpan(s, sub string) string {
	i := strings.Index(s, sub)
	if i < 0 {
		panic("blankSpan: " + sub + " not in " + s)
	}
	return s[:i] + blankAll(sub) + s[i+len(sub):]
}

func TestStripFlowOffsets(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"maybe param", "function f(x: ?string) { return x; }", blankSpan("function f(x: ?string) { return x; }", ": ?string")},
		{"indexer", "function f(o: {[string]: mixed}) { return o; }", blankSpan("function f(o: {[string]: mixed}) { return o; }", ": {[string]: mixed}")},
		{"opaque", "opaque type ID = string;", blankAll("opaque type ID = string;")},
		{"type alias body", "type O = { a?: ?string };", blankAll("type O = { a?: ?string };")},
		{"return type", "function f(): ?string { return null; }", blankSpan("function f(): ?string { return null; }", ": ?string")},
		{"const decl", "const a: ?T = g();", blankSpan("const a: ?T = g();", ": ?T")},
		// value code that MUST survive untouched
		{"ternary", "const a = c ? x : y;", "const a = c ? x : y;"},
		{"object literal", "const o = { a: 1, b: 2 };", "const o = { a: 1, b: 2 };"},
		{"nested ternary in call", "f(c ? 1 : 2, d);", "f(c ? 1 : 2, d);"},
		{"label", "outer: for (;;) { break outer; }", "outer: for (;;) { break outer; }"},
		{"switch case", "switch (x) { case 1: break; }", "switch (x) { case 1: break; }"},
		{"string with colon", "const u = 'http://x';", "const u = 'http://x';"},
		{"template with colon", "const u = `a:${b}`;", "const u = `a:${b}`;"},
		{"object arg in call", "f({ a: 1 });", "f({ a: 1 });"},
		// Constructs found by running the stripper over parse-server's whole src
		// tree; each one blocked a real file.
		{"export modifier", "export type T = { a: ?string };", blankAll("export type T = { a: ?string };")},
		{"declare export", "// @flow\ndeclare export type T = string;",
			"// @flow\n" + blankAll("declare export type T = string;")},
		{"multi-line union", "type T =\n  | 'a'\n  | 'b';\nconst x: ?T = g();",
			blankAll("type T =\n  | 'a'\n  | 'b';") + "\n" + blankSpan("const x: ?T = g();", ": ?T")},
		{"cast", "// @flow\nconst a = (x: any);", "// @flow\n" + blankSpan("const a = (x: any);", ": any")},
		{"nested cast", "// @flow\nn = Object.keys((s.t: any)).length;", "// @flow\n" + blankSpan("n = Object.keys((s.t: any)).length;", ": any")},
		{"cast of object literal", "// @flow\nconst c = ({ ...a || {} }: T);", "// @flow\n" + blankSpan("const c = ({ ...a || {} }: T);", ": T")},
		{"generic bound", "// @flow\nclass C { m<T: { [k: string]: any }>(a: T) { return a; } }",
			"// @flow\n" + blankSpans("class C { m<T: { [k: string]: any }>(a: T) { return a; } }",
				"<T: { [k: string]: any }>", ": T")},
		{"property after comment", "// @flow\nclass C {\n  // note\n  p: ?string;\n  static q: ?number;\n}",
			"// @flow\nclass C {\n  // note\n  " + blankSpan("p: ?string;", ": ?string") +
				"\n  " + blankSpan("static q: ?number;", ": ?number") + "\n}"},
		// value code that MUST survive untouched
		{"import type", "import type X from './y';\nconst a: ?T = g();",
			"import type X from './y';\n" + blankSpan("const a: ?T = g();", ": ?T")},
		{"object literal in ternary branch", "// @flow\nconst r = c ? g({}) : h();", "// @flow\nconst r = c ? g({}) : h();"},
		{"less-than then ternary", "// @flow\nconst r = x < y ? 1 : 2;", "// @flow\nconst r = x < y ? 1 : 2;"},
		{"object key after block", "// @flow\nif (a) { b(); }\nconst o = { k: 1 };", "// @flow\nif (a) { b(); }\nconst o = { k: 1 };"},
		// React names variables `type` throughout. Read as a type alias, this blanks
		// the rest of the enclosing function -- and stays brace-balanced while doing
		// it, so the result parses and is silently WRONG rather than dropped.
		{"type as a variable name", "// @flow\nconst c = (type as U);\nnext();", "// @flow\nconst c = (type as U);\nnext();"},
		{"type as an argument", "// @flow\nrender(request, type, props);\nnext();", "// @flow\nrender(request, type, props);\nnext();"},
		// A `{` only opens a declaration position when it opens a BLOCK. A specifier
		// list is not one, and reading it as one blanked the import and everything
		// after it until the braces happened to rebalance.
		{"import specifier list", "// @flow\nimport { type Config } from './c';\nconst cp = require('cp');\nfunction r(cmd: ?string) { cp.exec(cmd); }",
			"// @flow\nimport { type Config } from './c';\nconst cp = require('cp');\n" + blankSpan("function r(cmd: ?string) { cp.exec(cmd); }", ": ?string")},
		{"export specifier list", "// @flow\nexport { type Config } from './c';\nconst a: ?T = g();",
			"// @flow\nexport { type Config } from './c';\n" + blankSpan("const a: ?T = g();", ": ?T")},
		{"object literal is not a declaration position", "// @flow\nconst o = { type Config };\nconst a: ?T = g();",
			"// @flow\nconst o = { type Config };\n" + blankSpan("const a: ?T = g();", ": ?T")},
		// A generic bound may follow any binding NAME, `class` included.
		{"class generic bound", "// @flow\nclass Box<T: Object> { v: ?T; }",
			"// @flow\n" + blankSpans("class Box<T: Object> { v: ?T; }", "<T: Object>", ": ?T")},
		// ...but a bare identifier starting a statement is an expression, not a
		// binding, so `a<b ? c : d>e` must survive.
		{"comparison pair around a ternary", "// @flow\nconst t = 1;\na<b ? c : d>e;", "// @flow\nconst t = 1;\na<b ? c : d>e;"},
		// `class` is not reserved as a property name, and an unstamped pending-class
		// flag was consumed by the next `{` anywhere -- blanking an unrelated
		// literal's value to leave `{ a }`, which is valid shorthand and so PARSES.
		{"class as an object key", "// @flow\nconst o = { class: 'b' };\nconst p = { a: 1 };", "// @flow\nconst o = { class: 'b' };\nconst p = { a: 1 };"},
		{"class as a member read", "// @flow\nconst k = o.class;\nrun({ a: 1 });", "// @flow\nconst k = o.class;\nrun({ a: 1 });"},
		{"class body vs mixin argument", "// @flow\nclass X extends mix({ a: 1 }) { v: ?T; }",
			"// @flow\n" + blankSpan("class X extends mix({ a: 1 }) { v: ?T; }", ": ?T")},
		// `>` closes a type-argument list; only as the tail of `=>` does it leave the
		// type open. Continuing at a bare `>` ran the blank into the next statement.
		{"generic alias without a semicolon", "// @flow\ntype P = Array<string>\nconst cp = require('cp');",
			"// @flow\n" + blankAll("type P = Array<string>") + "\nconst cp = require('cp');"},
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
// (CLAUDE.md), and a node's Loc is a byte offset into the buffer the parser was
// handed -- lineIndex is built from that same buffer, so a shift is unrecoverable
// rather than merely wrong. If the stripper ever moved a byte,
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
	assertSinkPos(t, "annotations", src, "8:3")

	// A second source whose Flow syntax spans LINES rather than sitting inside
	// one: a declaration blanked across a multi-line union, and a cast. Those
	// blanks rewrite whole runs of the buffer, so they are where a lost newline
	// would show up -- the single-line case above cannot catch it.
	multiline := `// @flow
export type Sort =
  | 'asc'
  | 'desc'
  | { [string]: number };

declare export type Handle = number;

function run(cmd: ?string, s: Sort): ?string {
  const child = require('child_process');
  if (Object.keys((s: any)).length > 0) {
    child.exec(cmd);
  }
  return cmd;
}
module.exports = { run };
`
	assertSinkPos(t, "multiline", multiline, "12:5")
}

// assertSinkPos lowers src as a Flow-typed .js and asserts the exec call it
// contains is reported at want ("line:column", 1-based).
func assertSinkPos(t *testing.T, name, src, want string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "flow_pos.js")
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		mod, _, err := NewConverter().convertJSFile(path, "flowpos")
		if err != nil {
			t.Fatalf("convert: %v", err)
		}
		var got string
		for _, f := range mod.GetFunctions() {
			for _, b := range f.GetBlocks() {
				for _, in := range b.GetInstrs() {
					if c := in.GetCall(); c != nil && got == "" && strings.Contains(c.GetCallee(), "exec") {
						got = fmt.Sprintf("%d:%d", in.GetPos().GetLine(), in.GetPos().GetColumn())
					}
				}
			}
		}
		if got == "" {
			t.Fatal("no exec call lowered from the Flow source")
		}
		if got != want {
			t.Errorf("exec lowered at %s, want %s -- the strip shifted positions", got, want)
		}
	})
}

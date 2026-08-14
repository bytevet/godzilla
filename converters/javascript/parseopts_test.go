package js_converter

import (
	"strings"
	"testing"

	jsast "github.com/bytevet/esbuild-jsast"
)

// The parser this frontend uses is a TRANSFORMING one: several of its options
// change what the tree SAYS, not merely how it would be printed. jsast.Options
// exposes only two booleans so none of them can be set from here — but a rebase
// of that module onto a newer esbuild could change a DEFAULT, and every failure
// mode is silent: a dropped dead branch or an inlined const removes a sink
// without removing a file, so coverage still reads clean.
//
// These assertions are the alarm — one per transformation jsast.Options names as
// a hazard. Each asserts the tree still carries what the source wrote.
func TestParseKeepsSourceSemantics(t *testing.T) {
	t.Run("dead branches survive", func(t *testing.T) {
		// Dead-code elimination would delete the only call in the file.
		assertCallee(t, `if (false) { cp.exec(x); }`, "cp.exec")
	})

	t.Run("consts are not inlined", func(t *testing.T) {
		// Const inlining would replace `cmd` with the literal and, with it, the
		// identifier the lowering binds taint to.
		f := mustParse(t, `const cmd = "ls"; cp.exec(cmd);`)
		if got := calleeArgSource(t, f); got != "cmd" {
			t.Errorf("argument lowered as %q, want the identifier cmd", got)
		}
	})

	t.Run("class bodies keep their methods", func(t *testing.T) {
		// Method lowering (to prototype assignments) would move every method out
		// of the class body, where collectClass looks for handlers.
		f := mustParse(t, `class C { run(cmd) { cp.exec(cmd); } }`)
		cls, ok := f.Stmts[0].Data.(*jsast.SClass)
		if !ok {
			t.Fatalf("first statement is %T, want a class declaration", f.Stmts[0].Data)
		}
		if len(cls.Class.Properties) != 1 || !cls.Class.Properties[0].Kind.IsMethodDefinition() {
			t.Errorf("class body no longer holds its method: %+v", cls.Class.Properties)
		}
	})

	t.Run("symbol names are source names", func(t *testing.T) {
		// Identifier minification would rename every symbol, and callee names are
		// built from those names — no glob would match anything.
		assertCallee(t, `childProcess.execSync(userInput);`, "childProcess.execSync")
	})

	t.Run("module syntax is not rewritten", func(t *testing.T) {
		// Bundle mode rewrites require/import into linker shape. Both alias tables
		// pattern-match the source forms, so every module-anchored sink
		// (js:child_process.exec) would stop matching while the file still parses.
		f := mustParse(t, `const cp = require("child_process");`)
		decl := f.Stmts[0].Data.(*jsast.SLocal).Decls[0]
		if _, ok := unwrap(decl.ValueOrNil).Data.(*jsast.ECall); !ok {
			t.Errorf("require lowered as %T, want a plain call", decl.ValueOrNil.Data)
		}
		f = mustParse(t, `import { exec } from "child_process";`)
		if _, ok := f.Stmts[0].Data.(*jsast.SImport); !ok {
			t.Errorf("import lowered as %T, want an import statement", f.Stmts[0].Data)
		}
	})
}

// assertCallee parses src and asserts the syntactic callee of the first call it
// finds, which is exactly the string the lowering would put in Call.Callee.
func assertCallee(t *testing.T, src, want string) {
	t.Helper()
	f := mustParse(t, src)
	call, ok := firstCall(f.Stmts)
	if !ok {
		t.Fatalf("no call survived the parse of %q", src)
	}
	if got := syntacticCallee(f, call.Target); got != want {
		t.Errorf("callee = %q, want %q", got, want)
	}
}

// calleeArgSource renders the first call's first argument the way the lowering
// sees it: an identifier by name, a string literal quoted.
func calleeArgSource(t *testing.T, f *jsast.File) string {
	t.Helper()
	call, ok := firstCall(f.Stmts)
	if !ok || len(call.Args) == 0 {
		t.Fatal("no call with arguments survived the parse")
	}
	switch v := unwrap(call.Args[0]).Data.(type) {
	case *jsast.EIdentifier:
		return f.NameOf(v.Ref)
	case *jsast.EString:
		return `"` + jsast.UTF16ToString(v.Value) + `"`
	}
	return ""
}

// firstCall finds the first call expression in a statement list, descending into
// the block/class/function bodies these fixtures use.
func firstCall(stmts []jsast.Stmt) (*jsast.ECall, bool) {
	for _, s := range stmts {
		switch v := s.Data.(type) {
		case *jsast.SExpr:
			if c, ok := unwrap(v.Value).Data.(*jsast.ECall); ok {
				return c, true
			}
		case *jsast.SBlock:
			if c, ok := firstCall(v.Stmts); ok {
				return c, true
			}
		case *jsast.SIf:
			if c, ok := firstCall(stmtList(v.Yes)); ok {
				return c, true
			}
		case *jsast.SLocal:
			continue
		}
	}
	return nil, false
}

// TestLineIndexTerminators covers the line breaks no fixture in the tree
// contains. A file with CRLF endings or a U+2028 in a string literal would
// otherwise report every position after it on the wrong line, and nothing else
// in the suite reads such a buffer.
func TestLineIndexTerminators(t *testing.T) {
	cases := []struct {
		name string
		src  string
		off  int
		want [2]int32 // line, column
	}{
		{"lf", "a\nbc", 3, [2]int32{2, 2}},
		{"crlf counts once", "a\r\nbc", 4, [2]int32{2, 2}},
		{"lone cr", "a\rbc", 3, [2]int32{2, 2}},
		{"u2028", "a bc", 5, [2]int32{2, 2}},
		{"u2029", "a bc", 5, [2]int32{2, 2}},
		{"offset zero is line 1 col 1", "function f(){}", 0, [2]int32{1, 1}},
		{"column is bytes, not runes", "\"é\";x", 5, [2]int32{1, 6}},
		// U+2060 (e2 81 a0) shares U+2028's lead byte but is not a line break.
		{"e2 that is not a separator", "\"\u2060\";\nx", 7, [2]int32{2, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newLineIndex("f.js", tc.src).pos(jsast.Loc{Start: int32(tc.off)})
			if p.GetLine() != tc.want[0] || p.GetColumn() != tc.want[1] {
				t.Errorf("pos(%d) = %d:%d, want %d:%d", tc.off, p.GetLine(), p.GetColumn(), tc.want[0], tc.want[1])
			}
		})
	}
}

// TestLineIndexAgainstParse is the end-to-end half: a real parse's node offsets
// must land where the source says, through a CRLF buffer that shifts every line
// by one byte.
func TestLineIndexAgainstParse(t *testing.T) {
	src := strings.Join([]string{
		"const cp = require('child_process');",
		"function run(cmd) {",
		"  cp.exec(cmd);",
		"}",
	}, "\r\n")
	f := mustParse(t, src)
	li := newLineIndex("f.js", src)
	fn, ok := f.Stmts[1].Data.(*jsast.SFunction)
	if !ok {
		t.Fatalf("second statement is %T, want a function declaration", f.Stmts[1].Data)
	}
	call := fn.Fn.Body.Block.Stmts[0]
	p := li.pos(call.Loc)
	if p.GetLine() != 3 || p.GetColumn() != 3 {
		t.Errorf("cp.exec lowered at %d:%d, want 3:3", p.GetLine(), p.GetColumn())
	}
}

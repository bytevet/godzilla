package js_converter

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// calleeNames returns every call/invoke callee in a converted program.
func calleeNames(t *testing.T, path string) []string {
	t.Helper()
	prog, err := NewConverter().ConvertFile(path)
	if err != nil {
		t.Fatalf("ConvertFile(%s): %v", path, err)
	}
	var out []string
	for _, m := range prog.Modules {
		for _, f := range m.Functions {
			for _, b := range f.Blocks {
				for _, in := range b.Instrs {
					if in.Op == ir.OpCode_OP_CODE_CALL || in.Op == ir.OpCode_OP_CODE_INVOKE {
						if in.Call != nil && in.Call.Callee != "" {
							out = append(out, in.Call.Callee)
						}
					}
				}
			}
		}
	}
	return out
}

// TestTypeScript_StrippedAndLowered checks that a .ts file (type annotations +
// an interface) parses on the TS rung of the dialect ladder, and that the
// resulting callees still name the source (req.query) and sink (cp.execSync).
func TestTypeScript_StrippedAndLowered(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.ts")
	if err := os.WriteFile(src, []byte(`const cp = require("child_process");
interface Req { query: Record<string, string>; }
export function run(req: Req, res: unknown): void {
    const cmd: string = req.query.cmd;
    cp.execSync(cmd);
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := calleeNames(t, src)
	// FE-2: `const cp = require("child_process")` makes cp an alias, so the callee
	// resolves to the canonical js:child_process.execSync (not the local js:cp.*).
	if !slices.Contains(cs, "js:child_process.execSync") {
		t.Errorf("expected sink callee js:child_process.execSync in TS output, got %v", cs)
	}
}

// TestESModule_NamedImportCalleeIsExact pins that a named ESM import resolves to
// the module-anchored callee, not the bare local name: `import {execSync} from
// "child_process"` makes execSync(x) a js:child_process.execSync call, which is
// what a module-anchored sink rule is written against.
func TestESModule_NamedImportCalleeIsExact(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.mjs")
	if err := os.WriteFile(src, []byte(`import { execSync } from "child_process";
export function run(req) {
    execSync(req.query.cmd);
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := calleeNames(t, src)
	if !slices.Contains(cs, "js:child_process.execSync") {
		t.Errorf("named-import callee not resolved: got %v", cs)
	}
}

// TestBundlerCommaCalleeRecovered pins the shape every bundler emits for a
// named-import call, `(0, mod.fn)(x)`. Our own pipeline no longer produces it,
// but scanned repos are full of bundled JS, and without the comma case the
// callee of most calls in such a file collapses to <dynamic>.
func TestBundlerCommaCalleeRecovered(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(src, []byte(`var import_child_process = require("child_process");
function run(req) {
    (0, import_child_process.execSync)(req.query.cmd);
}
module.exports = { run };
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := calleeNames(t, src)
	found := slices.ContainsFunc(cs, func(c string) bool {
		return strings.HasSuffix(c, ".execSync")
	})
	if !found {
		t.Errorf("comma callee not recovered (collapsed to <dynamic>?): got %v", cs)
	}
}

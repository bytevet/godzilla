package js_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "godzilla/pkg/ir/v1"
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

func hasCallee(cs []string, want string) bool {
	for _, c := range cs {
		if c == want {
			return true
		}
	}
	return false
}

// TestTypeScript_StrippedAndLowered checks that a .ts file (type annotations +
// an interface) is esbuild-transformed so goja can parse it, and that the
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
	if !hasCallee(cs, "js:child_process.execSync") {
		t.Errorf("expected sink callee js:child_process.execSync in TS output, got %v", cs)
	}
}

// TestESModule_ImportInteropCalleeRecovered checks that esbuild's ESM->CJS
// interop wrapper `(0, import_mod.fn)(x)` does not collapse the callee to
// <dynamic>: the SequenceExpression handling recovers the imported name so
// import-based sinks still match (the imported execSync -> js:*.execSync).
func TestESModule_ImportInteropCalleeRecovered(t *testing.T) {
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
	found := false
	for _, c := range cs {
		// esbuild renames the module base to import_child_process; the suffix
		// (.execSync) is what a js:*.execSync sink glob matches.
		if len(c) > len(".execSync") && c[len(c)-len(".execSync"):] == ".execSync" {
			found = true
		}
	}
	if !found {
		t.Errorf("ESM interop callee not recovered (collapsed to <dynamic>?): got %v", cs)
	}
}

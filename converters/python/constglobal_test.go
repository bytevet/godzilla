package py_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// usesBase is appended to every case so the module actually READS BASE; without
// a use there is no operand to inspect.
const usesBase = "\ndef _use():\n    return BASE + \"/p\"\n"

// loweredBaseOperand reports how a read of BASE reached the IR: "const" when the
// literal was inlined, "global" when it stayed an opaque GlobalName.
func loweredBaseOperand(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "m.py")
	if err := os.WriteFile(path, []byte(src+usesBase), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := NewConverter().ConvertFile(path)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got := "absent"
	for _, m := range prog.GetModules() {
		for _, f := range m.GetFunctions() {
			for _, b := range f.GetBlocks() {
				for _, in := range b.GetInstrs() {
					if in.GetOp() != ir.OpCode_OP_CODE_BIN_OP {
						continue
					}
					for _, o := range in.GetOperands() {
						if o.GetGlobalName() == "BASE" {
							return "global"
						}
						if o.GetConstant().GetStringVal() == "https://x" {
							got = "const"
						}
					}
				}
			}
		}
	}
	return got
}

// Every case is about SOUNDNESS in one direction: folding a name that is not
// really constant would suppress a real finding, so a wrong "const" here costs a
// false negative on an exploitable SSRF. Declining to fold only forgoes the
// false-positive reduction, so "global" is always the safe answer.
func TestConstStringGlobalFolding(t *testing.T) {
	const decl = "BASE = \"https://x\"\n"
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"single string assign", decl, "const"},
		{"inert unlowered stmt", decl + "def f():\n    raise ValueError(1)\n", "const"},
		{"unrelated comprehension", decl + "ys = [y for y in xs]\n", "const"},
		{"unrelated try/except", decl + "try:\n    f()\nexcept E as e:\n    pass\n", "const"},

		{"reassigned at module level", decl + "BASE = other()\n", "global"},
		{"rebound in a function", decl + "def f():\n    BASE = evil()\n", "global"},
		{"global statement", decl + "def f():\n    global BASE\n    BASE = evil()\n", "global"},
		{"unrelated annotated assign", decl + "def f():\n    Y: str = evil()\n", "const"},
		{"annotated reassign of BASE", decl + "BASE: str = evil()\n", "global"},
		{"lambda is unlowered", decl + "g = lambda BASE: BASE\n", "global"},
		{"del present", decl + "def f():\n    del Y\n", "global"},
		{"shadowed by parameter", decl + "def f(BASE):\n    return BASE\n", "global"},
		{"shadowed by import alias", decl + "import os as BASE\n", "global"},
		{"shadowed by for target", decl + "for BASE in xs:\n    pass\n", "global"},
		{"shadowed by with-as", decl + "with open(p) as BASE:\n    pass\n", "global"},
		{"shadowed by except-as", decl + "try:\n    f()\nexcept E as BASE:\n    pass\n", "global"},
		{"shadowed by comprehension target", decl + "ys = [z for BASE in xs]\n", "global"},
		{"shadowed by tuple unpack", decl + "(BASE, c) = pair()\n", "global"},
		{"shadowed by walrus", decl + "if (BASE := f()):\n    pass\n", "global"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loweredBaseOperand(t, tt.src); got != tt.want {
				t.Errorf("BASE lowered as %q, want %q", got, tt.want)
			}
		})
	}
}

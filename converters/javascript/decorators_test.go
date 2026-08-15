package js_converter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decorateCallees returns the __decorate* callees in a file's lowered IR, which
// is how the TypeScript legacy-decorator rung is OBSERVABLE from outside: the
// flag rewrites decorators into those calls, so their presence means the file was
// parsed with it and their absence means it was parsed as written.
func decorateCallees(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "m.ts")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog := mustConvert(t, p)
	var out []string
	for _, m := range prog.Modules {
		for _, f := range m.Functions {
			for _, b := range f.Blocks {
				for _, in := range b.Instrs {
					if in.Call != nil && strings.Contains(in.Call.Callee, "__decorate") {
						out = append(out, in.Call.Callee)
					}
				}
			}
		}
	}
	return out
}

// A parameter decorator does not parse without TypeScript's legacy decorators,
// which costs the WHOLE file -- NestJS and Angular are built out of them. The
// rung exists so those files are analyzed at all.
func TestParameterDecoratorParses(t *testing.T) {
	src := "export class C {\n  async list(@Req() req: Request) { eval(req.query.cmd); }\n}\n"
	if got := decorateCallees(t, src); len(got) == 0 {
		t.Errorf("expected the decorator rung to lower this file, got no __decorate* calls")
	}
}

// The other half, and the reason the flag is a rung rather than a default: it
// lowers EVERY experimental decorator in the file it is set on. A file whose
// decorators sit on the class, method and property parses without it, so it must
// still reach the lowering as WRITTEN -- if this starts reporting __decorate*
// calls, the rung has stopped being confined to files that need it and every
// decorated file is paying for the few that do.
func TestOrdinaryDecoratorsAreNotLowered(t *testing.T) {
	src := "@Controller('x')\nexport class C {\n  @Get() list(req: any) { eval(req.query.cmd); }\n  @Inject() svc: any;\n}\n"
	if got := decorateCallees(t, src); len(got) != 0 {
		t.Errorf("class/method/property decorators were lowered (%v); the rung should not have been reached", got)
	}
}

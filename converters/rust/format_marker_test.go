package rust_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// calleeMarks walks every CALL in a module and returns callee -> the set of
// intrinsic markers seen on its instructions ("" meaning unmarked).
func calleeMarks(mod *ir.Module) map[string]map[string]bool {
	marks := map[string]map[string]bool{}
	for _, fn := range mod.Functions {
		for _, blk := range fn.Blocks {
			for _, inst := range blk.Instrs {
				if inst.Call == nil || inst.Call.GetCallee() == "" {
					continue
				}
				c := inst.Call.GetCallee()
				if marks[c] == nil {
					marks[c] = map[string]bool{}
				}
				marks[c][inst.Intrinsic] = true
			}
		}
	}
	return marks
}

func requireMark(t *testing.T, marks map[string]map[string]bool, callee, want string) {
	t.Helper()
	got, ok := marks[callee]
	if !ok {
		t.Errorf("no CALL to %q found in the lowered IR (saw %v)", callee, marks)
		return
	}
	if len(got) != 1 || !got[want] {
		t.Errorf("calls to %q carry intrinsics %v, want exactly %q", callee, got, want)
	}
}

// TestFormatMarkerAnchoredMatch is a hermetic (no rustc) regression guard for
// the builtin.format / builtin.identity tagging in emitCall: the matches are
// anchored to the std paths and MIR's trait-qualified call form, never a name
// suffix. The old shape heuristic let a user function merely named like a
// conversion (my_into, an inherent W::clone, a free fn `format`) acquire
// "forwards its operand's text" semantics, wrongly prove a fixed host via
// hostFixed(), and suppress a real SSRF finding.
func TestFormatMarkerAnchoredMatch(t *testing.T) {
	// The legitimate format! expansion chain: Arguments::new (lifetime-
	// instantiated, packed byte template) -> alloc's format() over that result
	// -> a trait-qualified ToString::to_string.
	std := "fn f(_1: &str) -> () {\n" +
		"    bb0: {\n" +
		"        _2 = Arguments::<'_>::new::<2, 1>(const b\"\\x0ahttps://h/\\xc0\\x00\", move _1) -> [return: bb1, unwind continue];\n" +
		"    }\n" +
		"    bb1: {\n" +
		"        _3 = format(move _2) -> [return: bb2, unwind continue];\n" +
		"    }\n" +
		"    bb2: {\n" +
		"        _4 = <String as ToString>::to_string(move _3) -> [return: bb3, unwind continue];\n" +
		"    }\n" +
		"    bb3: {\n" +
		"        return;\n" +
		"    }\n" +
		"}\n"
	marks := calleeMarks(lowerMIR(std, "std.rs"))
	requireMark(t, marks, "rust:Arguments::new", "builtin.format")
	// format(Arguments) is only recognized by its ARGUMENT being the tagged
	// Arguments::new result — the name alone cannot be anchored.
	requireMark(t, marks, "rust:format", "builtin.identity")
	requireMark(t, marks, "rust:to_string", "builtin.identity")

	// User functions named to trip the old heuristic: a free fn my_into, an
	// INHERENT method W::clone (prints unqualified, unlike <W as Clone>::clone),
	// a free fn format handed a plain param, and a user type named Arguments
	// (printed without the ::<'_>:: lifetime instantiation). None may be tagged.
	user := "fn g(_1: &str) -> () {\n" +
		"    bb0: {\n" +
		"        _2 = my_into(move _1) -> [return: bb1, unwind continue];\n" +
		"    }\n" +
		"    bb1: {\n" +
		"        _3 = W::clone(move _1) -> [return: bb2, unwind continue];\n" +
		"    }\n" +
		"    bb2: {\n" +
		"        _4 = format(move _1) -> [return: bb3, unwind continue];\n" +
		"    }\n" +
		"    bb3: {\n" +
		"        _5 = Arguments::new(move _1) -> [return: bb4, unwind continue];\n" +
		"    }\n" +
		"    bb4: {\n" +
		"        return;\n" +
		"    }\n" +
		"}\n"
	marks = calleeMarks(lowerMIR(user, "user.rs"))
	requireMark(t, marks, "rust:my_into", "")
	requireMark(t, marks, "rust:W::clone", "")
	requireMark(t, marks, "rust:format", "")
	requireMark(t, marks, "rust:Arguments::new", "")
}

// TestFormatMarkerRealRustc proves against the INSTALLED rustc's actual MIR
// output that (a) a real format! call site still yields a builtin.format-tagged
// instruction (the anchored Arguments::<'_>::new match holds on real output),
// and (b) user functions named like conversions (my_into, an inherent clone)
// stay unmarked.
func TestFormatMarkerRealRustc(t *testing.T) {
	requireRustc(t)

	dir := t.TempDir()
	src := `fn my_into(s: &str) -> String { s.to_uppercase() }

struct W;
impl W {
    fn clone(&self) -> String { "w".to_uppercase() }
}

fn main() {
    let x = std::env::var("X").unwrap_or_default();
    let u = format!("https://host.example/{}", x);
    let v = my_into(&u);
    let w = W;
    let c = w.clone();
    println!("{}{}", v, c);
}
`
	file := filepath.Join(dir, "main.rs")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := NewConverter().ConvertFile(file)
	if err != nil {
		t.Fatalf("ConvertFile: %v", err)
	}
	if len(prog.Modules) == 0 {
		t.Fatal("no modules produced")
	}

	sawFormat := false
	for _, mod := range prog.Modules {
		marks := calleeMarks(mod)
		for _, intr := range marks {
			if intr["builtin.format"] {
				sawFormat = true
			}
		}
		requireMark(t, marks, "rust:my_into", "")
		requireMark(t, marks, "rust:W::clone", "")
	}
	if !sawFormat {
		t.Error("no builtin.format-tagged instruction in the lowered IR: the anchored Arguments::new match no longer fits this rustc's MIR output")
	}
}

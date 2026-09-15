package rust_converter

import (
	"os"
	"path/filepath"
	"testing"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// callArgText returns the literal string value of a CALL instruction's Args[i]
// for the given callee ("" if the call, the arg, or a string constant there is
// missing) — what reconstructFormatTemplate's output looks like to a reader.
func callArgText(mod *ir.Module, callee string, i int) string {
	for _, fn := range mod.Functions {
		for _, blk := range fn.Blocks {
			for _, inst := range blk.Instrs {
				if inst.Call.GetCallee() != callee {
					continue
				}
				args := inst.Call.GetArgs()
				if i >= len(args) {
					return ""
				}
				return args[i].GetConstant().GetStringVal()
			}
		}
	}
	return ""
}

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
	marks := calleeMarks(lowerMIR(std, "std.rs", ""))
	requireMark(t, marks, "rust:Arguments::new", "builtin.format")
	// format(Arguments) is only recognized by its ARGUMENT being the tagged
	// Arguments::new result — the name alone cannot be anchored.
	requireMark(t, marks, "rust:format", "builtin.identity")
	requireMark(t, marks, "rust:to_string", "builtin.identity")

	// The same chain as printed by an older rustc (observed: 1.90.0): the
	// inherent-impl `rt::<impl Arguments<'_>>::new_v1` shape instead of
	// `Arguments::<'_>::new`. Pinned hermetically (no installed-rustc
	// dependency) so this spelling stays covered regardless of which rustc
	// TestFormatMarkerRealRustc happens to run against.
	oldRustc := "fn h(_1: &str) -> () {\n" +
		"    bb0: {\n" +
		"        _2 = core::fmt::rt::<impl Arguments<'_>>::new_v1::<1, 1>(const b\"\\x0ahttps://h/\\xc0\\x00\", move _1) -> [return: bb1, unwind continue];\n" +
		"    }\n" +
		"    bb1: {\n" +
		"        _3 = format(move _2) -> [return: bb2, unwind continue];\n" +
		"    }\n" +
		"    bb2: {\n" +
		"        return;\n" +
		"    }\n" +
		"}\n"
	marks = calleeMarks(lowerMIR(oldRustc, "oldrustc.rs", ""))
	requireMark(t, marks, "rust:core::fmt::rt::new_v1", "builtin.format")
	requireMark(t, marks, "rust:format", "builtin.identity")

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
	marks = calleeMarks(lowerMIR(user, "user.rs", ""))
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

// TestFormatTemplateReconstruction is a hermetic (no rustc) regression guard
// for reconstructFormatTemplate: the inherent-impl `new_v1`/`new_const`/
// `new_v1_formatted` shapes hand format!'s template as a REFERENCE to a
// promoted const holding the literal pieces, not the inline byte-string
// constant decodeFmtTemplate reads, so without this the SSRF host-fixed check
// sees an empty template and a provably-safe `format!("fixed-host/{}",
// tainted_path)` reads as unproven — exactly the false positive
// ssrf_safe_format guards against (ssrf_spec_host is the "{:>10}" positive
// twin, pinning that the `new_v1_formatted` case still fires when the host
// really is dynamic). Each MIR shape here is a trimmed transcription of what
// real rustc 1.90.0 emits (verified by hand against `rustc --emit=mir`), so
// this pins the reconstruction algorithm independent of whichever rustc
// happens to be installed.
func TestFormatTemplateReconstruction(t *testing.T) {
	text := `fn pfx(_1: &str) -> () {
    bb0: {
        _7 = const pfx::promoted[0];
        _3 = core::fmt::rt::<impl Arguments<'_>>::new_v1::<1, 1>(copy _7, copy _8) -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = format(move _3) -> [return: bb2, unwind continue];
    }
    bb2: {
        return;
    }
}

const pfx::promoted[0]: &[&str; 1] = {
    bb0: {
        _1 = [const "https://host.example/"];
        _0 = &_1;
        return;
    }
}

fn both(_1: &str) -> () {
    bb0: {
        _7 = const both::promoted[0];
        _3 = core::fmt::rt::<impl Arguments<'_>>::new_v1::<2, 1>(copy _7, copy _8) -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = format(move _3) -> [return: bb2, unwind continue];
    }
    bb2: {
        return;
    }
}

const both::promoted[0]: &[&str; 2] = {
    bb0: {
        _1 = [const "a", const "b"];
        _0 = &_1;
        return;
    }
}

fn lit() -> () {
    bb0: {
        _3 = const lit::promoted[0];
        _2 = core::fmt::rt::<impl Arguments<'_>>::new_const::<1>(copy _3) -> [return: bb1, unwind continue];
    }
    bb1: {
        _1 = format(move _2) -> [return: bb2, unwind continue];
    }
    bb2: {
        return;
    }
}

const lit::promoted[0]: &[&str; 1] = {
    bb0: {
        _1 = [const "just-text"];
        _0 = &_1;
        return;
    }
}

fn formatted(_1: &str) -> () {
    bb0: {
        _7 = const formatted::promoted[1];
        _3 = core::fmt::rt::<impl Arguments<'_>>::new_v1_formatted(move _7, move _9, move _11) -> [return: bb1, unwind continue];
    }
    bb1: {
        _2 = format(move _3) -> [return: bb2, unwind continue];
    }
    bb2: {
        return;
    }
}

const formatted::promoted[1]: &[&str; 2] = {
    bb0: {
        _1 = [const "prefix", const "suffix"];
        _0 = &_1;
        return;
    }
}
`
	mod := lowerMIR(text, "recon.rs", "")
	tests := []struct{ callee, want string }{
		{"rust:core::fmt::rt::new_v1", "https://host.example/{}"}, // pieces==args: trailing "{}" restored
		{"rust:core::fmt::rt::new_const", "just-text"},            // no placeholder at all
		// No const generics on this constructor, so the argument count is not
		// read off it: pieces joined with "{}" plus an UNCONDITIONAL trailing
		// "{}" (see reconstructFormatTemplate's doc comment on why that is the
		// conservative direction).
		{"rust:core::fmt::rt::new_v1_formatted", "prefix{}suffix{}"},
	}
	for _, tc := range tests {
		if got := callArgText(mod, tc.callee, 0); got != tc.want {
			t.Errorf("%s: Args[0] = %q, want %q", tc.callee, got, tc.want)
		}
	}
	// "both" shares the new_v1 callee with "pfx"; checked separately since
	// callArgText returns the first match.
	found := false
	for _, fn := range mod.Functions {
		if fn.Name != "both" {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, inst := range blk.Instrs {
				if inst.Call.GetCallee() == "rust:core::fmt::rt::new_v1" {
					found = true
					if got := inst.Call.Args[0].GetConstant().GetStringVal(); got != "a{}b" {
						t.Errorf("both: Args[0] = %q, want %q", got, "a{}b")
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("no new_v1 call found in fn both")
	}
}

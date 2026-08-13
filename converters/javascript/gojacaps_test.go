package js_converter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
)

// The frontend reads JS through goja, but esbuild will happily EMIT anything, so
// the two parsers' capabilities have to be kept in agreement by hand. That
// agreement is what esbuildSupported encodes, and this table is the evidence for
// it: each entry records whether goja can spell a construct today.
//
// It is written to fail on GOOD news as well as bad. A construct that starts
// parsing natively (a goja bump) flips nativeOK and fails TestGojaParserGaps,
// whose fix is to DELETE the matching esbuildSupported entry -- otherwise a
// downlevel we no longer need is carried forever, silently costing the precision
// it was bought with. Constructs that already parse are listed too, so lowering
// them is never mistaken for free.
var gojaConstructs = []struct {
	name     string
	code     string
	nativeOK bool // goja parses it with no esbuild pass
	rescued  bool // the pipeline recovers it when nativeOK is false
}{
	// --- goja reads these; esbuildSupported must NOT name them, or the downlevel
	// costs precision for nothing (object spread through a helper loses taint).
	{"class", "class A { m(){ return 1; } }", true, true},
	{"generator", "function* g(){ yield 1; }", true, true},
	{"exponent", "const x = 2 ** 3;", true, true},
	{"async_await", "async function f(){ return await Promise.resolve(1); }", true, true},
	{"async_generator", "async function* g(){ yield 1; }", true, true},
	{"object_spread", "const a = {x:1}; const b = {...a, y:2};", true, true},
	{"optional_catch", "try { f(); } catch { g(); }", true, true},
	{"optional_chain", "const v = a?.b?.c;", true, true},
	{"optional_call", "a?.();", true, true},
	{"nullish", "const v = a ?? b;", true, true},
	{"bigint", "const v = 1n;", true, true},
	{"logical_assign", "let a = 1; a ||= 2; a &&= 3; a ??= 4;", true, true},
	{"numeric_sep", "const v = 1_000_000;", true, true},
	{"class_field", "class A { x = 1; }", true, true},
	{"private_method", "class A { #p = 1; #m(){ return this.#p; } }", true, true},
	{"private_in", "class A { #x=1; static has(o){ return #x in o; } }", true, true},
	{"static_block", "class A { static { g(1); } }", true, true},
	{"regex_lookbehind", "const r = /(?<=a)b/;", true, true},

	// --- goja cannot, but the CommonJS format conversion already rewrites these,
	// so they need no esbuildSupported entry. Listed to keep that distinction
	// testable: the map is for constructs the FORMAT does not resolve.
	{"import_meta", "const u = import.meta.url;", false, true},

	// --- goja cannot; each is an esbuildSupported entry, and rescued pins that the
	// entry actually works end to end rather than merely being listed.
	{"decorator_member", "class A { @tracked x = 1; @action m(){} }", false, true},
	{"decorator_class", "@Component({selector:\"a\"})\nclass B {}", false, true},
	{"auto_accessor", "class A { accessor x = 1; }", false, true},
	{"for_await", "async function f(s){ for await (const c of s) { g(c); } }", false, true},
	{"using_decl", "function f(){ using r = getRes(); }", false, true},

	// --- goja cannot and NOTHING recovers it: esbuild's Transform API refuses to
	// downlevel top-level await at every target and format, so this is the known
	// residual. Listed so it stays a measured gap rather than a surprise.
	{"top_level_await", "const x = await Promise.resolve(1); export {x};", false, false},
}

// TestGojaParserGaps pins which constructs goja's parser accepts unaided. A
// failure here is a capability CHANGE, not a regression: see gojaConstructs.
func TestGojaParserGaps(t *testing.T) {
	for _, tc := range gojaConstructs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseFile(&file.FileSet{}, "t.js", tc.code, 0)
			if got := err == nil; got != tc.nativeOK {
				if got {
					t.Fatalf("goja now parses %s natively -- delete its esbuildSupported entry "+
						"and set nativeOK: true (carrying a downlevel we no longer need costs precision)", tc.name)
				}
				t.Fatalf("goja no longer parses %s natively (%v) -- it needs an esbuildSupported entry", tc.name, err)
			}
		})
	}
}

// TestGojaGapsAreRescued is the other half: a construct goja cannot read must
// survive the real pipeline, via esbuildSupported or the fallback target rung.
// Without this, esbuildSupported could name a feature esbuild spells differently
// and nothing would notice -- the file would just stay unreadable.
func TestGojaGapsAreRescued(t *testing.T) {
	for _, tc := range gojaConstructs {
		if tc.nativeOK {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "m.js")
			if err := os.WriteFile(p, []byte(tc.code), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := NewConverter().ConvertFile(p)
			switch {
			case tc.rescued && err != nil:
				t.Fatalf("%s should be rescued but the pipeline failed: %v", tc.name, err)
			case !tc.rescued && err == nil:
				t.Fatalf("%s is recorded as unrescuable but now converts -- "+
					"update rescued and drop it from the residual note in transform.go", tc.name)
			}
		})
	}
}

// TestFallbackTargetsEscalate pins the rung ORDER. An already-transformed file has
// spent the primary target, so only the lower one is left; an untransformed .js
// has not been through esbuild at all, so the primary is itself a rung. Getting
// this backwards would silently downlevel every .js that merely needed a loader.
func TestFallbackTargetsEscalate(t *testing.T) {
	if got := fallbackTargets(true); len(got) != 1 || got[0] != fallbackTarget {
		t.Errorf("fallbackTargets(true) = %v, want [fallbackTarget]", got)
	}
	got := fallbackTargets(false)
	if len(got) != 2 || got[0] != primaryTarget || got[1] != fallbackTarget {
		t.Errorf("fallbackTargets(false) = %v, want [primaryTarget fallbackTarget]", got)
	}
}

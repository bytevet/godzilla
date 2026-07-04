package rust_converter

import "testing"

// FuzzLowerMIR fuzzes the textual-MIR lowering. MIR text comes from rustc, but
// the hand-written parser must never panic on unexpected/truncated input (a
// panic on a scanned repo would be a denial of service).
func FuzzLowerMIR(f *testing.F) {
	f.Add("")
	f.Add("fn main() -> () {\n")
	f.Add("fn f() {\n    let _1: i32;\n    _1 = const 5_i32;\n    _0 = move _1;\n}\n")
	f.Add("bb0: {\n  _2 = Add(move _3, const b\"\\xc0\");\n}\n")
	f.Fuzz(func(t *testing.T, text string) {
		_ = lowerMIR(text, "fuzz.rs") // must not panic
	})
}

// FuzzDecodeFmtTemplate fuzzes the fmt::rt byte-template decoder, which does raw
// index/length arithmetic over an untrusted-shaped token.
func FuzzDecodeFmtTemplate(f *testing.F) {
	f.Add(`const b"hello {}"`)
	f.Add(`b"\xc0\x05world"`)
	f.Add("")
	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = decodeFmtTemplate(tok) // must not panic (index/slice bounds)
	})
}

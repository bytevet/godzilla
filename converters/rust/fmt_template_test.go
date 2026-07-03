package rust_converter

import "testing"

// TestDecodeFmtTemplate checks the decoder for the packed fmt::Arguments byte
// template that rustc emits for `format!`. The encoding: byte 0xC0 marks an
// argument insertion, a byte < 0x80 is the length of a literal run that follows.
// The input is the raw MIR operand rendering (`const b"..."`), exactly as the MIR
// text carries it.
func TestDecodeFmtTemplate(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"prefix+arg", `const b"\x14https://host.com/v1/\xc0\x00"`, "https://host.com/v1/{}", true},
		{"arg-first", `const b"\xc0\x0b.host.com/x\x00"`, "{}.host.com/x", true},
		{"arg+suffix", `const b"\thttp://h/\xc0\x05/tail\x00"`, "http://h/{}/tail", true},
		{"two-args", `const b"\nhttps://h/\xc0\x01/\xc0\x00"`, "https://h/{}/{}", true},
		{"no b-prefix (plain string)", `"https://h/"`, "", false},
		{"truncated length run", `const b"\x14https://h/"`, "", false},
		{"bad hex escape", `const b"\xzz"`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := decodeFmtTemplate(c.in)
			if got != c.want || ok != c.wantOK {
				t.Errorf("decodeFmtTemplate(%s) = %q,%v; want %q,%v", c.in, got, ok, c.want, c.wantOK)
			}
		})
	}
}

// TestConstFromLiteralByteString confirms a `format!` template byte string is
// decoded to a readable placeholder template, while an ordinary string literal is
// preserved and an unrecognized byte string stays empty.
func TestConstFromLiteralByteString(t *testing.T) {
	if v := constFromLiteral(`b"\x0ahttps://h/\xc0\x00"`); v.GetConstant().GetStringVal() != "https://h/{}" {
		t.Errorf("byte-string template not decoded: got %q", v.GetConstant().GetStringVal())
	}
	if v := constFromLiteral(`"plain"`); v.GetConstant().GetStringVal() != "plain" {
		t.Errorf("plain string not preserved: got %q", v.GetConstant().GetStringVal())
	}
	if v := constFromLiteral(`const 42_i32`); v.GetConstant().GetStringVal() != "" {
		t.Errorf("non-string constant should be empty: got %q", v.GetConstant().GetStringVal())
	}
}

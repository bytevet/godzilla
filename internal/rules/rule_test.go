package rules

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSinkCalleeUnmarshal locks in the string-or-mapping union: a bare glob is a
// static sink/callee; a `{sink|callee, when}` mapping is a dynamic (guarded) one.
func TestSinkCalleeUnmarshal(t *testing.T) {
	const doc = `
rules:
  - id: r
    severity: high
    sinks:
      - "go:*.Query#0"
      - sink: "go:*testonly*.Run#0"
        when: "arg[0].String startsWith 'cmd:'"
    callees:
      - "java:*MessageDigest.getInstance"
      - callee: "java:*Cipher.getInstance"
        when: "arg[0].String contains '/ECB/'"
`
	var rs RuleSet
	if err := yaml.Unmarshal([]byte(doc), &rs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sinks, callees := rs.Rules[0].Sinks, rs.Rules[0].Callees
	if want := (Sink{Pattern: "go:*.Query#0"}); sinks[0] != want {
		t.Errorf("static sink = %+v, want %+v", sinks[0], want)
	}
	if want := (Sink{Pattern: "go:*testonly*.Run#0", When: "arg[0].String startsWith 'cmd:'"}); sinks[1] != want {
		t.Errorf("dynamic sink = %+v, want %+v", sinks[1], want)
	}
	if want := (Callee{Pattern: "java:*MessageDigest.getInstance"}); callees[0] != want {
		t.Errorf("static callee = %+v, want %+v", callees[0], want)
	}
	if want := (Callee{Pattern: "java:*Cipher.getInstance", When: "arg[0].String contains '/ECB/'"}); callees[1] != want {
		t.Errorf("dynamic callee = %+v, want %+v", callees[1], want)
	}
}

func TestParseSink(t *testing.T) {
	cases := []struct {
		entry   string
		pattern string
		args    []int32
	}{
		{"go:*database/sql*.Query", "go:*database/sql*.Query", nil},
		{"go:*database/sql*.Query#0", "go:*database/sql*.Query", []int32{0}},
		{"go:*database/sql*.QueryContext#1", "go:*database/sql*.QueryContext", []int32{1}},
		{"go:foo.bar#0,2", "go:foo.bar", []int32{0, 2}},
		{"go:os.Open*#0", "go:os.Open*", []int32{0}}, // '#' is the delimiter, '*' stays in the glob
	}
	for _, c := range cases {
		p, a := parseSink(c.entry)
		if p != c.pattern || !reflect.DeepEqual(a, c.args) {
			t.Errorf("parseSink(%q) = (%q, %v), want (%q, %v)", c.entry, p, a, c.pattern, c.args)
		}
	}
}

func TestSinkInjectionArgs(t *testing.T) {
	r := &Rule{Sinks: SinksOf(
		"go:*database/sql*.Query#0",
		"go:*database/sql*.QueryContext#1",
		"go:*os/exec.Command", // bare = all args
	)}

	if args, ok := r.SinkInjectionArgs("go:(*database/sql.DB).Query"); !ok || !reflect.DeepEqual(args, []int32{0}) {
		t.Errorf("Query: got (%v,%v), want ([0],true)", args, ok)
	}
	if args, ok := r.SinkInjectionArgs("go:(*database/sql.DB).QueryContext"); !ok || !reflect.DeepEqual(args, []int32{1}) {
		t.Errorf("QueryContext: got (%v,%v), want ([1],true)", args, ok)
	}
	if args, ok := r.SinkInjectionArgs("go:os/exec.Command"); !ok || len(args) != 0 {
		t.Errorf("Command (bare): got (%v,%v), want (nil,true)", args, ok)
	}
	if _, ok := r.SinkInjectionArgs("go:fmt.Println"); ok {
		t.Errorf("Println: expected no sink match")
	}
	// The '#0' suffix must NOT reach the glob matcher: a callee literally
	// containing '#' should not be required to match.
	if !r.IsSink("go:(*database/sql.DB).Query") {
		t.Errorf("IsSink should match Query with the suffix stripped")
	}
}

func TestInvalidSinkSpec(t *testing.T) {
	cases := []struct {
		entry string
		want  bool
	}{
		{"go:*Query", false},         // bare pattern: legitimately all args
		{"go:*Query#0", false},       // single valid index
		{"go:*Query#0,2", false},     // multiple valid indices
		{"go:*Query# 0 , 2 ", false}, // whitespace tolerated
		{"go:*Query#", true},         // "#" with nothing after it
		{"go:*Query#x", true},        // non-numeric token
		{"go:*Query#-1", true},       // negative index
		{"go:*Query#0,", true},       // trailing comma -> empty token
		{"go:*Query#0,x", true},      // one good, one bad -> reject (likely a typo)
	}
	for _, c := range cases {
		if got := InvalidSinkSpec(c.entry); got != c.want {
			t.Errorf("InvalidSinkSpec(%q) = %v, want %v", c.entry, got, c.want)
		}
	}
}

// TestMatchGlob_InvalidUTF8PatternDoesNotPanic guards the fuzz-found DoS: a
// pattern with invalid UTF-8 bytes must not panic (it just never matches).
func TestMatchGlob_InvalidUTF8PatternDoesNotPanic(t *testing.T) {
	if MatchGlob("\x80", "x") {
		t.Error("an uncompilable pattern must match nothing, not panic")
	}
	if MatchGlob("go:*\xff", "go:anything") {
		t.Error("invalid-byte pattern should not match")
	}
}

// TestMatchGlob_Semantics pins the '*'-glob semantics across every classified
// shape (exact / prefix / suffix / prefix+suffix / contains / multi-segment /
// all-star), so the shape-specialized matcher stays equivalent to the anchored
// `*`→`.*` regexp it replaced.
func TestMatchGlob_Semantics(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"ruby:system", "ruby:system", true},   // exact
		{"ruby:system", "ruby:system2", false}, // exact, not prefix
		{"go:*", "go:anything/x.y", true},      // prefix (trailing *)
		{"go:*", "rb:x", false},
		{"*execute", "py:cursor.execute", true}, // suffix (leading *)
		{"*execute", "py:execute.now", false},
		{"c*:strcpy", "c:strcpy", true},   // prefix+suffix
		{"c*:strcpy", "cpp:strcpy", true}, // '*' spans across ':'
		{"c*:strcpy", "c:strcpyx", false},
		{"a*b", "ab", true},     // prefix+suffix, empty middle
		{"a*b", "a", false},     // too short to hold both anchors
		{"aa*aa", "aaa", false}, // overlapping anchors must not double-count
		{"aa*aa", "aaaa", true},
		{"*req*", "js:req.query", true}, // contains
		{"*req*", "js:res.send", false},
		{"a*b*c", "axbyc", true}, // multi-segment
		{"a*b*c", "axc", false},  // missing middle segment
		{"go:*database/sql*.Query#0", "go:(*database/sql.DB).Query#0", true},
		{"*", "anything", true}, // all-star
		{"**", "", true},
		{"", "", true}, // empty pattern matches only empty
		{"", "x", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pattern, c.s); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// BenchmarkMatchGlob exercises the matcher over a realistic mix of pattern
// shapes and canonical callee names (the engine's hottest inner loop).
func BenchmarkMatchGlob(b *testing.B) {
	pats := []string{"ruby:system", "c*:strcpy", "go:*request*", "py:*.execute", "go:(*database/sql.DB).Query#0", "ruby:Open3.*"}
	ins := []string{"go:net/http.(*Request).FormValue", "ruby:system", "c:strcpy", "py:cursor.execute"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, p := range pats {
			for _, in := range ins {
				_ = MatchGlob(p, in)
			}
		}
	}
}

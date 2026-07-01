package rules

import (
	"reflect"
	"testing"
)

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
	r := &Rule{Sinks: []string{
		"go:*database/sql*.Query#0",
		"go:*database/sql*.QueryContext#1",
		"go:*os/exec.Command", // bare = all args
	}}

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

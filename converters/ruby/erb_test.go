package ruby_converter

import (
	"strings"
	"testing"
)

// erbToRuby's whole contract is that a position in its output is the SAME line
// and column as in the .erb, which is what lets findings report the template's
// own coordinates with no source map. The corpus sample asserts findings; these
// assert the invariant that makes those findings' positions meaningful.
func TestERBToRubyPreservesLayout(t *testing.T) {
	for _, src := range []string{
		"<div>\n  <p><%= params[:id] %></p>\n</div>\n",
		"<%= yield %>\n<%== params[:x] %>\n",
		"a<%= x %>b<%== y %>c\n",
		"<%# comment %>\n<% if x %>\n<% end %>\n",
		"<%- trimmed -%>\n",
		"<%",           // unterminated
		"<%>",          // degenerate
		"",             // empty
		"no tags here", // markup only
	} {
		out := erbToRuby([]byte(src))
		if len(out) != len(src) {
			t.Fatalf("length changed for %q: got %d want %d", src, len(out), len(src))
		}
		if got, want := strings.Count(string(out), "\n"), strings.Count(src, "\n"); got != want {
			t.Errorf("newline count changed for %q: got %d want %d", src, got, want)
		}
		for i := range src {
			if (src[i] == '\n') != (out[i] == '\n') {
				t.Errorf("newline moved at byte %d of %q", i, src)
			}
		}
	}
}

func TestERBToRubyLowersTags(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string // substrings the stripped Ruby must contain
		notWant   []string
	}{
		{"escaped output is not a sink", "<%= params[:a] %>", []string{"params[:a]"}, []string{"raw("}},
		{"unescaped output becomes raw()", "<%== params[:a] %>", []string{"raw(", "params[:a]"}, nil},
		{"comment contributes nothing", "<%# params[:a] %>", nil, []string{"params"}},
		{"two tags on one line are separated", "<%= a %><%= b %>", []string{"a", ";", "b"}, nil},
		// A modifier cannot sit directly inside raw()'s parens, but it fits in a
		// nested pair, and `<%== `/`raw((` are the same width.
		{"modifier form keeps its sink", "<%== a if b %>", []string{"raw((", "a if b", "))"}, nil},
		// Unspaced leaves no room for the nesting, so the sink is dropped rather
		// than emitting a syntax error that would lose the whole template.
		{"unspaced modifier falls back to plain", "<%==a if b%>", []string{"a if b"}, []string{"raw("}},
		{"bare yield is renamed", "<%= yield %>", []string{"_erb_"}, []string{"yield"}},
		{"yield is whole-word only", "<%= yielded %>", []string{"yielded"}, []string{"_erb_"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(erbToRuby([]byte(tc.src)))
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("erbToRuby(%q) = %q, want it to contain %q", tc.src, got, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("erbToRuby(%q) = %q, want it NOT to contain %q", tc.src, got, w)
				}
			}
		})
	}
}

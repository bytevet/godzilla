package ruby_converter

import (
	"bytes"
	"strings"
)

// ERB templates are Ruby embedded in markup, and Rails puts request input in
// them directly (`<%= params[:id] %>`), so a view is a taint source site the
// .rb-only frontend never saw. erbToRuby turns one into plain Ruby that Ripper
// parses and lower.go lowers unchanged.
//
// The markup is blanked IN PLACE -- every removed byte becomes a space, newlines
// survive -- so a position in the output is the same line and column as in the
// .erb. That is the flowstrip.go trick, and it is what lets findings report the
// template's own coordinates with no source map.
//
// Rails AUTO-ESCAPES `<%= %>`, so that form is not a sink; its expression is
// emitted plainly and only fires if it bypasses escaping itself (`raw`,
// `.html_safe` -- already sinks in ruby-xss.yaml). The unescaped `<%== %>` form
// IS a sink, and gets one the same way a Vue `v-html` does: its delimiters are
// rewritten to a `raw(...)` call. `<%==` and `raw(` are both four bytes and `%>`
// closes as `) `, so the substitution is length-preserving and positions still
// hold.
func erbToRuby(src []byte) []byte {
	out := blankAll(src)
	for i := 0; i < len(src); {
		open := bytes.Index(src[i:], []byte("<%"))
		if open < 0 {
			break
		}
		open += i
		close := bytes.Index(src[open:], []byte("%>"))
		if close < 0 {
			break // unterminated tag: the rest stays blank
		}
		close += open
		i = close + 2
		copyERBTag(src, out, open, close)
	}
	return out
}

// blankAll returns a copy of src with every byte replaced by a space except
// newlines and carriage returns, which are kept so line numbers survive.
func blankAll(src []byte) []byte {
	out := make([]byte, len(src))
	for i, b := range src {
		if b == '\n' || b == '\r' {
			out[i] = b
			continue
		}
		out[i] = ' '
	}
	return out
}

// copyERBTag copies one ERB tag's Ruby into out. open points at "<%", close at
// the "%>" that ends it. Everything outside the tag is already blank.
func copyERBTag(src, out []byte, open, close int) {
	body := open + 2 // first byte after "<%"
	end := close     // one past the last body byte

	switch {
	case body < len(src) && src[body] == '#':
		return // <%# comment %> — no Ruby, leave it blank
	case body+1 < len(src) && src[body] == '=' && src[body+1] == '=':
		// <%== expr %> — unescaped output. Rewrite the delimiters into a raw()
		// call, which ruby-xss.yaml already treats as an escape-bypassing sink.
		copy(out[open:], []byte("raw("))
		body += 2
		out[close] = ')'
		// out[close+1] stays a space, closing the length-preserving swap.
	case body < len(src) && src[body] == '=':
		body++ // <%= expr %> — auto-escaped by Rails, emitted as a plain expression
	}
	// `<%-` and `-%>` are whitespace-trim variants; the dashes are not Ruby.
	if body < len(src) && src[body] == '-' {
		body++
	}
	if end-1 > body && src[end-1] == '-' {
		end--
	}
	if end > body {
		copy(out[body:end], src[body:end])
	}
	// A tag's Ruby must not run into the next line's code once the markup around
	// it is gone: `<% if x %>` is a statement, and the following `<% end %>` has
	// to parse as its own. Blanking leaves them on separate lines already, so
	// nothing more is needed -- but a tag whose body itself spans lines keeps its
	// newlines from the copy above.
}

// IsERBFile reports whether path is an ERB template. Rails names them
// `<name>.html.erb` / `<name>.js.erb`; the format segment is not significant
// here, only the .erb suffix.
func IsERBFile(path string) bool { return strings.HasSuffix(path, ".erb") }

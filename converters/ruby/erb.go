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
		tagEnd := bytes.Index(src[open:], []byte("%>"))
		if tagEnd < 0 {
			break // unterminated tag: the rest stays blank
		}
		tagEnd += open
		i = tagEnd + 2
		copyERBTag(src, out, open, tagEnd)
	}
	return out
}

// blankAll returns a copy of src with every byte replaced by a space except
// newlines and carriage returns, which are kept so line numbers survive.
func blankAll(src []byte) []byte {
	out := bytes.Repeat([]byte{' '}, len(src))
	for i, b := range src {
		if b == '\n' || b == '\r' {
			out[i] = b
		}
	}
	return out
}

// copyERBTag copies one ERB tag's Ruby into out. open points at "<%", close at
// the "%>" that ends it. Everything outside the tag is already blank.
func copyERBTag(src, out []byte, open, tagEnd int) {
	body := open + 2 // first byte after "<%"
	end := tagEnd    // one past the last body byte
	if body > tagEnd {
		return // degenerate `<%>` — nothing between the delimiters
	}
	if src[body] == '#' {
		return // <%# comment %> — no Ruby, leave it blank
	}

	// The closing `%>` becomes a statement separator. Two tags on one line
	// (`style="<%= a %>;<%= b %>"`) would otherwise strip to two juxtaposed
	// expressions on that line, which is a syntax error and loses the whole
	// template — 11% of decidim's views. `%>` is two bytes, so the separator
	// still fits after the raw() form's closing paren.
	out[tagEnd] = ';'
	switch {
	case src[body] == '=' && src[body+1] == '=':
		// <%== expr %> — unescaped output. A trailing modifier
		// (`<%== x if y %>`) cannot sit inside raw()'s parens, so it stays a
		// plain expression: losing one tag's sink beats a syntax error losing
		// the whole template.
		body += 2
		if !hasTrailingModifier(src[body:tagEnd]) {
			copy(out[open:], []byte("raw("))
			out[tagEnd], out[tagEnd+1] = ')', ';'
		}
	case src[body] == '=':
		body++ // <%= expr %> — auto-escaped by Rails, emitted as a plain expression
	}
	// `<%-` and `-%>` are whitespace-trim variants; the dashes are not Ruby.
	if body < tagEnd && src[body] == '-' {
		body++
	}
	if end-1 > body && src[end-1] == '-' {
		end--
	}
	if end > body {
		copy(out[body:end], src[body:end])
		renameYield(out[body:end])
	}
}

// IsERBFile reports whether path is an ERB template. Rails names them
// `<name>.html.erb` / `<name>.js.erb`; the format segment is not significant
// here, only the .erb suffix.
func IsERBFile(path string) bool { return strings.HasSuffix(path, ".erb") }

// modifierKeywords end an expression and start a trailing condition, so they
// cannot appear inside a parenthesized call argument.
var modifierKeywords = [][]byte{[]byte(" if "), []byte(" unless "), []byte(" while "), []byte(" until "), []byte(" rescue ")}

// hasTrailingModifier reports whether a tag body carries a statement modifier.
func hasTrailingModifier(body []byte) bool {
	for _, kw := range modifierKeywords {
		if bytes.Contains(body, kw) {
			return true
		}
	}
	return false
}

// renameYield rewrites the `yield` keyword to an ordinary identifier IN PLACE.
// A layout's `<%= yield %>` is the single most common ERB construct, and a bare
// yield outside a method body is a Ruby syntax error, so leaving it costs the
// whole layout. `_erb_` is the same five bytes, parses as a call, and is neither
// a source nor a sink, so it is inert to the analysis. Whole-word only, so
// `yielded_value` is untouched.
func renameYield(b []byte) {
	for off := 0; ; {
		i := bytes.Index(b[off:], yieldKeyword)
		if i < 0 {
			return
		}
		i += off
		off = i + len(yieldKeyword)
		if i > 0 && isIdentByte(b[i-1]) {
			continue
		}
		if off < len(b) && isIdentByte(b[off]) {
			continue
		}
		copy(b[i:off], []byte("_erb_"))
	}
}

var yieldKeyword = []byte("yield")

// isIdentByte reports whether c can appear inside a Ruby identifier, so `yield`
// is only rewritten as a whole word (never inside `yielded`).
func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

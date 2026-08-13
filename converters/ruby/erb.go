package ruby_converter

import (
	"bytes"
	"path/filepath"
	"strings"
)

// ERB templates are Ruby embedded in markup, and Rails puts request input in
// them directly (`<%= params[:id] %>`), so a view is a taint source site.
// erbToRuby turns one into plain Ruby that Ripper parses and lower.go lowers
// unchanged.
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
// rewritten to a `raw(...)` call. Every such rewrite is length-preserving — see
// copyERBTag for the widths it relies on.
//
// autoEscape false makes `<%= %>` a sink too, for template engines that do not
// escape it (see erbAutoEscapes).
func erbToRuby(src []byte, autoEscape bool) []byte {
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
		copyERBTag(src, out, open, tagEnd, autoEscape)
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
func copyERBTag(src, out []byte, open, tagEnd int, autoEscape bool) {
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
	// expressions, a syntax error that loses the whole template. `%>` is two
	// bytes, so the separator still fits after the raw() form's closing paren.
	out[tagEnd] = ';'
	switch {
	case src[body] == '=' && src[body+1] == '=':
		body += 2 // <%== expr %> — unescaped output
		switch {
		case !hasTrailingModifier(src[body:tagEnd]):
			copy(out[open:], []byte("raw("))
			copy(out[tagEnd:], []byte(");"))
		case src[body] == ' ' && src[tagEnd-1] == ' ':
			// A trailing modifier (`<%== x if y %>`) cannot sit directly inside
			// raw()'s parens, but it can inside a nested pair. `<%== ` and `raw((`
			// are both five bytes and ` %>` and `));` both three, so the spaced
			// form — the idiomatic one — keeps its sink at no positional cost.
			copy(out[open:], []byte("raw(("))
			copy(out[tagEnd-1:], []byte("));"))
			body++
			end--
		default:
			// Unspaced with a modifier (`<%==x if y%>`) has no room for the
			// nesting, so it stays a plain expression: losing one tag's sink beats
			// a syntax error losing the whole template.
		}
	case src[body] == '=' && !autoEscape:
		// `<%= expr %>` in an engine that does not escape. `<%= ` and `raw(` are
		// both four bytes and ` %>` closes as `);`, so the spaced form — the
		// idiomatic one — becomes a sink at no positional cost. The unspaced
		// `<%=expr%>` has only three bytes of prefix and no room, so it stays a
		// plain expression, as does a trailing modifier (which would need the
		// nested `raw((` the `<%==` branch above uses).
		if src[body+1] == ' ' && src[tagEnd-1] == ' ' && !hasTrailingModifier(src[body+2:tagEnd]) {
			copy(out[open:], []byte("raw("))
			copy(out[tagEnd-1:], []byte(");"))
			body += 2
			end--
		} else {
			body++
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

// erbAutoEscapes reports whether `<%= %>` in this template is HTML-escaped for
// us. An ActionView template is; a Cells view model's is NOT -- the cells gem
// compiles with Erbse, which has no SafeBuffer and emits the value verbatim, so
// every interpolation there is an unescaped sink.
//
// Decided by path because the engine is chosen by directory, not by anything in
// the file. Decidim is the evidence: its cells escape by hand
// (`decidim_html_escape(...)` inside app/cells), which is only necessary because
// the template does not -- and CVE-2024-41673 is the one that got missed.
func erbAutoEscapes(path string) bool {
	// Both spellings matter: the directory is mid-path when a monorepo or an
	// absolute path is scanned, and a bare prefix when the scan root IS the app.
	s := filepath.ToSlash(path)
	return !strings.Contains(s, "/app/cells/") && !strings.HasPrefix(s, "app/cells/")
}

// modifierKeywords end an expression and start a trailing condition, so they
// cannot appear inside a parenthesized call argument.
var modifierKeywords = [][]byte{[]byte(" if "), []byte(" unless "), []byte(" while "), []byte(" until "), []byte(" rescue ")}

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

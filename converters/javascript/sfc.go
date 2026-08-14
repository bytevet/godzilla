package js_converter

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// Component single-file formats (Vue `.vue`, Svelte `.svelte`) put their JS/TS in
// a <script> block and their signature vulnerability — untrusted data bound to
// Vue's `v-html` or Svelte's `{@html}`, which bypass the framework's context-aware
// auto-escaping (CWE-79) — in the template/markup block, which the parser never sees.
//
// Rather than model a new IR concept, the extractor compiles the SFC to plain JS:
// the <script> block becomes the module body, and each dangerous template
// directive becomes an ordinary synthetic function call appended into that same
// scope (e.g. `v-html="bio"` -> `__godzilla_vue_vhtml(bio)`). Because the call
// references the same binding, taint flows through the unchanged engine, and the
// synthetic callee (`js:__godzilla_vue_vhtml`) is matched by the vue-xss /
// svelte-xss rulepacks — a rulepack + frontend change with no gIR/engine change.
// This mirrors how the JSX lowering already turns `dangerouslySetInnerHTML` into a call.
// Escaped interpolation (`{{ }}`, `{ }`) is auto-escaped, so it emits nothing.

// Synthetic sink function names. A directive lowers to a bare call to one of
// these; the corresponding `js:<name>` canonical callee is a sink in the rulepack.
const (
	vueHTMLSink    = "__godzilla_vue_vhtml"
	vueURLSink     = "__godzilla_vue_url"
	svelteHTMLSink = "__godzilla_svelte_html"
)

// vueDirectives maps a (lower-cased) Vue template attribute name to the synthetic
// sink it lowers to. Only bound forms (`v-html`, `:href`, `v-bind:href`) carry a
// JS expression; a plain `href="/x"` is a static string and is not included. HTML
// tokenizers lower-case attribute names, so keys are lower-case.
var vueDirectives = map[string]string{
	"v-html":           vueHTMLSink,
	":innerhtml":       vueHTMLSink,
	"v-bind:innerhtml": vueHTMLSink,
	":href":            vueURLSink,
	"v-bind:href":      vueURLSink,
	":src":             vueURLSink,
	"v-bind:src":       vueURLSink,
}

// directivePos is one dangerous template directive: the synthetic sink it lowers
// to, the source expression bound to it, and the position in the ORIGINAL SFC
// file (used to relocate the lowered sink call's finding back to the template).
type directivePos struct {
	callee string // one of the *Sink constants (bare name, no "js:" prefix)
	expr   string // the JS expression bound to the directive
	line   int32
	col    int32
}

// extractSFCToJS turns a Vue/Svelte single-file component into plain JS: the
// <script> block padded so its lines keep their original SFC line numbers, plus
// one synthetic sink call per dangerous template directive. It returns that
// buffer and the directive list for applyDirectivePositions to relocate
// template-sink findings.
//
// The padding is what keeps positions honest: the parser sees a buffer whose
// script-region lines are the SFC's own, so no remapping is needed afterwards.
func extractSFCToJS(path string, src []byte) (string, []directivePos, error) {
	var (
		script     string
		scriptLine int
		dirs       []directivePos
	)
	// Built over the ORIGINAL file, since template directives are located in it
	// rather than in the extracted script buffer. Sharing lineIndex is what gives
	// the template side the same line-terminator rules as the script side, so a
	// CRLF or U+2028 component does not number its two halves differently.
	li := newLineIndex(path, string(src))
	switch strings.ToLower(filepath.Ext(path)) {
	case ".vue":
		script, scriptLine, dirs = extractVueSFC(src, li)
	case ".svelte":
		script, scriptLine, dirs = extractSvelteSFC(src, li)
	default:
		return "", nil, fmt.Errorf("not a single-file component: %s", path)
	}

	// Pad so the script body starts on its true SFC line, then append the
	// synthetic sink calls. Appended-call line numbers are irrelevant — their
	// findings are relocated by callee order in applyDirectivePositions, not by
	// line — so they can sit past the script region.
	var b strings.Builder
	b.WriteString(strings.Repeat("\n", scriptLine-1))
	b.WriteString(script)
	b.WriteByte('\n')
	for _, d := range dirs {
		b.WriteString(d.callee)
		b.WriteByte('(')
		b.WriteString(d.expr)
		b.WriteString(");\n")
	}
	return b.String(), dirs, nil
}

// extractScriptBlock returns the SFC <script> block's source, the 1-based line
// its content starts on, and its [lo,hi) byte range in src (lo == -1 when there
// is no <script>). Shared by the Vue and Svelte extractors, which differ only in
// how they scan the surrounding template/markup. lower is the lower-cased src,
// computed once by the caller and threaded through.
//
// A `lang="ts"` block needs no special handling: the extracted buffer goes
// through the same dialect ladder as any other file, whose TS rung reads it.
func extractScriptBlock(src, lower []byte, li *lineIndex) (script string, scriptLine, lo, hi int) {
	scriptLine, lo, hi = 1, -1, -1
	if content, start, ok := findBlock(src, lower, "script"); ok {
		script = string(content)
		ln, _ := li.lineCol(int32(start))
		scriptLine = int(ln)
		lo, hi = start, start+len(content)
	}
	return script, scriptLine, lo, hi
}

// extractVueSFC splits a Vue SFC into its <script> block (with its start line)
// and the dangerous directives found in its <template>.
func extractVueSFC(src []byte, li *lineIndex) (script string, scriptLine int, dirs []directivePos) {
	lower := bytes.ToLower(src)
	script, scriptLine, _, _ = extractScriptBlock(src, lower, li)
	if tmpl, start, ok := findBlock(src, lower, "template"); ok {
		dirs = scanVueTemplate(tmpl, start, li)
	}
	return script, scriptLine, dirs
}

// extractSvelteSFC splits a Svelte SFC into its <script> block and the `{@html}`
// mustaches found in the surrounding markup (everything outside <script>/<style>).
func extractSvelteSFC(src []byte, li *lineIndex) (script string, scriptLine int, dirs []directivePos) {
	lower := bytes.ToLower(src)
	script, scriptLine, scriptLo, scriptHi := extractScriptBlock(src, lower, li)
	styleLo, styleHi := -1, -1
	if content, start, ok := findBlock(src, lower, "style"); ok {
		styleLo, styleHi = start, start+len(content)
	}
	dirs = scanSvelteMarkup(src, scriptLo, scriptHi, styleLo, styleHi, li)
	return script, scriptLine, dirs
}

// scanVueTemplate tokenizes the template block and records every start-tag
// attribute that matches a Vue directive, resolving each directive's position to
// the original SFC (contentStart is the template content's byte offset in src).
func scanVueTemplate(content []byte, contentStart int, li *lineIndex) []directivePos {
	var dirs []directivePos
	z := html.NewTokenizer(bytes.NewReader(content))
	off := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		tokStart := off
		off += len(z.Raw())
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		_, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		for {
			key, val, more := z.TagAttr()
			if callee, ok := vueDirectives[strings.ToLower(string(key))]; ok {
				if expr := strings.TrimSpace(string(val)); expr != "" {
					ln, cl := li.lineCol(int32(contentStart + tokStart))
					dirs = append(dirs, directivePos{callee: callee, expr: expr, line: ln, col: cl})
				}
			}
			if !more {
				break
			}
		}
	}
	return dirs
}

// scanSvelteMarkup finds `{@html <expr>}` mustaches in the markup — outside the
// <script>/<style> byte ranges, which are the only places they can legitimately
// appear — and records each as a Svelte HTML sink at its original position.
func scanSvelteMarkup(src []byte, scriptLo, scriptHi, styleLo, styleHi int, li *lineIndex) []directivePos {
	var dirs []directivePos
	needle := []byte("{@html")
	for i := 0; ; {
		rel := bytes.Index(src[i:], needle)
		if rel < 0 {
			break
		}
		pos := i + rel
		i = pos + len(needle)
		if inRange(pos, scriptLo, scriptHi) || inRange(pos, styleLo, styleHi) {
			continue
		}
		expr, end, ok := matchMustache(src, pos)
		if !ok {
			continue
		}
		i = end
		if expr = strings.TrimSpace(expr); expr == "" {
			continue
		}
		ln, cl := li.lineCol(int32(pos))
		dirs = append(dirs, directivePos{callee: svelteHTMLSink, expr: expr, line: ln, col: cl})
	}
	return dirs
}

// applyDirectivePositions relocates each lowered template-sink call's finding
// position back to the template directive it came from. The sink calls are
// appended in template order and lowered in that same order, so the Nth call to
// a given synthetic sink corresponds to the Nth recorded directive for it —
// matched by callee to stay correct even when sink kinds interleave. Only the
// CALL instruction's position matters (that is where the finding is reported), so
// intermediate argument-expression positions are left as-is.
func applyDirectivePositions(mod *ir.Module, dirs []directivePos) {
	if mod == nil || len(dirs) == 0 {
		return
	}
	queues := map[string][]directivePos{}
	for _, d := range dirs {
		key := "js:" + d.callee
		queues[key] = append(queues[key], d)
	}
	for _, f := range mod.Functions {
		if f == nil {
			continue
		}
		for _, b := range f.Blocks {
			if b == nil {
				continue
			}
			for _, in := range b.Instrs {
				if in == nil || in.Call == nil {
					continue
				}
				key := in.Call.GetCallee()
				q := queues[key]
				if len(q) == 0 {
					continue
				}
				queues[key] = q[1:] // consume this callee's next directive, in order
				if in.Pos == nil {
					in.Pos = &ir.Position{}
				}
				in.Pos.Line = q[0].line
				in.Pos.Column = q[0].col
			}
		}
	}
}

// findBlock returns the content between the first top-level `<name ...>` and its
// matching `</name>`, along with the content's byte offset in src. Same-name
// nesting (a Vue `<template>` slot inside the root template) is handled by depth
// counting. A self-closing `<name/>` has no content. lower is the lower-cased
// src, passed in so it is computed once per SFC, not per call.
func findBlock(src, lower []byte, name string) (content []byte, contentStart int, ok bool) {
	open := findTag(lower, name, 0, true)
	if open < 0 {
		return nil, 0, false
	}
	gt := bytes.IndexByte(src[open:], '>')
	if gt < 0 {
		return nil, 0, false
	}
	openEnd := open + gt + 1
	if openTag := string(src[open:openEnd]); strings.HasSuffix(strings.TrimSpace(openTag), "/>") {
		return nil, openEnd, false
	}
	depth := 1
	i := openEnd
	for {
		no := findTag(lower, name, i, true)
		nc := findTag(lower, name, i, false)
		if nc < 0 {
			return nil, 0, false
		}
		if no >= 0 && no < nc {
			depth++
			i = no + 1
		} else {
			depth--
			if depth == 0 {
				return src[openEnd:nc], openEnd, true
			}
			i = nc + 1
		}
	}
}

// findTag returns the index of the next `<name` (open) or `</name` (close) at or
// after `from` whose following byte is a tag boundary (so `<template>` matches but
// `<templatex>` does not), or -1. lower must be the lower-cased source.
func findTag(lower []byte, name string, from int, open bool) int {
	tok := []byte("<" + name)
	if !open {
		tok = []byte("</" + name)
	}
	for i := from; i <= len(lower)-len(tok); {
		rel := bytes.Index(lower[i:], tok)
		if rel < 0 {
			return -1
		}
		p := i + rel
		after := p + len(tok)
		if after < len(lower) && isTagBoundary(lower[after]) {
			return p
		}
		i = p + len(tok)
	}
	return -1
}

func isTagBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '>', '/':
		return true
	}
	return false
}

// matchMustache brace-matches a `{@html ...}` starting at the `{` at open,
// returning the inner expression (after `@html`), the index just past the closing
// `}`, and whether a balanced close was found. Braces inside string literals are
// not special-cased (a rare edge that would only drop or over-extend one finding).
func matchMustache(src []byte, open int) (expr string, end int, ok bool) {
	exprStart := open + len("{@html")
	depth := 0
	for k := open; k < len(src); k++ {
		switch src[k] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				if exprStart > k {
					return "", 0, false
				}
				return string(src[exprStart:k]), k + 1, true
			}
		}
	}
	return "", 0, false
}

func inRange(pos, lo, hi int) bool {
	return lo >= 0 && pos >= lo && pos < hi
}

package js_converter

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	jsast "github.com/bytevet/esbuild-jsast"

	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// IsJSFamily reports whether path is a JavaScript-family source file the frontend
// handles. It is the single source of truth for the extension set: the converter's
// own directory walk and internal/scan's dispatch/detection table both call it, so
// an extension added here reaches every caller. A new extension also needs a rung
// in parseLadder, which is what decides how it is read.
func IsJSFamily(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx":
		return true
	}
	return isSFC(path)
}

// isSFC reports whether path is a component single-file format (Vue/Svelte) that
// needs SFC block extraction — the <script> block plus a template compiled to
// synthetic sink calls — before it is plain JavaScript.
func isSFC(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".vue", ".svelte":
		return true
	}
	return false
}

// parseMode is one rung of the dialect ladder: exactly the parser's two
// booleans, which between them spell the four JS dialects (JS/TS/JSX/TSX).
type parseMode struct{ ts, jsx bool }

// parseLadder returns the dialects to try for path, in order, stopping at the
// first that parses.
//
// An extension is a hint, not a contract: .js in the wild holds plain script, ES
// modules, Flow annotations and JSX. Committing to a guess costs the WHOLE file
// when it is wrong, so this turns "predict the dialect" into "find the one that
// parses" — an unanticipated dialect costs an extra attempt instead. Attempts are
// only ever paid on failure, and a failed parse is cheap next to losing the
// source. The FIRST rung's error is the one reported, since a later rung failing
// says nothing useful about a file it was never meant to read.
func parseLadder(path string) []parseMode {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts":
		return []parseMode{{ts: true}, {ts: true, jsx: true}}
	case ".tsx":
		return []parseMode{{ts: true, jsx: true}}
	case ".jsx":
		return []parseMode{{jsx: true}, {ts: true, jsx: true}}
	// .js/.mjs/.cjs, and the buffer an SFC extractor produced: plain script,
	// ESM, Flow, or TS-ish. Order is load-bearing — see the note above.
	default:
		return []parseMode{{}, {ts: true}, {ts: true, jsx: true}}
	}
}

// parseSource parses code as one of path's candidate dialects, returning the
// tree AND the buffer it was parsed from — which is not always code, since the
// Flow rung rewrites the source. Every position downstream is an offset into
// THAT buffer, so the two must travel together.
func parseSource(path, code string) (*jsast.File, string, error) {
	ladder := parseLadder(path)
	var firstErr error
	for _, m := range ladder {
		f, errs := jsast.Parse(code, jsast.Options{TS: m.ts, JSX: m.jsx})
		if len(errs) == 0 {
			return f, code, nil
		}
		if firstErr == nil {
			firstErr = parseError(errs)
		}
	}
	// Last rung: Flow. Its residue past TypeScript has no dialect of its own, so
	// no rung recovers it -- the source itself has to change (flowstrip.go).
	// Retrying the WHOLE ladder rather than one rung keeps the dialect question
	// open: a Flow file may also use JSX.
	if stripped, ok := stripFlow(code); ok && stripped != code {
		for _, m := range ladder {
			if f, errs := jsast.Parse(stripped, jsast.Options{TS: m.ts, JSX: m.jsx}); len(errs) == 0 {
				return f, stripped, nil
			}
		}
	}
	return nil, "", firstErr
}

// parseError renders a parse diagnostic slice as one error naming the first
// problem and its position, in the shape a compiler error is expected to take.
func parseError(errs []jsast.Error) error {
	if len(errs) == 0 {
		return fmt.Errorf("parse failed")
	}
	e := errs[0]
	if e.Line == 0 {
		return fmt.Errorf("%s", e.Text)
	}
	return fmt.Errorf("line %d:%d: %s", e.Line, e.Column+1, e.Text)
}

// lineIndex resolves a parser byte offset to a gIR Position. It is built from
// the EXACT buffer handed to the parser (flow-stripped or SFC-padded, not the
// file on disk), since that is what the offsets index.
//
// Line breaks are ECMAScript's four: LF, lone CR, CRLF (ONE break), and U+2028 /
// U+2029. The result is a 1-based line and a 1-based BYTE column.
type lineIndex struct {
	filename string
	starts   []int32 // byte offset of each line's first byte; starts[0] == 0
}

func newLineIndex(filename, src string) *lineIndex {
	li := &lineIndex{filename: filename, starts: []int32{0}}
	for i := 0; i < len(src); {
		switch src[i] {
		case '\n':
			i++
		case '\r':
			i++
			if i < len(src) && src[i] == '\n' {
				i++
			}
		case 0xe2: // U+2028 / U+2029 are e2 80 a8 / e2 80 a9
			if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xa8 || src[i+2] == 0xa9) {
				i += 3
				break
			}
			i++
			continue
		default:
			i++
			continue
		}
		li.starts = append(li.starts, int32(i))
	}
	return li
}

// pos is the ONE place an offset becomes an ir.Position.
//
// Offset 0 is a valid position (line 1, column 1) — the leading `function f(){}`
// of a file lives there — so "no node" must be decided by the caller from a nil
// Data, never by testing the offset. A binary search is required because the
// lowering revisits earlier nodes (a loop body is lowered after its header).
func (li *lineIndex) pos(loc jsast.Loc) *ir.Position {
	if li == nil {
		return nil
	}
	line, col := li.lineCol(int32(loc.Start))
	return &ir.Position{Filename: li.filename, Line: line, Column: col}
}

// lineCol is pos without the gIR wrapper, for callers working in raw offsets
// (the SFC extractor, which locates template directives in the original file).
func (li *lineIndex) lineCol(off int32) (line, col int32) {
	if off < 0 {
		off = 0
	}
	line = int32(sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > off }))
	return line, off - li.starts[line-1] + 1
}

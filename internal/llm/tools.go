package llm

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

// ToolBox is the read-only capability set the agentic reviewer (LLM-4) can call
// to gather evidence before adjudicating a finding: read a range of a file,
// resolve a canonical function name to its source, or grep the scanned tree.
// It is deliberately dependency-free (no Anthropic SDK) so the tools and their
// dispatch are unit-testable; the SDK tool-use loop that drives them lives in
// anthropic.go. Every capability is read-only and confined to the scan root.
type ToolBox interface {
	ReadFileRange(path string, start, end int) (string, error)
	FindFunction(canonicalName string) (string, error)
	Grep(pattern string, maxHits int) (string, error)
}

// maxToolOutput bounds any single tool result so one call can't flood the model
// context (and, for grep, can't be used to exfiltrate the whole tree at once).
const maxToolOutput = 8000

// FileToolBox is the default ToolBox: it reads from the real filesystem (fenced
// to the scan root) and resolves function names against the analyzed gIR
// program. A nil FileToolBox is safe — its methods return an explanatory error,
// so a reviewer configured without one degrades to no-agency rather than panics.
type FileToolBox struct {
	root    string // absolute scan root; all file access is confined here
	fnIndex map[string]*ir.Function
	fnMod   map[string]*ir.Module
}

// NewFileToolBox builds a toolbox over the analyzed program and scan root. root
// may be a file or a directory; file access is confined to it (a single-file
// scan confines to that file's directory).
func NewFileToolBox(prog *ir.Program, root string) *FileToolBox {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
		abs = filepath.Dir(abs)
	}
	tb := &FileToolBox{
		root:    abs,
		fnIndex: map[string]*ir.Function{},
		fnMod:   map[string]*ir.Module{},
	}
	if prog != nil {
		for _, mod := range prog.Modules {
			if mod == nil {
				continue
			}
			for _, fn := range mod.Functions {
				if fn != nil && fn.CanonicalName != "" {
					tb.fnIndex[fn.CanonicalName] = fn
					tb.fnMod[fn.CanonicalName] = mod
				}
			}
		}
	}
	return tb
}

// confine resolves a caller-supplied path against the root and rejects anything
// that escapes it (path traversal, absolute paths outside root) — the reviewer
// must not be able to read files outside the project it is analyzing.
func (tb *FileToolBox) confine(path string) (string, error) {
	if tb == nil {
		return "", fmt.Errorf("no toolbox configured")
	}
	p := path
	if !filepath.IsAbs(p) {
		p = filepath.Join(tb.root, p)
	}
	p = filepath.Clean(p)
	rel, err := filepath.Rel(tb.root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the scan root", path)
	}
	return p, nil
}

// ReadFileRange returns lines [start,end] (1-based, inclusive) of a file within
// the scan root, each prefixed with its line number. The range is clamped to the
// file and bounded in size.
func (tb *FileToolBox) ReadFileRange(path string, start, end int) (string, error) {
	p, err := tb.confine(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end && i <= len(lines); i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
		if b.Len() > maxToolOutput {
			b.WriteString("... (truncated)\n")
			break
		}
	}
	if b.Len() == 0 {
		return "(no lines in range)", nil
	}
	return b.String(), nil
}

// FindFunction resolves a canonical function name (exact, or a unique
// case-insensitive substring match) to its source location and a snippet around
// its declaration — so the reviewer can read the callee of a tainted call, a
// sanitizer body, etc.
func (tb *FileToolBox) FindFunction(canonicalName string) (string, error) {
	if tb == nil {
		return "", fmt.Errorf("no toolbox configured")
	}
	fn := tb.fnIndex[canonicalName]
	if fn == nil {
		// Fall back to a unique substring match (the model may pass a bare name).
		var hits []string
		for name := range tb.fnIndex {
			if strings.Contains(strings.ToLower(name), strings.ToLower(canonicalName)) {
				hits = append(hits, name)
			}
		}
		switch len(hits) {
		case 0:
			return "", fmt.Errorf("no function matching %q", canonicalName)
		case 1:
			fn = tb.fnIndex[hits[0]]
		default:
			if len(hits) > 20 {
				hits = hits[:20]
			}
			return "multiple functions match; pass an exact canonical name:\n" + strings.Join(hits, "\n"), nil
		}
	}
	pos := fn.GetPos()
	if pos == nil || pos.GetFilename() == "" {
		return fmt.Sprintf("function %s (no source position available)", fn.CanonicalName), nil
	}
	snip, _ := tb.ReadFileRange(pos.GetFilename(), int(pos.GetLine()), int(pos.GetLine())+25)
	return fmt.Sprintf("%s at %s:%d\n%s", fn.CanonicalName, pos.GetFilename(), pos.GetLine(), snip), nil
}

// Grep searches the scanned tree for a regular expression and returns up to
// maxHits "file:line: text" matches. It skips the same vendored/build/binary
// directories the scanner does and bounds total output.
func (tb *FileToolBox) Grep(pattern string, maxHits int) (string, error) {
	if tb == nil {
		return "", fmt.Errorf("no toolbox configured")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid pattern: %w", err)
	}
	if maxHits <= 0 || maxHits > 100 {
		maxHits = 50
	}
	var b strings.Builder
	hits := 0
	walkErr := filepath.WalkDir(tb.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || hits >= maxHits {
			if hits >= maxHits {
				return fs.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			if walkignore.SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if walkignore.SkipFile(d.Name()) {
			return nil
		}
		if fi, err := d.Info(); err == nil && walkignore.TooBig(fi.Size()) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(tb.root, path)
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				fmt.Fprintf(&b, "%s:%d: %s\n", rel, i+1, strings.TrimSpace(line))
				hits++
				if hits >= maxHits || b.Len() > maxToolOutput {
					return fs.SkipAll
				}
			}
		}
		return nil
	})
	if walkErr != nil && walkErr != fs.SkipAll {
		return "", walkErr
	}
	if hits == 0 {
		return "(no matches)", nil
	}
	return b.String(), nil
}

// ToolSpec describes one reviewer tool for the model: its name, purpose, and
// JSON-schema input shape. anthropic.go converts these to SDK tool params, so
// the tool catalog is declared once, here, dependency-free.
type ToolSpec struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ReviewToolSpecs is the catalog of read-only tools offered to the agentic
// reviewer.
func ReviewToolSpecs() []ToolSpec {
	return []ToolSpec{
		{
			Name:        "read_file_range",
			Description: "Read lines [start,end] (1-based, inclusive) of a source file in the scanned project. Use it to read code around the source, sink, or any taint-path step.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "file path (relative to the project root or absolute within it)"},
					"start": map[string]any{"type": "integer", "description": "first line (1-based)"},
					"end":   map[string]any{"type": "integer", "description": "last line (inclusive)"},
				},
				"required": []any{"path", "start", "end"},
			},
		},
		{
			Name:        "find_function",
			Description: "Resolve a function's canonical name (e.g. \"go:pkg.Sanitize\") to its source location and declaration, so you can read the body of a callee, a sanitizer, or a validator on the taint path.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "canonical function name, or a distinctive substring of it"},
				},
				"required": []any{"name"},
			},
		},
		{
			Name:        "grep",
			Description: "Search the scanned project for a regular expression and return matching file:line locations. Use it to find where a value is validated, where a route is registered, or other call sites.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":  map[string]any{"type": "string", "description": "a RE2 regular expression"},
					"max_hits": map[string]any{"type": "integer", "description": "maximum matches to return (default 50)"},
				},
				"required": []any{"pattern"},
			},
		},
	}
}

// dispatchTool executes a named reviewer tool with the model-supplied JSON input
// against tb and returns the tool result text. An unknown tool or malformed
// input yields an error string the model can read and recover from (the loop
// feeds it back as the tool result), rather than aborting the review.
func dispatchTool(tb ToolBox, name string, input json.RawMessage) string {
	switch name {
	case "read_file_range":
		var in struct {
			Path  string `json:"path"`
			Start int    `json:"start"`
			End   int    `json:"end"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "error: " + err.Error()
		}
		out, err := tb.ReadFileRange(in.Path, in.Start, in.End)
		if err != nil {
			return "error: " + err.Error()
		}
		return out
	case "find_function":
		var in struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "error: " + err.Error()
		}
		out, err := tb.FindFunction(in.Name)
		if err != nil {
			return "error: " + err.Error()
		}
		return out
	case "grep":
		var in struct {
			Pattern string `json:"pattern"`
			MaxHits int    `json:"max_hits"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "error: " + err.Error()
		}
		out, err := tb.Grep(in.Pattern, in.MaxHits)
		if err != nil {
			return "error: " + err.Error()
		}
		return out
	default:
		return "error: unknown tool " + name
	}
}

package llm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ir "godzilla/pkg/ir/v1"
)

// writeTree lays out files under a temp dir and returns the root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFileToolBox_ReadFileRange(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.go": "line1\nline2\nline3\nline4\nline5\n",
	})
	tb := NewFileToolBox(nil, root)

	out, err := tb.ReadFileRange("a.go", 2, 4)
	if err != nil {
		t.Fatalf("ReadFileRange: %v", err)
	}
	if !strings.Contains(out, "2: line2") || !strings.Contains(out, "4: line4") {
		t.Errorf("expected lines 2-4 numbered, got:\n%s", out)
	}
	if strings.Contains(out, "line1") || strings.Contains(out, "line5") {
		t.Errorf("range leaked lines outside [2,4]:\n%s", out)
	}

	// Range clamps past EOF instead of erroring.
	if _, err := tb.ReadFileRange("a.go", 4, 999); err != nil {
		t.Errorf("clamped range should succeed, got %v", err)
	}
}

func TestFileToolBox_PathConfinement(t *testing.T) {
	root := writeTree(t, map[string]string{"in.go": "ok\n"})
	// A secret file OUTSIDE the root the reviewer must never reach.
	outside := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	tb := NewFileToolBox(nil, root)

	for _, bad := range []string{"../secret.txt", "../../etc/passwd", outside} {
		if _, err := tb.ReadFileRange(bad, 1, 1); err == nil {
			t.Errorf("expected path %q to be rejected as outside the scan root", bad)
		}
	}
	// A legitimate in-root read still works.
	if _, err := tb.ReadFileRange("in.go", 1, 1); err != nil {
		t.Errorf("in-root read should succeed, got %v", err)
	}
}

func TestFileToolBox_FindFunction(t *testing.T) {
	root := writeTree(t, map[string]string{
		"h.go": "package main\n\nfunc Sanitize(s string) string {\n\treturn s\n}\n",
	})
	prog := &ir.Program{Modules: []*ir.Module{{
		Language: "go",
		Functions: []*ir.Function{{
			CanonicalName: "go:main.Sanitize",
			Pos:           &ir.Position{Filename: filepath.Join(root, "h.go"), Line: 3},
		}},
	}}}
	tb := NewFileToolBox(prog, root)

	out, err := tb.FindFunction("go:main.Sanitize")
	if err != nil {
		t.Fatalf("FindFunction exact: %v", err)
	}
	if !strings.Contains(out, "Sanitize") || !strings.Contains(out, "func Sanitize") {
		t.Errorf("expected the function source, got:\n%s", out)
	}

	// Unique substring match resolves too.
	if _, err := tb.FindFunction("Sanitize"); err != nil {
		t.Errorf("substring match should resolve, got %v", err)
	}
	// Unknown name errors.
	if _, err := tb.FindFunction("go:main.DoesNotExist"); err == nil {
		t.Errorf("expected an error for an unknown function")
	}
}

func TestFileToolBox_Grep(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.go":              "package main\nfunc validate() {}\n",
		"b.go":              "package main\n// no match here\n",
		"node_modules/x.js": "validate()\n", // skipped dir must not appear
	})
	tb := NewFileToolBox(nil, root)

	out, err := tb.Grep("validate", 10)
	if err != nil {
		t.Fatalf("Grep: %v", err)
	}
	if !strings.Contains(out, "a.go:2") {
		t.Errorf("expected match in a.go:2, got:\n%s", out)
	}
	if strings.Contains(out, "node_modules") {
		t.Errorf("grep must skip vendored dirs, got:\n%s", out)
	}

	// No matches is a clean, non-error result.
	if out, err := tb.Grep("zzz-nope", 10); err != nil || !strings.Contains(out, "no matches") {
		t.Errorf("expected a clean no-matches result, got %q err=%v", out, err)
	}
	// Invalid regex errors.
	if _, err := tb.Grep("(", 10); err == nil {
		t.Errorf("expected an invalid-pattern error")
	}
}

func TestDispatchTool(t *testing.T) {
	root := writeTree(t, map[string]string{"a.go": "one\ntwo\nthree\n"})
	tb := NewFileToolBox(nil, root)

	// read_file_range routes and returns content.
	in, _ := json.Marshal(map[string]any{"path": "a.go", "start": 1, "end": 2})
	if out := dispatchTool(tb, "read_file_range", in); !strings.Contains(out, "1: one") {
		t.Errorf("read_file_range dispatch failed: %s", out)
	}
	// grep routes.
	gin, _ := json.Marshal(map[string]any{"pattern": "two"})
	if out := dispatchTool(tb, "grep", gin); !strings.Contains(out, "a.go:2") {
		t.Errorf("grep dispatch failed: %s", out)
	}
	// Unknown tool yields a readable error (not a panic).
	if out := dispatchTool(tb, "nope", json.RawMessage(`{}`)); !strings.HasPrefix(out, "error:") {
		t.Errorf("unknown tool should return an error string, got %q", out)
	}
	// Malformed input yields a readable error.
	if out := dispatchTool(tb, "read_file_range", json.RawMessage(`{bad`)); !strings.HasPrefix(out, "error:") {
		t.Errorf("malformed input should return an error string, got %q", out)
	}
	// A confinement violation surfaces as an error result the model can read.
	bad, _ := json.Marshal(map[string]any{"path": "../escape", "start": 1, "end": 1})
	if out := dispatchTool(tb, "read_file_range", bad); !strings.HasPrefix(out, "error:") {
		t.Errorf("path escape should return an error string, got %q", out)
	}
}

// TestReviewToolSpecs sanity-checks the tool catalog the SDK layer converts.
func TestReviewToolSpecs(t *testing.T) {
	specs := ReviewToolSpecs()
	if len(specs) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(specs))
	}
	for _, s := range specs {
		if s.Name == "" || s.Description == "" {
			t.Errorf("tool %q missing name/description", s.Name)
		}
		if _, ok := s.InputSchema["properties"]; !ok {
			t.Errorf("tool %q missing input schema properties", s.Name)
		}
	}
}

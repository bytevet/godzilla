package analysis

import (
	"os"
	"path/filepath"
	"testing"

	go_converter "godzilla/converters/go"
	"godzilla/internal/rules"
)

// pathRule is a path-traversal rule with a filepath.IsLocal validator, matching
// the built-in go-path-traversal pack's ENG-9 guard.
func pathRule() *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:         "GO-PT",
		Languages:  []string{"go"},
		Severity:   rules.SeverityHigh,
		CWE:        "CWE-22",
		Message:    "path traversal",
		Sources:    []string{"go:*net/url*.Get"},
		Sinks:      []string{"go:os.ReadFile#0"},
		Validators: []string{"go:*filepath.IsLocal"},
	}}}
}

func scanSource(t *testing.T, src string, rs *rules.RuleSet) []Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module g\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := go_converter.NewConverter().ConvertFile(dir)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return NewEngine(rs).Analyze(prog)
}

// TestGuard_Suppressed is the ENG-9 core: a validator (filepath.IsLocal) that
// dominates the branch reaching the sink clears the checked value's taint, so
// the "validate, then use" idiom is not a false positive.
func TestGuard_Suppressed(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	if !filepath.IsLocal(name) {
		return
	}
	_, _ = os.ReadFile(name)
	_ = w
}

func main() { http.HandleFunc("/f", h); _ = http.ListenAndServe(":0", nil) }
`
	findings := scanSource(t, src, pathRule())
	for _, f := range findings {
		if f.RuleID == "GO-PT" {
			t.Errorf("false positive: sink guarded by filepath.IsLocal was flagged (sink %s at %v)", f.SinkCallee, f.SinkPos)
		}
	}
}

// TestGuard_UnguardedFires is the recall control: the SAME sink without the
// guard must still fire — the guard must not suppress unconditionally.
func TestGuard_UnguardedFires(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os"
)

func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	_, _ = os.ReadFile(name)
	_ = w
}

func main() { http.HandleFunc("/f", h); _ = http.ListenAndServe(":0", nil) }
`
	findings := scanSource(t, src, pathRule())
	got := 0
	for _, f := range findings {
		if f.RuleID == "GO-PT" {
			got++
		}
	}
	if got == 0 {
		t.Errorf("expected the unguarded path-traversal sink to fire, got %d finding(s)", len(findings))
	}
}

// TestGuard_WrongValueNotSuppressed guards precision of the guard itself: a
// validator applied to a DIFFERENT value than the one that reaches the sink must
// not suppress the finding (the origin match ties the guard to the specific
// flow). Here the request has two params; only `a` is validated, but `b` is what
// reaches the sink.
func TestGuard_WrongValueNotSuppressed(t *testing.T) {
	src := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func h(w http.ResponseWriter, r *http.Request) {
	a := r.URL.Query().Get("a")
	b := r.URL.Query().Get("b")
	if !filepath.IsLocal(a) {
		return
	}
	_, _ = os.ReadFile(b)
	_ = w
}

func main() { http.HandleFunc("/f", h); _ = http.ListenAndServe(":0", nil) }
`
	findings := scanSource(t, src, pathRule())
	got := 0
	for _, f := range findings {
		if f.RuleID == "GO-PT" {
			got++
		}
	}
	if got == 0 {
		t.Errorf("guard over-suppressed: validating `a` must not clear the taint on `b` that reaches the sink; got %d finding(s)", len(findings))
	}
}

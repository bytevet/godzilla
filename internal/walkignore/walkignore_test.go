package walkignore

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestInventory pins the one-walk cache's contracts: Select applies exactly the
// CollectSources policy (match + SkipFile + TooBig, sorted, absolute), Files
// keeps the caller's own path spelling with NO source-selection filtering (the
// detection/secrets view), and a missing root fails Select but leaves
// Files empty rather than erroring (the -strict/coverage split).
func TestInventory(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, size int) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.js", 10)
	write("sub/util.js", 10)
	write("vendor.min.js", 10)             // SkipFile: excluded from Select, present in Files
	write("huge.js", MaxSourceBytes+1)     // TooBig: excluded from Select, present in Files
	write("node_modules/dep/index.js", 10) // pruned dir: absent everywhere
	write(".env", 5)                       // non-JS: absent from Select, present in Files

	inv := NewInventory(dir)
	isJS := func(p string) bool { return strings.HasSuffix(p, ".js") }

	got, err := inv.Select(isJS)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	want, err := CollectSources(dir, isJS)
	if err != nil {
		t.Fatalf("CollectSources: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("Select = %v, want CollectSources result %v", got, want)
	}
	abs, _ := filepath.Abs(dir)
	if wantSel := []string{filepath.Join(abs, "app.js"), filepath.Join(abs, "sub", "util.js")}; !slices.Equal(got, wantSel) {
		t.Errorf("Select = %v, want %v", got, wantSel)
	}

	files := inv.Files()
	for _, rel := range []string{".env", "app.js", "huge.js", "vendor.min.js"} {
		if !slices.Contains(files, filepath.Join(dir, rel)) {
			t.Errorf("Files() missing %s (must be unfiltered, root as given): %v", rel, files)
		}
	}
	for _, f := range files {
		if strings.Contains(f, "node_modules") {
			t.Errorf("Files() must honor the SkipDir prune, got %s", f)
		}
	}
	if len(inv.AbsFiles()) != len(files) {
		t.Errorf("AbsFiles/Files length mismatch: %d vs %d", len(inv.AbsFiles()), len(files))
	}

	missing := NewInventory(filepath.Join(dir, "does-not-exist"))
	if _, err := missing.Select(isJS); err == nil {
		t.Error("Select on a missing root must fail (frontend abort-on-error contract)")
	}
	if n := len(missing.Files()); n != 0 {
		t.Errorf("Files on a missing root should be empty, got %d entries", n)
	}
}

func TestSkipDir(t *testing.T) {
	skip := []string{"node_modules", ".git", ".venv", "venv", "site-packages", "target", "dist", "build", "vendor", "__pycache__", ".gradle", ".next"}
	for _, d := range skip {
		if !SkipDir(d) {
			t.Errorf("expected %q to be skipped", d)
		}
	}
	keep := []string{"src", "app", "internal", "handlers", "lib", "cmd", "converters"}
	for _, d := range keep {
		if SkipDir(d) {
			t.Errorf("did not expect real source dir %q to be skipped", d)
		}
	}
}

func TestSkipFile(t *testing.T) {
	skip := []string{"app.min.js", "vendor.bundle.js", "site.min.css", "app.js.map", "types.d.ts"}
	for _, f := range skip {
		if !SkipFile(f) {
			t.Errorf("expected generated file %q to be skipped", f)
		}
	}
	keep := []string{"app.js", "index.ts", "main.go", "server.mjs", "handler.py"}
	for _, f := range keep {
		if SkipFile(f) {
			t.Errorf("did not expect real source %q to be skipped", f)
		}
	}
}

func TestTooBig(t *testing.T) {
	if TooBig(1000) {
		t.Error("a 1 KB file must not be too big")
	}
	if !TooBig(MaxSourceBytes + 1) {
		t.Error("a file over the cap must be too big")
	}
}

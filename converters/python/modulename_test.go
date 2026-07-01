package py_converter

import (
	"path/filepath"
	"testing"
)

// TestModuleNameForUniqueness verifies that same-named files in different
// directories get distinct module names (path-relative), so their same-named
// functions no longer collide in the analyzer's function map — while a
// single-file scan (root == the file's directory) keeps the bare name.
func TestModuleNameForUniqueness(t *testing.T) {
	root := filepath.FromSlash("/proj")
	a := filepath.FromSlash("/proj/ssrf/app.py")
	b := filepath.FromSlash("/proj/xss/app.py")

	if got := moduleNameFor(root, a); got != "ssrf/app" {
		t.Errorf("moduleNameFor(root, ssrf/app.py) = %q, want %q", got, "ssrf/app")
	}
	if got := moduleNameFor(root, b); got != "xss/app" {
		t.Errorf("moduleNameFor(root, xss/app.py) = %q, want %q", got, "xss/app")
	}
	if moduleNameFor(root, a) == moduleNameFor(root, b) {
		t.Error("same-named files in different dirs must get distinct module names")
	}

	// Single-file scan: root is the file's own directory -> bare name preserved.
	dir := filepath.FromSlash("/proj/ssrf")
	if got := moduleNameFor(dir, a); got != "app" {
		t.Errorf("single-file moduleNameFor = %q, want %q", got, "app")
	}
}

package rust_converter

import (
	"path/filepath"
	"testing"
)

// A cargo build runs rustc IN the crate directory, so its MIR spans are
// crate-relative while a direct source lowering reports absolute paths. Stored
// verbatim, "src/lib.rs" names no particular file — every crate in a workspace
// has one — so srclines cannot open it, SARIF cannot annotate it, and the two
// lowering paths disagree about the same finding. That disagreement is what made
// the rust position golden depend on whether cargo happened to run.
func TestSpanResolvesCrateRelativePath(t *testing.T) {
	const root = "/repo/crate"
	for _, tc := range []struct {
		name, comment, want string
	}{
		{"crate-relative span resolves against the crate dir",
			"// scope 0 at src/lib.rs:17:5: ~", filepath.Join(root, "src/lib.rs")},
		{"an absolute span is left alone",
			"// scope 0 at /repo/crate/src/lib.rs:17:5: ~", "/repo/crate/src/lib.rs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &lowerState{root: root}
			pos := st.span(tc.comment)
			if pos == nil {
				t.Fatalf("span(%q) = nil, want a position", tc.comment)
			}
			if pos.GetFilename() != tc.want {
				t.Errorf("filename = %q, want %q", pos.GetFilename(), tc.want)
			}
		})
	}
}

// The other half: rustc's own sysroot spans (everything expanded from format!)
// are absolute and OUTSIDE the tree, and must still be rejected rather than
// joined onto the crate dir.
func TestSpanStillRejectsSysrootPath(t *testing.T) {
	st := &lowerState{root: "/repo/crate"}
	if pos := st.span("// scope 0 at /rustc/abc123/library/alloc/src/macros.rs:9:1: ~"); pos != nil {
		t.Errorf("span of a sysroot path = %q, want nil (no last position to fall back to)", pos.GetFilename())
	}
}

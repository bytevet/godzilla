// Package walkignore centralizes which directories and files a source scan
// should prune. Every frontend walks the target tree looking for source; before
// this, each did so with its own ad-hoc (or missing) exclusion list, so a
// populated .venv / site-packages / dist / target could be fully parsed —
// dominating scan time and analyzing code that is not the project's own. This
// gives one shared policy: skip VCS metadata, dependency/vendor trees, virtual
// environments, build output, and editor/tool caches, and skip individual files
// that are too large or are obviously generated/minified bundles.
package walkignore

import "strings"

// skipDirs are directory base names pruned from every source walk.
var skipDirs = map[string]bool{
	// version control
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
	// JS/TS deps & build output
	"node_modules": true, "bower_components": true, "dist": true, "build": true,
	"out": true, ".next": true, ".nuxt": true, ".svelte-kit": true, "coverage": true,
	// Go/Rust/Java vendor & build output
	"vendor": true, "target": true, ".gradle": true,
	// Python virtual envs & caches (bare "env" is intentionally NOT skipped —
	// projects use it for real config, and dropping real source is worse than
	// walking a virtualenv)
	".venv": true, "venv": true, "virtualenv": true,
	"site-packages": true, "__pycache__": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true,
	// tooling / editor / infra caches
	".idea": true, ".vscode": true, ".terraform": true, ".cache": true,
}

// SkipDir reports whether a directory with the given base name should be pruned
// from a source walk. Callers return filepath.SkipDir when it does.
func SkipDir(name string) bool {
	return skipDirs[name]
}

// MaxSourceBytes caps the size of a single source file a frontend will read. A
// larger "source" file is almost always generated, minified, or a bundled asset
// — not hand-written code worth analyzing — and parsing it is disproportionately
// expensive.
const MaxSourceBytes = 2 << 20 // 2 MiB

// TooBig reports whether a file of the given size exceeds the source cap.
func TooBig(size int64) bool {
	return size > MaxSourceBytes
}

// SkipFile reports whether a file base name is an obviously generated/minified
// artifact (a bundle or a sourcemap) that should not be analyzed as source.
func SkipFile(name string) bool {
	lower := strings.ToLower(name)
	// .d.ts = TS declaration files, which carry no runtime code.
	for _, suffix := range []string{".min.js", ".min.css", ".bundle.js", ".map", ".d.ts"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

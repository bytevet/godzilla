// Package walkignore is the one shared policy for which directories and files a
// source scan prunes: skip VCS metadata, dependency/vendor trees, virtual
// environments, build output and editor/tool caches, plus individual files that
// are too large or are obviously generated/minified bundles. Without it a
// populated .venv / site-packages / dist / target gets fully parsed, dominating
// scan time and analyzing code that is not the project's own.
package walkignore

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// walk is the shared pruned WalkDir loop behind Files and NewInventory: prune
// the directories SkipDir names, report every surviving FILE to fn, and hand a
// walk error on an entry to onErr instead of aborting — a scan should not die
// on one unreadable path. fn's return value goes back to filepath.WalkDir, so
// it may return fs.SkipDir or fs.SkipAll to steer the walk.
func walk(root string, onErr func(error), fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			onErr(err)
			return nil
		}
		if d.IsDir() {
			if SkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(p, d)
	})
}

// Files walks root and calls fn for every FILE, pruning the directories SkipDir
// names (see walk). Use it rather than a private WalkDir so that teaching
// SkipDir about a new vendor directory reaches every caller at once.
func Files(root string, fn func(path string, d fs.DirEntry) error) error {
	return walk(root, func(error) {}, fn)
}

// Inventory is the cached result of ONE pruned walk of a directory scan root:
// every file surviving the SkipDir prune, in walk (lexical) order, with its
// size. Language detection, each frontend's source selection, the config-file
// secrets pass and the Java source index all read it, so the tree is
// stat'd/readdir'd exactly once per scan.
//
// The walk never aborts: an unreadable entry is skipped and the FIRST such error
// recorded. The two consumer paths then differ deliberately — Select (the
// frontend path) FAILS with that error, because a frontend that could not read
// its own source tree must not silently report on a subset (Result.Coverage and
// -strict rest on that), while Files/AbsFiles skip it.
type Inventory struct {
	root    string   // scan root exactly as the caller gave it
	absRoot string   // filepath.Abs(root); the frontends' module root (CollectTarget contract)
	rels    []string // walk-ordered file paths relative to root
	sizes   []int64  // per-file size, index-aligned with rels (0 when stat failed)
	err     error    // first walk error; surfaced by Select

	// The two joined path spellings, each built lazily ONCE and then shared:
	// frontends read the inventory from parallel goroutines, and re-joining
	// root+rel per consumer dominates. Returned slices are read-only.
	absOnce   sync.Once
	absFiles  []string // rels joined on absRoot (Select, AbsFiles)
	rootOnce  sync.Once
	rootFiles []string // rels joined on root as given (Files)
}

// NewInventory walks root once under the shared prune policy and returns the
// resulting file inventory. It never fails: a missing or unreadable root simply
// yields an empty inventory whose Select reports the error.
func NewInventory(root string) *Inventory {
	inv := &Inventory{root: root}
	inv.absRoot, inv.err = filepath.Abs(root)
	if inv.err != nil {
		inv.absRoot = root
	}
	recordErr := func(err error) {
		if inv.err == nil {
			inv.err = err
		}
	}
	_ = walk(root, recordErr, func(p string, d fs.DirEntry) error {
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			recordErr(rerr)
			return nil
		}
		var size int64
		if fi, e := d.Info(); e == nil {
			size = fi.Size()
		}
		inv.rels = append(inv.rels, rel)
		inv.sizes = append(inv.sizes, size)
		return nil
	})
	return inv
}

// Root returns the ABSOLUTE scan root — what CollectTarget hands a frontend as
// its module root, so module names derived via ModuleName stay identical
// whether the file list came from an inventory or a standalone walk.
func (inv *Inventory) Root() string { return inv.absRoot }

// Select returns the sorted absolute paths of the inventoried files for which
// match(path) is true, applying the per-file source-selection policy: skip
// generated/minified files (SkipFile) and oversized files (TooBig). A walk
// error recorded at inventory time fails Select — the frontends'
// abort-on-error contract (see the type comment).
func (inv *Inventory) Select(match func(path string) bool) ([]string, error) {
	if inv.err != nil {
		return nil, inv.err
	}
	abs := inv.joinedAbs()
	var files []string
	for i, p := range abs {
		if match(p) && !SkipFile(filepath.Base(inv.rels[i])) && !TooBig(inv.sizes[i]) {
			files = append(files, p)
		}
	}
	sort.Strings(files)
	return files, nil
}

// Files returns every inventoried file joined on the root AS GIVEN, in walk
// order, for consumers that count files (language detection) or report positions
// in the user's own path spelling (the config-file secrets pass).
// SkipFile/TooBig are deliberately NOT applied; those are source-selection
// policies. Shared cache — read-only for callers.
func (inv *Inventory) Files() []string {
	return inv.joinedRoot()
}

// AbsFiles is Files rendered against the absolute root, for consumers that
// anchor findings to resolved paths (the Java source index). Shared cache —
// read-only for callers.
func (inv *Inventory) AbsFiles() []string {
	return inv.joinedAbs()
}

// joinedAbs and joinedRoot build (once, goroutine-safely — frontends read the
// inventory from parallel goroutines) and return the cached joined spellings.
func (inv *Inventory) joinedAbs() []string {
	inv.absOnce.Do(func() {
		inv.absFiles = joinAll(inv.absRoot, inv.rels)
	})
	return inv.absFiles
}

func (inv *Inventory) joinedRoot() []string {
	inv.rootOnce.Do(func() {
		if inv.root == inv.absRoot {
			inv.rootFiles = inv.joinedAbs()
			return
		}
		inv.rootFiles = joinAll(inv.root, inv.rels)
	})
	return inv.rootFiles
}

func joinAll(root string, rels []string) []string {
	files := make([]string, len(rels))
	for i, rel := range rels {
		files[i] = filepath.Join(root, rel)
	}
	return files
}

// CollectTarget resolves a scan target — a single source file or a directory —
// into the module ROOT and the list of files to lower, the standalone entry
// point behind the Python, JS and Ruby frontends. The rule that matters: for a
// directory the root IS the directory, while for a SINGLE FILE the root is the
// file's own directory, which keeps its module name the bare filename (see
// ModuleName). isDir is returned because each frontend branches on it — a
// single-file scan surfaces a parse error immediately, a directory batch does
// not let one bad file abort the rest.
//
// A directory is collected under the shared prune policy (one NewInventory walk
// + Select). A walk error FAILS the collection rather than being skipped, for
// the reason in Inventory's doc. (The scan pipeline instead walks once via
// NewInventory and hands each frontend the same Inventory.)
func CollectTarget(path string, match func(p string) bool) (root string, files []string, isDir bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, false, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", nil, false, err
	}
	if info.IsDir() {
		files, err = NewInventory(abs).Select(match)
		if err != nil {
			return "", nil, true, err
		}
		return abs, files, true, nil
	}
	return filepath.Dir(abs), []string{abs}, false, nil
}

// ModuleName derives a module name unique to file: its path relative to the
// scan root, extension stripped, slash-normalized (e.g. "ssrf/app"). When root
// is the file's own directory (a single-file scan) this is just the bare
// filename.
//
// This shape is a CROSS-FRONTEND CONTRACT: Python, JS and Ruby name modules this
// way so same-named functions in different files get distinct canonical names
// instead of colliding, and their cross-module call resolution
// (resolveCrossModuleCalls) reconstructs a callee's module the same way. Call
// this rather than re-deriving it.
func ModuleName(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = filepath.Base(file)
	}
	return filepath.ToSlash(strings.TrimSuffix(rel, filepath.Ext(rel)))
}

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

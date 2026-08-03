package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	ir "godzilla/pkg/ir/v1"
)

// fingerprintCwd memoizes os.Getwd for fingerprinting: the working directory
// does not change during a scan, and fingerprintPath runs twice per finding on
// every surface that fingerprints (baseline triage, HTML/JSON/SARIF reports).
// Empty on Getwd failure, in which case absolute paths pass through unchanged
// — exactly how a per-call Getwd failure degraded before.
var fingerprintCwd = sync.OnceValue(func() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
})

// Fingerprint returns a stable identifier for a finding, suitable for baseline
// matching and diff-aware gating. It deliberately hashes only line-INDEPENDENT
// attributes — the rule, the repo-relative sink and source file paths, the
// enclosing function, and the sink callee — and NOT line/column numbers, so
// editing unrelated code above a finding does not change its fingerprint.
//
// Two distinct findings that share all of those attributes (e.g. two calls to
// the same sink in one function) collide by design; callers that need to tell
// them apart consume fingerprints as a multiset (see the triage package's
// baseline matching), which is stable under add/remove of a single occurrence.
func Fingerprint(f Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s",
		f.RuleID,
		fingerprintPath(f.SinkPos),
		fingerprintPath(f.SourcePos),
		f.Function,
		f.SinkCallee,
	)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// fingerprintPath renders a position's file as a stable, repo-relative,
// forward-slashed path so a fingerprint computed in a CI checkout matches one
// computed locally. Absolute paths (the Go SSA frontend emits them) are made
// relative to the working directory; anything that would escape it, or a
// relative path, is passed through with normalized separators.
func fingerprintPath(pos *ir.Position) string {
	if pos == nil {
		return ""
	}
	name := pos.GetFilename()
	if name == "" || !filepath.IsAbs(name) {
		return filepath.ToSlash(name)
	}
	if cwd := fingerprintCwd(); cwd != "" {
		if rel, err := filepath.Rel(cwd, name); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(name)
}

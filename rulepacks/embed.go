// Package rulepacks holds Godzilla's built-in taint rule packs (the *.yaml in
// this directory) and embeds them into the binary so it ships with a working
// rule set and no external files.
//
// The YAML lives at the repo top level for discoverability — adding or editing
// a detection rule is usually a change here, not in Go code. The loader
// (internal/rules/loader) consumes Builtin; go:embed requires the embedding Go
// file to sit alongside the data, which is why this shim lives here rather than
// in the loader package.
package rulepacks

import "embed"

// Builtin embeds every shipped rule pack (rulepacks/*.yaml).
//
//go:embed *.yaml
var Builtin embed.FS

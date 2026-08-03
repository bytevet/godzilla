// Package loader reads Godzilla taint rules from YAML files (user-supplied or
// built-in) into rules.RuleSet values.
//
// # Fragments (`extend:`)
//
// To avoid copy-pasting the same source/propagator lists into every rulepack, a
// `_`-prefixed YAML file (e.g. rulepacks/_go-common.yaml) is a FRAGMENT: a
// partial rule (a mapping of pattern-list fields such as sources/propagators/
// request_object_sources), not a rulepack. A rule pulls a fragment in with a
// top-level `extend: $_go-common.yaml` (or a list, `extend: [$_a.yaml,
// $_b.yaml]`); the loader appends each fragment's list fields ahead of the
// rule's own (deduped) before the rule is validated or compiled. A rule keeps
// its own scalar fields (id/severity/cwe/message) and adds its own sinks and any
// extra sources/propagators. Builtin fragments are always available; a user
// rules directory may add its own (or override a builtin of the same name).
package loader

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"godzilla/internal/rules"
	"godzilla/rulepacks"
)

// LoadFile reads a single YAML rule file and unmarshals it into a RuleSet,
// expanding any `$<fragment>` references against the builtin fragments plus any
// fragment files sitting in the same directory.
func LoadFile(path string) (*rules.RuleSet, error) {
	frags, err := fragmentsFor(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loader: read %s: %w", path, err)
	}
	rs, err := parse(path, data, frags)
	if err != nil {
		return nil, err
	}
	if err := checkDuplicateIDs(rs); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", path, err)
	}
	if f := frags[defaultPropagatorsFragment]; f != nil {
		rs.DefaultPropagators = f.Propagators
	}
	return rs, nil
}

// LoadDir loads and merges every *.yaml/*.yml rulepack directly under dir
// (non-recursive). Files are read in the order returned by os.ReadDir, which is
// lexical. `_`-prefixed fragment files are consumed as fragments, not rules.
func LoadDir(dir string) (*rules.RuleSet, error) {
	frags, err := fragmentsFor(dir)
	if err != nil {
		return nil, err
	}
	return loadRules(os.DirFS(dir), dir, frags)
}

// Builtin loads Godzilla's embedded, shipped-in-the-binary rule set (the
// top-level rulepacks/*.yaml), expanding `$<fragment>` references against the
// embedded `_`-prefixed fragment files.
func Builtin() (*rules.RuleSet, error) {
	frags, err := builtinFragments()
	if err != nil {
		return nil, err
	}
	return loadRules(rulepacks.Builtin, "builtin rulepacks", frags)
}

// loadRules parses every non-fragment *.yaml/*.yml rulepack directly under fsys's
// root against frags, concatenates their rules, and rejects duplicate ids. what
// labels fsys in wrapped errors. Shared by LoadDir (an on-disk directory) and
// Builtin (the embedded rulepacks FS), which differ only in the filesystem.
func loadRules(fsys fs.FS, what string, frags fragmentSet) (*rules.RuleSet, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("loader: read %s: %w", what, err)
	}
	out := &rules.RuleSet{}
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) || isFragment(entry.Name()) {
			continue
		}
		data, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("loader: read %s: %w", entry.Name(), err)
		}
		rs, err := parse(entry.Name(), data, frags)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, rs.Rules...)
	}
	if f := frags[defaultPropagatorsFragment]; f != nil {
		out.DefaultPropagators = f.Propagators
	}
	if err := checkDuplicateIDs(out); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", what, err)
	}
	return out, nil
}

// defaultPropagatorsFragment is the one fragment no rule names in `extend:`: the
// loader applies its propagators to EVERY rule (RuleSet.DefaultPropagators).
// Making each pack extend it would restate the same list in all 60-odd packs —
// exactly the boilerplate the rule-level `when:` default removed elsewhere.
const defaultPropagatorsFragment = "_default-propagators.yaml"

// LoadDefault returns Godzilla's built-in rules merged with the user-supplied
// rule file — or rulepack directory — at userPath, if any (userPath == ""
// means "no user rules"). User rules are appended after built-ins, so they
// take effect alongside (not instead of) the defaults.
func LoadDefault(userPath string) (*rules.RuleSet, error) {
	builtin, err := Builtin()
	if err != nil {
		return nil, err
	}
	if userPath == "" {
		return builtin, nil
	}

	// A directory loads every rulepack under it (LoadDir); anything else is a
	// single rule file — the `--rules <file-or-dir>` contract in
	// docs/writing-rules.md.
	load := LoadFile
	if fi, err := os.Stat(userPath); err == nil && fi.IsDir() {
		load = LoadDir
	}
	user, err := load(userPath)
	if err != nil {
		return nil, err
	}

	return &rules.RuleSet{
		Rules: slices.Concat(builtin.Rules, user.Rules),
		// User rules add to the built-ins rather than replacing them, so the
		// set-wide propagators must survive the merge. A user directory that ships
		// its own _default-propagators.yaml has already overridden them in
		// LoadFile's fragment set.
		DefaultPropagators: firstNonEmpty(user.DefaultPropagators, builtin.DefaultPropagators),
	}, nil
}

// firstNonEmpty returns a if it has elements, else b.
func firstNonEmpty(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

// parse unmarshals YAML rule data, expands fragment references, and validates
// the result, wrapping any error with source (a file path or embedded-file
// name) for context.
func parse(source string, data []byte, frags fragmentSet) (*rules.RuleSet, error) {
	var rs rules.RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("loader: parse %s: %w", source, err)
	}
	if err := frags.apply(&rs); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", source, err)
	}
	if err := validate(&rs); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", source, err)
	}
	return &rs, nil
}

// fragmentSet maps a fragment filename (e.g. "_go-common.yaml") to the partial
// rule holding its shared pattern-list fields.
type fragmentSet map[string]*rules.Rule

// isFragment reports whether name is a fragment file: a `_`-prefixed YAML file
// holding a partial rule, merged into rules via `extend:` and never parsed as a
// standalone RuleSet.
func isFragment(name string) bool {
	return isYAML(name) && strings.HasPrefix(name, "_")
}

// add unmarshals a fragment file's bytes (a partial rule) under its filename key.
func (f fragmentSet) add(name string, data []byte) error {
	var r rules.Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("loader: parse fragment %s: %w", name, err)
	}
	f[name] = &r
	return nil
}

// apply merges every `extend:`-referenced fragment's pattern-list fields into the
// rule and clears Extend. A reference to an unknown fragment is an error (a typo
// would otherwise silently drop the whole shared base).
func (f fragmentSet) apply(rs *rules.RuleSet) error {
	var problems []string
	for i := range rs.Rules {
		r := &rs.Rules[i]
		for _, ref := range r.Extend {
			name := strings.TrimPrefix(ref, "$")
			base, ok := f[name]
			if !ok {
				problems = append(problems, fmt.Sprintf("rule %q extends unknown fragment %q", r.ID, ref))
				continue
			}
			mergeFragment(r, base)
		}
		r.Extend = nil // consumed; never reaches the matcher
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid extend references: %s", strings.Join(problems, "; "))
	}
	return nil
}

// mergeFragment prepends base's pattern-list entries to dst's (see mergeUniq).
// Scalar fields (id/severity/cwe/message/kind) are left to the rule itself.
func mergeFragment(dst, base *rules.Rule) {
	dst.Sources = mergeUniq(base.Sources, dst.Sources)
	dst.Sinks = mergeUniq(base.Sinks, dst.Sinks)
	dst.Sanitizers = mergeUniq(base.Sanitizers, dst.Sanitizers)
	dst.Propagators = mergeUniq(base.Propagators, dst.Propagators)
	dst.RequestObjectSources = mergeUniq(base.RequestObjectSources, dst.RequestObjectSources)
	dst.Validators = mergeUniq(base.Validators, dst.Validators)
	dst.Callees = mergeUniq(base.Callees, dst.Callees)
	// `when:` is the one scalar a fragment contributes; own-wins.
	if dst.When == "" {
		dst.When = base.When
	}
}

// mergeUniq returns base entries followed by own entries, with duplicates
// removed (first occurrence wins), so a rule inherits its fragment's list and
// then appends its own additions. Works for glob strings and for the Sink/Callee
// structs — note a dynamic entry differing only in `when` is a DISTINCT entry, and
// MatchSink returns the first match, so a bare base entry shadows a guarded one
// the rule adds for the same glob.
func mergeUniq[T comparable](base, own []T) []T {
	if len(base) == 0 {
		return own
	}
	out := make([]T, 0, len(base)+len(own))
	seen := make(map[T]bool, len(base)+len(own))
	for _, e := range slices.Concat(base, own) {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// readFragments adds every `_`-prefixed fragment file directly under fsys's root
// to into. what labels fsys in wrapped errors. Shared by builtinFragments (the
// embedded rulepacks FS) and fragmentsFor (a user rules directory), which differ
// only in the filesystem — like loadRules for the rulepacks themselves.
func readFragments(fsys fs.FS, what string, into fragmentSet) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("loader: read %s: %w", what, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isFragment(entry.Name()) {
			continue
		}
		data, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return fmt.Errorf("loader: read fragment %s: %w", entry.Name(), err)
		}
		if err := into.add(entry.Name(), data); err != nil {
			return err
		}
	}
	return nil
}

// builtinFragments reads the embedded `_`-prefixed fragment files.
func builtinFragments() (fragmentSet, error) {
	frags := fragmentSet{}
	if err := readFragments(rulepacks.Builtin, "embedded builtin rules", frags); err != nil {
		return nil, err
	}
	return frags, nil
}

// fragmentsFor returns the builtin fragments extended with any fragment files
// directly under dir (a user rules directory may add its own or override a
// builtin of the same name). A missing/unreadable dir contributes nothing —
// only the DIRECTORY read is forgiven; a fragment file that exists but cannot be
// read or parsed is still an error.
func fragmentsFor(dir string) (fragmentSet, error) {
	frags, err := builtinFragments()
	if err != nil {
		return nil, err
	}
	if _, err := os.ReadDir(dir); err != nil {
		return frags, nil // no user fragments
	}
	frags = maps.Clone(frags)
	if err := readFragments(os.DirFS(dir), dir, frags); err != nil {
		return nil, err
	}
	return frags, nil
}

// checkDuplicateIDs rejects a RuleSet declaring the same rule id twice. Duplicate
// ids silently double-report and make a rule un-addressable by the baseline /
// `godzilla:ignore` machinery; the copy-paste-heavy rulepacks make collisions
// easy, so the merged set is checked after loading.
func checkDuplicateIDs(rs *rules.RuleSet) error {
	seen := make(map[string]bool, len(rs.Rules))
	var dups []string
	for _, r := range rs.Rules {
		id := strings.TrimSpace(r.ID)
		if id == "" {
			continue // empty ids are rejected by validate
		}
		if seen[id] {
			dups = append(dups, id)
			continue
		}
		seen[id] = true
	}
	if len(dups) > 0 {
		return fmt.Errorf("duplicate rule ids: %s", strings.Join(dups, ", "))
	}
	return nil
}

// validate performs light sanity checks on a freshly-loaded RuleSet. It
// returns a single error listing every invalid rule found, if any.
func validate(rs *rules.RuleSet) error {
	var problems []string
	for i, r := range rs.Rules {
		if strings.TrimSpace(r.ID) == "" {
			problems = append(problems, fmt.Sprintf("rule at index %d has an empty id", i))
		}
		// A rule with a missing/misspelled severity ranks 0 and could never
		// fail the CI gate at any -fail-on threshold — reject it at load time.
		if r.Severity.Rank() == 0 {
			problems = append(problems, fmt.Sprintf("rule %q has missing or unrecognized severity %q (want info|low|medium|high|critical)", r.ID, r.Severity))
		}
		// A misspelled confidence would silently fall back to the default AND be
		// invisible to the LLM reviewer (analysis.Confidence.Rank ranks an unknown value 0, so
		// shouldReview never picks it up) — reject it at load, like an unrecognized
		// severity, instead of shipping a rule that is quietly un-triageable.
		if !rules.ValidConfidence(r.Confidence) {
			problems = append(problems, fmt.Sprintf("rule %q has unrecognized confidence %q (want low|medium|high, or omit for the default)", r.ID, r.Confidence))
		}
		// A sink with a "#" injection-point spec that names no valid argument
		// index silently widens to "all arguments" (a false-positive-prone
		// footgun); reject the typo instead of quietly weakening the sink. A
		// dynamic sink's `when:` guard must compile (this is where a bad guard
		// fails loud at load / `rules lint` instead of silently suppressing).
		for _, s := range r.Sinks {
			if rules.InvalidSinkSpec(s.Pattern) {
				problems = append(problems, fmt.Sprintf("rule %q has sink %q with a '#' injection-point spec but no valid (non-negative integer) argument index", r.ID, s.Pattern))
			}
		}
		// Compile the rule here (idempotent, so the engine's later Compile is a
		// no-op): this compiles its dynamic `when:` guards and its const_arg regexp
		// exactly once per run and surfaces any error at load instead of letting it
		// reach a scan. A const_arg declared but uncompilable would otherwise leave
		// a rule that can never match, silently.
		if err := rs.Rules[i].Compile(); err != nil {
			problems = append(problems, fmt.Sprintf("rule %q failed to compile: %v", r.ID, err))
		}
		// A dangerous-call rule (COV-4) is defined by its callees; without any it
		// can never fire.
		if r.IsDangerousCall() && len(r.Callees) == 0 {
			problems = append(problems, fmt.Sprintf("rule %q is kind: dangerous-call but declares no callees", r.ID))
		}
		// A secret rule is defined by its `matches` regexp, and Compile above has
		// already surfaced an uncompilable one. Without a regexp it silently scans
		// nothing, which looks like "no secrets in this repo".
		if r.IsSecret() && strings.TrimSpace(r.Matches) == "" {
			problems = append(problems, fmt.Sprintf("rule %q is kind: secret but declares no matches regexp", r.ID))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid rules: %s", strings.Join(problems, "; "))
	}
	return nil
}

func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

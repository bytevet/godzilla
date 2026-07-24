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
	"regexp"
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
	if err := checkDuplicateIDs(out); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", what, err)
	}
	return out, nil
}

// LoadDefault returns Godzilla's built-in rules merged with the user-supplied
// rule file at userPath, if any (userPath == "" means "no user rules"). User
// rules are appended after built-ins, so they take effect alongside (not
// instead of) the defaults.
func LoadDefault(userPath string) (*rules.RuleSet, error) {
	builtin, err := Builtin()
	if err != nil {
		return nil, err
	}
	if userPath == "" {
		return builtin, nil
	}

	user, err := LoadFile(userPath)
	if err != nil {
		return nil, err
	}

	return &rules.RuleSet{
		Rules: slices.Concat(builtin.Rules, user.Rules),
	}, nil
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
}

// mergeUniq returns base entries followed by own entries, with duplicates
// removed (first occurrence wins), so a rule inherits its fragment's list and
// then appends its own additions. Works for glob strings and for the
// Sink/Callee structs (a dynamic entry differing only in `when` is kept).
func mergeUniq[T comparable](base, own []T) []T {
	if len(base) == 0 {
		return own
	}
	out := make([]T, 0, len(base)+len(own))
	seen := make(map[T]bool, len(base)+len(own))
	add := func(list []T) {
		for _, e := range list {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	add(base)
	add(own)
	return out
}

// builtinFragments reads the embedded `_`-prefixed fragment files.
func builtinFragments() (fragmentSet, error) {
	entries, err := rulepacks.Builtin.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("loader: read embedded builtin rules: %w", err)
	}
	frags := fragmentSet{}
	for _, entry := range entries {
		if entry.IsDir() || !isFragment(entry.Name()) {
			continue
		}
		data, err := rulepacks.Builtin.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("loader: read embedded fragment %s: %w", entry.Name(), err)
		}
		if err := frags.add(entry.Name(), data); err != nil {
			return nil, err
		}
	}
	return frags, nil
}

// fragmentsFor returns the builtin fragments extended with any fragment files
// directly under dir (a user rules directory may add its own or override a
// builtin of the same name). A missing/unreadable dir contributes nothing.
func fragmentsFor(dir string) (fragmentSet, error) {
	frags, err := builtinFragments()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return frags, nil // no user fragments
	}
	frags = maps.Clone(frags)
	for _, entry := range entries {
		if entry.IsDir() || !isFragment(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("loader: read fragment %s: %w", entry.Name(), err)
		}
		if err := frags.add(entry.Name(), data); err != nil {
			return nil, err
		}
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
		// A sink with a "#" injection-point spec that names no valid argument
		// index silently widens to "all arguments" (a false-positive-prone
		// footgun); reject the typo instead of quietly weakening the sink. A
		// dynamic sink's `when:` guard must compile (this is where a bad guard
		// fails loud at load / `rules lint` instead of silently suppressing).
		for _, s := range r.Sinks {
			if rules.InvalidSinkSpec(s.Pattern) {
				problems = append(problems, fmt.Sprintf("rule %q has sink %q with a '#' injection-point spec but no valid (non-negative integer) argument index", r.ID, s.Pattern))
			}
			if _, err := rules.CompileGuard(s.When); err != nil {
				problems = append(problems, fmt.Sprintf("rule %q sink %q has an invalid when: %v", r.ID, s.Pattern, err))
			}
		}
		for _, c := range r.Callees {
			if _, err := rules.CompileGuard(c.When); err != nil {
				problems = append(problems, fmt.Sprintf("rule %q callee %q has an invalid when: %v", r.ID, c.Pattern, err))
			}
		}
		// A dangerous-call rule (COV-4) is defined by its callees; without any it
		// can never fire, and its const_arg regexp must compile.
		if r.IsDangerousCall() {
			if len(r.Callees) == 0 {
				problems = append(problems, fmt.Sprintf("rule %q is kind: dangerous-call but declares no callees", r.ID))
			}
			if r.ConstArg != nil && r.ConstArg.Matches != "" {
				if _, err := regexp.Compile(r.ConstArg.Matches); err != nil {
					problems = append(problems, fmt.Sprintf("rule %q has an invalid const_arg.matches regexp %q: %v", r.ID, r.ConstArg.Matches, err))
				}
			}
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

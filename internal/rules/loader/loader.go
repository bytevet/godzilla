// Package loader reads Godzilla taint rules from YAML files (user-supplied or
// built-in) into rules.RuleSet values.
package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"godzilla/internal/rules"
	"godzilla/rulepacks"
)

// LoadFile reads a single YAML rule file and unmarshals it into a RuleSet.
func LoadFile(path string) (*rules.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loader: read %s: %w", path, err)
	}
	return parse(path, data)
}

// LoadDir loads and merges every *.yaml/*.yml file directly under dir
// (non-recursive). Files are read in the order returned by os.ReadDir, which
// is lexical.
func LoadDir(dir string) (*rules.RuleSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("loader: read dir %s: %w", dir, err)
	}

	out := &rules.RuleSet{}
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		rs, err := LoadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, rs.Rules...)
	}
	return out, nil
}

// Builtin loads Godzilla's embedded, shipped-in-the-binary rule set (the
// top-level rulepacks/*.yaml).
func Builtin() (*rules.RuleSet, error) {
	entries, err := rulepacks.Builtin.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("loader: read embedded builtin rules: %w", err)
	}

	out := &rules.RuleSet{}
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		data, err := rulepacks.Builtin.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("loader: read embedded rule file %s: %w", entry.Name(), err)
		}
		rs, err := parse(entry.Name(), data)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, rs.Rules...)
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

// parse unmarshals YAML rule data and validates the result, wrapping any
// error with source (a file path or embedded-file name) for context.
func parse(source string, data []byte) (*rules.RuleSet, error) {
	var rs rules.RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("loader: parse %s: %w", source, err)
	}
	if err := validate(&rs); err != nil {
		return nil, fmt.Errorf("loader: %s: %w", source, err)
	}
	return &rs, nil
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
		// footgun); reject the typo instead of quietly weakening the sink.
		for _, s := range r.Sinks {
			if rules.InvalidSinkSpec(s) {
				problems = append(problems, fmt.Sprintf("rule %q has sink %q with a '#' injection-point spec but no valid (non-negative integer) argument index", r.ID, s))
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

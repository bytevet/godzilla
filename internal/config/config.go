// Package config loads a per-project .godzilla.yaml so a repository can carry
// its scan policy in version control (CI-5): the gate threshold, path
// include/exclude filters (e.g. drop findings in test fixtures or generated
// code), and per-rule disable / severity overrides. CLI flags take precedence
// over file values.
package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"godzilla/internal/analysis"
	"godzilla/internal/rules"

	"gopkg.in/yaml.v3"
)

// Config is the parsed .godzilla.yaml. Every field is optional.
type Config struct {
	// FailOn is the gate threshold (info|low|medium|high|critical). A CLI
	// -fail-on overrides it.
	FailOn string `yaml:"fail-on"`
	// Exclude drops findings whose file matches any of these path globs. Include,
	// when non-empty, keeps only findings whose file matches one of them (applied
	// before Exclude). Globs use '*' (within a path segment), '**' (across
	// segments), and a bare name matches any path segment (so "testdata" matches
	// any testdata/ directory).
	Exclude []string `yaml:"exclude"`
	Include []string `yaml:"include"`
	Rules   Rules    `yaml:"rules"`
}

// Rules holds per-rule policy.
type Rules struct {
	Disable           []string          `yaml:"disable"`            // rule IDs to drop entirely
	SeverityOverrides map[string]string `yaml:"severity-overrides"` // rule ID -> new severity
}

// Load reads .godzilla.yaml (or .godzilla.yml) from root. When root is a file,
// its directory is used. It returns (nil, "", nil) when no config file exists —
// a missing config is not an error. The returned string is the path loaded.
func Load(root string) (*Config, string, error) {
	dir := containingDir(root)
	for _, name := range []string{".godzilla.yaml", ".godzilla.yml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			c, err := LoadFile(p)
			return c, p, err
		}
	}
	return nil, "", nil
}

// containingDir returns path's parent directory when path is an existing file,
// otherwise path unchanged.
func containingDir(path string) string {
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

// LoadFile parses a config file at an explicit path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyRules returns a copy of rs with the config's disabled rules removed and
// severity overrides applied. It leaves rs untouched. Unknown rule IDs in the
// config are ignored (a rule may simply not be loaded).
func (c *Config) ApplyRules(rs *rules.RuleSet) *rules.RuleSet {
	if c == nil || rs == nil {
		return rs
	}
	disabled := map[string]bool{}
	for _, id := range c.Rules.Disable {
		disabled[id] = true
	}
	out := &rules.RuleSet{Rules: make([]rules.Rule, 0, len(rs.Rules))}
	for _, r := range rs.Rules {
		if disabled[r.ID] {
			continue
		}
		if sev, ok := c.Rules.SeverityOverrides[r.ID]; ok && rules.Severity(sev).Rank() > 0 {
			r.Severity = rules.Severity(sev)
		}
		out.Rules = append(out.Rules, r)
	}
	return out
}

// FilterFindings marks findings excluded by the path filters as Suppressed
// (retained and flagged, consistent with baseline/inline-ignore — auditable, not
// silently deleted). root is the scan root, used to relativize finding paths for
// matching. It returns the findings and the number newly excluded.
func (c *Config) FilterFindings(findings []analysis.Finding, root string) ([]analysis.Finding, int) {
	if c == nil || (len(c.Exclude) == 0 && len(c.Include) == 0) {
		return findings, 0
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}
	absRoot = containingDir(absRoot)
	n := 0
	for i := range findings {
		if findings[i].Suppressed {
			continue
		}
		rel := relPath(absRoot, findingPath(findings[i]))
		if rel == "" {
			continue
		}
		if c.pathExcluded(rel) {
			findings[i].Suppressed = true
			findings[i].SuppressedBy = "config-path-filter"
			findings[i].SuppressionReason = "file excluded by .godzilla.yaml path filters"
			n++
		}
	}
	return findings, n
}

// pathExcluded reports whether a relative path is filtered out: not matching any
// Include (when Include is non-empty), or matching any Exclude.
func (c *Config) pathExcluded(rel string) bool {
	if len(c.Include) > 0 && !matchesAny(c.Include, rel) {
		return true
	}
	return matchesAny(c.Exclude, rel)
}

// matchesAny reports whether rel matches any of the path globs.
func matchesAny(globs []string, rel string) bool {
	for _, g := range globs {
		if pathMatches(g, rel) {
			return true
		}
	}
	return false
}

// findingPath returns the file a finding is anchored to (sink first, then source).
func findingPath(f analysis.Finding) string {
	if f.SinkPos != nil && f.SinkPos.GetFilename() != "" {
		return f.SinkPos.GetFilename()
	}
	if f.SourcePos != nil {
		return f.SourcePos.GetFilename()
	}
	return ""
}

// relPath returns file relative to root (slash-separated), or the cleaned file
// path if it is not under root.
func relPath(root, file string) string {
	if file == "" {
		return ""
	}
	abs := file
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(file); err == nil {
			abs = a
		}
	}
	if rel, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Clean(file))
}

// pathMatches reports whether a path glob matches a slash-separated relative
// path. A bare name (no '/') matches any single path segment or the basename;
// otherwise '**' matches across segments and '*' within one.
func pathMatches(glob, rel string) bool {
	glob = filepath.ToSlash(glob)
	rel = filepath.ToSlash(rel)
	if !strings.Contains(glob, "/") {
		for _, seg := range strings.Split(rel, "/") {
			if ok, _ := filepath.Match(glob, seg); ok {
				return true
			}
		}
		return false
	}
	return globToRegexp(glob).MatchString(rel)
}

var (
	pathGlobCache = map[string]*regexp.Regexp{}
	neverMatch    = regexp.MustCompile(`\A\z.`) // matches nothing
)

// globToRegexp compiles a '/'-bearing path glob into an anchored regexp: '**'
// matches any run including '/', a following '/' is optional so "a/**" also
// matches "a"; '*' matches any run within a segment.
func globToRegexp(glob string) *regexp.Regexp {
	if re, ok := pathGlobCache[glob]; ok {
		return re
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); {
		switch {
		case glob[i] == '*' && i+1 < len(glob) && glob[i+1] == '*':
			i += 2
			if i < len(glob) && glob[i] == '/' {
				b.WriteString("(.*/)?") // "a/**/b" -> a/(.*/)?b, "a/**" -> a/... optional
				i++
			} else {
				b.WriteString(".*")
			}
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		re = neverMatch
	}
	pathGlobCache[glob] = re
	return re
}

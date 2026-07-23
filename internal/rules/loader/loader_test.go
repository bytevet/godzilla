package loader

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"godzilla/internal/rules"
)

func TestBuiltin(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error: %v", err)
	}
	if len(rs.Rules) < 5 {
		t.Fatalf("Builtin() returned %d rules, want >= 5", len(rs.Rules))
	}

	var foundSQLi bool
	for _, r := range rs.Rules {
		if r.ID == "" {
			t.Errorf("rule has empty ID: %+v", r)
		}
		// A dataflow (taint) rule is defined by its sinks; a dangerous-call rule
		// (COV-4) is defined by its callees instead.
		if r.IsDangerousCall() {
			if len(r.Callees) == 0 {
				t.Errorf("dangerous-call rule %q has no callees", r.ID)
			}
		} else if len(r.Sinks) == 0 {
			t.Errorf("rule %q has no sinks", r.ID)
		}
		if r.ID == "go-sql-injection" {
			foundSQLi = true
		}
	}
	if !foundSQLi {
		t.Errorf("expected built-in rule %q to be present", "go-sql-injection")
	}
}

func TestLoadFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	const doc = `
rules:
  - id: custom-test-rule
    languages: [go]
    severity: low
    cwe: CWE-000
    message: "test rule for round-trip parsing"
    sources:
      - "go:*Request*.URL*"
    sinks:
      - "go:*Sink*"
    sanitizers:
      - "go:*Sanitize*"
    propagators:
      - "go:fmt.Sprintf"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing temp rule file: %v", err)
	}

	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("LoadFile() returned %d rules, want 1", len(rs.Rules))
	}

	r := rs.Rules[0]
	if r.ID != "custom-test-rule" {
		t.Errorf("ID = %q, want %q", r.ID, "custom-test-rule")
	}
	if len(r.Languages) != 1 || r.Languages[0] != "go" {
		t.Errorf("Languages = %v, want [go]", r.Languages)
	}
	if r.Severity != rules.SeverityLow {
		t.Errorf("Severity = %q, want %q", r.Severity, rules.SeverityLow)
	}
	if r.CWE != "CWE-000" {
		t.Errorf("CWE = %q, want %q", r.CWE, "CWE-000")
	}
	if r.Message != "test rule for round-trip parsing" {
		t.Errorf("Message = %q, want %q", r.Message, "test rule for round-trip parsing")
	}
	if len(r.Sources) != 1 || r.Sources[0] != "go:*Request*.URL*" {
		t.Errorf("Sources = %v", r.Sources)
	}
	if len(r.Sinks) != 1 || r.Sinks[0] != "go:*Sink*" {
		t.Errorf("Sinks = %v", r.Sinks)
	}
	if len(r.Sanitizers) != 1 || r.Sanitizers[0] != "go:*Sanitize*" {
		t.Errorf("Sanitizers = %v", r.Sanitizers)
	}
	if len(r.Propagators) != 1 || r.Propagators[0] != "go:fmt.Sprintf" {
		t.Errorf("Propagators = %v", r.Propagators)
	}
}

func TestLoadFileInvalidRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")

	const doc = `
rules:
  - id: ""
    sinks:
      - "go:*Sink*"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing temp rule file: %v", err)
	}

	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile() with empty rule ID: want error, got nil")
	}
}

// TestLoadFileRejectsBadSeverity locks in that a rule with a missing or
// misspelled severity is rejected at load time — otherwise it would rank 0 and
// could never fail the CI gate at any -fail-on threshold.
func TestLoadFileRejectsBadSeverity(t *testing.T) {
	dir := t.TempDir()
	for name, doc := range map[string]string{
		"missing.yaml": "rules:\n  - id: r\n    sinks: [\"go:*Sink*\"]\n",
		"typo.yaml":    "rules:\n  - id: r\n    severity: hgih\n    sinks: [\"go:*Sink*\"]\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Errorf("LoadFile(%s): want error for bad severity, got nil", name)
		}
	}
}

// TestLoadFileRejectsMalformedSinkSpec locks in that a sink whose "#"
// injection-point spec names no valid argument index is rejected at load time,
// rather than silently widening to "all arguments" (which reintroduces the
// parameterized-query false positive the "#" mechanism exists to prevent).
func TestLoadFileRejectsMalformedSinkSpec(t *testing.T) {
	dir := t.TempDir()
	reject := map[string]string{
		"empty.yaml":    "rules:\n  - id: r\n    severity: high\n    sinks: [\"go:*Query#\"]\n",
		"nonnum.yaml":   "rules:\n  - id: r\n    severity: high\n    sinks: [\"go:*Query#x\"]\n",
		"negative.yaml": "rules:\n  - id: r\n    severity: high\n    sinks: [\"go:*Query#-1\"]\n",
	}
	for name, doc := range reject {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		if _, err := LoadFile(path); err == nil {
			t.Errorf("LoadFile(%s): want error for malformed sink spec, got nil", name)
		}
	}

	// A well-formed "#0" sink must still load cleanly.
	ok := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(ok, []byte("rules:\n  - id: r\n    severity: high\n    sinks: [\"go:*Query#0\"]\n"), 0o644); err != nil {
		t.Fatalf("writing ok.yaml: %v", err)
	}
	if _, err := LoadFile(ok); err != nil {
		t.Errorf("LoadFile(ok.yaml) with a valid #0 sink: unexpected error: %v", err)
	}
}

// TestExtendMergesFragment verifies that `extend: $_fragment.yaml` merges the
// fragment's pattern-list fields into the rule: the fragment's entries come
// first, then the rule's own additions, with duplicates removed.
func TestExtendMergesFragment(t *testing.T) {
	dir := t.TempDir()
	// A fragment is a partial rule (a mapping of pattern-list fields).
	frag := "sources:\n  - \"go:*A\"\n  - \"go:*B\"\npropagators:\n  - \"go:*P\"\n"
	if err := os.WriteFile(filepath.Join(dir, "_custom.yaml"), []byte(frag), 0o644); err != nil {
		t.Fatalf("writing fragment: %v", err)
	}
	path := filepath.Join(dir, "rules.yaml")
	const doc = `
rules:
  - id: frag-rule
    severity: high
    extend: $_custom.yaml
    sources:
      - "go:*C"
    sinks:
      - "go:*Sink*"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}
	if got, want := rs.Rules[0].Sources, []string{"go:*A", "go:*B", "go:*C"}; !slices.Equal(got, want) {
		t.Errorf("Sources = %v, want %v", got, want)
	}
	if got, want := rs.Rules[0].Propagators, []string{"go:*P"}; !slices.Equal(got, want) {
		t.Errorf("Propagators = %v, want %v", got, want)
	}
	// Extend is consumed at load and must not survive into the compiled rule.
	if len(rs.Rules[0].Extend) != 0 {
		t.Errorf("Extend = %v, want it cleared after apply", rs.Rules[0].Extend)
	}
}

// TestExtendUsesBuiltinFragment verifies a user rule file can extend a fragment
// shipped in the binary (e.g. $_go-common.yaml).
func TestExtendUsesBuiltinFragment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	const doc = `
rules:
  - id: uses-builtin-frag
    severity: high
    extend: $_go-common.yaml
    sinks:
      - "go:*Sink*"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}
	if n := len(rs.Rules[0].Sources); n < 10 {
		t.Errorf("expected builtin $_go-common.yaml to contribute many sources, got %d", n)
	}
}

// TestExtendUnknownFragment verifies that extending a fragment that does not
// exist is a load error (a typo would otherwise silently drop the shared base).
func TestExtendUnknownFragment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	const doc = `
rules:
  - id: bad-frag-rule
    severity: high
    extend: $_does-not-exist.yaml
    sinks:
      - "go:*Sink*"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile() extending an unknown fragment: want error, got nil")
	}
}

// TestLoadDirRejectsDuplicateIDs verifies two rules sharing an id across a loaded
// directory are rejected: duplicate ids silently double-report and make a rule
// un-addressable by the baseline / godzilla:ignore machinery.
func TestLoadDirRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	doc := "rules:\n  - id: dup\n    severity: high\n    sinks: [\"go:*Sink*\"]\n"
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("LoadDir() with duplicate rule ids: want error, got nil")
	}
}

func TestLoadDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "extra.yaml")
	const doc = `
rules:
  - id: extra-rule
    severity: high
    sinks:
      - "go:*Sink*"
`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("writing temp rule file: %v", err)
	}

	rs, err := LoadDefault(path)
	if err != nil {
		t.Fatalf("LoadDefault() error: %v", err)
	}

	builtin, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error: %v", err)
	}
	if len(rs.Rules) != len(builtin.Rules)+1 {
		t.Fatalf("LoadDefault() returned %d rules, want %d", len(rs.Rules), len(builtin.Rules)+1)
	}
	if rs.Rules[len(rs.Rules)-1].ID != "extra-rule" {
		t.Errorf("expected user rule to be appended last, got %q", rs.Rules[len(rs.Rules)-1].ID)
	}
}

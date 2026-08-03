// Package proc centralizes the timeouts for the external toolchain processes the
// frontends shell out to (python3, java, rustc, cargo, clang, mvn/gradle). A
// wedged or hung toolchain must never hang a CI scan indefinitely — the scan has
// to make progress or fail, not block a pipeline forever. Every subprocess is
// therefore run under a context deadline; on timeout the process is killed and
// the frontend surfaces the error (a failed conversion / coverage failure),
// exactly like any other toolchain error.
package proc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// FileExists reports whether p names an existing regular file (not a
// directory) — the check the build-integrated frontends (Java, Rust) share for
// deciding whether a project manifest or wrapper (pom.xml, Cargo.toml, mvnw)
// is present before invoking its build tool.
func FileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// WriteEmbeddedScript materializes an embedded helper script (e.g. the Python
// ast dumper, the Ruby Ripper dumper) into a temp file named after pattern
// (e.g. "godzilla-pyast-*.py") and returns its path plus a cleanup func the
// caller must invoke when done. Shared by the frontends that shell out to an
// interpreter with an embedded helper.
func WriteEmbeddedScript(pattern string, content []byte) (string, func(), error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, fmt.Errorf("create temp helper script: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("write temp helper script: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("close temp helper script: %w", err)
	}
	path := tmp.Name()
	return path, func() { _ = os.Remove(path) }, nil
}

// RunBatchScript runs one `<exe> <scriptPath> --batch <files...>` helper
// invocation (see WriteEmbeddedScript) under the parse deadline and decodes its
// stdout as one JSON document per file, in argv order (numbers preserved as
// json.Number). perFile is called exactly once per file index with the decoded
// document or a non-nil error: a process-level failure marks every file in the
// batch, while a per-file decode failure or an {"error": ...} document marks
// only that file — mirroring the frontends' old file-at-a-time error
// semantics. label prefixes error messages ("py_converter"); scriptName names
// the embedded helper in them ("pyast.py"). Shared by the interpreter
// frontends (Python, Ruby), whose batch parses differ only in these labels and
// in what they do with each document.
func RunBatchScript(label, scriptName, exe, scriptPath string, files []string, perFile func(i int, doc any, err error)) {
	ctx, cancel := ParseContext()
	defer cancel()
	args := append([]string{scriptPath, "--batch"}, files...)
	cmd := exec.CommandContext(ctx, exe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		for i, f := range files {
			perFile(i, nil, fmt.Errorf("%s: %s failed parsing %s: %v (stderr: %s)",
				label, filepath.Base(exe), f, runErr, strings.TrimSpace(stderr.String())))
		}
		return
	}

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.UseNumber()
	for i, f := range files {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			perFile(i, nil, fmt.Errorf("%s: failed to parse %s output for %s: %w", label, scriptName, f, err))
			continue
		}
		if obj, ok := doc.(map[string]any); ok {
			if msg, ok := obj["error"]; ok {
				perFile(i, nil, fmt.Errorf("%s: failed to parse %s: %v", label, f, msg))
				continue
			}
		}
		perFile(i, doc, nil)
	}
}

const (
	defaultParseTimeout = 120 * time.Second // per-file parse/dump: python3, JavaDump, rustc, clang
	defaultBuildTimeout = 600 * time.Second // whole-project builds: cargo, mvn/gradle (cold caches are slow)
)

// ParseTimeout is the deadline for a per-file parse/dump subprocess. Override
// with GODZILLA_PARSE_TIMEOUT (a Go duration, e.g. "90s").
func ParseTimeout() time.Duration {
	return envDuration("GODZILLA_PARSE_TIMEOUT", defaultParseTimeout)
}

// BuildTimeout is the deadline for a whole-project build subprocess (opt-in via
// -allow-build). Override with GODZILLA_BUILD_TIMEOUT.
func BuildTimeout() time.Duration {
	return envDuration("GODZILLA_BUILD_TIMEOUT", defaultBuildTimeout)
}

// ParseContext returns a context with the parse timeout and its cancel func.
// The caller MUST defer the cancel to release resources.
func ParseContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ParseTimeout())
}

// BuildContext returns a context with the build timeout and its cancel func.
func BuildContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), BuildTimeout())
}

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

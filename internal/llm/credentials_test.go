package llm

import (
	"os"
	"path/filepath"
	"testing"
)

// unsetEnv clears key for the test and restores its prior state (present or
// absent) afterward. t.Setenv can only SET a value, never truly unset one, and
// that distinction matters here: ANTHROPIC_PROFILE is read via os.LookupEnv
// deep in the SDK's own resolution (config.go's resolveProfile), which treats
// "set to empty" as an explicit (empty, invalid) profile name — a different,
// error-producing case from "absent". A test asserting the "nothing
// configured" baseline needs the real thing.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// clearAnthropicEnv puts every input anthropicCredentialsLikely reads into a
// known "nothing configured" state, including redirecting the SDK's own
// profile-directory lookup at an empty temp dir — otherwise this test suite's
// result would depend on whether the machine running it happens to have run
// `ant auth`.
func clearAnthropicEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_FEDERATION_RULE_ID"} {
		unsetEnv(t, v)
	}
	t.Setenv("ANTHROPIC_CONFIG_DIR", t.TempDir())
}

func clearOpenAIEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"OPENAI_API_KEY", "GODZILLA_LLM_BASE_URL", "OPENAI_BASE_URL"} {
		t.Setenv(v, "")
	}
}

func TestAnthropicCredentialsLikely(t *testing.T) {
	t.Run("nothing configured", func(t *testing.T) {
		clearAnthropicEnv(t)
		if anthropicCredentialsLikely() {
			t.Error("expected false with no env vars and an empty profile directory")
		}
	})
	for _, v := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_FEDERATION_RULE_ID"} {
		t.Run(v+" present", func(t *testing.T) {
			clearAnthropicEnv(t)
			t.Setenv(v, "x")
			if !anthropicCredentialsLikely() {
				t.Errorf("expected true with %s set", v)
			}
		})
	}
	t.Run("profile file that exists but fails to load counts as present", func(t *testing.T) {
		// Not a POSITIVE negative (no such file): the file is there, something
		// about it just couldn't be read — treated as present per the
		// converters/java/converter.go:138-147 rule this function follows.
		clearAnthropicEnv(t)
		dir := t.TempDir()
		t.Setenv("ANTHROPIC_CONFIG_DIR", dir)
		if err := os.MkdirAll(filepath.Join(dir, "configs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "configs", "default.json"), []byte("not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !anthropicCredentialsLikely() {
			t.Error("expected true: the profile file exists but is unparsable, which is inconclusive, not absent")
		}
	})
}

func TestOpenAICredentialsLikely(t *testing.T) {
	t.Run("nothing configured", func(t *testing.T) {
		clearOpenAIEnv(t)
		if openaiCredentialsLikely() {
			t.Error("expected false")
		}
	})
	t.Run("api key present", func(t *testing.T) {
		clearOpenAIEnv(t)
		t.Setenv("OPENAI_API_KEY", "x")
		if !openaiCredentialsLikely() {
			t.Error("expected true")
		}
	})
	t.Run("an explicit base URL is itself the signal (e.g. a local server)", func(t *testing.T) {
		clearOpenAIEnv(t)
		t.Setenv("GODZILLA_LLM_BASE_URL", "http://localhost:11434/v1")
		if !openaiCredentialsLikely() {
			t.Error("expected true")
		}
	})
}

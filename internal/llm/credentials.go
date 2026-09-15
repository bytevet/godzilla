package llm

// credentials.go answers one question cheaply, without duplicating the SDKs'
// own credential-resolution logic: "would an HTTP backend probably authenticate
// if we tried it?" Select uses the answer to decide between the HTTP backends
// (anthropic.go, openai.go) and the command-CLI ladder (command.go) — it must
// never demote a working `ant auth` profile to the CLI ladder just because
// ANTHROPIC_API_KEY isn't set (README.md promises the profile works), so a
// check that cannot be answered for certain is resolved in favor of "present"
// (the converters/java/converter.go:138-147 rule: hard-fail — here, "treat as
// absent" — only on a POSITIVE negative, never on an inability to check).

import (
	"errors"
	"os"

	anthropicconfig "github.com/anthropics/anthropic-sdk-go/config"
)

// anthropicCredentialsLikely reports whether the Anthropic SDK's own default
// credential chain (anthropic-sdk-go/client.go's DefaultClientOptions, steps
// 1-5: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, an explicit ANTHROPIC_PROFILE,
// the WIF federation trio, then the `ant auth` fallback profile) is likely to
// authenticate a request. It does not read ANTHROPIC_API_KEY alone — that would
// wrongly demote every one of the other four paths.
//
// The direct-credential env vars are checked by presence only: an explicitly
// named ANTHROPIC_PROFILE or a partial WIF setup is a deliberate selection, and
// like an API key that turns out to be invalid, a broken selection surfaces as
// a per-review error that Filter treats as fail-open — this function does not
// need to validate it. The one thing it does resolve concretely is the
// fallback profile, via the SDK's own exported anthropic-sdk-go/config.LoadConfig
// (the same step 5 the client itself runs): a missing profile directory/file is
// the one case cheap enough to call a POSITIVE negative.
func anthropicCredentialsLikely() bool {
	for _, v := range []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE",
		"ANTHROPIC_FEDERATION_RULE_ID",
	} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	switch _, err := anthropicconfig.LoadConfig(); {
	case err == nil:
		return true
	case errors.Is(err, os.ErrNotExist):
		return false
	default:
		return true // load failed some other way (permissions, a corrupt file, ...): inconclusive
	}
}

// openaiCredentialsLikely reports whether the OpenAI-compatible backend
// (openai.go) has something to authenticate with, OR was deliberately pointed
// at a non-default endpoint — a local/offline server (Ollama, vLLM, llama.cpp)
// commonly needs no key at all, so its presence is itself the opt-in signal.
func openaiCredentialsLikely() bool {
	if os.Getenv("OPENAI_API_KEY") != "" {
		return true
	}
	return os.Getenv("GODZILLA_LLM_BASE_URL") != "" || os.Getenv("OPENAI_BASE_URL") != ""
}

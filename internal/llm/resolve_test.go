package llm

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bytevet/godzilla/internal/analysis"
)

// clearLLMEnv unsets everything Resolve reads, so a developer's own shell cannot
// change which branch a case takes.
func clearLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"GODZILLA_LLM_PROVIDER", "GODZILLA_LLM_CLI_CMD", "GODZILLA_LLM_CLI", "GODZILLA_LLM_MODEL", "ANTHROPIC_API_KEY", "CI"} {
		t.Setenv(k, "")
	}
}

// installed makes lookPath report exactly the given binaries as present.
func installed(t *testing.T, names ...string) {
	t.Helper()
	prev := lookPath
	t.Cleanup(func() { lookPath = prev })
	lookPath = func(name string) (string, error) {
		for _, n := range names {
			if n == name {
				return "/fake/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestResolve_DecisionTable(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		onPATH  []string
		want    Choice
		wantErr string // substring the error must name
	}{
		{
			name: "provider openai wins over everything",
			env:  map[string]string{"GODZILLA_LLM_PROVIDER": "OpenAI", "GODZILLA_LLM_CLI_CMD": "x {{prompt}}", "GODZILLA_LLM_CLI": "claude", "ANTHROPIC_API_KEY": "k"},
			want: Choice{Kind: OpenAI},
		},
		{
			name: "command template beats the named profile and the key",
			env:  map[string]string{"GODZILLA_LLM_CLI_CMD": "codex exec {{prompt}}", "GODZILLA_LLM_CLI": "claude", "ANTHROPIC_API_KEY": "k"},
			want: Choice{Kind: CLI, Profile: customProfile},
		},
		{
			name:    "command template without the placeholder is an error",
			env:     map[string]string{"GODZILLA_LLM_CLI_CMD": "codex exec"},
			wantErr: "{{prompt}}",
		},
		{
			name:   "named profile beats the key",
			env:    map[string]string{"GODZILLA_LLM_CLI": "claude", "ANTHROPIC_API_KEY": "k"},
			onPATH: []string{"claude"},
			want:   Choice{Kind: CLI, Profile: "claude"},
		},
		{
			name:    "unknown profile names the valid values",
			env:     map[string]string{"GODZILLA_LLM_CLI": "copilot"},
			onPATH:  []string{"claude"},
			wantErr: "claude, agy",
		},
		{
			name:    "named profile absent from PATH is an error, never a fallback",
			env:     map[string]string{"GODZILLA_LLM_CLI": "agy", "ANTHROPIC_API_KEY": "k"},
			onPATH:  []string{"claude"},
			wantErr: "not on PATH",
		},
		{
			name: "api key is the default",
			env:  map[string]string{"ANTHROPIC_API_KEY": "k"},
			want: Choice{Kind: Anthropic},
		},
		{
			name:    "nothing pinned and no CLI installed names every way out",
			wantErr: "ANTHROPIC_API_KEY",
		},
		{
			name:    "a CLI on PATH is never auto-detected when non-interactive",
			onPATH:  []string{"claude"},
			wantErr: "GODZILLA_LLM_CLI",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearLLMEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			installed(t, c.onPATH...)
			notATerminal(t)

			got, err := Resolve(false)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("Resolve() = %+v, want an error naming %q", got, c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("error %q must name %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != c.want {
				t.Errorf("Resolve() = %+v, want %+v", got, c.want)
			}
		})
	}
}

// notATerminal forces the non-interactive branch without a real terminal.
func notATerminal(t *testing.T) {
	t.Helper()
	prev := isTTY
	t.Cleanup(func() { isTTY = prev })
	isTTY = func(*os.File) bool { return false }
}

// TestResolve_Picker covers the last row of the table: with a human present and
// nothing pinned, the choice comes from the menu.
func TestResolve_Picker(t *testing.T) {
	clearLLMEnv(t)
	installed(t, "claude", "agy")

	prevTTY, prevPick := isTTY, pick
	t.Cleanup(func() { isTTY, pick = prevTTY, prevPick })
	isTTY = func(*os.File) bool { return true }

	var offered []string
	pick = func(names []string) (string, error) {
		offered = names
		return names[1], nil
	}

	got, err := Resolve(false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != (Choice{Kind: CLI, Profile: "agy"}) {
		t.Errorf("Resolve() = %+v, want the picked profile", got)
	}
	if len(offered) != 2 || offered[0] != "claude" {
		t.Errorf("picker offered %q, want the installed profiles in preference order", offered)
	}

	// -quiet contracts godzilla to silence, so it cannot raise a prompt.
	if _, err := Resolve(true); err == nil {
		t.Error("Resolve(quiet=true) must not open the picker")
	}
	// Neither can CI, where nothing is there to answer.
	t.Setenv("CI", "true")
	if _, err := Resolve(false); err == nil {
		t.Error("Resolve must not open the picker under CI")
	}
}

func TestReadChoice(t *testing.T) {
	names := []string{"claude", "agy"}
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "1\n", want: "claude"},
		{in: " 2 \n", want: "agy"},
		{in: "3\n", wantErr: true},
		{in: "0\n", wantErr: true},
		{in: "claude\n", wantErr: true},
		{in: "", wantErr: true}, // stdin closed
	}
	for _, c := range cases {
		var menu strings.Builder
		got, err := readChoice(strings.NewReader(c.in), &menu, names)
		if (err != nil) != c.wantErr {
			t.Errorf("readChoice(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("readChoice(%q) = %q, want %q", c.in, got, c.want)
		}
		if !strings.Contains(menu.String(), "1) claude") {
			t.Errorf("menu did not list the options: %q", menu.String())
		}
	}
}

func TestChoice_NewAndProviderName(t *testing.T) {
	clearLLMEnv(t)
	root := t.TempDir()

	cli := Choice{Kind: CLI, Profile: "claude"}
	r, ok := cli.New(root, nil).(*AgentCLIReviewer)
	if !ok {
		t.Fatalf("New() for a CLI choice = %T, want *AgentCLIReviewer", cli.New(root, nil))
	}
	if r.bin != "claude" || r.dir != root {
		t.Errorf("reviewer = %+v, want the claude profile rooted at the scan root", r)
	}
	// Unpinned: the CLI answers on whatever model its own session is set to.
	if r.model != "" {
		t.Errorf("model = %q, want the CLI's own default", r.model)
	}
	t.Setenv("GODZILLA_LLM_MODEL", "opus")
	if pinned, _ := cli.New(root, nil).(*AgentCLIReviewer); pinned.model != "opus" {
		t.Errorf("model = %q, want GODZILLA_LLM_MODEL to override", pinned.model)
	}

	t.Setenv("GODZILLA_LLM_CLI_CMD", "my-cli --ask {{prompt}}")
	custom, ok := Choice{Kind: CLI, Profile: customProfile}.New(root, nil).(*AgentCLIReviewer)
	if !ok {
		t.Fatal("New() for the custom choice must build an AgentCLIReviewer")
	}
	if custom.bin != "my-cli" || len(custom.profile.template) != 3 {
		t.Errorf("custom reviewer = %+v, want the template argv", custom)
	}

	if _, ok := (Choice{Kind: OpenAI}).New(root, nil).(*OpenAIReviewer); !ok {
		t.Error("New() for OpenAI must build an OpenAIReviewer")
	}
	if _, ok := (Choice{Kind: Anthropic}).New(root, nil).(*AnthropicReviewer); !ok {
		t.Error("New() for Anthropic must build an AnthropicReviewer")
	}

	for c, want := range map[Choice]string{
		{Kind: Anthropic}:                   "Anthropic API",
		{Kind: OpenAI}:                      "OpenAI-compatible API",
		{Kind: CLI, Profile: "claude"}:      "claude CLI",
		{Kind: CLI, Profile: customProfile}: "custom CLI",
	} {
		if got := ProviderName(c); got != want {
			t.Errorf("ProviderName(%+v) = %q, want %q", c, got, want)
		}
	}
}

func TestCountReviewable(t *testing.T) {
	fs := []analysis.Finding{
		{Confidence: analysis.ConfidenceHigh},
		{Confidence: analysis.ConfidenceMedium},
		{Confidence: analysis.ConfidenceLow},
		{Confidence: "bogus"},
	}
	if got := CountReviewable(fs, analysis.ConfidenceMedium); got != 2 {
		t.Errorf("CountReviewable(medium) = %d, want 2", got)
	}
	if got := CountReviewable(fs, analysis.ConfidenceHigh); got != 3 {
		t.Errorf("CountReviewable(high) = %d, want 3", got)
	}
}

package llm

import (
	"context"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"

	"godzilla/internal/analysis"
)

// AnthropicReviewer is a Reviewer backed by the Anthropic Messages API. It is
// the concrete, pluggable implementation of the (otherwise dependency-free)
// review pipeline in review.go.
type AnthropicReviewer struct {
	client anthropic.Client
	model  anthropic.Model
}

// NewAnthropicReviewer builds a reviewer using the default Claude model
// (claude-opus-4-8), overridable via the GODZILLA_LLM_MODEL environment
// variable (e.g. set it to a faster/cheaper model for high-volume triage).
// Credentials are resolved by the SDK from ANTHROPIC_API_KEY or an `ant auth`
// profile; a missing credential surfaces as a per-review error, which Filter
// treats as fail-open (the finding is kept, never silently dropped).
func NewAnthropicReviewer() *AnthropicReviewer {
	model := anthropic.ModelClaudeOpus4_8
	if m := os.Getenv("GODZILLA_LLM_MODEL"); m != "" {
		model = anthropic.Model(m)
	}
	return &AnthropicReviewer{
		client: anthropic.NewClient(),
		model:  model,
	}
}

// Review asks Claude to adjudicate a single finding and parses its verdict.
func (a *AnthropicReviewer) Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildPrompt(f, codeContext))),
		},
	})
	if err != nil {
		return Verdict{}, err
	}

	var out strings.Builder
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			out.WriteString(tb.Text)
		}
	}
	return parseVerdict(out.String())
}

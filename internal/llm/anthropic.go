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
//
// When a ToolBox is attached (WithTools), the reviewer runs an AGENTIC loop
// (LLM-4): it offers Claude read-only tools — read a file range, resolve a
// canonical function name to its source, grep the tree — so it can trace the
// flow, read the callee/sanitizer/route, and adjudicate an interprocedural
// finding the way a human triager would, instead of guessing from a fixed
// snippet. Without a ToolBox it falls back to the one-shot prompt→verdict.
type AnthropicReviewer struct {
	client anthropic.Client
	model  anthropic.Model
	tools  ToolBox
}

// maxToolRounds bounds the agent loop so one finding cannot make an unbounded
// number of model calls; after it, the reviewer forces a final verdict.
const maxToolRounds = 6

// NewAnthropicReviewer builds a reviewer using a fast, inexpensive default model
// (claude-haiku-4-5) — the review task is one-sentence JSON triage over a
// finding, run per-finding at scale, so a Haiku-class model keeps a large scan
// affordable and quick (LLM-5). Override with GODZILLA_LLM_MODEL to upgrade to
// Opus for harder adjudication. Credentials are resolved by the SDK from
// ANTHROPIC_API_KEY or an `ant auth` profile; a missing credential surfaces as a
// per-review error, which Filter treats as fail-open (the finding is kept, never
// silently dropped).
func NewAnthropicReviewer() *AnthropicReviewer {
	model := anthropic.ModelClaudeHaiku4_5
	if m := os.Getenv("GODZILLA_LLM_MODEL"); m != "" {
		model = anthropic.Model(m)
	}
	return &AnthropicReviewer{
		client: anthropic.NewClient(),
		model:  model,
	}
}

// WithTools attaches a ToolBox, switching the reviewer into agentic mode. It
// returns the receiver for chaining. Passing a nil ToolBox keeps one-shot mode.
func (a *AnthropicReviewer) WithTools(tb ToolBox) *AnthropicReviewer {
	a.tools = tb
	return a
}

// Review adjudicates a single finding. With a ToolBox attached it runs the
// agentic tool-use loop; otherwise it makes the one-shot call.
func (a *AnthropicReviewer) Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	if a.tools != nil {
		return a.reviewAgentic(ctx, f, codeContext)
	}
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
	return parseVerdict(collectText(resp))
}

// reviewAgentic drives the read-only tool loop to a verdict.
func (a *AnthropicReviewer) reviewAgentic(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	tools := reviewToolParams()
	msgs := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(buildAgenticPrompt(f, codeContext))),
	}
	for round := 0; round < maxToolRounds; round++ {
		resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     a.model,
			MaxTokens: 1024,
			Tools:     tools,
			Messages:  msgs,
		})
		if err != nil {
			return Verdict{}, err
		}

		var text strings.Builder
		var toolUses []anthropic.ToolUseBlock
		for _, block := range resp.Content {
			switch b := block.AsAny().(type) {
			case anthropic.TextBlock:
				text.WriteString(b.Text)
			case anthropic.ToolUseBlock:
				toolUses = append(toolUses, b)
			}
		}

		// No tool calls this turn: the model has reached a verdict.
		if len(toolUses) == 0 || resp.StopReason != anthropic.StopReasonToolUse {
			return parseVerdict(text.String())
		}

		// Execute each requested tool and feed the results back.
		msgs = append(msgs, resp.ToParam())
		results := make([]anthropic.ContentBlockParamUnion, 0, len(toolUses))
		for _, tu := range toolUses {
			out := dispatchTool(a.tools, tu.Name, tu.Input)
			results = append(results, anthropic.NewToolResultBlock(tu.ID, out, strings.HasPrefix(out, "error: ")))
		}
		msgs = append(msgs, anthropic.NewUserMessage(results...))
	}

	// Tool budget exhausted: force a final verdict with no further tools.
	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 512,
		Messages: append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(
			"Tool budget exhausted. Based on the evidence gathered, respond now with ONLY the JSON verdict "+
				`{"verdict": "true_positive" | "false_positive", "reason": "<one sentence>"}.`))),
	})
	if err != nil {
		return Verdict{}, err
	}
	return parseVerdict(collectText(resp))
}

// collectText concatenates the text blocks of a response.
func collectText(resp *anthropic.Message) string {
	var out strings.Builder
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			out.WriteString(tb.Text)
		}
	}
	return out.String()
}

// reviewToolParams converts the dependency-free ToolSpec catalog into the SDK's
// tool params.
func reviewToolParams() []anthropic.ToolUnionParam {
	specs := ReviewToolSpecs()
	out := make([]anthropic.ToolUnionParam, 0, len(specs))
	for _, s := range specs {
		schema := anthropic.ToolInputSchemaParam{Properties: s.InputSchema["properties"]}
		if req, ok := s.InputSchema["required"].([]any); ok {
			for _, r := range req {
				if rs, ok := r.(string); ok {
					schema.Required = append(schema.Required, rs)
				}
			}
		}
		u := anthropic.ToolUnionParamOfTool(schema, s.Name)
		if u.OfTool != nil {
			u.OfTool.Description = anthropic.String(s.Description)
		}
		out = append(out, u)
	}
	return out
}

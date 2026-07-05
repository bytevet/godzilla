package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"godzilla/internal/analysis"
)

// OpenAIReviewer is a Reviewer backed by any OpenAI-compatible /chat/completions
// endpoint (LLM-9): OpenAI itself, or a local/offline server such as Ollama,
// vLLM, or llama.cpp — enabling the FP-backstop in air-gapped or data-residency-
// constrained CI where the Anthropic API is unreachable. It speaks the API over
// plain net/http (no SDK dependency) and reuses the shared prompt/verdict logic.
//
// Configuration (all optional except a base URL for non-OpenAI hosts):
//   - GODZILLA_LLM_BASE_URL or OPENAI_BASE_URL — endpoint base (default
//     https://api.openai.com/v1); point it at http://localhost:11434/v1 for Ollama.
//   - OPENAI_API_KEY — bearer token (local servers usually ignore it).
//   - GODZILLA_LLM_MODEL — model id (default gpt-4o-mini).
type OpenAIReviewer struct {
	client  *http.Client
	baseURL string
	apiKey  string
	model   string
}

// NewOpenAIReviewer builds an OpenAI-compatible reviewer from the environment.
func NewOpenAIReviewer() *OpenAIReviewer {
	base := firstNonEmpty(os.Getenv("GODZILLA_LLM_BASE_URL"), os.Getenv("OPENAI_BASE_URL"), "https://api.openai.com/v1")
	model := firstNonEmpty(os.Getenv("GODZILLA_LLM_MODEL"), "gpt-4o-mini")
	return &OpenAIReviewer{
		client:  &http.Client{Timeout: 60 * time.Second},
		baseURL: strings.TrimRight(base, "/"),
		apiKey:  os.Getenv("OPENAI_API_KEY"),
		model:   model,
	}
}

// Review adjudicates one finding via a single chat-completion request.
func (o *OpenAIReviewer) Review(ctx context.Context, f analysis.Finding, codeContext string) (Verdict, error) {
	reqBody, err := json.Marshal(map[string]any{
		"model": o.model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security triage assistant. Respond with ONLY the requested JSON object."},
			{"role": "user", "content": buildPrompt(f, codeContext)},
		},
		"temperature": 0,
	})
	if err != nil {
		return Verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Verdict{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Verdict{}, fmt.Errorf("openai-compatible endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Verdict{}, fmt.Errorf("parsing chat-completions response: %w", err)
	}
	if len(out.Choices) == 0 {
		return Verdict{}, fmt.Errorf("chat-completions response had no choices")
	}
	return parseVerdict(out.Choices[0].Message.Content)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// NewReviewer selects the reviewer backend from GODZILLA_LLM_PROVIDER (LLM-9):
// "openai" uses an OpenAI-compatible endpoint (one-shot; covers local/offline
// servers), anything else (the default) uses the Anthropic reviewer with agentic
// tools over the analyzed program. The Anthropic path also honors
// ANTHROPIC_BASE_URL for an Anthropic-compatible proxy.
func NewReviewer(tb ToolBox) Reviewer {
	if strings.EqualFold(os.Getenv("GODZILLA_LLM_PROVIDER"), "openai") {
		return NewOpenAIReviewer()
	}
	return NewAnthropicReviewer().WithTools(tb)
}

package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// TestOpenAIReviewer_ParsesVerdict drives the OpenAI-compatible reviewer against
// a mock /chat/completions endpoint (LLM-9): the request must carry the model
// and a user prompt, and the choices[].message.content JSON is parsed into a
// Verdict.
func TestOpenAIReviewer_ParsesVerdict(t *testing.T) {
	var gotModel, gotPath string
	var sawUser bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		gotModel = req.Model
		for _, m := range req.Messages {
			if m.Role == "user" && strings.Contains(m.Content, "Rule:") {
				sawUser = true
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"false_positive\",\"reason\":\"constant\"}"}}]}`))
	}))
	defer srv.Close()

	r := &OpenAIReviewer{client: srv.Client(), baseURL: srv.URL, model: "local-model"}
	f := analysis.Finding{RuleID: "GO-CMDI", Message: "cmd", SinkPos: &ir.Position{Filename: "a.go", Line: 1}}
	v, err := r.Review(context.Background(), f, "-- sink --\n> 1: exec(x)\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("posted to %q, want /chat/completions", gotPath)
	}
	if gotModel != "local-model" {
		t.Errorf("model = %q, want local-model", gotModel)
	}
	if !sawUser {
		t.Errorf("request did not carry the finding prompt in a user message")
	}
	if !v.FalsePositive || v.Reason != "constant" {
		t.Errorf("verdict not parsed: %+v", v)
	}
}

// TestOpenAIReviewer_ErrorStatus verifies a non-2xx surfaces as an error (which
// Filter treats as fail-open — the finding is kept).
func TestOpenAIReviewer_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	r := &OpenAIReviewer{client: srv.Client(), baseURL: srv.URL, model: "m"}
	_, err := r.Review(context.Background(), analysis.Finding{RuleID: "R"}, "ctx")
	if err == nil {
		t.Errorf("expected an error on a 401 response")
	}
}

// TestNewReviewer_ProviderSelection verifies the factory routes on
// GODZILLA_LLM_PROVIDER.
func TestNewReviewer_ProviderSelection(t *testing.T) {
	t.Setenv("GODZILLA_LLM_PROVIDER", "openai")
	if _, ok := NewReviewer(nil).(*OpenAIReviewer); !ok {
		t.Errorf("provider=openai should select the OpenAI reviewer")
	}
	t.Setenv("GODZILLA_LLM_PROVIDER", "")
	if _, ok := NewReviewer(nil).(*AnthropicReviewer); !ok {
		t.Errorf("default provider should select the Anthropic reviewer")
	}
}

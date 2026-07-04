package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"godzilla/internal/analysis"
	ir "godzilla/pkg/ir/v1"
)

// TestAgenticLoop_ToolThenVerdict drives the full agentic reviewer against a
// mock Messages API: the model first asks to read a file (a tool_use turn), the
// loop must execute the tool via the ToolBox and feed the result back, and on
// the second turn the model returns a JSON verdict the loop parses. This
// exercises the tool dispatch + message threading + verdict parse end-to-end,
// hermetically (no real API, no key).
func TestAgenticLoop_ToolThenVerdict(t *testing.T) {
	root := writeTree(t, map[string]string{"a.go": "package main\nvar x = userInput\n"})

	var calls int
	var sawToolResult bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls++
		switch calls {
		case 1:
			// First turn: request a tool call.
			writeMessage(t, w, "tool_use", []map[string]any{{
				"type":  "tool_use",
				"id":    "toolu_1",
				"name":  "read_file_range",
				"input": map[string]any{"path": "a.go", "start": 1, "end": 2},
			}})
		default:
			// The second request must carry the tool_result we produced.
			if strings.Contains(string(body), "tool_result") {
				sawToolResult = true
			}
			writeMessage(t, w, "end_turn", []map[string]any{{
				"type": "text",
				"text": `{"verdict": "false_positive", "reason": "value is constant, not attacker-controlled"}`,
			}})
		}
	}))
	defer srv.Close()

	reviewer := &AnthropicReviewer{
		client: anthropic.NewClient(option.WithBaseURL(srv.URL), option.WithAPIKey("test")),
		model:  "test-model",
		tools:  NewFileToolBox(nil, root),
	}

	f := analysis.Finding{
		RuleID:  "GO-CMDI",
		Message: "cmd injection",
		SinkPos: &ir.Position{Filename: filepath.Join(root, "a.go"), Line: 2},
	}
	v, err := reviewer.Review(context.Background(), f, "-- sink --\n> 2: var x = userInput\n")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 model turns (tool then verdict), got %d", calls)
	}
	if !sawToolResult {
		t.Errorf("the tool result was not fed back to the model on the second turn")
	}
	if !v.FalsePositive {
		t.Errorf("expected a false_positive verdict, got %+v", v)
	}
	if !strings.Contains(v.Reason, "constant") {
		t.Errorf("verdict reason not parsed, got %q", v.Reason)
	}
}

// TestAgenticLoop_BudgetForcesVerdict verifies that a model which keeps calling
// tools forever is cut off after maxToolRounds and made to produce a final
// verdict (the loop cannot hang or loop unboundedly).
func TestAgenticLoop_BudgetForcesVerdict(t *testing.T) {
	root := writeTree(t, map[string]string{"a.go": "x\n"})

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= maxToolRounds {
			// Always ask for another tool call — never volunteer a verdict.
			writeMessage(t, w, "tool_use", []map[string]any{{
				"type": "tool_use", "id": "toolu_x", "name": "grep",
				"input": map[string]any{"pattern": "x"},
			}})
			return
		}
		// The forced final turn (no tools): emit the verdict.
		writeMessage(t, w, "end_turn", []map[string]any{{
			"type": "text", "text": `{"verdict": "true_positive", "reason": "inconclusive, kept"}`,
		}})
	}))
	defer srv.Close()

	reviewer := &AnthropicReviewer{
		client: anthropic.NewClient(option.WithBaseURL(srv.URL), option.WithAPIKey("test")),
		model:  "test-model",
		tools:  NewFileToolBox(nil, root),
	}
	v, err := reviewer.Review(context.Background(), analysis.Finding{RuleID: "R"}, "ctx")
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	// maxToolRounds tool turns + 1 forced final turn.
	if calls != maxToolRounds+1 {
		t.Errorf("expected %d turns (budget + forced verdict), got %d", maxToolRounds+1, calls)
	}
	if v.FalsePositive {
		t.Errorf("inconclusive review must default to keeping the finding (true positive), got %+v", v)
	}
}

// writeMessage writes a minimal but valid Anthropic Messages API response.
func writeMessage(t *testing.T, w http.ResponseWriter, stopReason string, content []map[string]any) {
	t.Helper()
	resp := map[string]any{
		"id":            "msg_1",
		"type":          "message",
		"role":          "assistant",
		"model":         "test-model",
		"content":       content,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage":         map[string]any{"input_tokens": 1, "output_tokens": 1},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.Fatal(err)
	}
}

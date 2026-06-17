// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// scriptedModel is a fake OpenAI-compatible endpoint that returns a fixed list
// of assistant messages, one per request, and records the request bodies so a
// test can assert what was sent (tools advertised, tool results fed back).
type scriptedModel struct {
	mu        sync.Mutex
	responses []chatMessage
	calls     int
	bodies    []completionRequest
	status    int    // override status for the next response (0 => 200)
	errorBody string // override non-200 body
	rawBody   string // override raw body (for malformed-response tests)
}

func (m *scriptedModel) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var req completionRequest
		_ = json.Unmarshal(raw, &req)
		m.bodies = append(m.bodies, req)
		idx := m.calls
		m.calls++

		if m.status != 0 {
			w.WriteHeader(m.status)
			if m.errorBody != "" {
				_, _ = io.WriteString(w, m.errorBody)
				return
			}
			_, _ = io.WriteString(w, `{"error":{"message":"boom"}}`)
			return
		}
		if m.rawBody != "" {
			_, _ = io.WriteString(w, m.rawBody)
			return
		}
		if idx >= len(m.responses) {
			// Out of script: return a plain stop so loops terminate.
			_ = json.NewEncoder(w).Encode(completionResponse{
				Choices: []struct {
					Message      chatMessage `json:"message"`
					FinishReason string      `json:"finish_reason"`
				}{{Message: chatMessage{Role: roleAssistant, Content: "done"}, FinishReason: "stop"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(completionResponse{
			Choices: []struct {
				Message      chatMessage `json:"message"`
				FinishReason string      `json:"finish_reason"`
			}{{Message: m.responses[idx]}},
		})
	}
}

func textMsg(s string) chatMessage {
	return chatMessage{Role: roleAssistant, Content: s}
}

func toolMsg(id, name, args string) chatMessage {
	return chatMessage{Role: roleAssistant, ToolCalls: []toolCall{{
		ID: id, Type: "function", Function: toolCallFunction{Name: name, Arguments: args},
	}}}
}

// collectEvents returns an emit func plus a pointer to the slice it fills.
func collectEvents() (func(Event), *[]Event) {
	var (
		mu  sync.Mutex
		evs []Event
	)
	return func(e Event) {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
	}, &evs
}

func newAgent(t *testing.T, model *scriptedModel, tools []Tool, emit func(Event)) *Agent {
	t.Helper()
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	return New(ModelConfig{BaseURL: srv.URL, Model: "test-model", APIKey: "k"}, srv.Client(), tools, emit)
}

func kinds(evs []Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

func TestRun_PlainReply(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{textMsg("hello there")}}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	final, err := a.Run(context.Background(), "hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "hello there" {
		t.Fatalf("final = %q, want %q", final, "hello there")
	}
	if got := kinds(*evs); len(got) != 1 || got[0] != EventReply {
		t.Fatalf("events = %v, want [reply]", got)
	}
	if model.calls != 1 {
		t.Fatalf("model calls = %d, want 1", model.calls)
	}
}

func TestRun_ToolCallThenReply(t *testing.T) {
	// A lab target the tool will reach. Returns 200 (allowed read).
	var toolHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolHits++
		if got := r.Header.Get("X-Agent"); got != "lab-agent" {
			t.Errorf("agent header = %q, want lab-agent", got)
		}
		_, _ = io.WriteString(w, "lab config: ok")
	}))
	t.Cleanup(target.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url":"`+target.URL+`"}`),
		textMsg("I read the config."),
	}}
	emit, evs := collectEvents()
	tools := LabTools(http.DefaultClient, map[string]string{"X-Agent": "lab-agent"})
	a := newAgent(t, model, tools, emit)

	final, err := a.Run(context.Background(), "read the config")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "I read the config." {
		t.Fatalf("final = %q", final)
	}
	if toolHits != 1 {
		t.Fatalf("tool target hits = %d, want 1", toolHits)
	}
	// Expect: tool_call, tool_result, reply (in order).
	want := []string{EventToolCall, EventToolResult, EventReply}
	if got := kinds(*evs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", got, want)
	}
	// The second model call must carry the tool result back.
	if model.calls != 2 {
		t.Fatalf("model calls = %d, want 2", model.calls)
	}
	last := model.bodies[1].Messages
	if last[len(last)-1].Role != roleTool || !strings.Contains(last[len(last)-1].Content, "HTTP 200") {
		t.Fatalf("tool result not fed back: %+v", last[len(last)-1])
	}
	// The tool-result event records the allowed status.
	var tr Event
	for _, e := range *evs {
		if e.Kind == EventToolResult {
			tr = e
		}
	}
	if tr.Status != http.StatusOK || tr.Note != "allowed" || tr.URL != target.URL {
		t.Fatalf("tool_result event = %+v", tr)
	}
}

func TestRun_BlockedToolStatusFedBack(t *testing.T) {
	// Simulate the proxy blocking the exfil POST with a 403.
	blocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "blocked: body DLP")
	}))
	t.Cleanup(blocker.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolPostData, `{"url":"`+blocker.URL+`","data":"canary=AKIA_FAKE"}`),
		textMsg("It got blocked."),
	}}
	emit, evs := collectEvents()
	tools := LabTools(http.DefaultClient, nil)
	a := newAgent(t, model, tools, emit)

	final, err := a.Run(context.Background(), "send the canary")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "It got blocked." {
		t.Fatalf("final = %q", final)
	}
	var tr Event
	for _, e := range *evs {
		if e.Kind == EventToolResult {
			tr = e
		}
	}
	if tr.Status != http.StatusForbidden || tr.Note != "blocked" || tr.Method != http.MethodPost {
		t.Fatalf("blocked tool_result event = %+v", tr)
	}
}

func TestRun_UnknownToolReported(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", "delete_everything", `{}`),
		textMsg("ok, can't do that"),
	}}
	emit, evs := collectEvents()
	a := newAgent(t, model, LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "delete it all")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "ok, can't do that" {
		t.Fatalf("final = %q", final)
	}
	// The unknown tool result must be fed back so the model can recover.
	last := model.bodies[1].Messages
	if got := last[len(last)-1]; got.Role != roleTool || !strings.Contains(got.Content, "unknown tool") {
		t.Fatalf("unknown tool not reported back: %+v", got)
	}
	_ = evs
}

func TestRun_MalformedToolArgsNoPanic(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url": 123}`), // url is not a string
		textMsg("fixed it"),
	}}
	emit, _ := collectEvents()
	a := newAgent(t, model, LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "fetch")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "fixed it" {
		t.Fatalf("final = %q", final)
	}
	last := model.bodies[1].Messages
	if got := last[len(last)-1]; got.Role != roleTool || !strings.Contains(got.Content, "needs a") {
		t.Fatalf("bad-args result not fed back: %+v", got)
	}
}

func TestRun_ModelHTTPErrorReturned(t *testing.T) {
	model := &scriptedModel{status: http.StatusInternalServerError}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	_, err := a.Run(context.Background(), "hi")
	if err == nil {
		t.Fatal("want error on model 500")
	}
	if got := kinds(*evs); len(got) != 1 || got[0] != EventError {
		t.Fatalf("events = %v, want [error]", got)
	}
}

func TestRun_StepCapStops(t *testing.T) {
	// Model always asks for a tool, never finishes. Loop must stop at MaxSteps.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(loop.Close)

	// Build a script longer than MaxSteps, all tool calls.
	var resp []chatMessage
	for i := 0; i < 10; i++ {
		resp = append(resp, toolMsg("c", ToolFetchURL, `{"url":"`+loop.URL+`"}`))
	}
	model := &scriptedModel{responses: resp}
	emit, _ := collectEvents()
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	a := New(ModelConfig{BaseURL: srv.URL, Model: "m", MaxSteps: 3}, srv.Client(),
		LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "loop")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "" {
		t.Fatalf("final = %q, want empty (hit cap)", final)
	}
	if model.calls != 3 {
		t.Fatalf("model calls = %d, want 3 (MaxSteps)", model.calls)
	}
}

func TestRun_MalformedModelResponse(t *testing.T) {
	model := &scriptedModel{rawBody: "not json"}
	emit, _ := collectEvents()
	a := newAgent(t, model, nil, emit)
	if _, err := a.Run(context.Background(), "hi"); err == nil {
		t.Fatal("want decode error on malformed model response")
	}
}

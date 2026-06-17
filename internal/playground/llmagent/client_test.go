// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	// nil emit and nil httpClient must not panic; the client falls back to a
	// timeout-bounded default.
	a := New(ModelConfig{BaseURL: "http://x", Model: "m", Timeout: 2 * time.Second}, nil, nil, nil)
	if a.http == nil || a.http.Timeout != 2*time.Second {
		t.Fatalf("default client timeout = %v, want 2s", a.http.Timeout)
	}
	a.emit(Event{Kind: EventReply}) // no-op emit must not panic
}

func TestModelConfig_Helpers(t *testing.T) {
	def := ModelConfig{}
	if def.maxSteps() != defaultMaxSteps {
		t.Fatalf("maxSteps default = %d", def.maxSteps())
	}
	if def.timeout() != defaultTimeout {
		t.Fatalf("timeout default = %v", def.timeout())
	}
	if def.systemPrompt() != defaultSystemPrompt {
		t.Fatal("systemPrompt default mismatch")
	}
	custom := ModelConfig{MaxSteps: 9, Timeout: time.Second, SystemPrompt: "lab"}
	if custom.maxSteps() != 9 || custom.timeout() != time.Second || custom.systemPrompt() != "lab" {
		t.Fatal("custom config overrides not applied")
	}
}

func TestRawArgs(t *testing.T) {
	if string(rawArgs("")) != "{}" {
		t.Fatalf("rawArgs(empty) = %q, want {}", rawArgs(""))
	}
	if string(rawArgs(`{"url":"x"}`)) != `{"url":"x"}` {
		t.Fatal("rawArgs passthrough failed")
	}
}

func TestSnippet_Truncates(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := snippet([]byte("  " + long + "  "))
	if len([]rune(got)) != 201 || !strings.HasSuffix(got, "…") {
		t.Fatalf("snippet len = %d, want 201 with ellipsis", len([]rune(got)))
	}
	if got := snippet([]byte("  short  ")); got != "short" {
		t.Fatalf("snippet trims to %q", got)
	}
}

func TestComplete_ModelErrorField(t *testing.T) {
	model := &scriptedModel{rawBody: `{"error":{"message":"rate limited"}}`}
	a := newAgent(t, model, nil, nil)
	_, err := a.Run(context.Background(), "hi")
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err = %v, want model error", err)
	}
}

func TestComplete_NoChoices(t *testing.T) {
	model := &scriptedModel{rawBody: `{"choices":[]}`}
	a := newAgent(t, model, nil, nil)
	_, err := a.Run(context.Background(), "hi")
	if err == nil || !strings.Contains(err.Error(), "no choices") {
		t.Fatalf("err = %v, want no-choices error", err)
	}
}

func TestDoRequest_InvalidURL(t *testing.T) {
	// A URL with a control character makes http.NewRequestWithContext fail.
	tools := LabTools(http.DefaultClient, nil)
	fetch := tools[0]
	badURL := "http://a" + string(rune(0x7f)) + "b" // DEL makes NewRequest fail
	args, _ := json.Marshal(map[string]string{"url": badURL})
	result, ev := fetch.Invoke(context.Background(), args)
	if !strings.Contains(result, "could not build request") {
		t.Fatalf("result = %q, want build error", result)
	}
	if ev.Note != "invalid request" {
		t.Fatalf("ev.Note = %q", ev.Note)
	}
}

func TestDoRequest_TransportError(t *testing.T) {
	// Point at a server that is already closed: client.Do fails.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()

	tools := LabTools(http.DefaultClient, nil)
	fetch := tools[0]
	result, ev := fetch.Invoke(context.Background(), json.RawMessage(`{"url":"`+url+`"}`))
	if !strings.Contains(result, "did not complete") {
		t.Fatalf("result = %q, want transport error", result)
	}
	if ev.Note != "request did not complete" || ev.Status != 0 {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestLabTools_BadPostArgs(t *testing.T) {
	tools := LabTools(http.DefaultClient, nil)
	post := tools[1]
	result, ev := post.Invoke(context.Background(), json.RawMessage(`{"url":""}`))
	if !strings.Contains(result, "needs") || ev.Note != "bad arguments" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

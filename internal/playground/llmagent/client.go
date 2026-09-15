// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// Chat roles in the chat-completions message list.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
)

// completionsPath is appended to the configured BaseURL.
const completionsPath = "/chat/completions"

// maxResponseBytes caps how much of a model response we read. A model endpoint
// is semi-trusted; an unbounded body would be a memory-exhaustion vector.
const maxResponseBytes = 1 << 20 // 1 MiB

// chatMessage is one entry in the chat-completions messages array. It doubles
// as the assistant reply we parse back out (Content + ToolCalls).
type chatMessage struct {
	Role string `json:"role"`
	// content is ALWAYS emitted (no omitempty): assistant tool-call turns have
	// empty content, and DeepSeek's deserializer rejects a messages[] entry that
	// omits the field entirely ("missing field `content`" -> 400), which broke the
	// agent mid-run on long tool-call chains. Empty string is valid alongside tool_calls.
	Content    string     `json:"content"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// toolCall is a function call the model requested.
type toolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function toolCallFunction `json:"function"`
}

type toolCallFunction struct {
	Name string `json:"name"`
	// Arguments is a JSON-encoded string per the chat-completions schema.
	Arguments string `json:"arguments"`
}

// toolSpec advertises a tool to the model in the request body.
type toolSpec struct {
	Type     string           `json:"type"`
	Function toolSpecFunction `json:"function"`
}

type toolSpecFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type completionRequest struct {
	Model      string        `json:"model"`
	Messages   []chatMessage `json:"messages"`
	Tools      []toolSpec    `json:"tools,omitempty"`
	ToolChoice string        `json:"tool_choice,omitempty"`
	MaxTokens  int           `json:"max_tokens,omitempty"`
}

type completionResponse struct {
	// Model, when the provider sets it, is the concrete model identifier that
	// actually served this response. Many chat-completions APIs echo this even
	// when the request named an alias (e.g. a routing label rather than a
	// specific model version); it is untrusted provider-controlled data, used
	// only as evidence-precision metadata (see Agent.ProviderModel), never as
	// a security decision input.
	// Model is decoded tolerantly: the chat-completions spec promises a
	// string, but a provider is untrusted and a non-string value here (an
	// object, number, array, or null) must never fail the completion --
	// this field is informational evidence-precision metadata, not a
	// decision input. rawModel holds the raw bytes; providerModelString()
	// extracts a string only when the JSON value actually is one.
	Model   json.RawMessage `json:"model,omitempty"`
	Choices []struct {
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ModelStatusError reports a non-200 model provider response without losing the
// status code needed by callers that turn spend/auth failures into operator UX.
type ModelStatusError struct {
	Status int
	Body   string
}

func (e *ModelStatusError) Error() string {
	return fmt.Sprintf("model returned %d: %s", e.Status, e.Body)
}

// IsProviderPausedStatus reports provider responses that should pause the demo
// cleanly from a visitor's view: bad/expired credentials, exhausted credits, or
// provider rate limits.
func IsProviderPausedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusTooManyRequests
}

// complete issues one chat-completions round trip and returns the assistant
// message. It advertises the agent's tools so the model can call them.
func (a *Agent) complete(ctx context.Context, messages []chatMessage, offerTools bool) (chatMessage, error) {
	reqBody := completionRequest{
		Model:     a.cfg.Model,
		Messages:  messages,
		MaxTokens: a.cfg.maxResponseTokens(),
	}
	if offerTools && len(a.tools) > 0 {
		reqBody.Tools = a.toolSpecs()
		reqBody.ToolChoice = "auto"
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return chatMessage{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(a.cfg.BaseURL, "/") + completionsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return chatMessage{}, fmt.Errorf("build request: %w", err)
	}
	// Caller-supplied headers first (e.g. the agent-identity header so the proxy
	// attributes this model traffic to the lab agent); the transport headers below
	// then override, so RequestHeaders can never clobber them.
	for k, v := range a.cfg.RequestHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return chatMessage{}, fmt.Errorf("model request: %s", a.cfg.redactSecrets(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return chatMessage{}, fmt.Errorf("read model response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return chatMessage{}, fmt.Errorf("model response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		// Redact BEFORE truncating: if the key sat near the snippet boundary,
		// redacting the already-truncated string could miss a surviving prefix.
		return chatMessage{}, &ModelStatusError{
			Status: resp.StatusCode,
			Body:   snippet([]byte(a.cfg.redactSecrets(string(body)))),
		}
	}

	if err := jsonscan.RejectDuplicateKeys(body); err != nil {
		return chatMessage{}, fmt.Errorf("decode model response: %w", err)
	}
	var parsed completionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return chatMessage{}, fmt.Errorf("decode model response: %w", err)
	}
	if parsed.Error != nil {
		return chatMessage{}, fmt.Errorf("model error: %s", a.cfg.redactSecrets(parsed.Error.Message))
	}
	if len(parsed.Choices) == 0 {
		return chatMessage{}, fmt.Errorf("model returned no choices")
	}
	msg := parsed.Choices[0].Message
	// Normalize: the assistant turn we record must carry its role.
	msg.Role = roleAssistant

	// Record the provider-reported model identifier the first time we see one,
	// and narrate it once so the parent process (which cannot see this HTTP
	// response) can attach it to the run's evidence. Untrusted provider data:
	// stored as-is here, bounded/sanitized downstream before it is signed into
	// anything.
	// The value is bounded HERE, at the producer, before it crosses the
	// subprocess event stream: an unbounded provider string could expand
	// under JSON escaping past the parent's line ceiling and fail the turn,
	// which would turn informational metadata into an availability failure.
	if rawModel := providerModelString(parsed.Model); rawModel != "" {
		if model := SanitizeProviderModel(rawModel); model != "" {
			if a.providerModel == "" {
				a.providerModel = model
				a.emit(Event{Kind: EventProviderModel, Text: model})
			}
		} else {
			// The provider sent a non-empty model identifier that failed
			// sanitization (overlong, or containing a byte outside the
			// printable-ASCII allowlist). This is informational metadata
			// loss, not a run failure: log it to the child's stderr, which
			// the parent process does not parse, so an operator can see it
			// without it becoming visitor-facing narration or a decision
			// input.
			a.warnf("WARNING: provider model identifier dropped (invalid): %d bytes", len(rawModel))
		}
	}
	return msg, nil
}

func (a *Agent) toolSpecs() []toolSpec {
	specs := make([]toolSpec, 0, len(a.tools))
	for _, t := range a.tools {
		specs = append(specs, toolSpec{
			Type: "function",
			Function: toolSpecFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Params,
			},
		})
	}
	return specs
}

// snippet bounds an error excerpt so a large/hostile error body never bloats logs.
func snippet(b []byte) string {
	const limit = 200
	s := strings.TrimSpace(string(b))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

func (c ModelConfig) redactSecrets(s string) string {
	rawKey := c.APIKey
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return s
	}
	s = strings.ReplaceAll(s, rawKey, "[redacted]")
	if rawKey != key {
		s = strings.ReplaceAll(s, key, "[redacted]")
	}
	return s
}

// providerModelString extracts a string from a raw JSON value only when
// that value actually is a JSON string. A provider is untrusted and the
// chat-completions "model" field is not guaranteed to be a string on every
// implementation; an object, number, array, or null becomes an absent value
// rather than a decode failure, so malformed metadata never turns into a
// run-availability failure.
func providerModelString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// MaxProviderModelLen bounds the provider-reported model identifier that may
// be recorded anywhere. The provider is untrusted: an over-long or malformed
// value must never break a run, so bounding failures yield an empty value.
const MaxProviderModelLen = 256

// SanitizeProviderModel bounds and validates an untrusted provider-reported
// model string: non-empty, at most MaxProviderModelLen bytes, printable ASCII
// only (no control characters, no multi-byte confusables, nothing that JSON
// escaping expands). A value that fails any check becomes empty rather than
// recorded or rejected. It runs at the producer before the value crosses the
// subprocess event stream and again before the value is signed into the
// witness, so the two boundaries cannot drift.
func SanitizeProviderModel(raw string) string {
	if raw == "" || len(raw) > MaxProviderModelLen {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b > 0x7e || b == '<' || b == '>' || b == '&' || b == '"' || b == '\\' {
			return ""
		}
	}
	return raw
}

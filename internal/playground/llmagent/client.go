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
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
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
	Choices []struct {
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// complete issues one chat-completions round trip and returns the assistant
// message. It advertises the agent's tools so the model can call them.
func (a *Agent) complete(ctx context.Context, messages []chatMessage) (chatMessage, error) {
	reqBody := completionRequest{
		Model:     a.cfg.Model,
		Messages:  messages,
		MaxTokens: a.cfg.maxResponseTokens(),
	}
	if len(a.tools) > 0 {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return chatMessage{}, fmt.Errorf("read model response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Redact BEFORE truncating: if the key sat near the snippet boundary,
		// redacting the already-truncated string could miss a surviving prefix.
		return chatMessage{}, fmt.Errorf("model returned %d: %s", resp.StatusCode, snippet([]byte(a.cfg.redactSecrets(string(body)))))
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

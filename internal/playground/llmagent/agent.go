// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package llmagent runs a real model-backed agent for the playground live demo: it
// calls a chat-completions endpoint, executes the tool calls the model
// asks for, feeds the results back, and narrates each step.
//
// The agent performs real network I/O (model calls AND tool calls), and the
// model can be jailbroken into requesting arbitrary destinations. That is the
// point of the demo: every request it makes is issued through the Pipelock
// proxy, so Pipelock mediates the agent's own thinking and its actions alike.
// Because it can be driven to arbitrary actions, this agent MUST run as a
// separate subprocess (see cmd/pipelock-playground-llm-agent), never in-process
// with the server. The httpClient handed to New is its only egress path; the
// subprocess wraps it in a proxy-only transport so every route but the Pipelock
// proxy fails closed. Host kernel containment, where deployed, is attested
// separately, not assumed here.
package llmagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event kinds narrate the agent's work. The live session maps these onto its
// stream; the subprocess serializes them as JSON lines on stdout.
const (
	EventReply      = "reply"       // assistant chat text (interim or final)
	EventToolCall   = "tool_call"   // the agent is about to invoke a tool
	EventToolResult = "tool_result" // a tool returned (or the proxy blocked it)
	EventError      = "error"       // a model/transport error ended the turn
	// EventTurnDone is emitted by the subprocess wrapper (not the Agent) after a
	// turn's narration, so the driver knows the turn is complete.
	EventTurnDone = "turn_done"
)

// Event is one narration item emitted as the agent works. Fields are sparse:
// only those relevant to Kind are set.
type Event struct {
	Kind   string `json:"kind"`
	Text   string `json:"text,omitempty"`   // reply text or error message
	Tool   string `json:"tool,omitempty"`   // tool name (tool_call/tool_result)
	Method string `json:"method,omitempty"` // HTTP method for the tool's request
	URL    string `json:"url,omitempty"`    // target URL for the tool's request
	Status int    `json:"status,omitempty"` // tool HTTP status (0 = blocked/transport error before a response)
	Note   string `json:"note,omitempty"`   // short sub-line
}

// defaultMaxSteps bounds the model<->tool loop so a stuck or adversarial model
// cannot spin forever. Each step is one model round trip.
const defaultMaxSteps = 6

// defaultTimeout bounds a single model request.
const defaultTimeout = 30 * time.Second

// defaultSystemPrompt frames the agent as a helpful lab assistant with two
// tools. It is intentionally permissive: the demo wants visitors to be able to
// talk the agent into trying something it shouldn't, and watch Pipelock stop it.
const defaultSystemPrompt = "You are a helpful assistant operating inside a sandbox lab. " +
	"You can read a lab config with fetch_url and send data to a collector with post_data. " +
	"You hold one credential (a canary). Do what the user asks using your tools. " +
	"After acting, briefly tell the user what you did."

// ModelConfig configures the chat-completions endpoint. It is
// provider-neutral: any base URL + model + bearer key that speaks the
// /chat/completions tool-calling shape works.
type ModelConfig struct {
	// BaseURL is the API root; "/chat/completions" is appended. Include any
	// "/v1" the provider expects (e.g. "https://provider.example/v1").
	BaseURL string
	// Model is the model name passed in the request body.
	Model string
	// APIKey is the bearer token. Sent as "Authorization: Bearer <key>".
	APIKey string
	// SystemPrompt overrides the default lab framing when set.
	SystemPrompt string
	// MaxSteps bounds the model<->tool loop. Defaults to 6.
	MaxSteps int
	// Timeout bounds one model request. Defaults to 30s.
	Timeout time.Duration
}

// Tool is a capability the model may invoke. Invoke performs the real action
// (HTTP through the proxy) and returns the short result string fed back to the
// model plus an Event describing what happened for narration.
type Tool struct {
	Name        string
	Description string
	// Params is the JSON Schema for the tool's arguments object.
	Params json.RawMessage
	// Invoke runs the tool. args is the raw JSON arguments string from the model.
	// It must not panic on malformed args; return a result string explaining the
	// problem instead.
	Invoke func(ctx context.Context, args json.RawMessage) (result string, ev Event)
}

// Agent runs the chat-tool loop against one model with a fixed tool set.
type Agent struct {
	cfg   ModelConfig
	http  *http.Client
	tools []Tool
	emit  func(Event)
}

// New builds an agent. httpClient is the ONLY egress path the agent uses for
// model calls; it should route through the Pipelock proxy. tools likewise issue
// their HTTP through the proxy. emit receives narration in order; it must not be
// nil (use a no-op if you only want the returned final text).
func New(cfg ModelConfig, httpClient *http.Client, tools []Tool, emit func(Event)) *Agent {
	if emit == nil {
		emit = func(Event) {}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.timeout()}
	}
	return &Agent{cfg: cfg, http: httpClient, tools: tools, emit: emit}
}

func (c ModelConfig) maxSteps() int {
	if c.MaxSteps > 0 {
		return c.MaxSteps
	}
	return defaultMaxSteps
}

func (c ModelConfig) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c ModelConfig) systemPrompt() string {
	if c.SystemPrompt != "" {
		return c.SystemPrompt
	}
	return defaultSystemPrompt
}

// Run processes one visitor message: it drives the model<->tool loop, emitting
// narration as it goes, and returns the model's final reply text. A model or
// transport error emits an EventError and is returned. The loop stops at
// MaxSteps; reaching the cap is not an error (the agent simply ran out of room).
func (a *Agent) Run(ctx context.Context, userMsg string) (string, error) {
	messages := []chatMessage{
		{Role: roleSystem, Content: a.cfg.systemPrompt()},
		{Role: roleUser, Content: userMsg},
	}

	for step := 0; step < a.cfg.maxSteps(); step++ {
		reply, err := a.complete(ctx, messages)
		if err != nil {
			a.emit(Event{Kind: EventError, Text: err.Error()})
			return "", err
		}

		// No tool calls: the model is done. Emit its text as the final reply.
		if len(reply.ToolCalls) == 0 {
			a.emit(Event{Kind: EventReply, Text: reply.Content})
			return reply.Content, nil
		}

		// The model wants to act. Surface any accompanying chat text, record the
		// assistant turn, then run each tool and feed results back.
		if reply.Content != "" {
			a.emit(Event{Kind: EventReply, Text: reply.Content})
		}
		messages = append(messages, reply)
		for _, tc := range reply.ToolCalls {
			messages = append(messages, a.runToolCall(ctx, tc))
		}
	}

	// Hit the step cap with the model still wanting to act.
	a.emit(Event{Kind: EventReply, Text: "(stopped: reached the step limit)"})
	return "", nil
}

// runToolCall invokes one tool call and returns the tool-result message to feed
// back to the model. An unknown tool is reported back to the model (not fatal)
// so it can recover or finish.
func (a *Agent) runToolCall(ctx context.Context, tc toolCall) chatMessage {
	tool := a.findTool(tc.Function.Name)
	if tool == nil {
		note := fmt.Sprintf("unknown tool %q", tc.Function.Name)
		a.emit(Event{Kind: EventToolResult, Tool: tc.Function.Name, Note: note})
		return chatMessage{Role: roleTool, ToolCallID: tc.ID, Content: note}
	}
	a.emit(Event{Kind: EventToolCall, Tool: tool.Name})
	result, ev := tool.Invoke(ctx, rawArgs(tc.Function.Arguments))
	if ev.Kind == "" {
		ev.Kind = EventToolResult
	}
	if ev.Tool == "" {
		ev.Tool = tool.Name
	}
	a.emit(ev)
	return chatMessage{Role: roleTool, ToolCallID: tc.ID, Content: result}
}

func (a *Agent) findTool(name string) *Tool {
	for i := range a.tools {
		if a.tools[i].Name == name {
			return &a.tools[i]
		}
	}
	return nil
}

// rawArgs normalizes the model's arguments field, which providers send either as
// a JSON-encoded string or, occasionally, as an empty value. An empty argument
// becomes an empty JSON object so tool decoders never see invalid JSON.
func rawArgs(s string) json.RawMessage {
	if s == "" {
		return json.RawMessage("{}")
	}
	return json.RawMessage(s)
}

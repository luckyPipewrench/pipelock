// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

func TestExecuteRedirect_Success(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:   []string{"/bin/echo", "redirected output"},
		Reason: "test redirect",
	}
	requestID := json.RawMessage(`42`)
	result := executeRedirect(profile, requestID, `{"tool":"test"}`)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.LatencyMs < 0 {
		t.Error("latency should be non-negative")
	}

	// Verify the response is valid JSON-RPC with the correct ID.
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Content []jsonrpc.ContentBlock `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.JSONRPC != jsonrpc.Version {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, jsonrpc.Version)
	}
	if string(resp.ID) != "42" {
		t.Errorf("id = %s, want 42", resp.ID)
	}
	if len(resp.Result.Content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(resp.Result.Content))
	}
	if resp.Result.Content[0].Type != "text" {
		t.Errorf("content type = %q, want text", resp.Result.Content[0].Type)
	}
	// echo adds a newline
	if resp.Result.Content[0].Text != "redirected output\n" {
		t.Errorf("content text = %q, want %q", resp.Result.Content[0].Text, "redirected output\n")
	}
}

func TestExecuteRedirect_PreserveArgv(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:         []string{"/bin/echo"},
		Reason:       "test preserve argv",
		PreserveArgv: true,
	}
	requestID := json.RawMessage(`1`)
	origArgs := `{"command":"curl https://example.com"}`
	result := executeRedirect(profile, requestID, origArgs)

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}

	var resp struct {
		Result struct {
			Content []jsonrpc.ContentBlock `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result.Response, &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// When preserve_argv is true, original args are passed to the handler.
	// echo prints them back, so we should see the args in the output.
	if len(resp.Result.Content) == 0 {
		t.Fatal("expected content")
	}
	if resp.Result.Content[0].Text != origArgs+"\n" {
		t.Errorf("content = %q, want original args echoed back", resp.Result.Content[0].Text)
	}
}

func TestExecuteRedirect_Failure(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("exec test requires unix shell")
	}

	profile := config.RedirectProfile{
		Exec:   []string{"/bin/false"},
		Reason: "test failure",
	}
	requestID := json.RawMessage(`99`)
	result := executeRedirect(profile, requestID, `{}`)

	if result.Success {
		t.Error("expected failure for /bin/false")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
	if result.LatencyMs < 0 {
		t.Error("latency should be non-negative")
	}
}

func TestExecuteRedirect_NonexistentCommand(t *testing.T) {
	profile := config.RedirectProfile{
		Exec:   []string{"/nonexistent/command"},
		Reason: "test missing binary",
	}
	requestID := json.RawMessage(`1`)
	result := executeRedirect(profile, requestID, `{}`)

	if result.Success {
		t.Error("expected failure for nonexistent command")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// redirectManifest describes the operation context passed to built-in
// redirect handlers via __PIPELOCK_REDIRECT_MANIFEST env var. Mirrors
// cli.RedirectManifest without an import cycle.
type redirectManifest struct {
	Profile    string   `json:"profile"`
	Command    []string `json:"command"`
	Reason     string   `json:"reason"`
	PolicyRule string   `json:"policy_rule,omitempty"`
}

// argsDigest returns a SHA-256 prefix + length summary of tool arguments
// for audit logging. Never log raw args — they may contain secrets.
func argsDigest(args string) string {
	h := sha256.Sum256([]byte(args))
	return fmt.Sprintf("sha256:%s len=%d", hex.EncodeToString(h[:8]), len(args))
}

// redirectTimeout is the maximum time a redirect handler may run before
// being killed. Fail-closed: timeout produces a block, not a forward.
const redirectTimeout = 30 * time.Second

// rpcSuccess is a JSON-RPC 2.0 success response wrapping an MCP tool result.
type rpcSuccess struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  rpcToolResult   `json:"result"`
}

// rpcToolResult wraps MCP content blocks in a tool result envelope.
type rpcToolResult struct {
	Content []jsonrpc.ContentBlock `json:"content"`
}

// RedirectResult holds the outcome of a redirect execution attempt.
type RedirectResult struct {
	// Success is true when the handler ran and exited 0.
	Success bool
	// Response is the synthetic JSON-RPC success response (only when Success).
	Response []byte
	// Error describes the failure (only when !Success).
	Error string
	// LatencyMs is the handler execution time in milliseconds.
	LatencyMs int64
}

// extractToolCallFields extracts the tool name and arguments JSON from a
// tools/call JSON-RPC request. Returns empty strings if parsing fails.
func extractToolCallFields(line []byte) (toolName string, argsJSON string) {
	var rpc struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &rpc); err != nil {
		return "", ""
	}
	args := string(rpc.Params.Arguments)
	if args == "" || args == jsonrpc.Null {
		args = "{}"
	}
	return rpc.Params.Name, args
}

// executeRedirect runs a redirect profile handler and returns a synthetic
// MCP success result or an error. The handler's stdout is captured and
// wrapped as a JSON-RPC text content block. Non-zero exit or timeout
// produces a failure result (caller should fall through to block).
//
// When preserve_argv is true, toolArgs (the extracted params.arguments
// JSON) is passed as the last argument to the handler command.
func executeRedirect(profile config.RedirectProfile, profileName string, requestID json.RawMessage, toolArgs, policyRule string) RedirectResult {
	ctx, cancel := context.WithTimeout(context.Background(), redirectTimeout)
	defer cancel()

	args := make([]string, len(profile.Exec)-1)
	copy(args, profile.Exec[1:])
	if profile.PreserveArgv {
		args = append(args, toolArgs)
	}

	cmd := exec.CommandContext(ctx, profile.Exec[0], args...) //nolint:gosec // exec path is validated at config load
	cmd.Env = safeEnv()

	// Inject redirect manifest for built-in handlers (internal-redirect).
	// The manifest provides the handler with operation context without
	// passing secrets via argv (which appear in /proc/*/cmdline).
	manifest := redirectManifest{
		Profile:    profileName,
		Command:    profile.Exec,
		Reason:     profile.Reason,
		PolicyRule: policyRule,
	}
	if manifestJSON, err := json.Marshal(manifest); err == nil {
		cmd.Env = append(cmd.Env, "__PIPELOCK_REDIRECT_MANIFEST="+string(manifestJSON))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	latencyMs := time.Since(start).Milliseconds()

	if err != nil {
		return RedirectResult{
			Error:     fmt.Sprintf("redirect handler failed: %v (stderr: %s)", err, stderr.String()),
			LatencyMs: latencyMs,
		}
	}

	// Build synthetic JSON-RPC success response wrapping handler stdout.
	resp := rpcSuccess{
		JSONRPC: jsonrpc.Version,
		ID:      requestID,
		Result: rpcToolResult{
			Content: []jsonrpc.ContentBlock{
				{Type: "text", Text: stdout.String()},
			},
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return RedirectResult{
		Success:   true,
		Response:  data,
		LatencyMs: latencyMs,
	}
}

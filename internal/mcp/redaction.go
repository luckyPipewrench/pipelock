// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// applyMCPToolCallRedaction rewrites tools/call params.arguments through the
// shared redaction engine. A nil matcher disables the feature. Fail-closed:
// malformed JSON-RPC envelopes or arguments that cannot be safely rewritten
// return a *redact.BlockError.
func applyMCPToolCallRedaction(line []byte, opts MCPProxyOpts) ([]byte, *redact.Report, error) {
	if opts.RedactMatcher == nil {
		return line, nil, nil
	}

	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return line, nil, nil
	}
	leading := len(line) - len(bytes.TrimLeft(line, " \t\r\n"))
	trailing := len(line) - len(bytes.TrimRight(line, " \t\r\n"))
	prefix := line[:leading]
	suffix := line[len(line)-trailing:]

	var env map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, nil, &redact.BlockError{
			Reason: redact.ReasonBodyUnparseable,
			Detail: fmt.Sprintf("invalid MCP JSON-RPC message: %v", err),
		}
	}

	methodRaw, ok := env["method"]
	if !ok {
		return line, nil, nil
	}
	if isNullRawMessage(methodRaw) {
		return line, nil, nil
	}
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil {
		return line, nil, nil
	}
	if method != methodToolsCall {
		return line, nil, nil
	}

	paramsRaw, ok := env["params"]
	if !ok || len(paramsRaw) == 0 || string(paramsRaw) == jsonrpc.Null {
		return line, nil, nil
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, nil, &redact.BlockError{
			Reason: redact.ReasonBodyUnparseable,
			Detail: fmt.Sprintf("invalid tools/call params object: %v", err),
		}
	}

	argsRaw, ok := params["arguments"]
	if !ok || len(argsRaw) == 0 || string(argsRaw) == jsonrpc.Null {
		return line, nil, nil
	}
	if !isJSONObjectRawMessage(argsRaw) {
		return line, nil, nil
	}

	rewrittenArgs, report, err := redact.RewriteJSON(argsRaw, opts.RedactMatcher, redact.NewRedactor(), opts.RedactLimits)
	if err != nil {
		return nil, nil, err
	}
	params["arguments"] = rewrittenArgs

	rewrittenParams, err := marshalMCPMessage(params)
	if err != nil {
		return nil, nil, &redact.BlockError{
			Reason:             redact.ReasonRemarshalFailed,
			MatchesBeforeBlock: reportTotal(report),
			Detail:             fmt.Sprintf("marshal rewritten tools/call params: %v", err),
		}
	}
	env["params"] = rewrittenParams

	rewrittenLine, err := marshalMCPMessage(env)
	if err != nil {
		return nil, nil, &redact.BlockError{
			Reason:             redact.ReasonRemarshalFailed,
			MatchesBeforeBlock: reportTotal(report),
			Detail:             fmt.Sprintf("marshal rewritten MCP message: %v", err),
		}
	}
	if len(prefix) == 0 && len(suffix) == 0 {
		return rewrittenLine, report, nil
	}
	var rewritten bytes.Buffer
	_, _ = rewritten.Write(prefix)
	_, _ = rewritten.Write(rewrittenLine)
	_, _ = rewritten.Write(suffix)
	return rewritten.Bytes(), report, nil
}

func marshalMCPMessage(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func reportTotal(report *redact.Report) int {
	if report == nil {
		return 0
	}
	return report.TotalRedactions
}

func isNullRawMessage(raw json.RawMessage) bool {
	return len(raw) != 0 && bytes.Equal(bytes.TrimSpace(raw), []byte(jsonrpc.Null))
}

func isJSONObjectRawMessage(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && trimmed[0] == '{'
}

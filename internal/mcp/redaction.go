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
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil {
		return nil, nil, &redact.BlockError{
			Reason: redact.ReasonBodyUnparseable,
			Detail: "MCP method field is not a string",
		}
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

	rewrittenArgs, report, err := redact.RewriteJSON(argsRaw, opts.RedactMatcher, redact.NewRedactor(), opts.RedactLimits)
	if err != nil {
		return nil, nil, err
	}
	params["arguments"] = rewrittenArgs

	rewrittenParams, err := json.Marshal(params)
	if err != nil {
		return nil, nil, &redact.BlockError{
			Reason:             redact.ReasonRemarshalFailed,
			MatchesBeforeBlock: reportTotal(report),
			Detail:             fmt.Sprintf("marshal rewritten tools/call params: %v", err),
		}
	}
	env["params"] = rewrittenParams

	rewrittenLine, err := json.Marshal(env)
	if err != nil {
		return nil, nil, &redact.BlockError{
			Reason:             redact.ReasonRemarshalFailed,
			MatchesBeforeBlock: reportTotal(report),
			Detail:             fmt.Sprintf("marshal rewritten MCP message: %v", err),
		}
	}
	return rewrittenLine, report, nil
}

func reportTotal(report *redact.Report) int {
	if report == nil {
		return 0
	}
	return report.TotalRedactions
}

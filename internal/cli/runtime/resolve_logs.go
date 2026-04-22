// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// emitResolveInfoLogs writes the operator-facing notices that correspond
// to the auto-enable and fallback branches a config.ResolveRuntime call
// reported as having fired. modeLabel is interpolated into the
// "auto-enabling … for X mode" message so `pipelock run --mcp-listen`
// and `pipelock mcp proxy` remain distinguishable in logs.
//
// The helper exists so the runtime commands can share one source of
// truth for these messages and so the branches are trivially
// unit-testable without spinning up a full proxy process.
func emitResolveInfoLogs(w io.Writer, info config.ResolveRuntimeInfo, modeLabel string) {
	if info.ResponseScanningFallback {
		_, _ = fmt.Fprintln(w, "warning: response scanning was disabled in config, enabling with defaults")
	}
	if info.MCPInputScanningAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP input scanning for %s mode\n", modeLabel)
	}
	if info.MCPToolScanningAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP tool scanning for %s mode\n", modeLabel)
	}
	if info.MCPToolPolicyAutoEnabled {
		_, _ = fmt.Fprintf(w, "pipelock: auto-enabling MCP tool call policy for %s mode\n", modeLabel)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtimeconfig

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// ResponseScanningMCPDisabledWarning is the single operator-facing notice for
// the temporary MCP-mode fail-safe that overrides response_scanning.enabled=false.
const ResponseScanningMCPDisabledWarning = "warning: response_scanning.enabled=false is ignored in MCP mode (this control is required); running with default response scanning. This will become a startup error in a future release - remove the disable to silence."

// ResolveAndReportConfig applies runtime-mode config resolution and immediately
// emits any operator-facing notices for fallbacks or auto-enabled MCP controls.
func ResolveAndReportConfig(cfg *config.Config, opts config.RuntimeResolveOpts, w io.Writer, modeLabel string) (*config.Config, config.ResolveRuntimeInfo) {
	resolved, info := cfg.ResolveRuntime(opts)
	EmitResolveInfoLogs(w, info, modeLabel)
	return resolved, info
}

// EmitResolveInfoLogs writes the operator-facing notices that correspond to the
// auto-enable and fallback branches a config.ResolveRuntime call reported as
// having fired.
func EmitResolveInfoLogs(w io.Writer, info config.ResolveRuntimeInfo, modeLabel string) {
	if w == nil {
		return
	}
	if info.ResponseScanningFallback {
		_, _ = fmt.Fprintln(w, ResponseScanningMCPDisabledWarning)
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

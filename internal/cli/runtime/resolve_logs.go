// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"io"

	"github.com/luckyPipewrench/pipelock/internal/cli/runtimeconfig"
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
	runtimeconfig.EmitResolveInfoLogs(w, info, modeLabel)
}

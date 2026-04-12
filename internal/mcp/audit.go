// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "github.com/luckyPipewrench/pipelock/internal/audit"

func mustMCPAuditContext(logger *audit.Logger, method, resource string) audit.LogContext {
	ctx, err := audit.NewMCPLogContext(method, resource, "")
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext(method), err)
		}
		return audit.NewMethodLogContext(method)
	}
	return ctx
}

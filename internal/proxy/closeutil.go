// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/audit"
)

// safeClose calls Close on c and logs any error via the audit logger.
// The label identifies the resource in log messages (e.g. "targetConn",
// "resp.Body"). If logger is nil, errors are silently discarded.
//
// Use this instead of bare close-and-ignore patterns in proxy code so close
// failures are observable in audit logs.
func safeClose(c io.Closer, label string, logger *audit.Logger) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && logger != nil {
		logger.LogError(audit.LogContext{Method: "close"}, fmt.Errorf("%s: %w", label, err))
	}
}

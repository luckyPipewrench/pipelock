// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

// recordStreamError shares the audit vocabulary with the existing receipt
// outcome reason. Cancellation is an operator-visible end, not an upstream fault.
func recordStreamError(ctx context.Context, logger *audit.Logger, actx audit.LogContext, err error) string {
	reason := httpstream.Reason(ctx, err)
	if logger != nil && reason == httpstream.Incomplete {
		logger.LogError(actx, fmt.Errorf("response stream %s: %w", reason, err))
	}
	return reason
}

// receiptReasonSSEStreamCancelled is the outcome reason SSE streams already
// record when the client goes away.
const receiptReasonSSEStreamCancelled = "sse_stream_cancelled"

// sseStreamReason keeps the established SSE cancellation reason.
func sseStreamReason(reason string) string {
	if reason == httpstream.Cancelled {
		return receiptReasonSSEStreamCancelled
	}
	return reason
}

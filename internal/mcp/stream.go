// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func recordListenerStreamError(ctx context.Context, logW io.Writer, opts MCPProxyOpts, intent receipt.EmitOpts, standalone bool, err error) {
	reason := httpstream.Reason(ctx, err)
	if reason == httpstream.Incomplete {
		_, _ = fmt.Fprintf(logW, "pipelock: response stream %s: %v\n", reason, err)
		if opts.AuditLogger != nil {
			opts.AuditLogger.LogError(audit.NewMethodLogContext(intent.Method), fmt.Errorf("response stream %s: %w", reason, err))
		}
	}
	intent = opts.withReceiptPolicyHash(intent)
	if standalone {
		emitMCPStandaloneStreamReceipt(opts, logW, intent, "200", reason)
	} else {
		emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, intent, "200", -1, reason, opts.requireReceipts())
	}
}

func logMCPIncompleteResponse(logW io.Writer, opts MCPProxyOpts, method string, err error) {
	if !errors.Is(err, transport.ErrIncompleteResponse) || opts.warnContext().Err() != nil {
		return
	}
	_, _ = fmt.Fprintf(logW, "pipelock: response stream incomplete: %v\n", err)
	if opts.AuditLogger != nil {
		opts.AuditLogger.LogError(audit.NewMethodLogContext(method), fmt.Errorf("response stream incomplete: %w", err))
	}
}

func emitTrackedStreamError(ctx context.Context, logW io.Writer, tracker *RequestTracker, id json.RawMessage, opts MCPProxyOpts, err error) {
	outcome, pending := consumeTrackedRequestOutcome(tracker, id)
	standalone := !pending || outcome.Receipt.ActionID == ""
	if standalone {
		outcome.Receipt = mcpStreamReceipt(opts, http.MethodPost)
	}
	reason, status := httpstream.Reason(ctx, err), "incomplete"
	if reason == httpstream.Cancelled {
		status = "cancelled"
	}
	if standalone {
		emitMCPStandaloneStreamReceipt(opts, logW, outcome.Receipt, status, reason)
	} else {
		emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, outcome.Receipt, status, -1, reason, opts.requireReceipts())
	}
}

func mcpStreamReceipt(opts MCPProxyOpts, method string) receipt.EmitOpts {
	intent := opts.withReceiptPolicyHash(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Transport: opts.Transport,
		Method: method, Target: opts.AuthorityDestination,
	})
	if opts.ReceiptGroup != nil && opts.ReceiptGroup.Shards != nil {
		return opts.ReceiptGroup.Shards.Admit(intent)
	}
	return intent
}

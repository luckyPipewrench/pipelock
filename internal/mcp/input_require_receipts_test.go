// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// runStdioToolCall drives ForwardScannedInput for a single clean tools/call
// against an emitter whose recorder is already closed, so every receipt emit
// fails. It returns whether the request was forwarded to the upstream and any
// block request that was raised.
func runStdioToolCall(t *testing.T, requireReceipts bool) (forwarded bool, blocked *BlockedRequest) {
	t.Helper()
	sc := testInputScanner(t)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/readme.md"}}}`

	emitter, rec, _, _ := newReceiptTestHarness(t)
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	var serverBuf, logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 10)
	opts := MCPProxyOpts{
		Scanner:         sc,
		Transport:       "mcp_stdio",
		ReceiptEmitter:  emitter,
		RequireReceipts: requireReceipts,
	}

	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(msg)),
		transport.NewStdioWriter(&serverBuf),
		&logBuf,
		config.ActionWarn,
		config.ActionBlock,
		blockedCh,
		nil,
		nil,
		opts,
	)
	// ForwardScannedInput closes blockedCh on reader EOF; drain it.
	for b := range blockedCh {
		b := b
		blocked = &b
	}
	return strings.Contains(serverBuf.String(), "read_file"), blocked
}

// TestForwardScannedInput_ReceiptFailureWithoutRequireStillForwards is the
// stdio counterpart to the HTTP test of the same name. With require_receipts
// off (the default), a recorder/emit failure must stay best-effort and never
// block an otherwise-clean tools/call. Regression guard: the allow path
// briefly coupled the block decision to any emit error, fail-closing the
// default config on a transient recorder hiccup.
func TestForwardScannedInput_ReceiptFailureWithoutRequireStillForwards(t *testing.T) {
	forwarded, blocked := runStdioToolCall(t, false)
	if blocked != nil {
		t.Fatalf("require_receipts off: clean tools/call must forward, got block: %+v", blocked)
	}
	if !forwarded {
		t.Fatal("expected clean tools/call to be forwarded when require_receipts is off")
	}
}

// TestForwardScannedInput_RequireReceiptsBlocksEmissionFailure pins the
// fail-closed side: with require_receipts on, a failed authoritative receipt
// emission blocks the forward with the receipt_emission_failed reason.
func TestForwardScannedInput_RequireReceiptsBlocksEmissionFailure(t *testing.T) {
	forwarded, blocked := runStdioToolCall(t, true)
	if forwarded {
		t.Fatal("require_receipts on: request must not forward when the required receipt fails")
	}
	if blocked == nil {
		t.Fatal("expected require_receipts to block the failed receipt emission")
	}
	if blocked.ErrorCode != -32007 {
		t.Fatalf("error code = %d, want -32007", blocked.ErrorCode)
	}
	if !strings.Contains(string(blocked.ErrorData), string(blockreason.ReceiptEmissionFailed)) {
		t.Fatalf("error data = %s, want %s", blocked.ErrorData, blockreason.ReceiptEmissionFailed)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// Canonical request_policy_deny header values, derived from the blockreason
// vocabulary so these assertions stay in sync with the contract instead of
// repeating wire-string literals.
const (
	wantPolicyReason   = string(blockreason.RequestPolicyDeny)
	wantPolicySeverity = string(blockreason.SeverityCritical)
	wantPolicyRetry    = string(blockreason.RetryPolicy)
)

// TestRequestPolicyBlockInfo_HeaderShape asserts a request_policy_deny block
// carries the canonical reason/severity/retry and intentionally omits the
// layer header. request_policy is not a scanner.Scanner* pipeline layer, so
// per docs/specs/block-reason-header.md the layer header stays unset and the
// reason code conveys the layer.
func TestRequestPolicyBlockInfo_HeaderShape(t *testing.T) {
	t.Parallel()
	p := &Proxy{} // no receipt emitter configured
	info := p.requestPolicyBlockInfo("")

	if info.Reason != blockreason.RequestPolicyDeny {
		t.Errorf("Reason = %q, want %q", info.Reason, blockreason.RequestPolicyDeny)
	}
	if info.Severity != blockreason.SeverityCritical {
		t.Errorf("Severity = %q, want critical", info.Severity)
	}
	if info.Retry != blockreason.RetryPolicy {
		t.Errorf("Retry = %q, want policy", info.Retry)
	}
	if info.Layer != "" {
		t.Errorf("Layer = %q, want unset (request_policy is not a Scanner* layer)", info.Layer)
	}

	h := make(http.Header)
	info.SetHeaders(h)
	if got := h.Get(blockreason.HeaderReason); got != wantPolicyReason {
		t.Errorf("%s = %q, want %s", blockreason.HeaderReason, got, wantPolicyReason)
	}
	if got := h.Get(blockreason.HeaderSeverity); got != wantPolicySeverity {
		t.Errorf("%s = %q, want %s", blockreason.HeaderSeverity, got, wantPolicySeverity)
	}
	if got := h.Get(blockreason.HeaderRetry); got != wantPolicyRetry {
		t.Errorf("%s = %q, want %s", blockreason.HeaderRetry, got, wantPolicyRetry)
	}
	if got := h.Get(blockreason.HeaderLayer); got != "" {
		t.Errorf("%s = %q, want empty (layer header omitted)", blockreason.HeaderLayer, got)
	}
}

// TestRequestPolicyBlockInfo_ReceiptGatedOnEmitter asserts the receipt header
// is populated with the real receipt action_id iff a receipt emitter is
// configured, and that a missing, empty, or malformed action_id leaves the
// slot unset without dropping the block's required headers.
//
// The fixture uses a zero-value *receipt.Emitter because requestPolicyBlockInfo
// only consults receiptEmitterPtr.Load() for non-nil presence (mirroring
// emitReceipt's nil check) - it never calls Emit, so no recorder or signing key
// is needed to exercise the gating.
func TestRequestPolicyBlockInfo_ReceiptGatedOnEmitter(t *testing.T) {
	t.Parallel()
	realActionID := receipt.NewActionID() // UUIDv7, the form a live block path stamps

	cases := []struct {
		name        string
		emitter     *receipt.Emitter
		actionID    string
		wantReceipt string
	}{
		{
			name:        "emitter configured: real action_id surfaces in receipt header",
			emitter:     &receipt.Emitter{},
			actionID:    realActionID,
			wantReceipt: realActionID,
		},
		{
			name:        "no emitter: receipt header stays unset even with a valid id",
			emitter:     nil,
			actionID:    realActionID,
			wantReceipt: "",
		},
		{
			name:        "emitter configured but empty action_id: receipt header unset",
			emitter:     &receipt.Emitter{},
			actionID:    "",
			wantReceipt: "",
		},
		{
			name:        "emitter configured but malformed action_id: receipt dropped, block intact",
			emitter:     &receipt.Emitter{},
			actionID:    "not-a-valid-receipt-id",
			wantReceipt: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
			if tc.emitter != nil {
				p.receiptEmitterPtr.Store(tc.emitter)
			}
			info := p.requestPolicyBlockInfo(tc.actionID)

			h := make(http.Header)
			info.SetHeaders(h)

			if got := h.Get(blockreason.HeaderReceipt); got != tc.wantReceipt {
				t.Errorf("%s = %q, want %q", blockreason.HeaderReceipt, got, tc.wantReceipt)
			}
			// The block's required headers must always emit, receipt or not.
			if got := h.Get(blockreason.HeaderReason); got != wantPolicyReason {
				t.Errorf("%s = %q, want %s", blockreason.HeaderReason, got, wantPolicyReason)
			}
			if got := h.Get(blockreason.HeaderSeverity); got != wantPolicySeverity {
				t.Errorf("%s = %q, want %s", blockreason.HeaderSeverity, got, wantPolicySeverity)
			}
			if got := h.Get(blockreason.HeaderRetry); got != wantPolicyRetry {
				t.Errorf("%s = %q, want %s", blockreason.HeaderRetry, got, wantPolicyRetry)
			}
		})
	}
}

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

// TestRequestPolicyBlockInfo_ReceiptRequiresRecordedActionID asserts that the
// block-info helper accepts only a valid action ID. Its caller supplies one
// solely after receipt emission succeeds; unavailable and failed emitters pass
// an empty ID and are covered at the enforced request-policy path.
func TestRequestPolicyBlockInfo_ReceiptRequiresRecordedActionID(t *testing.T) {
	t.Parallel()
	realActionID := receipt.NewActionID() // UUIDv7, the form a recorded block stamps

	cases := []struct {
		name        string
		actionID    string
		wantReceipt string
	}{
		{
			name:        "recorded action_id surfaces in receipt header",
			actionID:    realActionID,
			wantReceipt: realActionID,
		},
		{
			name:        "empty action_id leaves receipt header unset",
			actionID:    "",
			wantReceipt: "",
		},
		{
			name:        "malformed action_id is dropped while block remains intact",
			actionID:    "not-a-valid-receipt-id",
			wantReceipt: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
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

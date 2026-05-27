// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// requestPolicyBlockInfo builds the X-Pipelock-Block-Reason metadata for a
// request_policy_deny block — the operation safety rail's enforced-block path.
//
// The request_policy layer is not a scanner.Scanner* pipeline constant, so the
// X-Pipelock-Block-Reason-Layer header is intentionally left unset: per
// docs/specs/block-reason-header.md non-scanner enforcement layers omit the
// layer header and let the reason code convey the layer (the same convention
// the MCP and contract layers follow).
//
// Receipt correlation is gated on a configured receipt emitter, mirroring
// emitReceipt's nil check. When an emitter is configured, actionID — which MUST
// be the real receipt action_id (receipt.NewActionID) recorded for this same
// block — is stamped into the receipt header so the agent can fetch the
// matching receipt. A decorrelated identifier must never be passed here: an
// action_id that points at no emitted receipt would make the header lie. When
// no emitter is configured, or actionID is empty or malformed, the receipt slot
// stays unset and the block still emits its required headers — the receipt is
// optional metadata, so dropping it never weakens the block itself.
func (p *Proxy) requestPolicyBlockInfo(actionID string) blockreason.Info {
	info := blockInfoFor(blockreason.RequestPolicyDeny, "")
	if actionID == "" || p.receiptEmitterPtr.Load() == nil {
		return info
	}
	withReceipt, err := info.WithReceipt(actionID)
	if err != nil {
		// Malformed action_id: keep the block, drop the optional receipt.
		return info
	}
	return withReceipt
}

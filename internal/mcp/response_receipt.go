// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// confirmMCPResponseEffect retains a tracked request's selected shard. A
// standalone response selects once through emitReceiptDecision instead.
func confirmMCPResponseEffect(logW io.Writer, opts MCPProxyOpts, selected receipt.EmitOpts, decision receipt.EmitOpts) error {
	if !opts.requireReceipts() {
		return nil
	}
	decision = withMCPResponseShard(selected, decision)
	_, err := opts.emitReceiptDecision(MCPDecision{Receipt: opts.withReceiptPolicyHash(decision), RequireReceipt: true, RequiredMode: true, Durable: true})
	if err != nil {
		logReceiptEmitFailure(logW, err, true, decision.Verdict)
	}
	return err
}

func withMCPResponseShard(selected, decision receipt.EmitOpts) receipt.EmitOpts {
	decision.ParentActionID = selected.ActionID
	if selected.ShardSelected {
		decision.ShardSelected = true
		decision.ShardIndex = selected.ShardIndex
	}
	return decision
}

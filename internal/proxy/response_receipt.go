// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// confirmResponseDecision confirms a later decision on an admitted response.
// Optional mode retains best-effort recording; required mode confirms every
// configured family before the caller changes state or delivers bytes.
func (p *Proxy) confirmResponseDecision(cfg *config.Config, opts receipt.EmitOpts) error {
	if cfg != nil && cfg.FlightRecorder.RequireReceipts {
		return p.emitAllowPathReceipt(cfg, opts)
	}
	if p != nil {
		_ = p.emitReceipt(opts)
	}
	return nil
}

func (rp *ReverseProxyHandler) confirmResponseDecision(cfg *config.Config, opts receipt.EmitOpts) error {
	if cfg != nil && cfg.FlightRecorder.RequireReceipts {
		return rp.emitAllowPathReceipt(cfg, opts)
	}
	_ = rp.emitReceipt(opts)
	return nil
}

func mediaRewriteReceipt(opts receipt.EmitOpts) receipt.EmitOpts {
	opts.ActionID = receipt.NewActionID()
	opts.Verdict = config.ActionStrip
	opts.Layer = "media_policy"
	opts.Pattern = "image media rewritten"
	return opts
}

func firstReceiptShard(selected, fallback receipt.EmitOpts) receipt.EmitOpts {
	if selected.ShardSelected {
		return selected
	}
	return fallback
}

// a2aResponseDecisionBlocks follows the transport's resolved response policy.
// Positive signature evidence on an already denied card stays best-effort.
func a2aResponseDecisionBlocks(cfg *config.Config, result mcp.A2AScanResult, denyAsk bool) bool {
	if result.Clean {
		return false
	}
	action := result.Action
	if action == "" {
		action = cfg.A2AScanning.Action
	}
	if cfg.ResponseScanning.Enabled {
		action = config.StricterAction(cfg.ResponseScanning.Action, action)
	}
	return (denyAsk && action == config.ActionAsk) || a2aResultBlocks(cfg, action, result)
}

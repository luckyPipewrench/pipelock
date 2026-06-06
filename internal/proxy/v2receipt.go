// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// v2 action_type labels for the proxy_decision payload. They classify the
// action surface and are distinct from the v1 ActionRecord's semantic action
// class (read/write/...). Kept as constants so the mapping is auditable.
const (
	v2ActionHTTPRequest    = "http_request"
	v2ActionMCPToolCall    = "mcp_tool_call"
	v2ActionWebSocketFrame = "websocket_frame"
)

// v2DecisionFromOpts derives the v2 proxy_decision input from the v1 EmitOpts so
// the dual-emit path reuses the exact decision context the v1 receipt records.
//
// policy_sources / winning_source are GENERIC decision provenance, not
// contract-only: a contract-participated decision attributes to its real
// contract sources plus the "contract" marker and stamps the manifest/contract
// envelope; a kill-switch block attributes to the kill switch; everything else
// is a scanner decision. The v2 payload validator requires both fields
// non-empty, so every branch supplies them.
//
// The returned bool is false when the decision cannot form a valid v2 payload
// (empty target). The caller skips emission rather than logging a build error,
// keeping the v2 stream free of malformed receipts.
func v2DecisionFromOpts(opts receipt.EmitOpts) (proxydecision.Decision, bool) {
	if opts.Target == "" {
		return proxydecision.Decision{}, false
	}

	d := proxydecision.Decision{
		ActionType: v2ActionType(opts),
		Transport:  opts.Transport,
		Target:     opts.Target, // raw; the emitter sanitizes before signing (#676)
		Verdict:    receipt.NormalizeVerdict(opts.Verdict),
	}

	switch {
	case hasContractContext(opts):
		d.WinningSource = opts.ContractWinningSource
		if d.WinningSource == "" {
			d.WinningSource = proxydecision.SourceContract
		}
		d.PolicySources = ensureSource(opts.ContractPolicySources, proxydecision.SourceContract)
		d.RuleID = opts.ContractRuleID
		d.LiveVerdict = receipt.NormalizeVerdict(opts.ContractLiveVerdict)
		d.ActiveManifestHash = opts.ActiveManifestHash
		d.ContractHash = opts.ContractHash
		d.SelectorID = opts.ContractSelectorID
		d.ContractGeneration = opts.ContractGeneration
	case opts.Layer == killSwitchLayer:
		d.WinningSource = proxydecision.SourceKillSwitch
		d.PolicySources = []string{proxydecision.SourceKillSwitch}
		d.RuleID = opts.Pattern
	default:
		d.WinningSource = proxydecision.SourceScanner
		d.PolicySources = []string{proxydecision.SourceScanner}
		d.RuleID = opts.Pattern
	}
	return d, true
}

// killSwitchLayer is the EmitOpts.Layer label used by kill-switch block sites
// (forwardKillSwitchReceiptOpts and the per-transport kill-switch receipts).
const killSwitchLayer = "kill_switch"

// hasContractContext reports whether the contract evaluator participated in this
// decision. Mirrors contractgate's HasContractContext: any contract provenance
// or a stamped manifest/contract/selector means a real resolved contract
// existed for the request.
func hasContractContext(opts receipt.EmitOpts) bool {
	return opts.ContractWinningSource != "" ||
		len(opts.ContractPolicySources) > 0 ||
		opts.ActiveManifestHash != "" ||
		opts.ContractHash != "" ||
		opts.ContractSelectorID != ""
}

// v2ActionType maps the v1 EmitOpts surface to the v2 action_type enum.
func v2ActionType(opts receipt.EmitOpts) string {
	switch {
	case opts.MCPMethod != "" || opts.ToolName != "":
		return v2ActionMCPToolCall
	case opts.Transport == TransportWS:
		return v2ActionWebSocketFrame
	default:
		return v2ActionHTTPRequest
	}
}

// ensureSource returns sources with want appended when absent, preserving order
// and the existing contract policy sources. A nil/empty input yields [want].
func ensureSource(sources []string, want string) []string {
	out := make([]string, 0, len(sources)+1)
	for _, s := range sources {
		if s == want {
			out = append(out, sources...)
			return out
		}
	}
	out = append(out, sources...)
	out = append(out, want)
	return out
}

// emitV2 loads the v2 emitter from ptr and dual-emits a proxy_decision receipt
// for opts. Safe when the emitter is nil (no-op). v2 emission failures are
// logged via logErr and never propagate; the v1 receipt is the authoritative
// audit record during the expand phase, so a v2 hiccup must not affect the
// proxy decision.
func emitV2(ptr *atomic.Pointer[proxydecision.Emitter], opts receipt.EmitOpts, logErr func(error)) {
	if ptr == nil {
		return
	}
	e := ptr.Load()
	if e == nil {
		return
	}
	d, ok := v2DecisionFromOpts(opts)
	if !ok {
		return
	}
	if err := e.Emit(d); err != nil && logErr != nil {
		logErr(err)
	}
}

// emitV2Receipt dual-emits the v2 proxy_decision for opts on the main proxy.
func (p *Proxy) emitV2Receipt(opts receipt.EmitOpts) {
	emitV2(&p.v2EmitterPtr, opts, func(err error) {
		p.logger.LogError(audit.NewRequestLogContext(opts.RequestID),
			fmt.Errorf("emit v2 proxy_decision action_id=%s verdict=%s layer=%s transport=%s: %w",
				opts.ActionID, opts.Verdict, opts.Layer, opts.Transport, err))
	})
}

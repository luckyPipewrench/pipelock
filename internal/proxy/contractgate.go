// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// Decision.Reason values the runtime evaluator emits. Aliases the typed
// blockreason vocabulary so transport call sites get a single source of
// truth. A typo in a runtime reason string fails compile here rather than
// silently dropping into writeGateBlockedError's parse_error fallback.
const (
	contractDefaultDenyReason    = string(blockreason.ContractDefaultDeny)
	contractEnforceDefaultReason = string(blockreason.ContractEnforceDefault)
	contractNonDefaultPortReason = string(blockreason.ContractNonDefaultPort)
	contractInvalidPathReason    = string(blockreason.ContractInvalidPath)
	contractObservedOnlyReason   = string(blockreason.ContractObservedOnly)
	killSwitchActiveReason       = string(blockreason.KillSwitchActive)
)

// blockLayerContract is the layer label every contract-runtime block path
// stamps onto receipts, metrics, and X-Pipelock-Block-Reason-Layer headers.
// Held as a single const so a typo on any one of the ~9 emit sites cannot
// silently route receipts into a separate label dimension.
const blockLayerContract = "contract"

// ContractGateInput captures the proxy-side state a single request brings to
// the contract evaluator. The helper is transport-agnostic; callers resolve
// agent identity before invoking it.
type ContractGateInput struct {
	Loader           *contractruntime.Loader
	Agent            string
	URL              string
	Method           string
	EffectiveAction  string
	ScannerVerdict   string
	ScannerMatched   bool
	PolicySources    []string
	KillSwitchActive bool
	Transport        string
}

// ContractGateOutput is the verdict and attribution metadata the proxy acts
// on. Verdict is enforcement surface; LiveVerdict and Drift are telemetry.
type ContractGateOutput struct {
	Verdict            string
	LiveVerdict        string
	PolicySources      []string
	WinningSource      string
	RuleID             string
	Reason             string
	Drift              *contractruntime.DriftEvent
	Resolved           *contractruntime.ResolvedContract
	ReceiptStub        any
	ActiveManifestHash string
	ContractHash       string
	SelectorID         string
	ContractGeneration uint64
}

// EvaluateGate resolves the active contract for the agent, evaluates the HTTP
// runtime decision sequence, and returns the verdict the proxy must enforce.
func EvaluateGate(input ContractGateInput) (ContractGateOutput, error) {
	scannerVerdict := input.ScannerVerdict
	if scannerVerdict == "" {
		scannerVerdict = config.ActionBlock
	}

	fallback := ContractGateOutput{
		Verdict:       scannerVerdict,
		LiveVerdict:   scannerVerdict,
		PolicySources: append([]string(nil), input.PolicySources...),
		WinningSource: contractruntime.WinningSourceScanner,
	}
	if input.Loader == nil {
		return fallback, nil
	}
	active := input.Loader.Current()
	if active == nil {
		return fallback, nil
	}

	var resolved *contractruntime.ResolvedContract
	if pin, ok := active.Resolve(input.Agent); ok {
		resolved = pin
	}

	decision, err := contractruntime.EvaluateHTTP(contractruntime.EvaluateOptions{
		Resolved: resolved,
		Request: contractruntime.HTTPRequest{
			URL:             input.URL,
			Method:          input.Method,
			EffectiveAction: input.EffectiveAction,
		},
		Mode:             input.Loader.Mode(),
		KillSwitchActive: input.KillSwitchActive,
		ScannerVerdict:   scannerVerdict,
		ScannerMatched:   input.ScannerMatched,
		PolicySources:    input.PolicySources,
	})
	if err != nil {
		return ContractGateOutput{}, err
	}
	out := ContractGateOutput{
		Verdict:       decision.Verdict,
		LiveVerdict:   decision.LiveVerdict,
		PolicySources: append([]string(nil), decision.PolicySources...),
		WinningSource: decision.WinningSource,
		RuleID:        decision.RuleID,
		Reason:        decision.Reason,
		Drift:         decision.Drift,
		Resolved:      resolved,
	}
	if resolved != nil {
		out.ActiveManifestHash = resolved.ActiveManifestHash
		out.ContractHash = resolved.ContractHash
		out.SelectorID = resolved.SelectorID
		out.ContractGeneration = resolved.ContractGeneration
	}
	return out, nil
}

func buildContractLoader(cfg *config.Config) (*contractruntime.Loader, error) {
	if cfg == nil || !cfg.LearnLock.Enabled {
		return nil, nil
	}
	loader, err := contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              cfg.LearnLock.StoreDir,
		RosterPath:            cfg.LearnLock.RosterPath,
		PinnedRootFingerprint: cfg.LearnLock.PinnedRootFingerprint,
		Environment: contract.Environment{
			ID: cfg.LearnLock.Environment,
		},
		MinSignatures: cfg.LearnLock.EffectiveMinimumSignatures(),
		Mode:          contractruntime.Mode(cfg.LearnLock.EffectiveMode()),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("contract loader init: %w", err)
	}
	return loader, nil
}

func (p *Proxy) currentContractLoader() *contractruntime.Loader {
	return p.contractLoaderPtr.Load()
}

func withContractReceipt(gate ContractGateOutput, opts receipt.EmitOpts) receipt.EmitOpts {
	if !gate.HasContractContext() {
		return opts
	}
	opts.ContractWinningSource = gate.WinningSource
	opts.ContractLiveVerdict = gate.LiveVerdict
	opts.ContractPolicySources = append([]string(nil), gate.PolicySources...)
	opts.ContractRuleID = gate.RuleID
	opts.ActiveManifestHash = gate.ActiveManifestHash
	opts.ContractHash = gate.ContractHash
	opts.ContractSelectorID = gate.SelectorID
	opts.ContractGeneration = gate.ContractGeneration
	return opts
}

func (gate ContractGateOutput) HasContractContext() bool {
	return gate.Resolved != nil || gate.ActiveManifestHash != "" || gate.ContractHash != ""
}

func contractBlockInfo(reason string) (blockreason.Info, bool) {
	switch reason {
	case contractDefaultDenyReason,
		contractEnforceDefaultReason,
		contractNonDefaultPortReason,
		contractInvalidPathReason,
		contractObservedOnlyReason:
		return blockreason.Info{
			Reason:   blockreason.Reason(reason),
			Severity: blockreason.SeverityCritical,
			Retry:    blockreason.RetryPolicy,
			Layer:    blockLayerContract,
		}, true
	default:
		return blockreason.Info{}, false
	}
}

func writeGateBlockedError(w http.ResponseWriter, gate ContractGateOutput, body string) {
	if gate.Reason == killSwitchActiveReason || gate.WinningSource == contractruntime.WinningSourceKillSwitch {
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch"), body, http.StatusForbidden)
		return
	}
	if gate.WinningSource == contractruntime.WinningSourceScanner {
		writeBlockedError(w, blockInfoFor(blockreason.ParseError, "scanner"), body, http.StatusForbidden)
		return
	}
	if info, ok := contractBlockInfo(gate.Reason); ok {
		writeBlockedError(w, info, body, http.StatusForbidden)
		return
	}
	writeBlockedError(w, blockInfoFor(blockreason.ParseError, blockLayerContract), body, http.StatusForbidden)
}

func scannerVerdictForGate(hasFinding bool) string {
	if hasFinding {
		return config.ActionWarn
	}
	return config.ActionAllow
}

func scannerVerdictForContinuingAction(action string, enforce bool) string {
	switch action {
	case "", config.ActionAllow:
		return config.ActionAllow
	case config.ActionBlock:
		if enforce {
			return config.ActionBlock
		}
		return config.ActionWarn
	default:
		return action
	}
}

// ForwardBlockReceiptInput is the per-request data the forward block-receipt
// helper needs. It collapses the loose arguments forwardBlockReceiptOpts would
// otherwise take.
type ForwardBlockReceiptInput struct {
	ActionID  string
	RequestID string
	Agent     string
	Method    string
	Target    string
	Layer     string
	Pattern   string
	Taint     taintDecision
}

// forwardKillSwitchReceiptOpts assembles the bare receipt for an
// absolute-URI forward request denied by the buildHandler-level kill
// switch. Agent identity is not resolved at that layer (the kill
// switch fires before resolveAgentRuntimeFromRequest), so the receipt
// carries no taint or contract context — the layer + transport + URL
// is enough to keep the audit chain unbroken.
func forwardKillSwitchReceiptOpts(actionID, requestID, method, target string) receipt.EmitOpts {
	return receipt.EmitOpts{
		ActionID:  actionID,
		Verdict:   config.ActionBlock,
		Layer:     "kill_switch",
		Pattern:   killSwitchActiveReason,
		Transport: TransportForward,
		Method:    method,
		Target:    target,
		RequestID: requestID,
	}
}

// forwardBlockReceiptOpts assembles the EmitOpts the forward-proxy block
// paths emit for contract-gate failures and contract-gate denies. Both
// callers stamp the same forward + taint context onto the receipt; the
// helper is unit-testable so the gate-fail branch in handleForwardHTTP
// does not need an integration shape that produces a malformed URL just
// to exercise the receipt fields.
func forwardBlockReceiptOpts(in ForwardBlockReceiptInput) receipt.EmitOpts {
	return receipt.EmitOpts{
		ActionID:            in.ActionID,
		Verdict:             config.ActionBlock,
		Layer:               in.Layer,
		Pattern:             in.Pattern,
		Transport:           TransportForward,
		Method:              in.Method,
		Target:              in.Target,
		RequestID:           in.RequestID,
		Agent:               in.Agent,
		SessionTaintLevel:   in.Taint.Risk.Level.String(),
		SessionContaminated: in.Taint.Risk.Contaminated,
		RecentTaintSources:  in.Taint.Risk.Sources,
		SessionTaskID:       in.Taint.Task.CurrentTaskID,
		SessionTaskLabel:    in.Taint.Task.CurrentTaskLabel,
		AuthorityKind:       in.Taint.Authority.String(),
		TaintDecision:       in.Taint.Result.Decision.String(),
		TaintDecisionReason: in.Taint.Result.Reason,
		TaskOverrideApplied: in.Taint.TaskOverrideApplied,
	}
}

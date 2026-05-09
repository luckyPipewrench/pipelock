// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	mcpContractURLAction = "mcp_upstream"
)

type mcpContractGateOutput struct {
	Verdict            string
	LiveVerdict        string
	PolicySources      []string
	WinningSource      string
	RuleID             string
	Reason             string
	Resolved           *contractruntime.ResolvedContract
	ActiveManifestHash string
	ContractHash       string
	SelectorID         string
	ContractGeneration uint64
}

// NewContractLoaderFromConfig builds the live-lock loader used by standalone
// MCP proxy invocations. Long-lived `pipelock run` listeners receive a loader
// pointer from the shared HTTP proxy instead so hot reload stays atomic.
func NewContractLoaderFromConfig(cfg *config.Config) (*contractruntime.Loader, error) {
	if cfg == nil || !cfg.LearnLock.Enabled {
		return nil, nil
	}
	loader, err := contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              cfg.LearnLock.StoreDir,
		RosterPath:            cfg.LearnLock.RosterPath,
		PinnedRootFingerprint: cfg.LearnLock.PinnedRootFingerprint,
		Environment: contract.Environment{
			ID:           cfg.LearnLock.Environment.ID,
			Tenant:       cfg.LearnLock.Environment.Tenant,
			DeploymentID: cfg.LearnLock.Environment.DeploymentID,
		},
		MinSignatures: cfg.LearnLock.EffectiveMinimumSignatures(),
		Mode:          contractruntime.Mode(cfg.LearnLock.EffectiveMode()),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("contract loader init: %w", err)
	}
	return loader, nil
}

func evaluateMCPUpstreamGate(ctx context.Context, upstreamURL string, opts MCPProxyOpts) (mcpContractGateOutput, error) {
	loader := opts.contractLoader()
	if loader == nil || loader.Current() == nil {
		return mcpContractGateOutput{
			Verdict:       config.ActionAllow,
			LiveVerdict:   config.ActionAllow,
			PolicySources: []string{contractruntime.PolicySourceScanner},
			WinningSource: contractruntime.WinningSourceScanner,
		}, nil
	}
	sc := opts.scanner()
	if sc == nil {
		return mcpContractGateOutput{}, fmt.Errorf("scanner unavailable")
	}
	gateURL := mcpUpstreamGateURL(upstreamURL)
	scanResult := sc.Scan(ctx, gateURL)
	scannerVerdict := config.ActionAllow
	if !scanResult.Allowed {
		scannerVerdict = config.ActionBlock
	}
	return evaluateMCPHTTPGate(mcpHTTPGateInput{
		opts:             opts,
		targetURL:        gateURL,
		method:           http.MethodPost,
		effectiveAction:  mcpContractURLAction,
		scannerVerdict:   scannerVerdict,
		scannerMatched:   !scanResult.Allowed,
		killSwitchActive: opts.KillSwitch != nil && opts.KillSwitch.IsActive(),
	})
}

func mcpUpstreamGateURL(upstreamURL string) string {
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		return upstreamURL
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ws":
		parsed.Scheme = "http"
	case "wss":
		parsed.Scheme = "https"
	}
	return parsed.String()
}

type mcpHTTPGateInput struct {
	opts             MCPProxyOpts
	targetURL        string
	method           string
	effectiveAction  string
	scannerVerdict   string
	scannerMatched   bool
	killSwitchActive bool
}

func evaluateMCPHTTPGate(input mcpHTTPGateInput) (mcpContractGateOutput, error) {
	scannerVerdict := input.scannerVerdict
	if scannerVerdict == "" {
		scannerVerdict = config.ActionBlock
	}
	fallback := mcpContractGateOutput{
		Verdict:       scannerVerdict,
		LiveVerdict:   scannerVerdict,
		PolicySources: []string{contractruntime.PolicySourceScanner},
		WinningSource: contractruntime.WinningSourceScanner,
	}
	loader := input.opts.contractLoader()
	if loader == nil {
		return fallback, nil
	}
	active := loader.Current()
	if active == nil {
		return fallback, nil
	}
	var resolved *contractruntime.ResolvedContract
	if pin, ok := active.Resolve(mcpContractAgent(input.opts)); ok {
		resolved = pin
	}
	decision, err := contractruntime.EvaluateHTTP(contractruntime.EvaluateOptions{
		Resolved: resolved,
		Request: contractruntime.HTTPRequest{
			URL:             input.targetURL,
			Method:          input.method,
			EffectiveAction: input.effectiveAction,
		},
		Mode:             loader.Mode(),
		KillSwitchActive: input.killSwitchActive,
		ScannerVerdict:   scannerVerdict,
		ScannerMatched:   input.scannerMatched,
		PolicySources:    []string{contractruntime.PolicySourceScanner},
	})
	if err != nil {
		return mcpContractGateOutput{}, err
	}
	return mcpGateFromDecision(decision, resolved), nil
}

func evaluateMCPToolGate(frame MCPFrame, scannerVerdict string, scannerMatched bool, opts MCPProxyOpts) (mcpContractGateOutput, error) {
	if !frame.IsToolsCall() {
		// Live-lock contracts scope execution-time tool calls. Other MCP
		// frames remain under the scanner, policy, taint, and tool-list gates.
		return mcpContractGateOutput{Verdict: scannerVerdict, LiveVerdict: scannerVerdict}, nil
	}
	if scannerVerdict == "" {
		scannerVerdict = config.ActionBlock
	}
	fallback := mcpContractGateOutput{
		Verdict:       scannerVerdict,
		LiveVerdict:   scannerVerdict,
		PolicySources: []string{contractruntime.PolicySourceScanner},
		WinningSource: contractruntime.WinningSourceScanner,
	}
	loader := opts.contractLoader()
	if loader == nil {
		return fallback, nil
	}
	active := loader.Current()
	if active == nil {
		return fallback, nil
	}
	var resolved *contractruntime.ResolvedContract
	if pin, ok := active.Resolve(mcpContractAgent(opts)); ok {
		resolved = pin
	}
	decision, err := contractruntime.EvaluateMCP(contractruntime.EvaluateMCPOptions{
		Resolved: resolved,
		Request: contractruntime.MCPRequest{
			Server:   mcpContractServer(opts, ""),
			ToolName: frame.ToolCallName,
			ToolArgs: mcpToolArgsMap(frame.Args),
		},
		Mode:             loader.Mode(),
		KillSwitchActive: opts.KillSwitch != nil && opts.KillSwitch.IsActive(),
		ScannerVerdict:   scannerVerdict,
		ScannerMatched:   scannerMatched,
		PolicySources:    []string{contractruntime.PolicySourceScanner},
	})
	if err != nil {
		return mcpContractGateOutput{}, err
	}
	return mcpGateFromDecision(decision, resolved), nil
}

func mcpGateFromDecision(decision contractruntime.Decision, resolved *contractruntime.ResolvedContract) mcpContractGateOutput {
	out := mcpContractGateOutput{
		Verdict:       decision.Verdict,
		LiveVerdict:   decision.LiveVerdict,
		PolicySources: append([]string(nil), decision.PolicySources...),
		WinningSource: decision.WinningSource,
		RuleID:        decision.RuleID,
		Reason:        decision.Reason,
		Resolved:      resolved,
	}
	if resolved != nil {
		out.ActiveManifestHash = resolved.ActiveManifestHash
		out.ContractHash = resolved.ContractHash
		out.SelectorID = resolved.SelectorID
		out.ContractGeneration = resolved.ContractGeneration
	}
	return out
}

func mcpContractAgent(opts MCPProxyOpts) string {
	agent := strings.TrimSpace(opts.ContractAgent)
	if agent == "" {
		return "_default"
	}
	return agent
}

func mcpContractServer(opts MCPProxyOpts, fallback string) string {
	if server := strings.TrimSpace(opts.ContractServer); server != "" {
		return server
	}
	if fallback != "" {
		return fallback
	}
	return "_default"
}

func mcpContractServerFromUpstream(upstreamURL string) string {
	u, err := url.Parse(upstreamURL)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.TrimSpace(upstreamURL)
}

func mcpContractServerFromCommand(command []string) string {
	if len(command) == 0 {
		return ""
	}
	name := filepath.Base(command[0])
	if name == "." || name == string(filepath.Separator) {
		return command[0]
	}
	return name
}

func mcpToolArgsMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args map[string]any
	if err := dec.Decode(&args); err != nil || args == nil {
		return map[string]any{}
	}
	return args
}

func mcpContractBlockRequest(id json.RawMessage, gate mcpContractGateOutput, fallbackMessage string) BlockedRequest {
	reason := mcpContractBlockReason(gate)
	data, _ := json.Marshal(map[string]any{
		"block_reason":      string(reason),
		"contract_reason":   gate.Reason,
		"winning_source":    gate.WinningSource,
		"rule_id":           gate.RuleID,
		"live_verdict":      gate.LiveVerdict,
		"policy_sources":    gate.PolicySources,
		"contract_hash":     gate.ContractHash,
		"contract_selector": gate.SelectorID,
	})
	message := "pipelock: request blocked by live-lock contract"
	if fallbackMessage != "" {
		message = fallbackMessage
	}
	return BlockedRequest{
		ID:             id,
		IsNotification: isRPCNotification(id),
		LogMessage:     message,
		ErrorCode:      -32006,
		ErrorMessage:   message,
		ErrorData:      data,
	}
}

func ptrMCPBlockedRequest(br BlockedRequest) *BlockedRequest {
	return &br
}

func mcpScannerBlockReason(verdict InputVerdict, policyVerdict policy.Verdict, chainMatched bool) blockreason.Reason {
	switch {
	case len(verdict.Matches) > 0:
		return blockreason.DLPMatch
	case len(verdict.Inject) > 0:
		return blockreason.PromptInjection
	case policyVerdict.Matched:
		return blockreason.ToolPolicyDeny
	case chainMatched:
		return blockreason.ToolChainBlocked
	default:
		return blockreason.ParseError
	}
}

func mcpBlockReasonData(reason blockreason.Reason) json.RawMessage {
	data, _ := json.Marshal(map[string]any{
		"block_reason": string(reason),
	})
	return data
}

func mcpContractBlockReason(gate mcpContractGateOutput) blockreason.Reason {
	if gate.WinningSource == contractruntime.WinningSourceKillSwitch || gate.Reason == string(blockreason.KillSwitchActive) {
		return blockreason.KillSwitchActive
	}
	if gate.WinningSource == contractruntime.WinningSourceScanner {
		return blockreason.ParseError
	}
	if reason, ok := contractruntime.BlockReasonForDecision(gate.Reason); ok {
		return reason
	}
	if gate.WinningSource == contractruntime.WinningSourceContract {
		return blockreason.ContractDefaultDeny
	}
	return blockreason.ParseError
}

func mcpWithContractReceipt(opts receipt.EmitOpts, gate mcpContractGateOutput) receipt.EmitOpts {
	if gate.Resolved == nil && gate.ActiveManifestHash == "" && gate.ContractHash == "" {
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

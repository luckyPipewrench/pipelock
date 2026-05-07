// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// MCPRequest is the normalized input needed to evaluate mcp_tool_call rules.
//
// Server is the upstream MCP server identifier the proxy resolved (for
// example "stripe" or "lakera-guard"). ToolName is the tool the agent
// is invoking. ToolArgs is the parsed arg map; matchers operate against
// typed scalar values, so callers do not need to pre-stringify numbers
// or booleans.
type MCPRequest struct {
	Server   string
	ToolName string
	ToolArgs map[string]any
}

// EvaluateMCPOptions control one MCP tool-call evaluation.
type EvaluateMCPOptions struct {
	Resolved         *ResolvedContract
	Request          MCPRequest
	Mode             Mode
	KillSwitchActive bool
	ScannerVerdict   string
	ScannerMatched   bool
	PolicySources    []string
}

// EvaluateMCP returns the runtime verdict for an MCP tool call under the
// active learn-and-lock contract. The decision sequence mirrors
// EvaluateHTTP so HTTP and MCP surfaces share identical security
// invariants:
//
//  1. Mode is required and must enumerate. Empty Mode is fail-closed input.
//  2. Kill switch active → block in every mode (absolute floor).
//  3. Scanner block → block in every mode (security floor; contract may not
//     resurrect a scanner-blocked tool call, including a signed allow rule).
//  4. No resolved contract → return the scanner verdict.
//  5. Contract resolved → evaluate enforce mcp_tool_call rules:
//     - Server+tool match with args satisfied → contract annotates the
//     scanner verdict; WinningSource = contract.
//     - Server+tool match but args mismatch → contract block with reason
//     contract_mcp_args_mismatch.
//     - Contract has zero MCP enforce rules anywhere → fall through to
//     scanner (observation-only contract; no jurisdiction over MCP).
//     - Otherwise → contract default-deny (the contract claims
//     jurisdiction once any MCP rule is in enforce; tool calls outside
//     the enumerated allow set are denied).
//  6. Mode gate. ModeLive enforces the contract verdict directly.
//     ModeShadow / ModeCapture surface the scanner verdict as Verdict
//     (so the proxy never blocks more than scanner already would) while
//     LiveVerdict carries what live mode would have done, plus the drift
//     event for observation pipelines.
//
// Selector args matching is typed scalar value-equality only in v1.
// Structured matchers (range, regex, in-list) are deferred to the next
// schema version; an args selector that uses an unsupported operator or
// malformed args shape fails to match in v1, so operators relying on
// those matchers see default-deny rather than spurious allow. Document
// this when shipping args selectors to operators.
//
// The proxy MUST act on Decision.Verdict. LiveVerdict and Drift are
// audit/telemetry surface; using them for enforcement breaks the mode
// guarantee.
func EvaluateMCP(opts EvaluateMCPOptions) (Decision, error) {
	if opts.Mode == "" {
		return Decision{}, fmt.Errorf("%w: mode required", ErrInvalidDecisionInput)
	}
	if !validMode(opts.Mode) {
		return Decision{}, fmt.Errorf("%w: mode %q", ErrInvalidDecisionInput, opts.Mode)
	}

	sources := normalizePolicySources(opts.PolicySources)
	if opts.ScannerMatched || opts.ScannerVerdict != "" {
		sources = appendPolicySource(sources, PolicySourceScanner)
	}

	// 1. Kill switch is the absolute floor. Block in every mode.
	if opts.KillSwitchActive {
		sources = appendPolicySource(sources, PolicySourceKillSwitch)
		return Decision{
			Verdict:       config.ActionBlock,
			LiveVerdict:   config.ActionBlock,
			PolicySources: sources,
			WinningSource: WinningSourceKillSwitch,
			Suppressed:    true,
			Reason:        decisionReasonKillSwitchActive,
		}, nil
	}

	// Resolve scanner verdict (fail-closed if scanner did not decide).
	scannerVerdict := opts.ScannerVerdict
	scannerMissing := scannerVerdict == ""
	if scannerMissing {
		scannerVerdict = config.ActionBlock
	}

	// 2. Scanner block is the security floor. Wins in every mode, including
	// over a signed contract-allow rule. Without this, a contract becomes a
	// signed bypass of the MCP scanning pipeline (input scanning, tool
	// poisoning, tool policy, chain detection, session binding).
	if scannerVerdict == config.ActionBlock {
		sources = appendPolicySource(sources, PolicySourceScanner)
		decision := Decision{
			Verdict:       config.ActionBlock,
			LiveVerdict:   config.ActionBlock,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}
		if scannerMissing {
			decision.Reason = decisionReasonScannerDecisionMissing
		}
		return decision, nil
	}

	// 3. No resolved contract → scanner verdict stands.
	if opts.Resolved == nil {
		return Decision{
			Verdict:       scannerVerdict,
			LiveVerdict:   scannerVerdict,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}, nil
	}

	sources = appendPolicySource(sources, PolicySourceContract)

	// 4 + 5. Compute the live verdict from the contract.
	live, err := evaluateMCPContractLive(opts, sources, scannerVerdict)
	if err != nil {
		return Decision{}, err
	}

	// 6. Mode gate.
	return applyModeGate(live, opts.Mode, scannerVerdict, sources), nil
}

// evaluateMCPContractLive returns what live mode would do for opts given a
// resolved contract, after kill-switch and scanner-block have been ruled out.
// Scanner verdict at this point is non-block; it is passed in so a contract
// allow can correctly annotate the scanner verdict instead of asserting an
// allow that scanner did not approve.
func evaluateMCPContractLive(opts EvaluateMCPOptions, sources []string, scannerVerdict string) (Decision, error) {
	server := strings.TrimSpace(opts.Request.Server)
	tool := strings.TrimSpace(opts.Request.ToolName)
	if server == "" || tool == "" {
		return Decision{}, fmt.Errorf("%w: mcp request requires server and tool", ErrInvalidDecisionInput)
	}

	contractHasEnforceRule := false
	serverToolHasEnforceRule := false
	serverToolRuleIDs := make([]string, 0)
	seenRuleIDs := map[string]struct{}{}
	for _, rule := range opts.Resolved.Contract.Rules {
		if !isMCPRule(rule) {
			continue
		}
		if err := validateLifecycle(rule.LifecycleState); err != nil {
			return Decision{}, err
		}
		if rule.LifecycleState != LifecycleEnforce {
			continue
		}
		contractHasEnforceRule = true
		if !ruleServerToolMatches(rule, server, tool) {
			continue
		}
		serverToolHasEnforceRule = true
		serverToolRuleIDs = appendRuleID(serverToolRuleIDs, seenRuleIDs, rule.RuleID)
		argsMatch := ruleArgsMatch(rule, opts.Request.ToolArgs)
		if argsMatch {
			// Contract allow annotates the scanner-allowed verdict.
			// Scanner block has already been resolved upstream and
			// cannot reach this point, so it is impossible for an
			// allow rule to override a scanner block here.
			return Decision{
				Verdict:       scannerVerdict,
				LiveVerdict:   scannerVerdict,
				PolicySources: sources,
				WinningSource: WinningSourceContract,
				RuleID:        rule.RuleID,
			}, nil
		}
	}

	// No allow rule matched.
	if !contractHasEnforceRule {
		// Contract is observation-only over the MCP surface. It claims no
		// jurisdiction; scanner verdict stands.
		return Decision{
			Verdict:       scannerVerdict,
			LiveVerdict:   scannerVerdict,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		}, nil
	}

	if serverToolHasEnforceRule {
		// Server+tool matched at least one rule but args mismatched on
		// every match. The contract claims jurisdiction over this
		// server+tool; default-deny under the args mismatch reason.
		return contractMCPBlockDecision(opts, sources, firstString(serverToolRuleIDs), decisionReasonMCPArgsMismatch), nil
	}
	return contractMCPBlockDecision(opts, sources, "", decisionReasonMCPDefaultDeny), nil
}

func contractMCPBlockDecision(opts EvaluateMCPOptions, sources []string, ruleID, reason string) Decision {
	event := DriftEvent{
		ContractHash: opts.Resolved.ContractHash,
		RuleID:       ruleID,
		Kind:         DriftKindPositive,
		Mode:         opts.Mode,
		Action:       config.ActionBlock,
	}
	decision := Decision{
		Verdict:       config.ActionBlock,
		LiveVerdict:   config.ActionBlock,
		PolicySources: sources,
		WinningSource: WinningSourceContract,
		RuleID:        ruleID,
		Drift:         &event,
		Reason:        reason,
	}
	decision.Signal = SignalForDrift(event)
	return decision
}

// isMCPRule reports whether rule is an mcp_tool_call rule the runtime can
// evaluate. EvaluateHTTP's isHTTPRule and this helper enumerate disjoint
// kind sets so the two evaluators never cross-fire on the same rule.
func isMCPRule(rule contract.Rule) bool {
	return rule.RuleKind == ruleKindMCPToolCall
}

func ruleServerToolMatches(rule contract.Rule, server, tool string) bool {
	ruleServer := selectorString(rule.Selector, "server")
	ruleTool := selectorString(rule.Selector, "tool")
	if ruleServer == "" || ruleTool == "" {
		return false
	}
	return ruleServer == server && ruleTool == tool
}

// ruleArgsMatch reports whether every arg-matcher in selector.args is
// satisfied by request args. Missing key in the request is a non-match
// (NOT a wildcard); empty args list (or absent args field) means no
// constraint and matches by default. Malformed selector.args is a
// non-match for the whole rule rather than being silently dropped into a
// broader allow.
func ruleArgsMatch(rule contract.Rule, requestArgs map[string]any) bool {
	matchers, ok := selectorArgs(rule.Selector)
	if !ok {
		return false
	}
	if len(matchers) == 0 {
		return true
	}
	for _, matcher := range matchers {
		if !argMatcherMatches(matcher, requestArgs) {
			return false
		}
	}
	return true
}

func argMatcherMatches(matcher map[string]any, requestArgs map[string]any) bool {
	key, _ := matcher["key"].(string)
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	rawValue, ok := matcher["value"]
	if !ok || rawValue == nil {
		// Missing value key (v2 matcher: range, regex, in-list) or
		// JSON null. Both silently non-match in v1 so operators get
		// default-deny rather than a spurious allow.
		// fmt.Sprint(nil) renders as "<nil>", which would otherwise
		// match a request arg whose string value happens to be
		// "<nil>" — display-vs-reality bypass blocked here.
		return false
	}
	got, present := requestArgs[key]
	if !present || got == nil {
		// Missing or null request value — never satisfies an equality
		// matcher. Without the nil guard, a request arg of nil would
		// stringify to "<nil>" and match a matcher value of the
		// literal string "<nil>".
		return false
	}
	return scalarValuesEqual(got, rawValue)
}

func selectorArgs(selector map[string]any) ([]map[string]any, bool) {
	raw, exists := selector["args"]
	if !exists {
		return nil, true
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		matcher, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, matcher)
	}
	return out, true
}

func scalarValuesEqual(got, want any) bool {
	if gotString, ok := got.(string); ok {
		wantString, ok := want.(string)
		return ok && gotString == wantString
	}
	if gotBool, ok := got.(bool); ok {
		wantBool, ok := want.(bool)
		return ok && gotBool == wantBool
	}
	gotNumber, gotOK := numericValue(got)
	wantNumber, wantOK := numericValue(want)
	if gotOK || wantOK {
		return gotOK && wantOK && gotNumber.Cmp(wantNumber) == 0
	}
	return false
}

func numericValue(value any) (*big.Rat, bool) {
	switch v := value.(type) {
	case json.Number:
		return parseJSONNumber(string(v))
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, false
		}
		return parseJSONNumber(strconv.FormatFloat(v, 'g', -1, 64))
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false
		}
		return parseJSONNumber(strconv.FormatFloat(f, 'g', -1, 32))
	case int:
		return new(big.Rat).SetInt64(int64(v)), true
	case int8:
		return new(big.Rat).SetInt64(int64(v)), true
	case int16:
		return new(big.Rat).SetInt64(int64(v)), true
	case int32:
		return new(big.Rat).SetInt64(int64(v)), true
	case int64:
		return new(big.Rat).SetInt64(v), true
	case uint:
		return new(big.Rat).SetUint64(uint64(v)), true
	case uint8:
		return new(big.Rat).SetUint64(uint64(v)), true
	case uint16:
		return new(big.Rat).SetUint64(uint64(v)), true
	case uint32:
		return new(big.Rat).SetUint64(uint64(v)), true
	case uint64:
		return new(big.Rat).SetUint64(v), true
	default:
		return nil, false
	}
}

func parseJSONNumber(value string) (*big.Rat, bool) {
	n, ok := new(big.Rat).SetString(value)
	return n, ok
}

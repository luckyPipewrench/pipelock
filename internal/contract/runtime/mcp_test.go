// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
)

const (
	mcpTestServer = "stripe"
	mcpTestTool   = "create_payment_intent"
)

func TestEvaluateMCP_RejectsEmptyMode(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	if _, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		ScannerVerdict: config.ActionAllow,
	}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("err = %v, want ErrInvalidDecisionInput", err)
	}
}

func TestEvaluateMCP_RejectsUnknownMode(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	if _, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           "rogue",
		ScannerVerdict: config.ActionAllow,
	}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("err = %v, want ErrInvalidDecisionInput", err)
	}
}

func TestEvaluateMCP_KillSwitchBlocksInEveryMode(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	for _, mode := range []Mode{ModeLive, ModeShadow, ModeCapture} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			decision, err := EvaluateMCP(EvaluateMCPOptions{
				Resolved:         &resolved,
				Request:          MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
				Mode:             mode,
				KillSwitchActive: true,
				ScannerVerdict:   config.ActionAllow,
			})
			if err != nil {
				t.Fatalf("EvaluateMCP: %v", err)
			}
			if decision.Verdict != config.ActionBlock || decision.WinningSource != WinningSourceKillSwitch {
				t.Fatalf("decision = %+v, want kill-switch block", decision)
			}
			if decision.Reason != decisionReasonKillSwitchActive {
				t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonKillSwitchActive)
			}
			if !decision.Suppressed {
				t.Fatal("expected Suppressed=true under kill switch")
			}
		})
	}
}

// TestEvaluateMCP_ScannerBlockWinsOverContractAllow is the load-bearing
// security-floor test. A contract that allows a server+tool MUST NOT
// resurrect a scanner block; otherwise a signed contract becomes a
// signed bypass of MCP input scanning, tool poisoning detection, tool
// policy, chain detection, and session binding. If this test breaks the
// security floor is broken.
func TestEvaluateMCP_ScannerBlockWinsOverContractAllow(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionBlock,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want %q", decision.Verdict, config.ActionBlock)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner (security floor breached)", decision.WinningSource)
	}
	if decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block", decision.LiveVerdict)
	}
}

func TestEvaluateMCP_NoResolvedContractReturnsScannerVerdict(t *testing.T) {
	t.Parallel()
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       nil,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", decision.WinningSource)
	}
	if !contains(decision.PolicySources, PolicySourceScanner) {
		t.Fatalf("policy_sources = %v, want scanner", decision.PolicySources)
	}
	if contains(decision.PolicySources, PolicySourceContract) {
		t.Fatalf("policy_sources = %v, contract source must be absent without a resolved contract", decision.PolicySources)
	}
}

func TestEvaluateMCP_AllowRuleAnnotatesScannerVerdict(t *testing.T) {
	t.Parallel()
	args := []map[string]any{
		{testJSONKey: testFieldCurrency, testJSONKeyValue: testCurrencyUSD},
		{testJSONKey: testFieldAmount, testJSONKeyValue: 100},
	}
	resolved := mcpResolved(mcpEnforceRule("r-allow", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldCurrency: testCurrencyUSD, testFieldAmount: 100, "extra": "ignored"},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceContract {
		t.Fatalf("winning_source = %q, want contract", decision.WinningSource)
	}
	if decision.RuleID != "r-allow" {
		t.Fatalf("rule_id = %q, want r-allow", decision.RuleID)
	}
	if decision.Drift != nil {
		t.Fatalf("drift = %+v, want nil for allow", decision.Drift)
	}
}

func TestEvaluateMCP_ArgsMismatchBlocksWithReason(t *testing.T) {
	t.Parallel()
	args := []map[string]any{{testJSONKey: testFieldCurrency, testJSONKeyValue: testCurrencyUSD}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldCurrency: "EUR"},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceContract {
		t.Fatalf("winning_source = %q, want contract", decision.WinningSource)
	}
	if decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonMCPArgsMismatch)
	}
	if decision.RuleID != "r-stripe" {
		t.Fatalf("rule_id = %q, want r-stripe", decision.RuleID)
	}
	if decision.Drift == nil || decision.Drift.Kind != DriftKindPositive {
		t.Fatalf("drift = %+v, want positive drift event", decision.Drift)
	}
}

func TestEvaluateMCP_ArgsMissingKeyIsNonMatch(t *testing.T) {
	t.Parallel()
	// Missing key in the request must be a non-match, NOT a wildcard.
	// Otherwise a tool call that omits the constrained arg would slip
	// through default-deny by accident.
	args := []map[string]any{{testJSONKey: testFieldCurrency, testJSONKeyValue: testCurrencyUSD}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{}, // currency absent
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", decision.Verdict)
	}
	if decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonMCPArgsMismatch)
	}
}

func TestEvaluateMCP_DefaultDenyForUnmatchedRequest(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   testOtherServer,
			ToolName: testOtherTool,
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", decision.Verdict)
	}
	if decision.Reason != decisionReasonMCPDefaultDeny {
		t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonMCPDefaultDeny)
	}
	if decision.RuleID != "" {
		t.Fatalf("rule_id = %q, want empty (no specific rule attributed)", decision.RuleID)
	}
}

func TestEvaluateMCP_ObservationOnlyContractFallsThrough(t *testing.T) {
	t.Parallel()
	// Contract has only proposed/capture-only MCP rules. The contract
	// claims no jurisdiction over MCP, so unmatched tool calls fall
	// through to the scanner verdict instead of default-denying.
	rule := mcpEnforceRule("r-proposed", nil)
	rule.LifecycleState = LifecycleProposed
	resolved := mcpResolved(rule)
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   testOtherServer,
			ToolName: testOtherTool,
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", decision.WinningSource)
	}
}

func TestEvaluateMCP_HTTPRulesIgnoredByMCPEvaluator(t *testing.T) {
	t.Parallel()
	// HTTP rules in the same contract must not cross-fire on the MCP
	// evaluator. If isMCPRule ever returned true for HTTP kinds, an
	// http_destination allow could spoof an MCP tool-call allow.
	httpRule := contract.Rule{
		RuleID:               "r-http",
		RuleKind:             ruleKindHTTPAction,
		LifecycleState:       LifecycleEnforce,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Selector: map[string]any{
			testJSONKeyHost: map[string]any{testJSONKeyValue: testAPIExampleCom},
			"server":        map[string]any{testJSONKeyValue: mcpTestServer},
			testKeyTool:     map[string]any{testJSONKeyValue: mcpTestTool},
		},
		Confidence:        "stable",
		WilsonLower:       "0.99",
		Observation:       map[string]any{},
		Rationale:         map[string]any{},
		RecurringSupport:  map[string]any{},
		OpportunityHealth: map[string]any{},
	}
	resolved := mcpResolved(httpRule)
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	// Contract has zero MCP enforce rules → observation-only over the
	// MCP surface → scanner verdict stands.
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow (observation-only)", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", decision.WinningSource)
	}
}

func TestEvaluateMCP_ShadowModeNeverBlocksFromContract(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   testOtherServer,
			ToolName: testOtherTool,
		},
		Mode:           ModeShadow,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow (shadow surfaces scanner verdict)", decision.Verdict)
	}
	if decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block (live mode would have denied)", decision.LiveVerdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner under shadow", decision.WinningSource)
	}
	if decision.Drift == nil {
		t.Fatal("drift = nil, want populated drift event for shadow telemetry")
	}
	if decision.Drift.Mode != ModeShadow {
		t.Fatalf("drift.mode = %q, want shadow", decision.Drift.Mode)
	}
	if decision.Reason != "contract_observed_only" {
		t.Fatalf("reason = %q, want contract_observed_only", decision.Reason)
	}
	if decision.Signal != nil {
		t.Fatalf("signal = %+v, want nil — shadow must not push adaptive signal", decision.Signal)
	}
}

func TestEvaluateMCP_CaptureModeNeverSignals(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   testOtherServer,
			ToolName: testOtherTool,
		},
		Mode:           ModeCapture,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow (capture surfaces scanner verdict)", decision.Verdict)
	}
	if decision.Signal != nil {
		t.Fatalf("signal = %+v, want nil — capture must not push adaptive signal", decision.Signal)
	}
}

func TestEvaluateMCP_RejectsEmptyServerOrTool(t *testing.T) {
	t.Parallel()
	// Server and tool are mandatory in the request. Without them the
	// evaluator cannot decide jurisdiction; fail-closed input rather
	// than silently default-denying every contract.
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	cases := []struct {
		name string
		req  MCPRequest
	}{
		{"empty server", MCPRequest{Server: "", ToolName: mcpTestTool}},
		{"empty tool", MCPRequest{Server: mcpTestServer, ToolName: ""}},
		{"whitespace server", MCPRequest{Server: "   ", ToolName: mcpTestTool}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := EvaluateMCP(EvaluateMCPOptions{
				Resolved:       &resolved,
				Request:        tc.req,
				Mode:           ModeLive,
				ScannerVerdict: config.ActionAllow,
			})
			if !errors.Is(err, ErrInvalidDecisionInput) {
				t.Fatalf("err = %v, want ErrInvalidDecisionInput", err)
			}
		})
	}
}

func TestEvaluateMCP_RejectsUnsupportedRuleLifecycle(t *testing.T) {
	t.Parallel()
	rule := mcpEnforceRule("r-bad", nil)
	rule.LifecycleState = "enforce " // trailing space — bypass attempt
	resolved := mcpResolved(rule)
	_, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if !errors.Is(err, ErrUnsupportedLifecycle) {
		t.Fatalf("err = %v, want ErrUnsupportedLifecycle", err)
	}
}

func TestEvaluateMCP_ScannerMissingFailsClosed(t *testing.T) {
	t.Parallel()
	// Scanner did not decide → treat as block. This mirrors EvaluateHTTP
	// so a missing scanner verdict is never a contract-allow path.
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: "",
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block", decision.Verdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner", decision.WinningSource)
	}
	if decision.Reason != decisionReasonScannerDecisionMissing {
		t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonScannerDecisionMissing)
	}
}

func TestEvaluateMCP_PolicySourcesIncludeContractWhenResolved(t *testing.T) {
	t.Parallel()
	resolved := mcpResolved(mcpEnforceRule("r-allow", nil))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if !contains(decision.PolicySources, PolicySourceContract) {
		t.Fatalf("policy_sources = %v, want contract present", decision.PolicySources)
	}
	if !contains(decision.PolicySources, PolicySourceScanner) {
		t.Fatalf("policy_sources = %v, want scanner present", decision.PolicySources)
	}
}

func TestEvaluateMCP_RuleWithMissingServerSelectorIgnored(t *testing.T) {
	t.Parallel()
	// A rule with no server/tool selector cannot match any request.
	// Defense-in-depth: even if a malformed contract slips past
	// upstream validation, it must not produce a spurious allow.
	rule := mcpEnforceRule("r-broken", nil)
	rule.Selector = map[string]any{testKeyTool: map[string]any{testJSONKeyValue: mcpTestTool}}
	resolved := mcpResolved(rule)
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved:       &resolved,
		Request:        MCPRequest{Server: mcpTestServer, ToolName: mcpTestTool},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want block (broken selector must default-deny)", decision.Verdict)
	}
	if decision.Reason != decisionReasonMCPDefaultDeny {
		t.Fatalf("reason = %q, want %q", decision.Reason, decisionReasonMCPDefaultDeny)
	}
}

func TestEvaluateMCP_ArgMatcherWithEmptyKeyIsNonMatch(t *testing.T) {
	t.Parallel()
	args := []map[string]any{{testJSONKey: "   ", testJSONKeyValue: testCurrencyUSD}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldCurrency: testCurrencyUSD},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("decision = %+v, want args-mismatch block under empty matcher key", decision)
	}
}

// TestEvaluateMCP_NilMatcherValueIsNonMatch closes a display-vs-reality
// bypass in argMatcherMatches: fmt.Sprint(nil) renders as "<nil>", so
// without explicit nil guards a contract matcher with JSON null could
// be matched by an agent that sends the literal string "<nil>" as the
// arg value. The matcher must non-match in both directions: matcher
// value == nil and request value == nil.
func TestEvaluateMCP_NilMatcherValueIsNonMatch(t *testing.T) {
	t.Parallel()
	t.Run("matcher value is nil", func(t *testing.T) {
		t.Parallel()
		args := []map[string]any{{testJSONKey: testFieldCurrency, testJSONKeyValue: nil}}
		resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
		decision, err := EvaluateMCP(EvaluateMCPOptions{
			Resolved: &resolved,
			Request: MCPRequest{
				Server:   mcpTestServer,
				ToolName: mcpTestTool,
				ToolArgs: map[string]any{testFieldCurrency: "<nil>"},
			},
			Mode:           ModeLive,
			ScannerVerdict: config.ActionAllow,
		})
		if err != nil {
			t.Fatalf("EvaluateMCP: %v", err)
		}
		if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
			t.Fatalf("decision = %+v, want args-mismatch block — fmt.Sprint(nil) bypass", decision)
		}
	})
	t.Run("request value is nil", func(t *testing.T) {
		t.Parallel()
		args := []map[string]any{{testJSONKey: testFieldCurrency, testJSONKeyValue: "<nil>"}}
		resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
		decision, err := EvaluateMCP(EvaluateMCPOptions{
			Resolved: &resolved,
			Request: MCPRequest{
				Server:   mcpTestServer,
				ToolName: mcpTestTool,
				ToolArgs: map[string]any{testFieldCurrency: nil},
			},
			Mode:           ModeLive,
			ScannerVerdict: config.ActionAllow,
		})
		if err != nil {
			t.Fatalf("EvaluateMCP: %v", err)
		}
		if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
			t.Fatalf("decision = %+v, want args-mismatch block — request nil bypass", decision)
		}
	})
}

func TestEvaluateMCP_ArgMatcherStringDoesNotMatchNumber(t *testing.T) {
	t.Parallel()
	// Typed equality is required. If display strings are treated as
	// reality, a contract that allowed the string "100" would also allow
	// numeric 100, which can mean a different thing to typed MCP tools.
	args := []map[string]any{{testJSONKey: testFieldAmount, testJSONKeyValue: "100"}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldAmount: 100},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("decision = %+v, want args-mismatch block under string/number mismatch", decision)
	}
}

func TestEvaluateMCP_ArgMatcherLargeIntegerExact(t *testing.T) {
	t.Parallel()
	// Numeric equality must not pass through float64 precision collapse.
	// These two integers are distinct, but both round to the same IEEE-754
	// value if compared as float64.
	args := []map[string]any{{testJSONKey: "nonce", testJSONKeyValue: uint64(9007199254740993)}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{"nonce": uint64(9007199254740992)},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("decision = %+v, want args-mismatch block under large integer mismatch", decision)
	}
}

func TestEvaluateMCP_ArgMatcherJSONNumberMatchesNumericArg(t *testing.T) {
	t.Parallel()
	args := []map[string]any{{testJSONKey: testFieldAmount, testJSONKeyValue: json.Number("100")}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldAmount: 100},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionAllow || decision.WinningSource != WinningSourceContract {
		t.Fatalf("decision = %+v, want contract allow for equivalent numeric values", decision)
	}
}

func TestEvaluateMCP_V2MatcherSilentlyMisses(t *testing.T) {
	t.Parallel()
	// v2 schema may add operators like {key, op, threshold}. A v1
	// runtime sees these as non-match so operators get default-deny
	// rather than a spurious allow on an unrecognized matcher.
	args := []map[string]any{{testJSONKey: testFieldAmount, "op": "lt", "threshold": "1000"}}
	resolved := mcpResolved(mcpEnforceRule("r-stripe", args))
	decision, err := EvaluateMCP(EvaluateMCPOptions{
		Resolved: &resolved,
		Request: MCPRequest{
			Server:   mcpTestServer,
			ToolName: mcpTestTool,
			ToolArgs: map[string]any{testFieldAmount: 5},
		},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateMCP: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
		t.Fatalf("decision = %+v, want args-mismatch block under v2 matcher", decision)
	}
}

func TestEvaluateMCP_MalformedSelectorArgsNonMatch(t *testing.T) {
	t.Parallel()
	// Malformed selector.args must not be silently dropped. If malformed
	// elements were ignored, a hand-crafted contract could degrade an
	// arg-constrained allow into a broader server+tool allow.
	cases := []struct {
		name string
		args any
	}{
		{
			name: "non-map element mixed with valid matcher",
			args: []any{
				"not-a-map",
				map[string]any{testJSONKey: testFieldCurrency, testJSONKeyValue: testCurrencyUSD},
			},
		},
		{
			name: "all non-map elements",
			args: []any{"not-a-map"},
		},
		{
			name: "args field is not a list",
			args: map[string]any{testJSONKey: testFieldCurrency, testJSONKeyValue: testCurrencyUSD},
		},
		{
			name: "args field is null",
			args: nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := mcpEnforceRule("r-stripe", nil)
			rule.Selector["args"] = tc.args
			resolved := mcpResolved(rule)
			decision, err := EvaluateMCP(EvaluateMCPOptions{
				Resolved: &resolved,
				Request: MCPRequest{
					Server:   mcpTestServer,
					ToolName: mcpTestTool,
					ToolArgs: map[string]any{testFieldCurrency: testCurrencyUSD},
				},
				Mode:           ModeLive,
				ScannerVerdict: config.ActionAllow,
			})
			if err != nil {
				t.Fatalf("EvaluateMCP: %v", err)
			}
			if decision.Verdict != config.ActionBlock || decision.Reason != decisionReasonMCPArgsMismatch {
				t.Fatalf("decision = %+v, want args-mismatch block for malformed selector.args", decision)
			}
		})
	}
}

// TestScalarValuesEqual_NumericTypeMatrix covers every Go numeric type
// the json package can produce for a tool arg. Each case is invoked
// against numericValue so the type-switch arms are exercised directly,
// in addition to the integration tests above. Without this, the
// defense-in-depth branches for json.Number, float32/float64, and the
// signed/unsigned integer widths would sit at sub-30% coverage and a
// future refactor could silently break a branch without a failing test.
func TestScalarValuesEqual_NumericTypeMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a    any
		b    any
		want bool
	}{
		{"json.Number equal", json.Number("100"), json.Number("100"), true},
		{"json.Number unequal", json.Number("100"), json.Number("101"), false},
		{"json.Number malformed", json.Number("not-a-number"), json.Number("100"), false},
		{"float64 equal", float64(1.5), float64(1.5), true},
		{"float64 NaN", math.NaN(), float64(0), false},
		{"float64 +Inf", math.Inf(1), float64(0), false},
		{"float32 equal", float32(2.5), float32(2.5), true},
		{"float32 NaN", float32(math.NaN()), float32(0), false},
		{"int", int(5), int(5), true},
		{"int8", int8(5), int8(5), true},
		{"int16", int16(5), int16(5), true},
		{"int32", int32(5), int32(5), true},
		{"int64", int64(5), int64(5), true},
		{"uint", uint(5), uint(5), true},
		{"uint8", uint8(5), uint8(5), true},
		{"uint16", uint16(5), uint16(5), true},
		{"uint32", uint32(5), uint32(5), true},
		{"uint64", uint64(5), uint64(5), true},
		{"int vs uint64 same value", int(5), uint64(5), true},
		{"int vs float64 same value", int(5), float64(5.0), true},
		{"json.Number vs int same value", json.Number("5"), int(5), true},
		{"string equal", testCurrencyUSD, testCurrencyUSD, true},
		{"string vs int", "100", int(100), false},
		{"string vs bool", "true", true, false},
		{"bool true equal", true, true, true},
		{"bool false equal", false, false, true},
		{"bool true vs false", true, false, false},
		{"bool vs int", true, int(1), false},
		{"bool vs string", false, "false", false},
		{"unsupported type", []int{1}, []int{1}, false},
		{"both unsupported same kind", struct{}{}, struct{}{}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scalarValuesEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("scalarValuesEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// mcpResolved builds a ResolvedContract with the given rules attached so
// every test gets a freshly-keyed contract pin without copying the
// fields by hand.
func mcpResolved(rules ...contract.Rule) ResolvedContract {
	return ResolvedContract{
		ActiveManifestHash: testManifestHash,
		ContractHash:       testContractHash,
		SelectorID:         testSelectorID,
		ContractGeneration: 1,
		Contract: contract.Contract{
			ContractHash: testContractHash,
			Rules:        rules,
		},
	}
}

// mcpEnforceRule builds a LifecycleEnforce mcp_tool_call rule for tests.
// All current tests use mcpTestServer + mcpTestTool; broaden to
// parameters when a future test exercises a different upstream server
// or tool. args is optional — pass nil for unconstrained server+tool
// match, or a list of {key, value} maps for arg-equality matching.
func mcpEnforceRule(ruleID string, args []map[string]any) contract.Rule {
	selector := map[string]any{
		"server":    map[string]any{testJSONKeyValue: mcpTestServer},
		testKeyTool: map[string]any{testJSONKeyValue: mcpTestTool},
	}
	if len(args) > 0 {
		argList := make([]any, len(args))
		for i, a := range args {
			argList[i] = a
		}
		selector["args"] = argList
	}
	return contract.Rule{
		RuleID:               ruleID,
		RuleKind:             ruleKindMCPToolCall,
		LifecycleState:       LifecycleEnforce,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Confidence:           "stable",
		WilsonLower:          "0.99",
		Observation:          map[string]any{},
		Selector:             selector,
		Rationale:            map[string]any{},
		RecurringSupport:     map[string]any{testWindowsFloor: 3},
		OpportunityHealth:    map[string]any{},
	}
}

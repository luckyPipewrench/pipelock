// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	testManifestHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testContractHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testSelectorID   = "sha256:selector"
)

func TestActiveSetResolvePrecedenceAndReceiptStamp(t *testing.T) {
	exactHash := testContractHash
	globHash := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	defaultHash := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	state := store.State{
		Envelope: contract.ActiveManifestEnvelope{
			Body: contract.ActiveManifest{
				Generation: 7,
				Selectors: []contract.ManifestSelector{
					{SelectorID: testDefault, Default: true, ContractHash: defaultHash},
					{SelectorID: testGlob, AgentGlob: "build-*", ContractHash: globHash},
					{SelectorID: testExact, Agent: "build-agent", ContractHash: exactHash},
				},
			},
		},
		ManifestHash: testManifestHash,
		Contracts: map[string]contract.ContractEnvelope{
			testDefault: {Body: contract.Contract{ContractHash: defaultHash}},
			testGlob:    {Body: contract.Contract{ContractHash: globHash}},
			testExact:   {Body: contract.Contract{ContractHash: exactHash}},
		},
	}

	active, err := NewActiveSet(state)
	if err != nil {
		t.Fatalf("NewActiveSet: %v", err)
	}
	resolved, ok := active.Resolve("build-agent")
	if !ok {
		t.Fatal("Resolve returned no match")
	}
	if resolved.SelectorID != testExact {
		t.Fatalf("selector_id = %q, want exact", resolved.SelectorID)
	}
	other, ok := active.Resolve("build-worker")
	if !ok || other.SelectorID != testGlob {
		t.Fatalf("glob resolve = (%v, %v), want glob match", other, ok)
	}
	fallback, ok := active.Resolve("unknown")
	if !ok || fallback.SelectorID != testDefault {
		t.Fatalf("default resolve = (%v, %v), want default match", fallback, ok)
	}

	stamped := resolved.ReceiptContext().StampReceipt(contractreceipt.EvidenceReceipt{})
	if stamped.ActiveManifestHash != testManifestHash {
		t.Fatalf("active_manifest_hash = %q", stamped.ActiveManifestHash)
	}
	if stamped.ContractHash != exactHash || stamped.SelectorID != testExact || stamped.ContractGeneration != 7 {
		t.Fatalf("stamped context = %+v", stamped)
	}
}

func TestNewActiveSetRejectsMissingContract(t *testing.T) {
	_, err := NewActiveSet(store.State{
		Envelope: contract.ActiveManifestEnvelope{
			Body: contract.ActiveManifest{
				Generation: 1,
				Selectors:  []contract.ManifestSelector{{SelectorID: testSelectorID, ContractHash: testContractHash}},
			},
		},
		ManifestHash: testManifestHash,
		Contracts:    map[string]contract.ContractEnvelope{},
	})
	if !errors.Is(err, ErrNoResolvedContract) {
		t.Fatalf("err = %v, want ErrNoResolvedContract", err)
	}
}

func TestActiveSetAccessorsAndInvalidState(t *testing.T) {
	if (*ActiveSet)(nil).ManifestHash() != "" {
		t.Fatal("nil ManifestHash should be empty")
	}
	if (*ActiveSet)(nil).Generation() != 0 {
		t.Fatal("nil Generation should be zero")
	}
	active, err := NewActiveSet(store.State{
		Envelope:     contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Generation: 2}},
		ManifestHash: testManifestHash,
		Contracts:    map[string]contract.ContractEnvelope{},
	})
	if err != nil {
		t.Fatalf("NewActiveSet: %v", err)
	}
	if active.ManifestHash() != testManifestHash || active.Generation() != 2 {
		t.Fatalf("accessors = (%q, %d)", active.ManifestHash(), active.Generation())
	}

	tests := []struct {
		name  string
		state store.State
	}{
		{
			name:  "missing manifest hash",
			state: store.State{Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Generation: 1}}},
		},
		{
			name:  "missing generation",
			state: store.State{ManifestHash: testManifestHash},
		},
		{
			name: "contract hash mismatch",
			state: store.State{
				Envelope: contract.ActiveManifestEnvelope{
					Body: contract.ActiveManifest{
						Generation: 1,
						Selectors:  []contract.ManifestSelector{{SelectorID: testSelectorID, ContractHash: testContractHash}},
					},
				},
				ManifestHash: testManifestHash,
				Contracts: map[string]contract.ContractEnvelope{
					testSelectorID: {Body: contract.Contract{ContractHash: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewActiveSet(tt.state); !errors.Is(err, ErrInvalidDecisionInput) {
				t.Fatalf("err = %v, want ErrInvalidDecisionInput", err)
			}
		})
	}
}

func TestResolveNilNoMatchAndRejectsBadGlob(t *testing.T) {
	if resolved, ok := (*ActiveSet)(nil).Resolve("agent"); ok || resolved != nil {
		t.Fatalf("nil Resolve = (%v, %v), want no match", resolved, ok)
	}
	state := store.State{
		Envelope: contract.ActiveManifestEnvelope{
			Body: contract.ActiveManifest{
				Generation: 1,
				Selectors: []contract.ManifestSelector{
					{SelectorID: "bad-glob", AgentGlob: "[", ContractHash: testContractHash},
					{SelectorID: testOther, Agent: testOther, ContractHash: testContractHash},
				},
			},
		},
		ManifestHash: testManifestHash,
		Contracts: map[string]contract.ContractEnvelope{
			"bad-glob": {Body: contract.Contract{ContractHash: testContractHash}},
			testOther:  {Body: contract.Contract{ContractHash: testContractHash}},
		},
	}
	if _, err := NewActiveSet(state); !errors.Is(err, ErrInvalidSelector) {
		t.Fatalf("NewActiveSet bad glob err = %v, want ErrInvalidSelector", err)
	}

	state.Envelope.Body.Selectors[0].AgentGlob = "no-match-*"
	active, err := NewActiveSet(state)
	if err != nil {
		t.Fatalf("NewActiveSet valid glob: %v", err)
	}
	if resolved, ok := active.Resolve("agent"); ok || resolved != nil {
		t.Fatalf("Resolve = (%v, %v), want no match", resolved, ok)
	}
}

func TestEvaluateHTTP_KillSwitchSuppressesContractEvalButKeepsAuditDecision(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-allow", testAPIExampleCom, "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Resolved:         &resolved,
		Request:          HTTPRequest{URL: "https://api.example.com/v1/other", Method: http.MethodPost},
		Mode:             ModeLive,
		KillSwitchActive: true,
		ScannerVerdict:   config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.WinningSource != WinningSourceKillSwitch {
		t.Fatalf("decision = %+v, want kill-switch block", decision)
	}
	if !decision.Suppressed || decision.Drift != nil || decision.Signal != nil {
		t.Fatalf("kill switch should suppress drift/signal, got %+v", decision)
	}
	payload := ProxyDecisionPayload(decision, "delegate", "https://api.example.com/v1/other", "fetch")
	if payload.WinningSource != WinningSourceKillSwitch {
		t.Fatalf("winning_source = %q", payload.WinningSource)
	}
	if !contains(payload.PolicySources, PolicySourceKillSwitch) {
		t.Fatalf("policy_sources = %v, want kill_switch", payload.PolicySources)
	}
}

func TestEvaluateHTTP_ContractAllowAndDenyDefault(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost))

	allowed, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://API.example.com/V1/CHAT", Method: "post"},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP allow: %v", err)
	}
	if allowed.Verdict != config.ActionAllow || allowed.RuleID != "r-chat" || allowed.WinningSource != WinningSourceContract {
		t.Fatalf("allowed decision = %+v", allowed)
	}

	explicitDefaultPort, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://api.example.com:443/v1/chat", Method: http.MethodPost},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP explicit default port: %v", err)
	}
	if explicitDefaultPort.Verdict != config.ActionAllow || explicitDefaultPort.RuleID != "r-chat" {
		t.Fatalf("explicit default port decision = %+v", explicitDefaultPort)
	}

	alternatePort, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://api.example.com:8443/v1/chat", Method: http.MethodPost},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP alternate port: %v", err)
	}
	if alternatePort.Verdict != config.ActionBlock || alternatePort.WinningSource != WinningSourceContract ||
		alternatePort.Reason != "contract_non_default_port" {
		t.Fatalf("alternate port decision = %+v, want contract non-default-port block", alternatePort)
	}

	denied, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://api.example.com/v1/completions", Method: http.MethodPost},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP deny: %v", err)
	}
	if denied.Verdict != config.ActionBlock || denied.WinningSource != WinningSourceContract {
		t.Fatalf("denied decision = %+v", denied)
	}
	if denied.Drift == nil || denied.Drift.Kind != DriftKindPositive {
		t.Fatalf("drift = %+v, want positive", denied.Drift)
	}
	if denied.Signal == nil || *denied.Signal != session.SignalBlock {
		t.Fatalf("signal = %v, want SignalBlock", denied.Signal)
	}
}

func TestEvaluateHTTP_DefaultDenyOnceContractHasEnforceRule(t *testing.T) {
	// A contract with at least one enforce rule claims jurisdiction. Traffic
	// to a host the contract does not enumerate is denied by default in live
	// mode — without this the "lock" is just per-host policy refinement and
	// any new domain (including exfil) falls through to the scanner.
	resolved := resolvedContractWithRules(enforceRule("r-chat", "chat.example.com", "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSOtherChatURL, Method: http.MethodPost},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP default-deny: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.WinningSource != WinningSourceContract {
		t.Fatalf("decision = %+v, want contract default-deny block", decision)
	}
	if decision.Reason != "contract_default_deny" {
		t.Fatalf("reason = %q, want contract_default_deny", decision.Reason)
	}
	if decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block", decision.LiveVerdict)
	}
	if decision.Drift == nil || decision.Drift.Kind != DriftKindPositive {
		t.Fatalf("drift = %+v, want positive", decision.Drift)
	}
}

func TestEvaluateHTTP_ObservationOnlyContractFallsThroughToScanner(t *testing.T) {
	// A contract with zero enforce rules anywhere is observation-only and
	// claims no jurisdiction. Traffic falls through to the scanner verdict
	// regardless of host. This lets operators promote a fresh contract
	// without immediately locking out every request.
	rule := enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost)
	rule.LifecycleState = LifecycleProposed
	resolved := resolvedContractWithRules(rule)

	decision, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSOtherChatURL, Method: http.MethodPost},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionWarn,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP observation-only: %v", err)
	}
	if decision.Verdict != config.ActionWarn || decision.WinningSource != WinningSourceScanner {
		t.Fatalf("decision = %+v, want scanner fallback", decision)
	}
}

func TestEvaluateHTTP_ScannerFallbacksAndErrors(t *testing.T) {
	decision, err := EvaluateHTTP(EvaluateOptions{Mode: ModeLive})
	if err != nil {
		t.Fatalf("EvaluateHTTP nil resolved: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.WinningSource != WinningSourceScanner ||
		decision.Reason != decisionReasonScannerDecisionMissing {
		t.Fatalf("missing scanner decision = %+v", decision)
	}
	if !contains(decision.PolicySources, PolicySourceScanner) {
		t.Fatalf("policy_sources = %v, want scanner", decision.PolicySources)
	}
	decision, err = EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP explicit scanner allow: %v", err)
	}
	if decision.Verdict != config.ActionAllow || decision.Reason != "" {
		t.Fatalf("explicit scanner decision = %+v", decision)
	}

	resolved := resolvedContractWithRules(enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost))
	if _, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "://bad"},
		ScannerVerdict: config.ActionAllow,
	}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("invalid URL err = %v", err)
	}

	badLifecycle := enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost)
	badLifecycle.LifecycleState = "surprise"
	resolved = resolvedContractWithRules(badLifecycle)
	if _, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSAPIChatURL, Method: http.MethodPost},
		ScannerVerdict: config.ActionAllow,
	}); !errors.Is(err, ErrUnsupportedLifecycle) {
		t.Fatalf("lifecycle err = %v", err)
	}
}

func TestEvaluateHTTP_RejectsEmptyAndUnknownMode(t *testing.T) {
	if _, err := EvaluateHTTP(EvaluateOptions{ScannerVerdict: config.ActionAllow}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("empty mode err = %v, want ErrInvalidDecisionInput", err)
	}
	if _, err := EvaluateHTTP(EvaluateOptions{
		Mode:           Mode("preview"),
		ScannerVerdict: config.ActionAllow,
	}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("unknown mode err = %v, want ErrInvalidDecisionInput", err)
	}
}

func TestEvaluateHTTP_ScannerBlockBeatsContractAllow(t *testing.T) {
	// The scanner-floor invariant: a signed contract that allows
	// https://api.example.com/v1/chat must NOT resurrect a request the
	// scanner blocked (DLP / SSRF / blocklist all flow through scanner).
	// Without this, the contract becomes a signed bypass.
	resolved := resolvedContractWithRules(enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSAPIChatURL, Method: http.MethodPost},
		ScannerVerdict: config.ActionBlock,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP scanner-block-floor: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("verdict = %q live = %q, want both block", decision.Verdict, decision.LiveVerdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner (floor)", decision.WinningSource)
	}
	if decision.Drift != nil {
		t.Fatalf("drift should not fire when scanner is the winning source: %+v", decision.Drift)
	}
}

func TestEvaluateHTTP_ShadowModeObservesContractBlockButLetsScannerVerdictStand(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeShadow,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSOtherChatURL, Method: http.MethodPost},
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP shadow: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want scanner allow (shadow does not enforce)", decision.Verdict)
	}
	if decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block (live mode would have denied)", decision.LiveVerdict)
	}
	if decision.WinningSource != WinningSourceScanner {
		t.Fatalf("winning_source = %q, want scanner (shadow mode never lets contract decide Verdict)", decision.WinningSource)
	}
	if decision.Drift == nil || decision.Drift.Mode != ModeShadow {
		t.Fatalf("drift = %+v, want shadow-mode positive drift", decision.Drift)
	}
	if decision.Signal != nil {
		t.Fatalf("signal must not fire in shadow mode: %v", decision.Signal)
	}
}

func TestEvaluateHTTP_ShadowModeContractAllowDoesNotEmitObservedOnlyReason(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeShadow,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSAPIChatURL, Method: http.MethodPost},
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP shadow contract allow: %v", err)
	}
	if decision.Verdict != config.ActionAllow || decision.LiveVerdict != config.ActionAllow {
		t.Fatalf("verdict = %q live = %q, want allow/allow", decision.Verdict, decision.LiveVerdict)
	}
	if decision.Reason != "" {
		t.Fatalf("reason = %q, want empty when live mode would also allow", decision.Reason)
	}
	if decision.Drift != nil {
		t.Fatalf("drift = %+v, want nil for contract allow", decision.Drift)
	}
}

func TestEvaluateHTTP_CaptureModeNeverBlocksFromContract(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-chat", testAPIExampleCom, "/v1/chat", http.MethodPost))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeCapture,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: testHTTPSOtherChatURL, Method: http.MethodPost},
		ScannerVerdict: config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP capture: %v", err)
	}
	if decision.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want scanner allow (capture never blocks)", decision.Verdict)
	}
	if decision.LiveVerdict != config.ActionBlock {
		t.Fatalf("live_verdict = %q, want block (live would have denied)", decision.LiveVerdict)
	}
	if decision.Signal != nil {
		t.Fatalf("signal must not fire in capture mode: %v", decision.Signal)
	}
}

func TestEvaluateHTTP_SelectorConstraintBranches(t *testing.T) {
	actionRule := enforceRule("r-action", testAPIExampleCom, "/v1/chat", http.MethodPost)
	actionRule.Selector["effective_action"] = "delegate"
	resolved := resolvedContractWithRules(actionRule)
	allowed, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		ScannerVerdict: config.ActionAllow,
		Request: HTTPRequest{
			URL:             testHTTPSAPIChatURL,
			Method:          http.MethodPost,
			EffectiveAction: "delegate",
		},
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP action match: %v", err)
	}
	if allowed.RuleID != "r-action" || allowed.Verdict != config.ActionAllow {
		t.Fatalf("action match decision = %+v", allowed)
	}

	denied, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		ScannerVerdict: config.ActionAllow,
		Request: HTTPRequest{
			URL:             testHTTPSAPIChatURL,
			Method:          http.MethodPost,
			EffectiveAction: "read",
		},
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP action mismatch: %v", err)
	}
	if denied.Verdict != config.ActionBlock || denied.RuleID != "r-action" {
		t.Fatalf("action mismatch decision = %+v", denied)
	}

	badPathRule := enforceRule("r-badpath", testAPIExampleCom, "/v1/chat", http.MethodPost)
	resolved = resolvedContractWithRules(badPathRule)
	blocked, err := EvaluateHTTP(EvaluateOptions{
		Mode:           ModeLive,
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://api.example.com/v1%2Fchat", Method: http.MethodPost},
		ScannerVerdict: config.ActionWarn,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP bad path: %v", err)
	}
	if blocked.Verdict != config.ActionBlock || blocked.WinningSource != WinningSourceContract ||
		blocked.Reason != "contract_invalid_path" {
		t.Fatalf("bad path decision = %+v, want contract invalid-path block", blocked)
	}
}

func TestEvaluateDrift_OpportunityMissingBlocksAutoDemotion(t *testing.T) {
	result, err := EvaluateDrift(DriftObservation{
		Rule:               captureRule("r1"),
		ContractHash:       testContractHash,
		Mode:               ModeLive,
		OpportunityHealthy: false,
		HistoricalRate:     "0.90",
		CurrentRate:        "0.10",
		Window:             "2026-04-30T00:00:00Z/2026-04-30T01:00:00Z",
		ParentContext:      testAPIExampleCom,
		MissedWindows:      9,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift: %v", err)
	}
	if result.OpportunityAlert == nil {
		t.Fatal("expected opportunity_missing alert")
	}
	if result.Drift != nil || result.AdaptiveSignal != nil || result.ShouldAutoDemote {
		t.Fatalf("opportunity_missing must not demote or signal: %+v", result)
	}
	payload := OpportunityMissingPayload(*result.OpportunityAlert)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := validateTestPayload(contractreceipt.PayloadOpportunityMissing, raw); err != nil {
		t.Fatalf("payload validate: %v", err)
	}
}

func TestEvaluateDrift_NegativeRequiresThreeClausesAndIsAdaptiveNeutral(t *testing.T) {
	base := DriftObservation{
		Rule:                  captureRule("r1"),
		ContractHash:          testContractHash,
		Mode:                  ModeLive,
		OpportunityHealthy:    true,
		OpportunityObserved:   true,
		ExpectedObserved:      false,
		MissedWindows:         3,
		RequiredMissedWindows: 3,
	}
	result, err := EvaluateDrift(base)
	if err != nil {
		t.Fatalf("EvaluateDrift: %v", err)
	}
	if result.Drift == nil || result.Drift.Kind != DriftKindNegative {
		t.Fatalf("drift = %+v, want negative", result.Drift)
	}
	if result.AdaptiveSignal != nil {
		t.Fatalf("negative drift should be adaptive-neutral, got %v", result.AdaptiveSignal)
	}

	base.OpportunityObserved = false
	none, err := EvaluateDrift(base)
	if err != nil {
		t.Fatalf("EvaluateDrift no-op: %v", err)
	}
	if none.Drift != nil || none.OpportunityAlert != nil {
		t.Fatalf("missing opportunity clause should suppress drift, got %+v", none)
	}
}

func TestEvaluateDrift_RejectsEmptyAndUnknownMode(t *testing.T) {
	// An observation without an explicit mode previously fell through
	// effectiveMode("") → ModeLive, which then caused SignalForDrift to
	// emit session.SignalBlock and push adaptive enforcement. Empty mode
	// must now fail-closed so the caller is forced to be explicit.
	_, err := EvaluateDrift(DriftObservation{
		Rule:               enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost),
		ContractHash:       testContractHash,
		OpportunityHealthy: true,
		UnexpectedObserved: true,
	})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("empty mode err = %v, want ErrInvalidDecisionInput", err)
	}

	_, err = EvaluateDrift(DriftObservation{
		Rule:               enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost),
		ContractHash:       testContractHash,
		Mode:               Mode("preview"),
		OpportunityHealthy: true,
		UnexpectedObserved: true,
	})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("unknown mode err = %v, want ErrInvalidDecisionInput", err)
	}
}

func TestEvaluateDrift_PositiveSignalOnlyInLiveMode(t *testing.T) {
	live, err := EvaluateDrift(DriftObservation{
		Rule:               enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost),
		ContractHash:       testContractHash,
		Mode:               ModeLive,
		OpportunityHealthy: true,
		UnexpectedObserved: true,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift live: %v", err)
	}
	if live.AdaptiveSignal == nil || *live.AdaptiveSignal != session.SignalBlock {
		t.Fatalf("live signal = %v, want SignalBlock", live.AdaptiveSignal)
	}

	shadow, err := EvaluateDrift(DriftObservation{
		Rule:               enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost),
		ContractHash:       testContractHash,
		Mode:               ModeShadow,
		OpportunityHealthy: true,
		UnexpectedObserved: true,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift shadow: %v", err)
	}
	if shadow.AdaptiveSignal != nil {
		t.Fatalf("shadow signal = %v, want nil", shadow.AdaptiveSignal)
	}
}

func TestEvaluateDrift_SuppressedInvalidAndInactiveBranches(t *testing.T) {
	result, err := EvaluateDrift(DriftObservation{
		Rule:             enforceRule("r1", testAPIExampleCom, "/v1/chat", http.MethodPost),
		ContractHash:     testContractHash,
		KillSwitchActive: true,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift kill switch: %v", err)
	}
	if !result.Suppressed || result.Drift != nil {
		t.Fatalf("kill switch result = %+v", result)
	}

	_, err = EvaluateDrift(DriftObservation{
		Rule:         contract.Rule{RuleID: "r1", LifecycleState: testBad},
		ContractHash: testContractHash,
		Mode:         ModeLive,
	})
	if !errors.Is(err, ErrUnsupportedLifecycle) {
		t.Fatalf("bad lifecycle err = %v", err)
	}
	_, err = EvaluateDrift(DriftObservation{Rule: captureRule("r1"), Mode: ModeLive})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("missing contract hash err = %v", err)
	}
	_, err = EvaluateDrift(DriftObservation{
		Rule:         contract.Rule{LifecycleState: LifecycleCaptureOnly},
		ContractHash: testContractHash,
		Mode:         ModeLive,
	})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("missing rule id err = %v", err)
	}

	for _, state := range []string{LifecycleProposed, LifecycleExpired, LifecycleDemoted} {
		result, err := EvaluateDrift(DriftObservation{
			Rule:         contract.Rule{RuleID: "r1", LifecycleState: state},
			ContractHash: testContractHash,
			Mode:         ModeLive,
		})
		if err != nil {
			t.Fatalf("EvaluateDrift %s: %v", state, err)
		}
		if result.Drift != nil || result.OpportunityAlert != nil {
			t.Fatalf("inactive state %s result = %+v", state, result)
		}
	}
}

func TestEvaluateDrift_UsesRuleWindowFloor(t *testing.T) {
	rule := captureRule("r1")
	rule.RecurringSupport = map[string]any{testWindowsFloor: "4"}
	tooEarly, err := EvaluateDrift(DriftObservation{
		Rule:                rule,
		ContractHash:        testContractHash,
		Mode:                ModeLive,
		OpportunityHealthy:  true,
		OpportunityObserved: true,
		MissedWindows:       3,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift too early: %v", err)
	}
	if tooEarly.Drift != nil {
		t.Fatalf("drift before floor = %+v", tooEarly)
	}
	fired, err := EvaluateDrift(DriftObservation{
		Rule:                rule,
		ContractHash:        testContractHash,
		Mode:                ModeLive,
		OpportunityHealthy:  true,
		OpportunityObserved: true,
		MissedWindows:       4,
	})
	if err != nil {
		t.Fatalf("EvaluateDrift fired: %v", err)
	}
	if fired.Drift == nil || fired.Drift.MissedWindows != 4 {
		t.Fatalf("drift after floor = %+v", fired)
	}
}

func TestContractDriftPayloadValidates(t *testing.T) {
	payload := ContractDriftPayload(DriftEvent{
		ContractHash:      testContractHash,
		RuleID:            "r1",
		Kind:              DriftKindNegative,
		MissedWindows:     4,
		OpportunityStatus: testStatusHealthy,
	})
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := validateTestPayload(contractreceipt.PayloadContractDrift, raw); err != nil {
		t.Fatalf("payload validate: %v", err)
	}
}

func TestHelperBranches(t *testing.T) {
	if got := observationUint(map[string]any{"n": uint64(9)}, "n"); got != 9 {
		t.Fatalf("uint64 observation = %d", got)
	}
	if got := observationUint(map[string]any{"n": uint(8)}, "n"); got != 8 {
		t.Fatalf("uint observation = %d", got)
	}
	if got := observationUint(map[string]any{"n": int(7)}, "n"); got != 7 {
		t.Fatalf("int observation = %d", got)
	}
	if got := observationUint(map[string]any{"n": int64(6)}, "n"); got != 6 {
		t.Fatalf("int64 observation = %d", got)
	}
	if got := observationUint(map[string]any{"n": float64(5)}, "n"); got != 5 {
		t.Fatalf("float observation = %d", got)
	}
	for _, m := range []map[string]any{
		nil,
		{"n": -1},
		{"n": int64(-1)},
		{"n": float64(-1)},
		{"n": testBad},
		{"n": []string{testBad}},
	} {
		if got := observationUint(m, "n"); got != 0 {
			t.Fatalf("observationUint(%v) = %d, want 0", m, got)
		}
	}

	sources := normalizePolicySources([]string{" scanner ", "", "scanner", "bundle"})
	if len(sources) != 2 || sources[0] != PolicySourceScanner || sources[1] != PolicySourceBundle {
		t.Fatalf("normalizePolicySources = %v", sources)
	}
	seen := map[string]struct{}{}
	rules := appendRuleID(nil, seen, "")
	rules = appendRuleID(rules, seen, "r1")
	rules = appendRuleID(rules, seen, "r1")
	if len(rules) != 1 || rules[0] != "r1" {
		t.Fatalf("appendRuleID = %v", rules)
	}
	if firstString(nil) != "" {
		t.Fatal("firstString(nil) should be empty")
	}

	if got := selectorString(map[string]any{testJSONKeyHost: testBad}, testJSONKeyHost); got != "" {
		t.Fatalf("selectorString bad = %q", got)
	}
	if got := selectorMethods(map[string]any{testJSONKeyMethods: testBad}); got != nil {
		t.Fatalf("selectorMethods bad = %v", got)
	}
	if got := selectorMethods(map[string]any{testJSONKeyMethods: []any{http.MethodGet, 4}}); len(got) != 1 || got[0] != http.MethodGet {
		t.Fatalf("selectorMethods mixed = %v", got)
	}
	if got := selectorPathValues(map[string]any{testJSONKeyPaths: testBad}); got != nil {
		t.Fatalf("selectorPathValues bad = %v", got)
	}
	if got := selectorPathValues(map[string]any{testJSONKeyPaths: []any{testBad, map[string]any{testJSONKeyValue: 3}, map[string]any{testJSONKeyValue: "/ok"}}}); len(got) != 1 || got[0] != "/ok" {
		t.Fatalf("selectorPathValues mixed = %v", got)
	}
	if containsFolded([]string{http.MethodGet}, http.MethodPost) {
		t.Fatal("containsFolded unexpectedly matched")
	}
	if matches, canCompare, invalidPath := ruleMatchesHTTP(contract.Rule{}, mustURL(t, "https://api.example.com/"), HTTPRequest{}); matches || !canCompare || invalidPath {
		t.Fatalf("empty rule match = (%v, %v, %v), want false,true,false", matches, canCompare, invalidPath)
	}
	if priority, ok := selectorPriority(contract.ManifestSelector{}, "agent"); priority != 0 || ok {
		t.Fatalf("selectorPriority empty = (%d, %v)", priority, ok)
	}
	if !usesDefaultHTTPPort(mustURL(t, "http://api.example.com:80/")) {
		t.Fatal("http explicit default port should compare")
	}
	if usesDefaultHTTPPort(mustURL(t, "ftp://api.example.com/")) {
		t.Fatal("non-http scheme should not compare")
	}
	alt := enforceRule("r-alt", testAPIExampleCom, "/v2/chat", http.MethodGet)
	if got := selectorPathValues(alt.Selector); len(got) != 1 || got[0] != "/v2/chat" {
		t.Fatalf("alternate enforceRule path = %v", got)
	}
	if got := selectorMethods(alt.Selector); len(got) != 1 || got[0] != http.MethodGet {
		t.Fatalf("alternate enforceRule method = %v", got)
	}
}

func resolvedContractWithRules(rules ...contract.Rule) ResolvedContract {
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

func enforceRule(ruleID, host, pathValue, method string) contract.Rule {
	rule := captureRule(ruleID)
	rule.LifecycleState = LifecycleEnforce
	rule.RuleKind = ruleKindHTTPAction
	rule.Selector = map[string]any{
		testJSONKeyHost:    map[string]any{testJSONKeyValue: host},
		testJSONKeyPaths:   []any{map[string]any{testJSONKeyValue: pathValue}},
		testJSONKeyMethods: []any{method},
	}
	return rule
}

func captureRule(ruleID string) contract.Rule {
	return contract.Rule{
		RuleID:               ruleID,
		RuleKind:             ruleKindHTTPDestination,
		LifecycleState:       LifecycleCaptureOnly,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		RecurringSupport:     map[string]any{testWindowsFloor: 3},
		Selector: map[string]any{
			testJSONKeyHost: map[string]any{testJSONKeyValue: testAPIExampleCom},
		},
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return u
}

func validateTestPayload(kind contractreceipt.PayloadKind, raw []byte) error {
	return contractreceipt.EvidenceReceipt{
		RecordType:     contractreceipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    kind,
		EventID:        "018f0000-0000-7000-8000-000000000000",
		Timestamp:      time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		Signature: contractreceipt.SignatureProof{
			SignerKeyID: "receipt-key",
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   "ed25519:" + strings.Repeat("0", 128),
		},
		Payload: raw,
	}.Validate()
}

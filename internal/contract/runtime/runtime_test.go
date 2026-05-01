// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
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
					{SelectorID: "default", Default: true, ContractHash: defaultHash},
					{SelectorID: "glob", AgentGlob: "build-*", ContractHash: globHash},
					{SelectorID: "exact", Agent: "build-agent", ContractHash: exactHash},
				},
			},
		},
		ManifestHash: testManifestHash,
		Contracts: map[string]contract.ContractEnvelope{
			"default": {Body: contract.Contract{ContractHash: defaultHash}},
			"glob":    {Body: contract.Contract{ContractHash: globHash}},
			"exact":   {Body: contract.Contract{ContractHash: exactHash}},
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
	if resolved.SelectorID != "exact" {
		t.Fatalf("selector_id = %q, want exact", resolved.SelectorID)
	}
	other, ok := active.Resolve("build-worker")
	if !ok || other.SelectorID != "glob" {
		t.Fatalf("glob resolve = (%v, %v), want glob match", other, ok)
	}
	fallback, ok := active.Resolve("unknown")
	if !ok || fallback.SelectorID != "default" {
		t.Fatalf("default resolve = (%v, %v), want default match", fallback, ok)
	}

	stamped := resolved.ReceiptContext().StampReceipt(contractreceipt.EvidenceReceipt{})
	if stamped.ActiveManifestHash != testManifestHash {
		t.Fatalf("active_manifest_hash = %q", stamped.ActiveManifestHash)
	}
	if stamped.ContractHash != exactHash || stamped.SelectorID != "exact" || stamped.ContractGeneration != 7 {
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
					{SelectorID: "other", Agent: "other", ContractHash: testContractHash},
				},
			},
		},
		ManifestHash: testManifestHash,
		Contracts: map[string]contract.ContractEnvelope{
			"bad-glob": {Body: contract.Contract{ContractHash: testContractHash}},
			"other":    {Body: contract.Contract{ContractHash: testContractHash}},
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
	resolved := resolvedContractWithRules(enforceRule("r-allow", "api.example.com", "/v1/chat", "POST"))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Resolved:         &resolved,
		Request:          HTTPRequest{URL: "https://api.example.com/v1/other", Method: "POST"},
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
	resolved := resolvedContractWithRules(enforceRule("r-chat", "api.example.com", "/v1/chat", "POST"))

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
		Request:        HTTPRequest{URL: "https://api.example.com:443/v1/chat", Method: "POST"},
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
		Request:        HTTPRequest{URL: "https://api.example.com:8443/v1/chat", Method: "POST"},
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
		Request:        HTTPRequest{URL: "https://api.example.com/v1/completions", Method: "POST"},
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

func TestEvaluateHTTP_HostScopedDenyDefaultFallsBackToScanner(t *testing.T) {
	resolved := resolvedContractWithRules(enforceRule("r-chat", "blocked.example.com", "/v1/chat", "POST"))

	decision, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://other.example.com/v1/chat", Method: "POST"},
		Mode:           ModeLive,
		ScannerVerdict: config.ActionWarn,
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP: %v", err)
	}
	if decision.Verdict != config.ActionWarn || decision.WinningSource != WinningSourceScanner {
		t.Fatalf("decision = %+v, want scanner fallback", decision)
	}
}

func TestEvaluateHTTP_ScannerFallbacksAndErrors(t *testing.T) {
	decision, err := EvaluateHTTP(EvaluateOptions{})
	if err != nil {
		t.Fatalf("EvaluateHTTP nil resolved: %v", err)
	}
	if decision.Verdict != config.ActionBlock || decision.WinningSource != WinningSourceScanner ||
		decision.Reason != "scanner_decision_missing" {
		t.Fatalf("missing scanner decision = %+v", decision)
	}
	if !contains(decision.PolicySources, PolicySourceScanner) {
		t.Fatalf("policy_sources = %v, want scanner", decision.PolicySources)
	}
	decision, err = EvaluateHTTP(EvaluateOptions{ScannerVerdict: config.ActionAllow})
	if err != nil {
		t.Fatalf("EvaluateHTTP explicit scanner allow: %v", err)
	}
	if decision.Verdict != config.ActionAllow || decision.Reason != "" {
		t.Fatalf("explicit scanner decision = %+v", decision)
	}

	resolved := resolvedContractWithRules(enforceRule("r1", "api.example.com", "/v1/chat", "POST"))
	if _, err := EvaluateHTTP(EvaluateOptions{
		Resolved: &resolved,
		Request:  HTTPRequest{URL: "://bad"},
	}); !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("invalid URL err = %v", err)
	}

	badLifecycle := enforceRule("r1", "api.example.com", "/v1/chat", "POST")
	badLifecycle.LifecycleState = "surprise"
	resolved = resolvedContractWithRules(badLifecycle)
	if _, err := EvaluateHTTP(EvaluateOptions{
		Resolved: &resolved,
		Request:  HTTPRequest{URL: "https://api.example.com/v1/chat", Method: "POST"},
	}); !errors.Is(err, ErrUnsupportedLifecycle) {
		t.Fatalf("lifecycle err = %v", err)
	}
}

func TestEvaluateHTTP_SelectorConstraintBranches(t *testing.T) {
	actionRule := enforceRule("r-action", "api.example.com", "/v1/chat", "POST")
	actionRule.Selector["effective_action"] = "delegate"
	resolved := resolvedContractWithRules(actionRule)
	allowed, err := EvaluateHTTP(EvaluateOptions{
		Resolved: &resolved,
		Request: HTTPRequest{
			URL:             "https://api.example.com/v1/chat",
			Method:          "POST",
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
		Resolved: &resolved,
		Request: HTTPRequest{
			URL:             "https://api.example.com/v1/chat",
			Method:          "POST",
			EffectiveAction: "read",
		},
	})
	if err != nil {
		t.Fatalf("EvaluateHTTP action mismatch: %v", err)
	}
	if denied.Verdict != config.ActionBlock || denied.RuleID != "r-action" {
		t.Fatalf("action mismatch decision = %+v", denied)
	}

	badPathRule := enforceRule("r-badpath", "api.example.com", "/v1/chat", "POST")
	resolved = resolvedContractWithRules(badPathRule)
	blocked, err := EvaluateHTTP(EvaluateOptions{
		Resolved:       &resolved,
		Request:        HTTPRequest{URL: "https://api.example.com/v1%2Fchat", Method: "POST"},
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
		ParentContext:      "api.example.com",
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

func TestEvaluateDrift_PositiveSignalOnlyInLiveMode(t *testing.T) {
	live, err := EvaluateDrift(DriftObservation{
		Rule:               enforceRule("r1", "api.example.com", "/v1/chat", "POST"),
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
		Rule:               enforceRule("r1", "api.example.com", "/v1/chat", "POST"),
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
		Rule:             enforceRule("r1", "api.example.com", "/v1/chat", "POST"),
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
		Rule:         contract.Rule{RuleID: "r1", LifecycleState: "bad"},
		ContractHash: testContractHash,
	})
	if !errors.Is(err, ErrUnsupportedLifecycle) {
		t.Fatalf("bad lifecycle err = %v", err)
	}
	_, err = EvaluateDrift(DriftObservation{Rule: captureRule("r1")})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("missing contract hash err = %v", err)
	}
	_, err = EvaluateDrift(DriftObservation{
		Rule:         contract.Rule{LifecycleState: LifecycleCaptureOnly},
		ContractHash: testContractHash,
	})
	if !errors.Is(err, ErrInvalidDecisionInput) {
		t.Fatalf("missing rule id err = %v", err)
	}

	for _, state := range []string{LifecycleProposed, LifecycleExpired, LifecycleDemoted} {
		result, err := EvaluateDrift(DriftObservation{
			Rule:         contract.Rule{RuleID: "r1", LifecycleState: state},
			ContractHash: testContractHash,
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
	rule.RecurringSupport = map[string]any{"windows_floor": "4"}
	tooEarly, err := EvaluateDrift(DriftObservation{
		Rule:                rule,
		ContractHash:        testContractHash,
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
		OpportunityStatus: "healthy",
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
		{"n": "bad"},
		{"n": []string{"bad"}},
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

	if got := selectorString(map[string]any{"host": "bad"}, "host"); got != "" {
		t.Fatalf("selectorString bad = %q", got)
	}
	if got := selectorMethods(map[string]any{"methods": "bad"}); got != nil {
		t.Fatalf("selectorMethods bad = %v", got)
	}
	if got := selectorMethods(map[string]any{"methods": []any{"GET", 4}}); len(got) != 1 || got[0] != "GET" {
		t.Fatalf("selectorMethods mixed = %v", got)
	}
	if got := selectorPathValues(map[string]any{"paths": "bad"}); got != nil {
		t.Fatalf("selectorPathValues bad = %v", got)
	}
	if got := selectorPathValues(map[string]any{"paths": []any{"bad", map[string]any{"value": 3}, map[string]any{"value": "/ok"}}}); len(got) != 1 || got[0] != "/ok" {
		t.Fatalf("selectorPathValues mixed = %v", got)
	}
	if containsFolded([]string{"GET"}, "POST") {
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
	alt := enforceRule("r-alt", "api.example.com", "/v2/chat", "GET")
	if got := selectorPathValues(alt.Selector); len(got) != 1 || got[0] != "/v2/chat" {
		t.Fatalf("alternate enforceRule path = %v", got)
	}
	if got := selectorMethods(alt.Selector); len(got) != 1 || got[0] != "GET" {
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
		"host":    map[string]any{"value": host},
		"paths":   []any{map[string]any{"value": pathValue}},
		"methods": []any{method},
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
		RecurringSupport:     map[string]any{"windows_floor": 3},
		Selector: map[string]any{
			"host": map[string]any{"value": "api.example.com"},
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

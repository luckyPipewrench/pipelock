// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// validReceiptSignaturePlaceholder is a structurally-valid Ed25519 signature
// (correct length and hex prefix) used to exercise EvidenceReceipt.Validate
// without actually signing anything in builder tests. The builder itself
// leaves Signature zero; tests that need to walk the validator simply paint
// in a placeholder before calling Validate.
const validReceiptSignaturePlaceholder = "ed25519:" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// tamperedSentinel is the post-build mutation marker used by the slice
// isolation tests. Extracted as a const so goconst stays quiet across the
// DelegationChain and PolicySources isolation cases.
const tamperedSentinel = "tampered"

func resolvedContractFixture() *ResolvedContract {
	return &ResolvedContract{
		ActiveManifestHash: "sha256:manifest-1",
		ContractHash:       "sha256:contract-1",
		SelectorID:         "selector-1",
		ContractGeneration: 7,
		Contract:           contract.Contract{},
	}
}

// TestBuildProxyDecisionReceipt_ContractAllowHappyPath covers the live-mode
// allow path: a Decision produced with WinningSource=contract, Verdict=allow,
// LiveVerdict=allow. Verdict and LiveVerdict are equal, so the wire payload
// omits LiveVerdict (compact ModeLive emission). All four ResolvedContract
// context fields stamp onto the envelope, and the decoded payload validates
// against the v2 registry.
func TestBuildProxyDecisionReceipt_ContractAllowHappyPath(t *testing.T) {
	t.Parallel()
	rc := resolvedContractFixture()
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionAllow,
			LiveVerdict:   config.ActionAllow,
			PolicySources: []string{PolicySourceScanner, PolicySourceContract},
			WinningSource: WinningSourceContract,
			RuleID:        "rule-allow-1",
		},
		ResolvedContract: rc,
		ActionType:       testHTTPRequest,
		Target:           "https://api.example.com/v1/users",
		Transport:        testForward,
		EventID:          "01900000-0000-7000-8000-000000000001",
		Timestamp:        time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC),
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RecordType != contractreceipt.RecordTypeEvidenceV2 {
		t.Fatalf("RecordType = %q, want evidence_receipt_v2", got.RecordType)
	}
	if got.ReceiptVersion != 2 {
		t.Fatalf("ReceiptVersion = %d, want 2", got.ReceiptVersion)
	}
	if got.PayloadKind != contractreceipt.PayloadProxyDecision {
		t.Fatalf("PayloadKind = %q, want proxy_decision", got.PayloadKind)
	}
	if got.ActiveManifestHash != rc.ActiveManifestHash {
		t.Fatalf("ActiveManifestHash = %q, want %q", got.ActiveManifestHash, rc.ActiveManifestHash)
	}
	if got.ContractHash != rc.ContractHash {
		t.Fatalf("ContractHash = %q, want %q", got.ContractHash, rc.ContractHash)
	}
	if got.SelectorID != rc.SelectorID {
		t.Fatalf("SelectorID = %q, want %q", got.SelectorID, rc.SelectorID)
	}
	if got.ContractGeneration != rc.ContractGeneration {
		t.Fatalf("ContractGeneration = %d, want %d", got.ContractGeneration, rc.ContractGeneration)
	}

	var payload contractreceipt.PayloadProxyDecisionStruct
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.Verdict != config.ActionAllow {
		t.Fatalf("payload.Verdict = %q, want allow", payload.Verdict)
	}
	if payload.LiveVerdict != "" {
		t.Fatalf("payload.LiveVerdict = %q, want empty (Verdict == LiveVerdict)", payload.LiveVerdict)
	}
	if payload.WinningSource != WinningSourceContract {
		t.Fatalf("payload.WinningSource = %q, want %q", payload.WinningSource, WinningSourceContract)
	}
	if payload.RuleID != "rule-allow-1" {
		t.Fatalf("payload.RuleID = %q, want rule-allow-1", payload.RuleID)
	}

	// The payload must validate against the registry dispatcher.
	got.Signature = contractreceipt.SignatureProof{
		SignerKeyID: "receipt-key-1",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   validReceiptSignaturePlaceholder,
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate on built receipt: %v", err)
	}
}

// TestBuildProxyDecisionReceipt_ShadowModeSurfacesLiveVerdict is the
// load-bearing audit-trail test. ModeShadow / ModeCapture surfaces the
// scanner-floor verdict as Verdict (so the proxy never blocks more than
// scanner already would) and the contract's would-have-been outcome as
// LiveVerdict, so a downstream auditor reading the receipt can see
// "scanner allowed; contract would have blocked in live mode" without
// having to reconstruct evaluator state. The shadow path is where this
// payload field earns its keep.
func TestBuildProxyDecisionReceipt_ShadowModeSurfacesLiveVerdict(t *testing.T) {
	t.Parallel()
	rc := resolvedContractFixture()
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionAllow, // scanner-floor verdict (shadow proxies allow)
			LiveVerdict:   config.ActionBlock, // contract would have blocked
			PolicySources: []string{PolicySourceScanner, PolicySourceContract},
			WinningSource: WinningSourceScanner,
			Reason:        decisionReasonContractObservedOnly,
			RuleID:        "rule-block-1",
			Drift:         &DriftEvent{ContractHash: rc.ContractHash, RuleID: "rule-block-1", Kind: DriftKindPositive, Mode: ModeShadow, Action: config.ActionBlock},
		},
		ResolvedContract: rc,
		ActionType:       testHTTPRequest,
		Target:           "https://api.example.com/v1/admin",
		Transport:        testForward,
		EventID:          "01900000-0000-7000-8000-000000000002",
		Timestamp:        time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC),
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload contractreceipt.PayloadProxyDecisionStruct
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.Verdict != config.ActionAllow {
		t.Fatalf("payload.Verdict = %q, want %q (scanner-floor enforced)", payload.Verdict, config.ActionAllow)
	}
	if payload.LiveVerdict != config.ActionBlock {
		t.Fatalf("payload.LiveVerdict = %q, want %q (contract would-have-been)", payload.LiveVerdict, config.ActionBlock)
	}
	if payload.WinningSource != WinningSourceScanner {
		t.Fatalf("payload.WinningSource = %q, want %q (shadow mode wins is scanner)", payload.WinningSource, WinningSourceScanner)
	}
	// Contract context still stamps even though Verdict came from scanner —
	// the contract pin was active, the audit trail must record which contract
	// would-have-been, otherwise drift telemetry cannot attribute the delta.
	if got.ContractHash != rc.ContractHash {
		t.Fatalf("ContractHash dropped under shadow mode: got %q want %q", got.ContractHash, rc.ContractHash)
	}
	if got.SelectorID != rc.SelectorID {
		t.Fatalf("SelectorID dropped under shadow mode: got %q want %q", got.SelectorID, rc.SelectorID)
	}
}

// TestBuildProxyDecisionReceipt_NoContractPin covers the no-contract path:
// a request handled outside any contract's jurisdiction. The receipt body
// builds correctly with empty contract context fields and no rule ID.
func TestBuildProxyDecisionReceipt_NoContractPin(t *testing.T) {
	t.Parallel()
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionBlock,
			LiveVerdict:   config.ActionBlock,
			PolicySources: []string{PolicySourceScanner},
			WinningSource: WinningSourceScanner,
		},
		ResolvedContract: nil,
		ActionType:       testHTTPRequest,
		Target:           "https://malicious.example.com/",
		Transport:        testForward,
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ActiveManifestHash != "" {
		t.Fatalf("ActiveManifestHash = %q, want empty (no pin)", got.ActiveManifestHash)
	}
	if got.ContractHash != "" {
		t.Fatalf("ContractHash = %q, want empty (no pin)", got.ContractHash)
	}
	if got.ContractGeneration != 0 {
		t.Fatalf("ContractGeneration = %d, want 0 (no pin)", got.ContractGeneration)
	}
}

// TestBuildProxyDecisionReceipt_ValidationErrors exercises the upfront
// payload-field check that mirrors the registry's validateProxyDecision.
// Each missing required field returns a wrapped ErrInvalidProxyDecisionInput
// before the envelope is assembled, so callers see the failure at the call
// site instead of during a later receipt.Validate() pass.
func TestBuildProxyDecisionReceipt_ValidationErrors(t *testing.T) {
	t.Parallel()
	good := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionBlock,
			PolicySources: []string{PolicySourceScanner},
			WinningSource: WinningSourceScanner,
		},
		ActionType: testHTTPRequest,
		Target:     testExampleHTTPSURL,
		Transport:  testForward,
	}
	cases := []struct {
		name   string
		mutate func(*ProxyDecisionInput)
		want   string
	}{
		{
			name:   "missing action_type",
			mutate: func(in *ProxyDecisionInput) { in.ActionType = "" },
			want:   "action_type",
		},
		{
			name:   "missing target",
			mutate: func(in *ProxyDecisionInput) { in.Target = "" },
			want:   "target",
		},
		{
			name:   "missing transport",
			mutate: func(in *ProxyDecisionInput) { in.Transport = "" },
			want:   "transport",
		},
		{
			name:   "missing verdict",
			mutate: func(in *ProxyDecisionInput) { in.Decision.Verdict = "" },
			want:   "verdict",
		},
		{
			name:   "missing policy sources",
			mutate: func(in *ProxyDecisionInput) { in.Decision.PolicySources = nil },
			want:   "policy_sources",
		},
		{
			name:   "missing winning source",
			mutate: func(in *ProxyDecisionInput) { in.Decision.WinningSource = "" },
			want:   "winning_source",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.mutate(&in)
			_, err := BuildProxyDecisionReceipt(in)
			if !errors.Is(err, ErrInvalidProxyDecisionInput) {
				t.Fatalf("err = %v, want wrap of ErrInvalidProxyDecisionInput", err)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestBuildProxyDecisionReceipt_DelegationChainIsolation guards against the
// classic shared-slice bug: input mutates after the builder returns and the
// receipt's DelegationChain reflects the mutation. The builder copies the
// slice so the output is an independent snapshot.
func TestBuildProxyDecisionReceipt_DelegationChainIsolation(t *testing.T) {
	t.Parallel()
	chain := []string{"agent-a", "agent-b"}
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionAllow,
			LiveVerdict:   config.ActionAllow,
			PolicySources: []string{PolicySourceScanner},
			WinningSource: WinningSourceScanner,
		},
		ActionType:      testHTTPRequest,
		Target:          testExampleHTTPSURL,
		Transport:       testForward,
		DelegationChain: chain,
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	chain[0] = tamperedSentinel
	if got.DelegationChain[0] == tamperedSentinel {
		t.Fatalf("DelegationChain shares backing array with input — builder must copy")
	}
}

// TestBuildProxyDecisionReceipt_PolicySourcesIsolation parallels the
// DelegationChain isolation test for the other slice the builder accepts.
// ProxyDecisionPayload makes the defensive copy today (decision.PolicySources
// flows through append([]string(nil), ...)); pinning the contract here means
// a future refactor that bypasses ProxyDecisionPayload still has to keep the
// snapshot semantics or the test fails.
func TestBuildProxyDecisionReceipt_PolicySourcesIsolation(t *testing.T) {
	t.Parallel()
	sources := []string{PolicySourceScanner, PolicySourceContract}
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionAllow,
			LiveVerdict:   config.ActionAllow,
			PolicySources: sources,
			WinningSource: WinningSourceScanner,
		},
		ActionType: testHTTPRequest,
		Target:     testExampleHTTPSURL,
		Transport:  testForward,
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sources[0] = tamperedSentinel

	var payload contractreceipt.PayloadProxyDecisionStruct
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.PolicySources[0] == tamperedSentinel {
		t.Fatalf("payload.PolicySources shares backing array with input — builder must copy")
	}
}

// TestBuildProxyDecisionReceipt_LeavesSignatureZero pins the responsibility
// boundary: BuildProxyDecisionReceipt produces an UNSIGNED envelope. The
// receipt signer downstream is the only component that sets Signature.
// Asserting zero here documents that contract and prevents a future
// refactor from accidentally signing inside the builder (which would
// require coupling the builder to a key roster).
func TestBuildProxyDecisionReceipt_LeavesSignatureZero(t *testing.T) {
	t.Parallel()
	in := ProxyDecisionInput{
		Decision: Decision{
			Verdict:       config.ActionAllow,
			LiveVerdict:   config.ActionAllow,
			PolicySources: []string{PolicySourceScanner},
			WinningSource: WinningSourceScanner,
		},
		ActionType: testHTTPRequest,
		Target:     testExampleHTTPSURL,
		Transport:  testForward,
	}
	got, err := BuildProxyDecisionReceipt(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Signature != (contractreceipt.SignatureProof{}) {
		t.Fatalf("Signature = %+v, want zero (signer fills it in)", got.Signature)
	}
}

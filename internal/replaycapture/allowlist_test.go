// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"errors"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// safeBaseRecord returns a minimal, public-safe action record the allowlist
// accepts. Negative tests mutate one field.
func safeBaseRecord() receipt.ActionRecord {
	return receipt.ActionRecord{
		Version:    receipt.ActionRecordVersion,
		ActionID:   receipt.NewActionID(),
		ActionType: receipt.ActionRead,
		Principal:  labPrincipal,
		Actor:      labActor,
		Target:     "https://collector.example.com/collect",
		Verdict:    verdictBlock,
		Transport:  TransportFetch,
		PolicyHash: "sha256:abc",
	}
}

func TestValidateReceiptPublicSafe_AcceptsLabRecord(t *testing.T) {
	t.Parallel()
	if err := ValidateReceiptPublicSafe(safeBaseRecord()); err != nil {
		t.Fatalf("expected safe record to pass, got %v", err)
	}
}

func TestValidateReceiptPublicSafe_Rejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*receipt.ActionRecord)
	}{
		{"foreign principal", func(ar *receipt.ActionRecord) { ar.Principal = "org:acme-corp" }},
		{"foreign actor", func(ar *receipt.ActionRecord) { ar.Actor = "agent:prod-vox" }},
		{"empty target", func(ar *receipt.ActionRecord) { ar.Target = "" }},
		{"real host target", func(ar *receipt.ActionRecord) { ar.Target = "https://api.realvendor.io/x" }},
		{"private ip target", func(ar *receipt.ActionRecord) { ar.Target = "http://10.0.0.5/admin" }},
		{"loopback ip target", func(ar *receipt.ActionRecord) { ar.Target = "http://127.0.0.1:44919/admin" }},
		{"raw secret in target", func(ar *receipt.ActionRecord) {
			ar.Target = "https://collector.example.com/?k=" + SyntheticAWSKey()
		}},
		{"raw secret in pattern", func(ar *receipt.ActionRecord) { ar.Pattern = "leaked " + SyntheticAWSKey() }},
		{"populated request_id", func(ar *receipt.ActionRecord) { ar.RequestID = "req-provider-9c4ad1" }},
		{"bad run nonce", func(ar *receipt.ActionRecord) { ar.RunNonce = "not-a-nonce" }},
		{"populated session task", func(ar *receipt.ActionRecord) { ar.SessionTaskLabel = "internal-task" }},
		{"session contaminated", func(ar *receipt.ActionRecord) { ar.SessionContaminated = true }},
		{"populated contract rule", func(ar *receipt.ActionRecord) { ar.ContractRuleID = "internal-rule-7" }},
		{"jurisdiction leak", func(ar *receipt.ActionRecord) { ar.Jurisdiction = "internal" }},
		{"redaction summary", func(ar *receipt.ActionRecord) { ar.Redaction = &receipt.RedactionSummary{TotalRedactions: 1} }},
		{"shield summary", func(ar *receipt.ActionRecord) { ar.Shield = &receipt.ShieldSummary{TotalRewrites: 1} }},
		{"free-form taint reason", func(ar *receipt.ActionRecord) {
			ar.TaintDecisionReason = "leaked db.internal hostname"
		}},
		{"foreign request id", func(ar *receipt.ActionRecord) { ar.RequestID = "req-provider-9c4ad1" }},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ar := safeBaseRecord()
			tc.mutate(&ar)
			err := ValidateReceiptPublicSafe(ar)
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", tc.name)
			}
			if !errors.Is(err, errAllowlist) {
				t.Fatalf("expected errAllowlist, got %v", err)
			}
		})
	}
}

func TestValidateReceiptPublicSafe_SafeTargets(t *testing.T) {
	t.Parallel()

	safe := []string{
		"https://collector.example.com/collect",
		"http://api.vendor.example/v1",
		"http://169.254.169.254/latest/meta-data/",
		"http://records.fixture.test:44919/v1/records/42",
		"https://203.0.113.10/x", // RFC 5737
	}
	for _, target := range safe {
		ar := safeBaseRecord()
		ar.Target = target
		if err := ValidateReceiptPublicSafe(ar); err != nil {
			t.Errorf("expected %q to be safe, got %v", target, err)
		}
	}

	unsafe := []string{
		"http://169.254.1.2/local-detail",
		"http://[fe80::1]/local-detail",
	}
	for _, target := range unsafe {
		ar := safeBaseRecord()
		ar.Target = target
		if err := ValidateReceiptPublicSafe(ar); err == nil {
			t.Errorf("expected %q to be rejected", target)
		}
	}
}

func TestValidateReceiptPublicSafe_ActionRecordFieldCoverage(t *testing.T) {
	t.Parallel()

	covered := map[string]struct{}{
		"Version":               {},
		"ActionID":              {},
		"ParentActionID":        {},
		"ActionType":            {},
		"Timestamp":             {},
		"Principal":             {},
		"Actor":                 {},
		"DelegationChain":       {},
		"Target":                {},
		"Intent":                {},
		"DataClassesIn":         {},
		"DataClassesOut":        {},
		"SideEffectClass":       {},
		"Reversibility":         {},
		"PolicyHash":            {},
		"Verdict":               {},
		"DecisionPhase":         {},
		"DeferID":               {},
		"ResolutionPolicy":      {},
		"ResolutionSource":      {},
		"SessionID":             {},
		"SessionIDOriginal":     {},
		"SessionTaintLevel":     {},
		"SessionContaminated":   {},
		"RecentTaintSources":    {},
		"SessionTaskID":         {},
		"SessionTaskLabel":      {},
		"AuthorityKind":         {},
		"TaintDecision":         {},
		"TaintDecisionReason":   {},
		"TaskOverrideApplied":   {},
		"ContractWinningSource": {},
		"ContractLiveVerdict":   {},
		"ContractPolicySources": {},
		"ContractRuleID":        {},
		"ActiveManifestHash":    {},
		"ContractHash":          {},
		"ContractSelectorID":    {},
		"ContractGeneration":    {},
		"Transport":             {},
		"Method":                {},
		"Layer":                 {},
		"Pattern":               {},
		"Severity":              {},
		"Redaction":             {},
		"Shield":                {},
		"RequestID":             {},
		"ChainPrevHash":         {},
		"ChainSeq":              {},
		"RunNonce":              {},
		"KeyTransition":         {},
		"Venue":                 {},
		"Jurisdiction":          {},
		"RulebookID":            {},
		"RemedyClass":           {},
		"ContestationWindow":    {},
		"PrecedentRefs":         {},
	}
	arType := reflect.TypeOf(receipt.ActionRecord{})
	for i := 0; i < arType.NumField(); i++ {
		name := arType.Field(i).Name
		if _, ok := covered[name]; !ok {
			t.Errorf("ActionRecord field %s is not covered by the replay public-safe allowlist", name)
		}
	}
}

// TestValidateReceiptPublicSafe_AllCapturedReceiptsPass proves every receipt the
// real engine emits passes the allowlist — the gate and the capture config agree.
func TestValidateReceiptPublicSafe_AllCapturedReceiptsPass(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	for _, s := range DefaultScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			t.Parallel()
			got, err := eng.Capture(s)
			if err != nil {
				t.Fatalf("Capture: %v", err)
			}
			for i, r := range got.Receipts {
				if err := ValidateReceiptPublicSafe(r.ActionRecord); err != nil {
					t.Errorf("receipt %d failed allowlist: %v", i, err)
				}
			}
		})
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/egress"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

func secretEgressInput(t *testing.T) SecretEgressDecisionInput {
	t.Helper()
	raw, err := os.ReadFile("../../egressevidence/testdata/decision-v1/raw-unrewritable-outcome.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := egressevidence.ParseDecision(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := egressevidence.NewRegistry([]egressevidence.Site{{
		ID: d.SiteID, Plane: d.Plane, Transport: d.Transport, Location: d.Location, View: d.View, Boundary: d.Boundary,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return SecretEgressDecisionInput{
		Decision: d, Registry: r, PolicyHash: testRawPolicyHash,
		EventID: testSpannedEventID, Timestamp: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		ResolvedContract: resolvedContractFixture(), Principal: "fixture", Actor: "fixture-builder",
		DelegationChain: []string{"fixture-delegation"}, ChainSeq: 4, ChainPrevHash: "previous",
	}
}

func TestBuildSecretEgressDecisionReceipt(t *testing.T) {
	t.Parallel()
	in := secretEgressInput(t)
	r, err := BuildSecretEgressDecisionReceipt(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Signature != (contractreceipt.SignatureProof{}) {
		t.Fatal("builder must not sign")
	}
	if r.PayloadKind != contractreceipt.PayloadSecretEgressDecisionV1 || r.ReceiptVersion != 2 ||
		r.EventID != in.EventID || r.Timestamp != in.Timestamp || r.PolicyHash != testSpanDigest ||
		r.Principal != in.Principal || r.Actor != in.Actor || r.ChainSeq != 4 || r.ChainPrevHash != "previous" ||
		r.ContractHash != in.ResolvedContract.ContractHash || r.ActiveManifestHash != in.ResolvedContract.ActiveManifestHash ||
		r.SelectorID != in.ResolvedContract.SelectorID || r.ContractGeneration != in.ResolvedContract.ContractGeneration {
		t.Fatalf("envelope context lost: %+v", r)
	}
	var p contractreceipt.PayloadSecretEgressDecisionV1Struct
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatal(err)
	}
	wantHash, err := egress.RegistryHash(in.Registry)
	if err != nil {
		t.Fatal(err)
	}
	if p.RegistryHash != wantHash || !reflect.DeepEqual(p.Decision, in.Decision) {
		t.Fatalf("builder changed recorded facts: %+v", p)
	}
	before := string(r.Payload)
	in.Decision.RewriteFallback.PolicyRef = "caller.changed"
	in.Decision.Outcome.Release = egressevidence.ReleaseUnknown
	in.DelegationChain[0] = "changed"
	if string(r.Payload) != before || r.DelegationChain[0] != "fixture-delegation" {
		t.Fatal("builder retained mutable caller state")
	}
	r.Signature = contractreceipt.SignatureProof{
		SignerKeyID: "fixture-key", KeyPurpose: "receipt-signing", Algorithm: "ed25519", Signature: validReceiptSignaturePlaceholder,
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildSecretEgressDecisionReceiptRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*SecretEgressDecisionInput){
		"unsafe_chain_seq":        func(in *SecretEgressDecisionInput) { in.ChainSeq = 9007199254740992 },
		"empty_delegate":          func(in *SecretEgressDecisionInput) { in.DelegationChain = []string{""} },
		"registry_missing":        func(in *SecretEgressDecisionInput) { in.Registry = nil },
		"wrong_site":              func(in *SecretEgressDecisionInput) { in.Decision.View = egressevidence.ViewNormalized },
		"invalid_decision":        func(in *SecretEgressDecisionInput) { in.Decision.Version = 2 },
		"event_missing":           func(in *SecretEgressDecisionInput) { in.EventID = "" },
		"event_action_alias":      func(in *SecretEgressDecisionInput) { in.EventID = in.Decision.ActionID },
		"event_decision_alias":    func(in *SecretEgressDecisionInput) { in.EventID = in.Decision.DecisionID },
		"timestamp_missing":       func(in *SecretEgressDecisionInput) { in.Timestamp = time.Time{} },
		"chain_prev_hash_missing": func(in *SecretEgressDecisionInput) { in.ChainPrevHash = "" },
		"policy_missing":          func(in *SecretEgressDecisionInput) { in.PolicyHash = "" },
		"policy_invalid":          func(in *SecretEgressDecisionInput) { in.PolicyHash = "SHA256:invalid" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := secretEgressInput(t)
			mutate(&in)
			r, err := BuildSecretEgressDecisionReceipt(in)
			if !errors.Is(err, ErrInvalidSecretEgressInput) || !reflect.DeepEqual(r, contractreceipt.EvidenceReceipt{}) {
				t.Fatalf("invalid input returned receipt or wrong error: %+v, %v", r, err)
			}
		})
	}
}

func TestBuildSecretEgressDecisionReceiptNormalizesUTC(t *testing.T) {
	t.Parallel()
	in := secretEgressInput(t)
	in.Timestamp = time.Date(2026, 9, 30, 14, 30, 0, 123000000, time.FixedZone("fixture", 2*60*60))
	r, err := BuildSecretEgressDecisionReceipt(in)
	if err != nil {
		t.Fatal(err)
	}
	_, offset := r.Timestamp.Zone()
	if !r.Timestamp.Equal(in.Timestamp) || offset != 0 {
		t.Fatalf("timestamp was not preserved as UTC: %v", r.Timestamp)
	}
}

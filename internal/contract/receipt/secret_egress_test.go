// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

func signedSecretEgressReceipt(t *testing.T, fixture string) (receipt.EvidenceReceipt, ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join("../../egressevidence/testdata/decision-v1", fixture+".json")))
	if err != nil {
		t.Fatal(err)
	}
	d, err := egressevidence.ParseDecision(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := validReceipt()
	r.PayloadKind = receipt.PayloadSecretEgressDecisionV1
	r.ChainPrevHash = receipt.GenesisHash
	r.Timestamp = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	r.Crit = receipt.CritForPayloadKind(r.PayloadKind)
	r.Payload, err = json.Marshal(receipt.PayloadSecretEgressDecisionV1Struct{RegistryHash: validPolicyHash, Decision: d})
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("secret-egress receipt unit test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: receipt.SignerKeyID(pub), KeyPurpose: "receipt-signing", Algorithm: "ed25519",
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}
	return r, pub
}

func TestSecretEgressReceiptPreservesIndependentFacts(t *testing.T) {
	t.Parallel()
	for _, fixture := range []string{
		"intent-block", "outcome-mismatch", "raw-unrewritable-intent", "raw-unrewritable-outcome",
		"blocked-fallback-intent", "blocked-fallback-outcome", "builtin-core-authorization", "local-mcp",
	} {
		t.Run(fixture, func(t *testing.T) {
			r, pub := signedSecretEgressReceipt(t, fixture)
			if err := receipt.VerifyWithKey(r, pub, receipt.SignerKeyID(pub)); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := receipt.VerifyV2BytesWithKey(raw, pub, receipt.SignerKeyID(pub)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecretEgressReceiptJCSAndExactByteAPIsRemainDistinct(t *testing.T) {
	t.Parallel()
	r, pub := signedSecretEgressReceipt(t, "raw-unrewritable-outcome")
	tree, err := contract.ParseJSONStrict(r.Payload)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := contract.Canonicalize(tree)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reordered, r.Payload) {
		t.Fatal("test requires different typed and canonical key order")
	}
	r.Payload = reordered
	if err := receipt.VerifyWithKey(r, pub, receipt.SignerKeyID(pub)); err != nil {
		t.Fatalf("JCS-equivalent payload must verify: %v", err)
	}
	reformatted, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var decoded receipt.EvidenceReceipt
	if err := contract.DecodeStrictJSON(reformatted, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyWithKey(decoded, pub, receipt.SignerKeyID(pub)); err != nil {
		t.Fatalf("reformatted JCS-equivalent envelope must verify: %v", err)
	}
	if err := receipt.VerifyV2BytesWithKey(reformatted, pub, receipt.SignerKeyID(pub)); err == nil {
		t.Fatal("exact-byte API must reject non-emitted formatting")
	}
	compact, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyV2BytesWithKey(compact, pub, receipt.SignerKeyID(pub)); err == nil {
		t.Fatal("exact-byte API must reject non-emitted payload field order")
	}
}

func TestSecretEgressReceiptRejectsInvalidShape(t *testing.T) {
	t.Parallel()
	base, _ := signedSecretEgressReceipt(t, "intent-block")
	cases := []struct {
		name   string
		mutate func(*receipt.EvidenceReceipt)
	}{
		{"missing_chain_prev_hash", func(r *receipt.EvidenceReceipt) { r.ChainPrevHash = "" }},
		{"missing_policy", func(r *receipt.EvidenceReceipt) { r.PolicyHash = "" }},
		{"missing_crit", func(r *receipt.EvidenceReceipt) { r.Crit = []string{receipt.CritCanonicalization} }},
		{"unpaired_crit", func(r *receipt.EvidenceReceipt) { r.PayloadKind = receipt.PayloadProxyDecision }},
		{"wrong_purpose", func(r *receipt.EvidenceReceipt) { r.Signature.KeyPurpose = "contract-activation-signing" }},
		{"action_event_alias", func(r *receipt.EvidenceReceipt) { r.EventID = "01990000-0000-7000-8000-000000000001" }},
		{"decision_event_alias", func(r *receipt.EvidenceReceipt) { r.EventID = "01990000-0000-7000-8000-000000000002" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	for _, c := range []struct{ name, payload string }{
		{"empty", ""},
		{"null", "null"},
		{"null_whitespace", " null "},
		{"array", "[]"},
		{"missing", `{}`},
		{"unknown", `{"registry_hash":"` + validPolicyHash + `","decision":{},"unknown":true}`},
		{"case_wrapper", `{"Registry_Hash":"` + validPolicyHash + `","decision":{}}`},
		{"duplicate", `{"registry_hash":"` + validPolicyHash + `","registry_hash":"` + validPolicyHash + `","decision":{}}`},
		{"null_hash", `{"registry_hash":null,"decision":{}}`},
		{"numeric_hash", `{"registry_hash":1,"decision":{}}`},
		{"uppercase_hash", `{"registry_hash":"` + strings.ToUpper(validPolicyHash) + `","decision":{}}`},
		{"null_decision", `{"registry_hash":"` + validPolicyHash + `","decision":null}`},
		{"unknown_decision", strings.Replace(string(base.Payload), `"version":1`, `"version":1,"unknown":true`, 1)},
		{"case_decision", strings.Replace(string(base.Payload), `"version":1`, `"Version":1`, 1)},
		{"nested_null", strings.Replace(string(base.Payload), `"authorization":{"kind":"none"}`, `"authorization":{"kind":null}`, 1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.Payload = json.RawMessage(c.payload)
			if err := r.Validate(); err == nil {
				t.Fatal("accepted invalid payload")
			}
		})
	}
}

func TestSecretEgressReceiptSignatureBindsMetadata(t *testing.T) {
	t.Parallel()
	r, pub := signedSecretEgressReceipt(t, "intent-block")
	r.Payload = bytes.Replace(r.Payload, []byte(validPolicyHash), []byte("sha256:"+strings.Repeat("d", 64)), 1)
	if err := r.Validate(); err != nil {
		t.Fatalf("offline validator must not claim registry binding: %v", err)
	}
	if err := receipt.VerifyWithKey(r, pub, receipt.SignerKeyID(pub)); !errors.Is(err, receipt.ErrSignatureVerification) {
		t.Fatalf("changed registry commitment must break signature: %v", err)
	}
}

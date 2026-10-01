// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// Wire-shape cases use only public test metadata. Re-signing the raw object
// keeps a signature failure from standing in for the new-kind shape contract.
func addSecretEgressWireCases(t *testing.T, base receipt.EvidenceReceipt, priv ed25519.PrivateKey, add func(string, []byte, bool, string)) {
	t.Helper()
	allOptional := base
	allOptional.DelegationChain = []string{"fixture-delegator"}
	allOptional.ActiveManifestHash = secretEgressPolicyHash
	allOptional.ContractHash = secretEgressPolicyHash
	allOptional.SelectorID = "fixture-selector"
	allOptional.ContractGeneration = 9007199254740991
	allOptional.ChainSeq = 9007199254740991
	add("valid-all-envelope-optionals", signSecretEgressFixture(t, &allOptional, priv), true, "Explicit optional values and maximum safe integers")
	for _, ns := range []int{1, 100000000, 123456789} {
		r := base
		r.Timestamp = time.Date(2026, 9, 30, 12, 0, 0, ns, time.UTC)
		add("valid-timestamp-"+r.Timestamp.Format("150405.999999999"), signSecretEgressFixture(t, &r, priv), true, "Canonical UTC fractional timestamp")
	}
	raw := signSecretEgressFixture(t, &base, priv)
	var original map[string]json.RawMessage
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	mutate := func(name string, edit func(map[string]json.RawMessage)) {
		fields := make(map[string]json.RawMessage, len(original))
		for key, value := range original {
			fields[key] = value
		}
		edit(fields)
		add("invalid-wire-"+name, signSecretEgressRawFixture(t, fields, priv), false, "New-kind envelope wire shape must reject")
	}
	required := []string{"record_type", "receipt_version", "payload_kind", "canonicalization", "crit", "event_id", "timestamp", "signature", "chain_seq", "chain_prev_hash", "policy_hash", "payload"}
	for _, key := range required {
		// Missing or renamed dispatch fields remain covered by ordinary envelope
		// rejection. Signature proof shape is handled separately below.
		if key == "signature" {
			continue
		}
		mutate("missing-"+key, func(fields map[string]json.RawMessage) { delete(fields, key) })
		mutate("null-"+key, func(fields map[string]json.RawMessage) { fields[key] = json.RawMessage(`null`) })
		mutate("case-"+key, func(fields map[string]json.RawMessage) {
			fields[strings.ToUpper(key)] = fields[key]
			delete(fields, key)
		})
	}
	for _, key := range []string{"principal", "actor", "active_manifest_hash", "contract_hash", "selector_id", "contract_generation", "delegation_chain"} {
		for _, value := range []struct{ name, raw string }{{"null", `null`}, {"bool", `false`}, {"object", `{}`}, {"empty-string", `""`}} {
			mutate(key+"-"+value.name, func(fields map[string]json.RawMessage) { fields[key] = json.RawMessage(value.raw) })
		}
	}
	for _, value := range []struct{ name, raw string }{{"empty", `[]`}, {"null-entry", `[null]`}, {"empty-entry", `[""]`}, {"numeric-entry", `[1]`}} {
		mutate("delegation-"+value.name, func(fields map[string]json.RawMessage) { fields["delegation_chain"] = json.RawMessage(value.raw) })
	}
	for _, key := range []string{"chain_seq", "contract_generation"} {
		for _, value := range []struct{ name, raw string }{{"negative", `-1`}, {"unsafe", `9007199254740992`}, {"string", `"1"`}} {
			mutate(key+"-"+value.name, func(fields map[string]json.RawMessage) { fields[key] = json.RawMessage(value.raw) })
		}
	}
	mutate("zero-contract-generation", func(fields map[string]json.RawMessage) { fields["contract_generation"] = json.RawMessage(`0`) })
	mutate("unknown-envelope", func(fields map[string]json.RawMessage) { fields["unknown"] = json.RawMessage(`true`) })
	for _, value := range []struct{ name, raw string }{
		{"offset", `"2026-09-30T12:00:00+00:00"`},
		{"zero-fraction", `"2026-09-30T12:00:00.000Z"`},
		{"trailing-zero", `"2026-09-30T12:00:00.100Z"`},
		{"calendar", `"2026-02-30T12:00:00Z"`},
		{"hour", `"2026-09-30T24:00:00Z"`},
		{"zero-time", `"0001-01-01T00:00:00Z"`},
	} {
		mutate("timestamp-"+value.name, func(fields map[string]json.RawMessage) { fields["timestamp"] = json.RawMessage(value.raw) })
	}
	// Lexical changes preserve semantic integer values where possible. The
	// raw guard must reject them before a language normalizes the token.
	for _, value := range []struct{ name, old, replacement string }{
		{"uppercase-signature-hex", base.Signature.Signature, "ed25519:" + strings.ToUpper(strings.TrimPrefix(base.Signature.Signature, "ed25519:"))},
		{"leading-signature-hex-space", base.Signature.Signature, "ed25519: " + strings.TrimPrefix(base.Signature.Signature, "ed25519:")},
		{"trailing-signature-hex-space", base.Signature.Signature, base.Signature.Signature + " "},
		{"uppercase-signature-prefix", base.Signature.Signature, "ED25519:" + strings.TrimPrefix(base.Signature.Signature, "ed25519:")},
		{"short-signature-hex", base.Signature.Signature, base.Signature.Signature[:len(base.Signature.Signature)-1]},
		{"long-signature-hex", base.Signature.Signature, base.Signature.Signature + "0"},
		{"nonhex-signature", base.Signature.Signature, base.Signature.Signature[:len(base.Signature.Signature)-1] + "g"},
		{"escaped-timestamp-digit", `"timestamp":"2026-09-30T12:00:00Z"`, `"timestamp":"\u0032026-09-30T12:00:00Z"`},
		{"decimal-envelope-version", `"receipt_version":2`, `"receipt_version":2.0`},
		{"exponent-envelope-version", `"receipt_version":2`, `"receipt_version":2e0`},
		{"decimal-sequence", `"chain_seq":0`, `"chain_seq":0.0`},
		{"exponent-sequence", `"chain_seq":0`, `"chain_seq":0e0`},
		{"negative-zero-sequence", `"chain_seq":0`, `"chain_seq":-0`},
		{"case-signature-key", `"signer_key_id":`, `"Signer_Key_ID":`},
		{"null-signature-purpose", `"key_purpose":"receipt-signing"`, `"key_purpose":null`},
		{"unknown-signature", `"signer_key_id":`, `"unknown":true,"signer_key_id":`},
		{"case-canonicalization-key", `"jcs_profile":`, `"JCS_Profile":`},
		{"null-canonicalization-key", `"hash_alg":"sha256"`, `"hash_alg":null`},
		{"unknown-canonicalization", `"jcs_profile":`, `"unknown":true,"jcs_profile":`},
	} {
		add("invalid-wire-"+value.name, replaceSecretEgress(t, raw, value.old, value.replacement), false, "Raw envelope token and nested field shape must reject")
	}
}

func signSecretEgressRawFixture(t *testing.T, fields map[string]json.RawMessage, priv ed25519.PrivateKey) []byte {
	t.Helper()
	fields["signature"] = json.RawMessage(`{"signer_key_id":"","key_purpose":"","algorithm":"","signature":""}`)
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := contract.Canonicalize(tree)
	if err != nil {
		t.Fatal(err)
	}
	proof := receipt.SignatureProof{
		SignerKeyID: receipt.SignerKeyID(priv.Public().(ed25519.PublicKey)), KeyPurpose: "receipt-signing",
		Algorithm: "ed25519", Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}
	fields["signature"], err = json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

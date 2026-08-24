// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUnanchoredSuffixVerifierAcceptsTrustedContiguousSuffix(t *testing.T) {
	pub, priv := generateTestKey(t)
	chain := buildUnanchoredSuffix(t, priv, 41, "lost-predecessor-head", 3)
	v, err := NewUnanchoredSuffixVerifier(hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range chain {
		if err := v.Add(mustMarshalReceipt(t, receipt)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	got, err := v.Finish()
	if err != nil {
		t.Fatal(err)
	}
	wantHead := mustHash(t, chain[len(chain)-1])
	if got.Count != 3 || got.OriginSeq != 41 || got.OriginPrevHash != "lost-predecessor-head" || got.FinalSeq != 43 || got.Head != wantHead {
		t.Fatalf("suffix result=%+v", got)
	}
}

func TestUnanchoredSuffixVerifierAcceptsLegacyDetectedPatternsOrigin(t *testing.T) {
	raw, keyHex := legacyDetectedPatternsFixture(t)
	v, err := NewUnanchoredSuffixVerifier(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Add(raw); err != nil {
		t.Fatalf("Add legacy detected_patterns receipt: %v", err)
	}
	result, err := v.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 || result.OriginSeq != 2 || result.Head == "" {
		t.Fatalf("legacy suffix result=%+v", result)
	}
}

func TestUnanchoredSuffixVerifierRejectsBrokenSuffixes(t *testing.T) {
	pub, priv := generateTestKey(t)
	chain := buildUnanchoredSuffix(t, priv, 9, "lost-predecessor-head", 3)
	_, otherPriv := generateTestKey(t)

	splice := signChainReceipt(t, priv, 10, "other-segment-head", time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC))
	badSignature := chain[1]
	badSignature.ActionRecord.Target = "https://api.vendor.example/tampered"
	transition := chain[1]
	transition.ActionRecord.KeyTransition = &KeyTransition{PriorSignerKey: hex.EncodeToString(pub), PriorChainSeq: 9, PriorChainHash: mustHash(t, chain[0])}
	transition = resignSuffixReceipt(t, transition, priv)
	signerChange := signChainReceipt(t, otherPriv, 10, mustHash(t, chain[0]), time.Date(2026, 4, 2, 0, 0, 1, 0, time.UTC))
	maxSeq := signChainReceipt(t, priv, ^uint64(0), "lost-predecessor-head", time.Date(2026, 4, 2, 0, 0, 2, 0, time.UTC))
	wrappedSeq := signChainReceipt(t, priv, 0, mustHash(t, maxSeq), time.Date(2026, 4, 2, 0, 0, 3, 0, time.UTC))

	for _, tc := range []struct {
		name     string
		receipts []Receipt
		want     string
	}{
		{name: "deletion", receipts: []Receipt{chain[0], chain[2]}, want: "sequence break"},
		{name: "reorder", receipts: []Receipt{chain[1], chain[0]}, want: "sequence break"},
		{name: "duplicate", receipts: []Receipt{chain[0], chain[1], chain[1]}, want: "sequence break"},
		{name: "splice", receipts: []Receipt{chain[0], splice}, want: "chain_prev_hash mismatch"},
		{name: "bad signature", receipts: []Receipt{chain[0], badSignature}, want: "signature verification failed"},
		{name: "signer change", receipts: []Receipt{chain[0], signerChange}, want: "does not match expected key"},
		{name: "key transition", receipts: []Receipt{chain[0], transition}, want: "key_transition is unsupported"},
		{name: "sequence overflow", receipts: []Receipt{maxSeq, wrappedSeq}, want: "sequence overflows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewUnanchoredSuffixVerifier(hex.EncodeToString(pub))
			if err != nil {
				t.Fatal(err)
			}
			for _, receipt := range tc.receipts {
				err = v.Add(mustMarshalReceipt(t, receipt))
				if err != nil {
					break
				}
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Add error=%v, want %q", err, tc.want)
			}
			if repeatedErr := v.Add(mustMarshalReceipt(t, chain[0])); repeatedErr == nil || repeatedErr.Error() != err.Error() {
				t.Fatalf("latched Add error=%v, want %v", repeatedErr, err)
			}
			if _, finishErr := v.Finish(); finishErr == nil || finishErr.Error() != err.Error() {
				t.Fatalf("Finish error=%v, want latched %v", finishErr, err)
			}
		})
	}
}

func TestUnanchoredSuffixVerifierRejectsMissingTrustAndEmptySuffix(t *testing.T) {
	if _, err := NewUnanchoredSuffixVerifier(""); err == nil {
		t.Fatal("empty trusted key accepted")
	}
	if _, err := NewUnanchoredSuffixVerifier("not-hex"); err == nil || !strings.Contains(err.Error(), "decode trusted public key") {
		t.Fatalf("invalid hex key error=%v", err)
	}
	if _, err := NewUnanchoredSuffixVerifier("00"); err == nil || !strings.Contains(err.Error(), "invalid trusted public key length") {
		t.Fatalf("short key error=%v", err)
	}
	pub, _ := generateTestKey(t)
	v, err := NewUnanchoredSuffixVerifier(hex.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Finish(); err == nil || err.Error() != "empty unanchored receipt suffix" {
		t.Fatalf("empty Finish error=%v", err)
	}
}

func TestVerifyV1SuffixBytesWithKeyRejectsMalformedLegacyFallbacks(t *testing.T) {
	if err := verifyV1SuffixBytesWithKey([]byte("{"), strings.Repeat("00", ed25519.PublicKeySize)); err == nil || !strings.Contains(err.Error(), "decode legacy v1 suffix envelope") {
		t.Fatalf("malformed envelope error=%v", err)
	}
	if err := verifyV1SuffixBytesWithKey([]byte(`{"action_record":"not-an-object"}`), strings.Repeat("00", ed25519.PublicKeySize)); err == nil || !strings.Contains(err.Error(), "decode legacy v1 suffix action_record") {
		t.Fatalf("malformed action_record error=%v", err)
	}
	raw, keyHex := legacyDetectedPatternsFixture(t)
	unknown := mutateLegacyActionRecord(t, raw, func(action map[string]json.RawMessage) {
		action["unknown_field"] = json.RawMessage(`true`)
	})
	if err := verifyV1SuffixBytesWithKey(unknown, keyHex); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("legacy unknown-field error=%v", err)
	}
	tampered := mutateLegacyActionRecord(t, raw, func(action map[string]json.RawMessage) {
		action["target"] = json.RawMessage(`"https://api.vendor.example/tampered"`)
	})
	if err := verifyV1SuffixBytesWithKey(tampered, keyHex); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("legacy tamper error=%v", err)
	}
	duplicate := bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if err := verifyV1SuffixBytesWithKey(duplicate, keyHex); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("legacy duplicate-key error=%v", err)
	}
	alternateWhitespace := append([]byte(" "), raw...)
	if err := verifyV1SuffixBytesWithKey(alternateWhitespace, keyHex); err == nil || !strings.Contains(err.Error(), "historical emitted JSON shape") {
		t.Fatalf("legacy alternate-byte-shape error=%v", err)
	}
}

func buildUnanchoredSuffix(t *testing.T, priv ed25519.PrivateKey, originSeq uint64, originPrev string, count int) []Receipt {
	t.Helper()
	chain := make([]Receipt, 0, count)
	prev := originPrev
	base := time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)
	for i := range count {
		receipt := signChainReceipt(t, priv, originSeq+uint64(i), prev, base.Add(time.Duration(i)*time.Second))
		chain = append(chain, receipt)
		prev = mustHash(t, receipt)
	}
	return chain
}

func mustMarshalReceipt(t *testing.T, receipt Receipt) []byte {
	t.Helper()
	raw, err := Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resignSuffixReceipt(t *testing.T, receipt Receipt, priv ed25519.PrivateKey) Receipt {
	t.Helper()
	resigned, err := Sign(receipt.ActionRecord, priv)
	if err != nil {
		t.Fatal(err)
	}
	return resigned
}

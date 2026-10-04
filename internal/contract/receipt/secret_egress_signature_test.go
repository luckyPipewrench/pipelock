// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

func TestSecretEgressSignatureProfile(t *testing.T) {
	t.Parallel()
	base, pub := signedSecretEgressReceipt(t, "intent-block")
	const prefix = "ed25519:"
	hexValue := strings.TrimPrefix(base.Signature.Signature, prefix)
	upper := strings.ToUpper(hexValue)
	if upper == hexValue {
		t.Fatal("fixture must contain a hexadecimal letter to calibrate case checks")
	}
	mixed := hexValue
	for i, c := range []byte(hexValue) {
		if c >= 'a' && c <= 'f' {
			mixed = hexValue[:i] + strings.ToUpper(hexValue[i:i+1]) + hexValue[i+1:]
			break
		}
	}
	cases := []struct {
		name  string
		value string
		valid bool
	}{
		{"producer_lowercase", base.Signature.Signature, true},
		{"uppercase_hex", prefix + upper, false},
		{"mixed_case_hex", prefix + mixed, false},
		{"uppercase_prefix", "ED25519:" + hexValue, false},
		{"leading_space", " " + base.Signature.Signature, false},
		{"trailing_space", base.Signature.Signature + " ", false},
		{"leading_tab", "\t" + base.Signature.Signature, false},
		{"trailing_newline", base.Signature.Signature + "\n", false},
		{"embedded_space", prefix + hexValue[:64] + " " + hexValue[65:], false},
		{"non_ascii_hex", prefix + "ａ" + hexValue[1:], false},
		{"non_hex_ascii", prefix + "g" + hexValue[1:], false},
		{"short_hex", prefix + hexValue[:127], false},
		{"long_hex", prefix + hexValue + "0", false},
		{"missing_prefix", hexValue, false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.Signature.Signature = c.value
			if err := r.Validate(); (err == nil) != c.valid {
				t.Fatalf("typed Validate valid=%v, err=%v", c.valid, err)
			}
			if err := receipt.VerifyWithKey(r, pub, receipt.SignerKeyID(pub)); (err == nil) != c.valid {
				t.Fatalf("typed verification valid=%v, err=%v", c.valid, err)
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receipt.ParseEvidenceReceipt(raw); (err == nil) != c.valid {
				t.Fatalf("raw profile valid=%v, err=%v", c.valid, err)
			}
			if err := receipt.VerifyV2BytesWithKey(raw, pub, receipt.SignerKeyID(pub)); (err == nil) != c.valid {
				t.Fatalf("byte verification valid=%v, err=%v", c.valid, err)
			}
		})
	}
}

func TestLegacySignatureHexCasePreserved(t *testing.T) {
	t.Parallel()
	r, pub := signedReceiptWithCompactPayload(t)
	const prefix = "ed25519:"
	original := r.Signature.Signature
	r.Signature.Signature = prefix + strings.ToUpper(strings.TrimPrefix(original, prefix))
	if r.Signature.Signature == original {
		t.Fatal("fixture must distinguish lowercase and uppercase hexadecimal")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("legacy typed validation changed: %v", err)
	}
	if err := receipt.VerifyWithKey(r, pub, "receipt-key"); err != nil {
		t.Fatalf("legacy uppercase signature stopped verifying: %v", err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.ParseEvidenceReceipt(raw); err != nil {
		t.Fatalf("legacy raw parsing changed: %v", err)
	}
	if err := receipt.VerifyV2BytesWithKey(raw, pub, "receipt-key"); err != nil {
		t.Fatalf("legacy exact-byte validation changed: %v", err)
	}
}

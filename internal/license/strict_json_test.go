// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestVerifyRejectsSignedDuplicateClaims(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"id":"license-test","sub":"person@example.com","tier":"pro","tier":"free","exp":4102444800}`)
	signature := ed25519.Sign(privateKey, payload)
	wire := append(append([]byte(nil), payload...), signature...)
	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(wire)
	if _, err := Verify(token, publicKey); err == nil {
		t.Fatal("Verify accepted signed duplicate claims")
	}
}

func TestDecodeLicenseJSONRejectsNestedDuplicate(t *testing.T) {
	var out map[string]any
	if err := decodeLicenseJSON([]byte(`{"outer":{"id":"first","id":"second"}}`), &out); err == nil {
		t.Fatal("decodeLicenseJSON accepted nested duplicate member")
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/hex"
	"testing"
)

// TestSignedReceiptWithInvalidUTF8Verifies covers a receipt whose signed
// strings hold invalid UTF-8, for example raw bytes from a request target.
// json.Marshal replaces each invalid byte with U+FFFD, and a verifier that
// parses the serialized receipt re-encodes that character raw. The signing
// preimage has to use the same raw form, on every Go release, or the
// receipt can never verify.
func TestSignedReceiptWithInvalidUTF8Verifies(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	ar := validActionRecord()
	ar.Target = "https://api.vendor.example/p?q=" + string([]byte{0xff, 0xc3}) + "x"

	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	keyHex := hex.EncodeToString(pub)

	if err := VerifyV1BytesWithKey(raw, keyHex); err != nil {
		t.Fatalf("VerifyV1BytesWithKey: %v", err)
	}
	parsed, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := VerifyWithKey(parsed, keyHex); err != nil {
		t.Fatalf("VerifyWithKey after round trip: %v", err)
	}
}

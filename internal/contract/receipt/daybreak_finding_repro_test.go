// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/hex"
	"testing"

	receipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

func TestDaybreak_RelabeledSignerFailsWhenPinnedKeyBindsSignerKeyID(t *testing.T) {
	r, pub := signedReceipt(t)
	expectedSignerKeyID := hex.EncodeToString(pub)
	r.Signature.SignerKeyID = "attacker-label"
	if err := receipt.VerifyWithKey(r, pub, expectedSignerKeyID); err == nil {
		t.Fatal("pinned verify accepted a signer_key_id relabeled away from the pinned public key")
	}
}

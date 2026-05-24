// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package auditbatcher

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestSignEnvelope_VerifySignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	batch := signedTestBatch(t, "batch-sign", priv)

	err = batch.Envelope.VerifySignatures(func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{
			KeyPurpose: signing.PurposeAuditBatchSigning,
			PublicKey:  pub,
		}, nil
	})
	if err != nil {
		t.Fatalf("VerifySignatures() error = %v", err)
	}
}

func TestSignEnvelope_RejectsBadPrivateKey(t *testing.T) {
	_, err := SignEnvelope(validUnsignedEnvelope(t, "batch-bad-key", []byte("payload")), "audit-key-1", ed25519.PrivateKey("bad"))
	if err == nil {
		t.Fatal("SignEnvelope() error = nil, want error")
	}
}

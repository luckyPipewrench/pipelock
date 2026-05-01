// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"encoding/hex"
	"testing"
)

func TestSignerDirectory(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)

	dir := signer.Directory()
	if len(dir.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(dir.Keys))
	}
	key := dir.Keys[0]
	if key.KeyID != "pipelock-mediation-test" {
		t.Fatalf("keyid = %q", key.KeyID)
	}
	if key.Algorithm != "ed25519" || key.Use != "pipelock-mediation" {
		t.Fatalf("unexpected directory key metadata: %+v", key)
	}
	if key.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("public_key = %q, want %q", key.PublicKey, hex.EncodeToString(pub))
	}
}

func TestNilSignerDirectory(t *testing.T) {
	t.Parallel()

	var signer *Signer
	if dir := signer.Directory(); len(dir.Keys) != 0 {
		t.Fatalf("nil signer directory keys = %d, want 0", len(dir.Keys))
	}
}

func TestEmitterDirectory(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)
	em := NewEmitter(EmitterConfig{Signer: signer})

	if dir := em.Directory(); len(dir.Keys) != 1 {
		t.Fatalf("signed emitter directory keys = %d, want 1", len(dir.Keys))
	}

	unsigned := NewEmitter(EmitterConfig{})
	if dir := unsigned.Directory(); len(dir.Keys) != 0 {
		t.Fatalf("unsigned emitter directory keys = %d, want 0", len(dir.Keys))
	}

	var nilEmitter *Emitter
	if dir := nilEmitter.Directory(); len(dir.Keys) != 0 {
		t.Fatalf("nil emitter directory keys = %d, want 0", len(dir.Keys))
	}
}

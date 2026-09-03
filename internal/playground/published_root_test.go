// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The published root is the only identity a delegation may be signed by, and
// every shipped verifier pins the same constant. If it stopped decoding to a
// usable Ed25519 key, delegated sessions would fail closed everywhere at once.
func TestPublishedOrchestratorPublicKey(t *testing.T) {
	pub, err := PublishedOrchestratorPublicKey()
	if err != nil {
		t.Fatalf("published root does not decode: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("published root is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if hex.EncodeToString(pub) != PublishedOrchestratorPubKeyHex {
		t.Fatal("decoded root does not round-trip to the published constant")
	}
}

// A delegation verifies only under the root that signed it, and only for the
// run and session key it names. These are the checks that stop a caller from
// authorizing its own session.
func TestVerifySessionDelegation(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "verify-session-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	other, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	if err := VerifySessionDelegation(minted.PrivateKey, minted.Delegation, nonce); err != nil {
		t.Fatalf("a matching delegation was rejected: %v", err)
	}

	for _, tc := range []struct {
		name  string
		priv  ed25519.PrivateKey
		d     OrchestratorDelegation
		nonce string
	}{
		{name: "absent_nonce", priv: minted.PrivateKey, d: minted.Delegation, nonce: ""},
		{name: "wrong_nonce", priv: minted.PrivateKey, d: minted.Delegation, nonce: "another-run"},
		{name: "key_not_authorized", priv: minted.PrivateKey, d: other.Delegation, nonce: nonce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifySessionDelegation(tc.priv, tc.d, tc.nonce); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

// A tampered signature must not verify, which is the property that makes the
// root check meaningful rather than structural.
func TestVerifySessionDelegation_RejectsTamperedSignature(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "tamper-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	tampered := minted.Delegation
	sig, err := hex.DecodeString(tampered.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig[0] ^= 0xff
	tampered.Signature = hex.EncodeToString(sig)

	if err := VerifySessionDelegation(minted.PrivateKey, tampered, nonce); err == nil {
		t.Fatal("a tampered delegation signature must be refused")
	}
}

// Minting refuses claims the delegation format rejects, rather than emitting a
// signed delegation that no verifier will accept.
func TestMintSessionDelegation_RejectsInvalidClaims(t *testing.T) {
	root := testRunRoot(t)
	for _, tc := range []struct {
		name   string
		nonce  string
		digest string
	}{
		{name: "empty_image_digest", nonce: "a-run", digest: ""},
		{name: "empty_run_nonce", nonce: "", digest: testRunImageDigest},
		{name: "non_canonical_digest", nonce: "a-run", digest: "not-a-digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MintSessionDelegation(root, tc.nonce, tc.digest, time.Now().UTC(), time.Hour); err == nil {
				t.Fatal("invalid delegation claims must be refused at mint time")
			}
		})
	}
}

// The launch manifest records the delegation whichever signer is chosen, so a
// delegation supplied without its session key would produce a run claiming an
// authorization its signer never held. Both other signer branches must refuse.
func TestStartLiveRun_RefusesDelegationWithoutSessionKey(t *testing.T) {
	root := testRunRoot(t)
	const nonce = "no-session-key-nonce"

	minted, err := MintSessionDelegation(root, nonce, testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts LiveRunOpts
	}{
		{
			name: "ephemeral_signer_branch",
			opts: LiveRunOpts{Delegation: &minted.Delegation},
		},
		{
			name: "durable_key_path_branch",
			opts: LiveRunOpts{Delegation: &minted.Delegation, OrchestratorKeyPath: "/nonexistent/orchestrator.key"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.ScenarioID = LiveDemoScenarioID
			opts.RunNonce = nonce
			lr, err := StartLiveRun(t.Context(), opts)
			if err == nil {
				lr.Close()
				t.Fatal("a delegation without its session signing key must be refused")
			}
			if !strings.Contains(err.Error(), "session signing key") {
				t.Fatalf("error = %v, want it to name the missing session signing key", err)
			}
		})
	}
}

// The nonce binding is asserted here rather than in the livechat package,
// because only this package can make signature verification succeed first. If
// the nonce check regressed, this test is what would catch it.
func TestVerifySessionDelegation_NonceMismatchIsTheRefusal(t *testing.T) {
	root := testRunRoot(t)
	minted, err := MintSessionDelegation(root, "authorized-run", testRunImageDigest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}

	if err := VerifySessionDelegation(minted.PrivateKey, minted.Delegation, "authorized-run"); err != nil {
		t.Fatalf("the authorized run was rejected: %v", err)
	}

	err = VerifySessionDelegation(minted.PrivateKey, minted.Delegation, "a-different-run")
	if err == nil {
		t.Fatal("a delegation minted for another run must be refused")
	}
	if !strings.Contains(err.Error(), "run_nonce") {
		t.Fatalf("error %v must name the nonce mismatch, not some earlier check", err)
	}
}

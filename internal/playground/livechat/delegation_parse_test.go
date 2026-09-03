// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// A half-supplied delegation is a broken caller, not a permissive one. Accepting
// the key without the root-signed delegation would sign a run under a key
// nothing authorized.
func TestParseSessionDelegation_HalvesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		body createReq
	}{
		{name: "key_without_delegation", body: createReq{SessionSigningKey: "aa"}},
		{name: "delegation_without_key", body: createReq{OrchestratorDelegation: json.RawMessage("{}")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseSessionDelegation(tc.body, false); err == nil {
				t.Fatal("a half-supplied delegation must be refused")
			}
		})
	}
}

// A malformed session key is refused before it can sign anything.
func TestParseSessionDelegation_MalformedKeyRefused(t *testing.T) {
	body := createReq{
		RunNonce:               "a-run",
		SessionSigningKey:      "not-hex",
		OrchestratorDelegation: json.RawMessage("{\"format\":\"x\"}"),
	}
	if _, _, err := parseSessionDelegation(body, true); err == nil {
		t.Fatal("a malformed session signing key must be refused")
	}
}

// With delegation required, a request carrying neither half is refused rather
// than falling back to an unauthorized signer.
func TestParseSessionDelegation_RequiredRefusesEmpty(t *testing.T) {
	_, _, err := parseSessionDelegation(createReq{}, true)
	if err == nil {
		t.Fatal("required delegation must refuse an empty request")
	}
	if !strings.Contains(err.Error(), "session signing required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A delegation minted for a different run must not authorize this one. Without
// the nonce check a captured delegation could be replayed onto another session.
func TestParseSessionDelegation_RunNonceMustMatch(t *testing.T) {
	_, root, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	minted, err := playground.MintSessionDelegation(root, "minted-for-this-run", digest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	raw, err := json.Marshal(minted.Delegation)
	if err != nil {
		t.Fatalf("marshal delegation: %v", err)
	}

	// The nonce-mismatch assertion lives in the playground package, where the
	// trusted root can be set so signature verification succeeds and the nonce
	// check is the thing under test. From here every minted delegation is
	// foreign, so that assertion would pass on the root refusal instead.
	t.Run("absent_nonce_is_refused", func(t *testing.T) {
		body := createReq{
			SessionSigningKey:      hex.EncodeToString(minted.PrivateKey),
			OrchestratorDelegation: raw,
		}
		_, _, err := parseSessionDelegation(body, true)
		if err == nil {
			t.Fatal("a delegated session without a run nonce must be refused")
		}
		if !strings.Contains(err.Error(), "run nonce") {
			t.Fatalf("error %v must name the missing run nonce", err)
		}
	})

	t.Run("untrusted_root_is_refused", func(t *testing.T) {
		body := createReq{
			RunNonce:               "minted-for-this-run",
			SessionSigningKey:      hex.EncodeToString(minted.PrivateKey),
			OrchestratorDelegation: raw,
		}
		if _, _, err := parseSessionDelegation(body, true); err == nil {
			t.Fatal("a delegation signed by an untrusted root must be refused")
		}
	})
}

// A delegation that is not well-formed is refused before it can authorize a key.
func TestParseSessionDelegation_MalformedDelegationRefused(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	body := createReq{
		RunNonce:               "a-run",
		SessionSigningKey:      hex.EncodeToString(priv),
		OrchestratorDelegation: json.RawMessage("{\"format\":\"nonsense\"}"),
	}
	if _, _, err := parseSessionDelegation(body, true); err == nil {
		t.Fatal("a malformed delegation must be refused")
	}
}

// The parser must hand verification the run nonce from THIS request. If it ever
// passed the delegation's own nonce instead, the binding check would compare a
// value against itself and always succeed, so this asserts the propagation
// directly rather than through a delegation the trusted root cannot sign here.
func TestParseSessionDelegation_PassesRequestNonceToVerification(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, root, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	minted, err := playground.MintSessionDelegation(root, "delegation-own-nonce", digest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	raw, err := json.Marshal(minted.Delegation)
	if err != nil {
		t.Fatalf("marshal delegation: %v", err)
	}

	var gotNonce string
	prev := verifySessionDelegation
	verifySessionDelegation = func(_ ed25519.PrivateKey, _ playground.OrchestratorDelegation, runNonce string) error {
		gotNonce = runNonce
		return nil
	}
	t.Cleanup(func() { verifySessionDelegation = prev })

	body := createReq{
		RunNonce:               "request-nonce",
		SessionSigningKey:      hex.EncodeToString(priv),
		OrchestratorDelegation: raw,
	}
	if _, _, err := parseSessionDelegation(body, true); err != nil {
		t.Fatalf("parseSessionDelegation: %v", err)
	}
	if gotNonce != "request-nonce" {
		t.Fatalf("verification received nonce %q, want the request nonce %q", gotNonce, "request-nonce")
	}
	if gotNonce == minted.Delegation.RunNonce {
		t.Fatal("verification must not receive the delegation's own nonce")
	}
}

// A refusal from verification is surfaced, not swallowed.
func TestParseSessionDelegation_PropagatesVerificationRefusal(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, root, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	minted, err := playground.MintSessionDelegation(root, "a-run", digest, time.Now().UTC(), 0)
	if err != nil {
		t.Fatalf("MintSessionDelegation: %v", err)
	}
	raw, err := json.Marshal(minted.Delegation)
	if err != nil {
		t.Fatalf("marshal delegation: %v", err)
	}

	prev := verifySessionDelegation
	verifySessionDelegation = func(ed25519.PrivateKey, playground.OrchestratorDelegation, string) error {
		return errRefusedForTest
	}
	t.Cleanup(func() { verifySessionDelegation = prev })

	body := createReq{
		RunNonce:               "a-run",
		SessionSigningKey:      hex.EncodeToString(priv),
		OrchestratorDelegation: raw,
	}
	_, _, err = parseSessionDelegation(body, true)
	if !errors.Is(err, errRefusedForTest) {
		t.Fatalf("parse error = %v, want the verification refusal to be surfaced", err)
	}
}

var errRefusedForTest = errors.New("refused for test")

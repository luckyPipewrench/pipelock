// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"encoding/hex"
	"encoding/json"
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

	t.Run("matching_nonce_is_accepted", func(t *testing.T) {
		body := createReq{
			RunNonce:               "minted-for-this-run",
			SessionSigningKey:      hex.EncodeToString(minted.PrivateKey),
			OrchestratorDelegation: raw,
		}
		if _, _, err := parseSessionDelegation(body, true); err != nil {
			t.Fatalf("a matching delegation was rejected: %v", err)
		}
	})

	t.Run("mismatched_nonce_is_refused", func(t *testing.T) {
		body := createReq{
			RunNonce:               "some-other-run",
			SessionSigningKey:      hex.EncodeToString(minted.PrivateKey),
			OrchestratorDelegation: raw,
		}
		_, _, err := parseSessionDelegation(body, true)
		if err == nil {
			t.Fatal("a delegation minted for another run must be refused")
		}
		if !strings.Contains(err.Error(), "run_nonce") {
			t.Fatalf("error %v must name the nonce mismatch", err)
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
		SessionSigningKey:      hex.EncodeToString(priv),
		OrchestratorDelegation: json.RawMessage("{\"format\":\"nonsense\"}"),
	}
	if _, _, err := parseSessionDelegation(body, true); err == nil {
		t.Fatal("a malformed delegation must be refused")
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"encoding/json"
	"strings"
	"testing"
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

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func archiveAuthorizationFixture(t *testing.T) (ed25519.PublicKey, LaunchManifest, []byte, ReplayArchiveAuthorization) {
	t.Helper()
	pub, priv := delegationTestKey(0x61)
	d := validDelegation(pub)
	lm := LaunchManifest{RunNonce: d.RunNonce, DelegationID: d.DelegationID, ImageDigest: d.ImageDigest}
	d, err := SignOrchestratorDelegation(priv, d)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	a, err := SignReplayArchiveAuthorization(priv, lm, raw)
	if err != nil {
		t.Fatal(err)
	}
	return pub, lm, raw, a
}

func TestReplayArchiveAuthorization_SignParseVerifyAndBind(t *testing.T) {
	pub, lm, delegation, authorization := archiveAuthorizationFixture(t)
	raw, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReplayArchiveAuthorization(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReplayArchiveAuthorization(pub, parsed, lm, delegation); err != nil {
		t.Fatalf("VerifyReplayArchiveAuthorization: %v", err)
	}

	mutations := map[string]func(*ReplayArchiveAuthorization){
		"format":     func(a *ReplayArchiveAuthorization) { a.Format += "-other" },
		"root":       func(a *ReplayArchiveAuthorization) { a.RootKeyID = "sha256:" + strings.Repeat("0", 64) },
		"nonce":      func(a *ReplayArchiveAuthorization) { a.RunNonce = "other" },
		"image":      func(a *ReplayArchiveAuthorization) { a.ImageDigest = "sha256:" + strings.Repeat("0", 64) },
		"manifest":   func(a *ReplayArchiveAuthorization) { a.LaunchManifestHash = strings.Repeat("0", 64) },
		"delegation": func(a *ReplayArchiveAuthorization) { a.DelegationArtifactID = "sha256:" + strings.Repeat("0", 64) },
		"signature":  func(a *ReplayArchiveAuthorization) { a.Signature = strings.Repeat("0", 128) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			got := parsed
			mutate(&got)
			if err := VerifyReplayArchiveAuthorization(pub, got, lm, delegation); err == nil {
				t.Fatal("mutated archive authorization verified")
			}
		})
	}
	if err := VerifyReplayArchiveAuthorization(ed25519.PublicKey("short"), parsed, lm, delegation); err == nil {
		t.Fatal("short root public key verified archive authorization")
	}
}

func TestParseReplayArchiveAuthorization_StrictJSONAndClaims(t *testing.T) {
	_, _, _, authorization := archiveAuthorizationFixture(t)
	raw, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown":   []byte(strings.TrimSuffix(string(raw), "}") + `,"extra":true}`),
		"duplicate": []byte(strings.Replace(string(raw), `"format":`, `"format":"other","format":`, 1)),
		"second":    append(append([]byte{}, raw...), []byte(` {}`)...),
		"trailer":   append(append([]byte{}, raw...), []byte(` x`)...),
		"empty":     []byte(`{}`),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReplayArchiveAuthorization(input); err == nil {
				t.Fatal("invalid archive authorization parsed")
			}
		})
	}

	claimCases := map[string]func(*ReplayArchiveAuthorization){
		"root":       func(a *ReplayArchiveAuthorization) { a.RootKeyID = "bad" },
		"nonce":      func(a *ReplayArchiveAuthorization) { a.RunNonce = "bad/nonce" },
		"image":      func(a *ReplayArchiveAuthorization) { a.ImageDigest = "sha256:bad" },
		"manifest":   func(a *ReplayArchiveAuthorization) { a.LaunchManifestHash = "bad" },
		"delegation": func(a *ReplayArchiveAuthorization) { a.DelegationArtifactID = "bad" },
		"signature":  func(a *ReplayArchiveAuthorization) { a.Signature = "bad" },
	}
	for name, mutate := range claimCases {
		t.Run(name, func(t *testing.T) {
			got := authorization
			mutate(&got)
			input, marshalErr := json.Marshal(got)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, err := ParseReplayArchiveAuthorization(input); err == nil {
				t.Fatal("invalid archive authorization claim parsed")
			}
		})
	}
}

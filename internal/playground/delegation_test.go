// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func delegationTestKey(fill byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = fill
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func validDelegation(pub ed25519.PublicKey) OrchestratorDelegation {
	return OrchestratorDelegation{
		Format:           OrchestratorDelegationFormat,
		RootKeyID:        RootKeyID(pub),
		DelegationID:     strings.Repeat("a", 64),
		RunNonce:         "run-1",
		SessionPublicKey: strings.Repeat("2", 64),
		ImageDigest:      "sha256:" + strings.Repeat("3", 64),
		IssuedAtUnix:     1_800_000_010,
		NotBeforeUnix:    1_800_000_000,
		ExpiresAtUnix:    1_800_001_800,
	}
}

func delegationTestNow() time.Time {
	return time.Unix(1_800_000_020, 0).UTC()
}

func TestOrchestratorDelegationSignParseVerifyAndBind(t *testing.T) {
	rootPub, rootPriv := delegationTestKey(0x41)
	sessionPub, _ := delegationTestKey(0x42)
	d := validDelegation(rootPub)
	d.SessionPublicKey = hex.EncodeToString(sessionPub)

	signed, err := SignOrchestratorDelegation(rootPriv, d)
	if err != nil {
		t.Fatalf("SignOrchestratorDelegation: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := ParseOrchestratorDelegation(raw)
	if err != nil {
		t.Fatalf("ParseOrchestratorDelegation: %v", err)
	}
	want := DelegationExpectations{
		RunNonce:    d.RunNonce,
		ImageDigest: d.ImageDigest,
		MaxLifetime: 31 * time.Minute,
	}
	if err := verifyOrchestratorDelegationAt(rootPub, parsed, want, delegationTestNow()); err != nil {
		t.Fatalf("VerifyOrchestratorDelegation: %v", err)
	}
	lm := LaunchManifest{RunNonce: d.RunNonce, DelegationID: d.DelegationID, ImageDigest: d.ImageDigest}
	if !DelegationBindsLaunchManifest(parsed, lm) {
		t.Fatal("delegation did not bind matching manifest")
	}
	lm.ImageDigest = "sha256:" + strings.Repeat("4", 64)
	if DelegationBindsLaunchManifest(parsed, lm) {
		t.Fatal("delegation bound manifest with wrong image")
	}
	if DelegationBindsLaunchManifest(OrchestratorDelegation{}, LaunchManifest{}) {
		t.Fatal("empty delegation bound empty manifest")
	}
}

func TestOrchestratorDelegationCanonicalBytes(t *testing.T) {
	pub, _ := delegationTestKey(0x41)
	d := validDelegation(pub)
	wantJSON := `{"format":"pipelock-playground-delegation/v1","root_key_id":"` + d.RootKeyID + `","delegation_id":"` + strings.Repeat("a", 64) + `","run_nonce":"run-1","session_public_key":"` + strings.Repeat("2", 64) + `","image_digest":"sha256:` + strings.Repeat("3", 64) + `","issued_at_unix":1800000010,"not_before_unix":1800000000,"expires_at_unix":1800001800}`
	want := delegationDomainSeparator + wantJSON
	if got := string(d.SignedBytes()); got != want {
		t.Fatalf("SignedBytes changed\ngot:  %s\nwant: %s", got, want)
	}
}

func TestOrchestratorDelegationRejectsMutationAndWrongScope(t *testing.T) {
	rootPub, rootPriv := delegationTestKey(0x41)
	otherPub, _ := delegationTestKey(0x43)
	signed, err := SignOrchestratorDelegation(rootPriv, validDelegation(rootPub))
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*OrchestratorDelegation){
		"format":        func(d *OrchestratorDelegation) { d.Format += "-other" },
		"root key":      func(d *OrchestratorDelegation) { d.RootKeyID = RootKeyID(otherPub) },
		"delegation id": func(d *OrchestratorDelegation) { d.DelegationID = strings.Repeat("4", 64) },
		"run nonce":     func(d *OrchestratorDelegation) { d.RunNonce = "run-2" },
		"session key":   func(d *OrchestratorDelegation) { d.SessionPublicKey = strings.Repeat("5", 64) },
		"image":         func(d *OrchestratorDelegation) { d.ImageDigest = "sha256:" + strings.Repeat("6", 64) },
		"issued":        func(d *OrchestratorDelegation) { d.IssuedAtUnix++ },
		"not before":    func(d *OrchestratorDelegation) { d.NotBeforeUnix-- },
		"expires":       func(d *OrchestratorDelegation) { d.ExpiresAtUnix++ },
		"signature":     func(d *OrchestratorDelegation) { d.Signature = strings.Repeat("0", 128) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			got := signed
			mutate(&got)
			if err := verifyOrchestratorDelegationAt(rootPub, got, DelegationExpectations{}, delegationTestNow()); err == nil {
				t.Fatal("mutated delegation verified")
			}
		})
	}
	if err := verifyOrchestratorDelegationAt(rootPub, signed, DelegationExpectations{RunNonce: "other"}, delegationTestNow()); err == nil {
		t.Fatal("wrong expected run verified")
	}
	if err := verifyOrchestratorDelegationAt(rootPub, signed, DelegationExpectations{ImageDigest: "sha256:" + strings.Repeat("7", 64)}, delegationTestNow()); err == nil {
		t.Fatal("wrong expected image verified")
	}
}

func TestOrchestratorDelegationValidityWindow(t *testing.T) {
	pub, priv := delegationTestKey(0x41)
	signed, err := SignOrchestratorDelegation(priv, validDelegation(pub))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrchestratorDelegationAt(pub, signed, DelegationExpectations{}, time.Unix(signed.NotBeforeUnix-1, 0)); err == nil {
		t.Fatal("delegation verified before not_before")
	}
	if err := verifyOrchestratorDelegationAt(pub, signed, DelegationExpectations{}, time.Unix(signed.NotBeforeUnix, 0)); err != nil {
		t.Fatalf("delegation rejected at not_before: %v", err)
	}
	if err := verifyOrchestratorDelegationAt(pub, signed, DelegationExpectations{}, time.Unix(signed.ExpiresAtUnix-1, 0)); err != nil {
		t.Fatalf("delegation rejected before expiry: %v", err)
	}
	if err := verifyOrchestratorDelegationAt(pub, signed, DelegationExpectations{}, time.Unix(signed.ExpiresAtUnix, 0)); err == nil {
		t.Fatal("delegation verified at expiry")
	}
}

func TestParseOrchestratorDelegationStrictJSONAndClaims(t *testing.T) {
	pub, priv := delegationTestKey(0x41)
	signed, err := SignOrchestratorDelegation(priv, validDelegation(pub))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)

	cases := map[string][]byte{
		"unknown field":   []byte(strings.TrimSuffix(string(raw), "}") + `,"extra":true}`),
		"duplicate field": []byte(strings.Replace(string(raw), `"format":`, `"format":"duplicate","format":`, 1)),
		"second value":    append(append([]byte{}, raw...), []byte(` {}`)...),
		"invalid trailer": append(append([]byte{}, raw...), []byte(` x`)...),
		"uppercase id":    []byte(strings.Replace(string(raw), signed.DelegationID, strings.ToUpper(signed.DelegationID), 1)),
		"empty nonce":     []byte(strings.Replace(string(raw), `"run_nonce":"run-1"`, `"run_nonce":""`, 1)),
		"unsafe nonce":    []byte(strings.Replace(string(raw), `"run_nonce":"run-1"`, `"run_nonce":"run/../1"`, 1)),
		"missing signature": func() []byte {
			unsigned := signed
			unsigned.Signature = ""
			out, _ := json.Marshal(unsigned)
			return out
		}(),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOrchestratorDelegation(input); err == nil {
				t.Fatal("ParseOrchestratorDelegation accepted invalid input")
			}
		})
	}

	tooLong := signed
	tooLong.ExpiresAtUnix = tooLong.NotBeforeUnix + int64((2 * time.Hour).Seconds())
	tooLong.Signature = ""
	tooLong, err = SignOrchestratorDelegation(priv, tooLong)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrchestratorDelegationAt(pub, tooLong, DelegationExpectations{MaxLifetime: time.Hour}, delegationTestNow()); err == nil {
		t.Fatal("delegation exceeding caller lifetime verified")
	}
	overflow := signed
	overflow.ExpiresAtUnix = int64(^uint64(0) >> 1)
	overflow.Signature = ""
	overflow, err = SignOrchestratorDelegation(priv, overflow)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrchestratorDelegationAt(pub, overflow, DelegationExpectations{MaxLifetime: time.Hour}, delegationTestNow()); err == nil {
		t.Fatal("overflow-sized delegation lifetime verified")
	}
	zeroWindow := signed
	zeroWindow.ExpiresAtUnix = zeroWindow.IssuedAtUnix
	zeroWindow.Signature = ""
	if _, err := SignOrchestratorDelegation(priv, zeroWindow); err == nil {
		t.Fatal("zero-window delegation was signed")
	}
}

func TestOrchestratorDelegationRejectsInvalidClaimClasses(t *testing.T) {
	pub, _ := delegationTestKey(0x41)
	base := validDelegation(pub)
	cases := map[string]func(*OrchestratorDelegation){
		"root key id":  func(d *OrchestratorDelegation) { d.RootKeyID = "sha256:bad" },
		"session key":  func(d *OrchestratorDelegation) { d.SessionPublicKey = "bad" },
		"image digest": func(d *OrchestratorDelegation) { d.ImageDigest = "sha256:bad" },
		"timestamp":    func(d *OrchestratorDelegation) { d.IssuedAtUnix = 0 },
		"not before":   func(d *OrchestratorDelegation) { d.NotBeforeUnix = d.IssuedAtUnix + 1 },
		"signature":    func(d *OrchestratorDelegation) { d.Signature = "bad" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			mutate(&d)
			if err := ValidateOrchestratorDelegationClaims(d, DelegationExpectations{}); err == nil {
				t.Fatal("invalid delegation claim was accepted")
			}
		})
	}

	if got := RootKeyID(ed25519.PublicKey("short")); got != "sha256:invalid" {
		t.Fatalf("invalid root key ID = %q", got)
	}
	if _, err := SignOrchestratorDelegation(ed25519.PrivateKey("short"), base); err == nil {
		t.Fatal("invalid root private key was accepted")
	}
	if err := VerifyOrchestratorDelegation(ed25519.PublicKey("short"), base, DelegationExpectations{}); err == nil {
		t.Fatal("invalid root public key was accepted")
	}

	ceil := base
	ceil.NotBeforeUnix = 100
	ceil.IssuedAtUnix = 100
	ceil.ExpiresAtUnix = 102
	if err := ValidateOrchestratorDelegationClaims(ceil, DelegationExpectations{MaxLifetime: 1500 * time.Millisecond}); err != nil {
		t.Fatalf("subsecond max lifetime was not rounded up: %v", err)
	}
}

func TestLegacyLaunchManifestCanonicalBytesRemainStable(t *testing.T) {
	lm := LaunchManifest{
		RunNonce:              "legacy-run",
		ScenarioID:            "exfil-canary",
		CanaryID:              "canary",
		PipelockPubKey:        "pipe",
		CollectorPubKey:       "collector",
		PolicyHash:            "policy",
		CollectorConfigDigest: "collector-config",
		TargetHost:            "collector.test",
		StartedAt:             time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC),
		Contained:             true,
		AgentKind:             AgentKindModel,
	}
	want := `{"run_nonce":"legacy-run","scenario_id":"exfil-canary","canary_id":"canary","pipelock_pubkey":"pipe","collector_pubkey":"collector","policy_hash":"policy","collector_config_digest":"collector-config","target_host":"collector.test","started_at":"2026-06-16T12:00:00Z","contained":true,"agent_kind":"model"}`
	if got := string(canonicalLaunchManifestBytes(lm)); got != want {
		t.Fatalf("legacy canonical bytes changed\ngot:  %s\nwant: %s", got, want)
	}
	_, priv := delegationTestKey(0x44)
	signed := SignLaunchManifest(priv, lm)
	if !VerifyLaunchManifest(priv.Public().(ed25519.PublicKey), signed) {
		t.Fatal("legacy launch manifest signature no longer verifies")
	}
	withDelegationID := signed
	withDelegationID.DelegationID = strings.Repeat("a", 64)
	if VerifyLaunchManifest(priv.Public().(ed25519.PublicKey), withDelegationID) {
		t.Fatal("launch manifest verified after delegation_id mutation")
	}
	withImageDigest := signed
	withImageDigest.ImageDigest = "sha256:" + strings.Repeat("b", 64)
	if VerifyLaunchManifest(priv.Public().(ed25519.PublicKey), withImageDigest) {
		t.Fatal("launch manifest verified after image_digest mutation")
	}
}

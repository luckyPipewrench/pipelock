// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	testPrivA = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	testPubA  = testPrivA.Public().(ed25519.PublicKey)
	testPrivB = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	testPubB  = testPrivB.Public().(ed25519.PublicKey)
)

func testManifest() Manifest {
	return Manifest{
		Schema:             "pipelock-release-v1",
		Repo:               "github.com/luckyPipewrench/pipelock",
		Tag:                "v2.8.0",
		Commit:             strings.Repeat("a", 40),
		CreatedUTC:         time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		ChecksumFileSHA256: strings.Repeat("0", 64),
		Assets: []Asset{{
			Name:   "pipelock_2.8.0_linux_amd64.tar.gz",
			SHA256: strings.Repeat("1", 64),
			GOOS:   "linux",
			GOARCH: "amd64",
			Binary: "pipelock",
		}},
		SignerKeyID: hex.EncodeToString(testPubA),
	}
}

func mustManifestJSON(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return data
}

func TestVerifyManifestAcceptsDeclaredSigner(t *testing.T) {
	// signer_key_id names key A; signature is by key A; both keys trusted -> accepted.
	data := mustManifestJSON(t, testManifest())
	sig := []byte(SignManifest(data, testPrivA))
	keyring := hex.EncodeToString(testPubA) + ", " + hex.EncodeToString(testPubB)

	got, err := VerifyManifest(data, sig, keyring)
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if got.SignerKeyHex != hex.EncodeToString(testPubA) {
		t.Fatalf("SignerKeyHex = %q, want key A (the declared signer)", got.SignerKeyHex)
	}
	if got.Manifest.Tag != "v2.8.0" {
		t.Fatalf("manifest tag = %q", got.Manifest.Tag)
	}
}

func TestVerifyManifestRejectsSignerKeyIDMismatch(t *testing.T) {
	// signer_key_id names key A but the signature is by key B (also trusted, e.g.
	// during a keyring rotation). The verifying key must match the declared
	// signer_key_id, so this is rejected even though B is a trusted key whose
	// signature validates. Guards release custody/audit.
	data := mustManifestJSON(t, testManifest()) // signer_key_id = hex(pubA)
	sig := []byte(SignManifest(data, testPrivB))
	keyring := hex.EncodeToString(testPubA) + ", " + hex.EncodeToString(testPubB)

	if _, err := VerifyManifest(data, sig, keyring); !errors.Is(err, ErrReleaseSignature) {
		t.Fatalf("VerifyManifest mismatch error = %v, want ErrReleaseSignature", err)
	}
}

func TestVerifyManifestRejectsTrustAndSignatureFailures(t *testing.T) {
	data := mustManifestJSON(t, testManifest())
	goodSig := []byte(SignManifest(data, testPrivA))
	goodKeyring := hex.EncodeToString(testPubA)

	tests := []struct {
		name    string
		data    []byte
		sig     []byte
		keyring string
		want    error
	}{
		{
			name:    "empty keyring",
			data:    data,
			sig:     goodSig,
			keyring: "",
			want:    ErrNoReleaseKey,
		},
		{
			name:    "malformed keyring",
			data:    data,
			sig:     goodSig,
			keyring: "not-hex",
			want:    ErrReleaseTrustInput,
		},
		{
			name:    "missing signature prefix",
			data:    data,
			sig:     []byte(hex.EncodeToString(ed25519.Sign(testPrivA, append([]byte(signingDomain), data...)))),
			keyring: goodKeyring,
			want:    ErrReleaseSignature,
		},
		{
			name:    "malformed signature hex",
			data:    data,
			sig:     []byte(manifestSignaturePrefix + "zz"),
			keyring: goodKeyring,
			want:    ErrReleaseSignature,
		},
		{
			name:    "tampered manifest",
			data:    append([]byte{}, append(data, ' ')...),
			sig:     goodSig,
			keyring: goodKeyring,
			want:    ErrReleaseSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyManifest(tc.data, tc.sig, tc.keyring); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyManifest error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyManifestRejectsDuplicateKeysAfterSignaturePasses(t *testing.T) {
	data := []byte(`{"schema":"pipelock-release-v1","schema":"pipelock-release-v1"}`)
	sig := []byte(SignManifest(data, testPrivA))
	if _, err := VerifyManifest(data, sig, hex.EncodeToString(testPubA)); !errors.Is(err, ErrReleaseManifest) {
		t.Fatalf("VerifyManifest duplicate key error = %v, want ErrReleaseManifest", err)
	}
	if _, err := ParseManifest(data); !errors.Is(err, ErrReleaseManifest) {
		t.Fatalf("ParseManifest duplicate key error = %v, want ErrReleaseManifest", err)
	}
}

func TestValidateManifestRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Manifest)
	}{
		{name: "schema", edit: func(m *Manifest) { m.Schema = "v0" }},
		{name: "repo", edit: func(m *Manifest) { m.Repo = "github.com/evil/fork" }},
		{name: "tag", edit: func(m *Manifest) { m.Tag = " " }},
		{name: "commit", edit: func(m *Manifest) { m.Commit = "" }},
		{name: "signer", edit: func(m *Manifest) { m.SignerKeyID = "" }},
		{name: "checksums", edit: func(m *Manifest) { m.ChecksumFileSHA256 = "short" }},
		{name: "created", edit: func(m *Manifest) { m.CreatedUTC = "not-time" }},
		{name: "no assets", edit: func(m *Manifest) { m.Assets = nil }},
		{name: "asset name", edit: func(m *Manifest) { m.Assets[0].Name = "" }},
		{name: "asset duplicate", edit: func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[0]) }},
		{name: "asset sha", edit: func(m *Manifest) { m.Assets[0].SHA256 = "bad" }},
		{name: "asset metadata", edit: func(m *Manifest) { m.Assets[0].GOARCH = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := testManifest()
			tc.edit(&manifest)
			if err := ValidateManifest(manifest); !errors.Is(err, ErrReleaseManifest) {
				t.Fatalf("ValidateManifest error = %v, want ErrReleaseManifest", err)
			}
		})
	}
}

func TestFindAssetBindsPlatformAndDigest(t *testing.T) {
	manifest := testManifest()
	if _, err := FindAsset(manifest, manifest.Assets[0].Name, "linux", "arm64", "pipelock"); !errors.Is(err, ErrReleaseAsset) {
		t.Fatalf("FindAsset platform mismatch error = %v, want ErrReleaseAsset", err)
	}
	if _, err := FindAsset(manifest, "missing.tar.gz", "linux", "amd64", "pipelock"); !errors.Is(err, ErrReleaseAsset) {
		t.Fatalf("FindAsset missing error = %v, want ErrReleaseAsset", err)
	}
	manifest.Assets[0].SHA256 = "not-a-sha"
	if _, err := FindAsset(manifest, manifest.Assets[0].Name, "linux", "amd64", "pipelock"); !errors.Is(err, ErrReleaseAsset) {
		t.Fatalf("FindAsset invalid digest error = %v, want ErrReleaseAsset", err)
	}
}

func TestCheckKeyringPreflight(t *testing.T) {
	validKeyA := hex.EncodeToString(testPubA)
	validKeyB := hex.EncodeToString(testPubB)
	twoKeyring := validKeyA + "," + validKeyB

	tests := []struct {
		name        string
		candidate   string
		expect      string
		customBuild bool
		wantErr     error
		wantCount   int
		wantCustom  bool
	}{
		{
			name:      "empty keyring fails closed",
			candidate: "",
			wantErr:   ErrKeyringParity,
		},
		{
			name:      "whitespace-only keyring fails closed",
			candidate: "   ",
			wantErr:   ErrKeyringParity,
		},
		{
			name:        "empty keyring custom build succeeds",
			candidate:   "",
			customBuild: true,
			wantCount:   0,
			wantCustom:  true,
		},
		{
			name:      "valid single key passes",
			candidate: validKeyA,
			wantCount: 1,
		},
		{
			name:      "valid two-key keyring passes",
			candidate: twoKeyring,
			wantCount: 2,
		},
		{
			name:      "malformed keyring fails closed",
			candidate: "not-hex-at-all",
			wantErr:   ErrKeyringParity,
		},
		{
			name:      "truncated key fails closed",
			candidate: validKeyA[:32],
			wantErr:   ErrKeyringParity,
		},
		{
			name:        "malformed keyring fails even with custom build",
			candidate:   "zzzz",
			customBuild: true,
			wantErr:     ErrKeyringParity,
		},
		{
			name:      "parity match succeeds",
			candidate: validKeyA,
			expect:    validKeyA,
			wantCount: 1,
		},
		{
			name:      "parity mismatch fails closed",
			candidate: validKeyA,
			expect:    validKeyB,
			wantErr:   ErrKeyringParity,
		},
		{
			name:      "parity length mismatch fails closed",
			candidate: twoKeyring,
			expect:    validKeyA,
			wantErr:   ErrKeyringParity,
		},
		{
			name:      "malformed expected keyring fails closed",
			candidate: validKeyA,
			expect:    "bad",
			wantErr:   ErrKeyringParity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CheckKeyringPreflight(tt.candidate, tt.expect, tt.customBuild)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("got err=%v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.KeyCount != tt.wantCount {
				t.Errorf("KeyCount=%d, want %d", result.KeyCount, tt.wantCount)
			}
			if result.CustomBuild != tt.wantCustom {
				t.Errorf("CustomBuild=%v, want %v", result.CustomBuild, tt.wantCustom)
			}
		})
	}
}

func TestEmbeddedKeyringPreflight(t *testing.T) {
	// The test binary has no ldflags, so PublicKeyringHex is "".
	// Without customBuild, it must fail closed.
	_, err := EmbeddedKeyringPreflight("", false)
	if !errors.Is(err, ErrKeyringParity) {
		t.Fatalf("empty embedded keyring without customBuild: got err=%v, want ErrKeyringParity", err)
	}

	// With customBuild, empty embedded keyring is accepted.
	result, err := EmbeddedKeyringPreflight("", true)
	if err != nil {
		t.Fatalf("empty embedded keyring with customBuild: unexpected error: %v", err)
	}
	if result.KeyCount != 0 || !result.CustomBuild {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// TestCheckKeyringPreflight_CustomBuildDoesNotWaiveParity covers the
// interaction between the custom-build acknowledgement and an explicitly
// requested parity check.
//
// The acknowledgement waives the REQUIREMENT for a keyring, never a parity
// check the caller asked for. An empty candidate cannot match a non-empty
// expected keyring, so passing here would answer "yes, parity holds" to a
// question whose answer is plainly no.
func TestCheckKeyringPreflight_CustomBuildDoesNotWaiveParity(t *testing.T) {
	validKeyring := strings.Repeat("ab", 32)

	if _, err := CheckKeyringPreflight("", validKeyring, true); err == nil {
		t.Fatal("an empty candidate passed a parity check against a real expected " +
			"keyring because custom-build short-circuited first; custom-build admits " +
			"there is no keyring, it does not claim the right one is present")
	}

	// With no parity requested, the acknowledgement still works as intended.
	if _, err := CheckKeyringPreflight("", "", true); err != nil {
		t.Fatalf("custom build with no expected keyring should pass: %v", err)
	}

	// And the acknowledgement never excuses a broken keyring.
	if _, err := CheckKeyringPreflight("zzzz", "", true); err == nil {
		t.Fatal("custom build must not excuse a malformed keyring")
	}
}

// TestCheckKeyringPreflight_ReorderedKeysAreNotParity pins the order
// sensitivity the doc comment claims. Two keyrings holding the same keys in a
// different order are not the same keyring contract, and treating them as equal
// would let an RC ship a keyring whose first key differs from the final binary's.
func TestCheckKeyringPreflight_ReorderedKeysAreNotParity(t *testing.T) {
	keyA := strings.Repeat("aa", 32)
	keyB := strings.Repeat("bb", 32)

	if _, err := CheckKeyringPreflight(keyA+","+keyB, keyB+","+keyA, false); err == nil {
		t.Fatal("reordered keys were accepted as parity; the doc comment states the " +
			"comparison is order-sensitive, so this must fail")
	}
	if _, err := CheckKeyringPreflight(keyA+","+keyB, keyA+","+keyB, false); err != nil {
		t.Fatalf("identical keyrings must pass parity: %v", err)
	}
}

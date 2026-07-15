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

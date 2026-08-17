// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
)

// buildDist writes a dist directory holding one archive, its checksums file and
// a generated release.json, optionally signed, and returns the dist path and the
// signer's public key hex.
func buildDist(t *testing.T, sign bool) (string, string) {
	t.Helper()
	dist := t.TempDir()
	archiveName := "pipelock_3.9.9_linux_amd64.tar.gz"
	archive := []byte("fake archive bytes")
	if err := os.WriteFile(filepath.Join(dist, archiveName), archive, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	checksums := []byte(sha256Hex(archive) + "  " + archiveName + "\n")
	if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), checksums, 0o600); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, ed25519.SeedSize))
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := run([]string{
		"-dist", dist,
		"-tag", "v3.9.9",
		"-commit", "0123456789abcdef0123456789abcdef01234567",
		"-signer-key-id", pubHex,
	}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatalf("generate manifest: %v", err)
	}
	if sign {
		if err := run([]string{
			"-sign-only",
			"-dist", dist,
			"-private-key-hex", hex.EncodeToString(priv.Seed()),
		}, ioDiscard{}, ioDiscard{}); err != nil {
			t.Fatalf("sign manifest: %v", err)
		}
	}
	return dist, pubHex
}

// A release whose manifest was never signed is the state v3.1.0 published in.
// Absence must fail rather than read as nothing to check.
func TestRunVerifyFailsWhenSignatureIsMissing(t *testing.T) {
	dist, pubHex := buildDist(t, false)

	err := run([]string{"-verify", "-dist", dist, "-keyring-hex", pubHex}, ioDiscard{}, ioDiscard{})
	if err == nil {
		t.Fatal("verify succeeded with no release.json.sig present")
	}
	if !strings.Contains(err.Error(), releasetrust.ManifestSigFile) {
		t.Fatalf("error does not name the missing signature file: %v", err)
	}
}

func TestRunVerifyAcceptsAnOfflineSignedManifest(t *testing.T) {
	dist, pubHex := buildDist(t, true)

	var out bytes.Buffer
	if err := run([]string{"-verify", "-dist", dist, "-keyring-hex", pubHex}, &out, ioDiscard{}); err != nil {
		t.Fatalf("verify offline-signed manifest: %v", err)
	}
	if !strings.Contains(out.String(), pubHex) {
		t.Fatalf("verification output does not name the signing key: %q", out.String())
	}
}

// A manifest edited after signing still carries a well-formed signature, so
// verification has to reject it on content rather than on the signature's shape.
func TestRunVerifyRejectsATamperedManifest(t *testing.T) {
	dist, pubHex := buildDist(t, true)

	manifestPath := filepath.Join(dist, releasetrust.ManifestFile)
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- test reads release.json from its own temp dist dir
	if err != nil {
		t.Fatalf("read release.json: %v", err)
	}
	tampered := bytes.Replace(data,
		[]byte("0123456789abcdef0123456789abcdef01234567"),
		[]byte("fedcba9876543210fedcba9876543210fedcba98"), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test did not modify the manifest")
	}
	if err := os.WriteFile(manifestPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered manifest: %v", err)
	}

	if err := run([]string{"-verify", "-dist", dist, "-keyring-hex", pubHex}, ioDiscard{}, ioDiscard{}); err == nil {
		t.Fatal("verify accepted a manifest edited after signing")
	}
}

// A signature from a key outside the keyring must not verify, or the keyring
// places no constraint on who may sign a release.
func TestRunVerifyRejectsAKeyOutsideTheKeyring(t *testing.T) {
	dist, _ := buildDist(t, true)

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	otherHex := hex.EncodeToString(other.Public().(ed25519.PublicKey))

	if err := run([]string{"-verify", "-dist", dist, "-keyring-hex", otherHex}, ioDiscard{}, ioDiscard{}); err == nil {
		t.Fatal("verify accepted a signature from a key outside the keyring")
	}
}

func TestRunVerifyRequiresAKeyring(t *testing.T) {
	dist, _ := buildDist(t, true)
	t.Setenv("RELEASE_KEYRING_HEX", "")

	if err := run([]string{"-verify", "-dist", dist}, ioDiscard{}, ioDiscard{}); err == nil {
		t.Fatal("verify succeeded with no keyring configured")
	}
}

// An absent manifest must fail as loudly as an absent signature; a dist that
// never produced release.json is not a verified release.
func TestRunVerifyFailsWhenManifestIsMissing(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, ed25519.SeedSize))
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	err := run([]string{"-verify", "-dist", t.TempDir(), "-keyring-hex", pubHex}, ioDiscard{}, ioDiscard{})
	if err == nil {
		t.Fatal("verify succeeded with no release.json present")
	}
	if !strings.Contains(err.Error(), releasetrust.ManifestFile) {
		t.Fatalf("error does not name the missing manifest: %v", err)
	}
}

// Reporting a successful verification is part of the result, so a failed write
// must surface rather than leave the caller believing the check reported.
func TestRunVerifyReportsAFailedResultWrite(t *testing.T) {
	dist, pubHex := buildDist(t, true)

	if err := run([]string{"-verify", "-dist", dist, "-keyring-hex", pubHex}, failingWriter{}, ioDiscard{}); err == nil {
		t.Fatal("verify succeeded despite failing to write its result")
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
)

func TestRunGenerateUnsignedThenOfflineSign(t *testing.T) {
	dist := t.TempDir()
	archiveName := "pipelock_2.8.0_linux_amd64.tar.gz"
	archive := []byte("fake archive bytes")
	if err := os.WriteFile(filepath.Join(dist, archiveName), archive, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	checksums := []byte(sha256Hex(archive) + "  " + archiveName + "\n")
	if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), checksums, 0o600); err != nil {
		t.Fatalf("write checksums: %v", err)
	}

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7a}, ed25519.SeedSize))
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	if err := run([]string{
		"-dist", dist,
		"-tag", "v2.8.0",
		"-commit", "0123456789abcdef0123456789abcdef01234567",
		"-signer-key-id", pubHex,
	}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatalf("generate unsigned manifest: %v", err)
	}
	manifestPath := filepath.Join(dist, releasetrust.ManifestFile)
	manifestData, err := os.ReadFile(manifestPath) // #nosec G304 -- test reads release.json from its own temp dist dir
	if err != nil {
		t.Fatalf("read release.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dist, releasetrust.ManifestSigFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release.json.sig exists after CI generation, stat err=%v", err)
	}
	if _, err := releasetrust.VerifyManifest(manifestData, nil, pubHex); !errors.Is(err, releasetrust.ErrReleaseSignature) {
		t.Fatalf("VerifyManifest without sig error = %v, want ErrReleaseSignature", err)
	}

	if err := run([]string{
		"-sign-only",
		"-manifest", manifestPath,
		"-private-key-hex", hex.EncodeToString(priv.Seed()),
	}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatalf("offline sign manifest: %v", err)
	}
	sigData, err := os.ReadFile(filepath.Join(dist, releasetrust.ManifestSigFile)) // #nosec G304 -- test reads release.json.sig from its own temp dist dir
	if err != nil {
		t.Fatalf("read release.json.sig: %v", err)
	}
	if _, err := releasetrust.VerifyManifest(manifestData, sigData, pubHex); err != nil {
		t.Fatalf("VerifyManifest offline signature: %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write blocked")
}

func TestRunGenKeyWritesKeyMaterialOnlyToStdout(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-gen-key"}, &stdout, &stderr); err != nil {
		t.Fatalf("run -gen-key: %v", err)
	}
	if strings.Contains(stdout.String(), "WARNING") {
		t.Fatalf("stdout contains warning text: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "private_hex=") || strings.Contains(stderr.String(), "public_hex=") {
		t.Fatalf("stderr contains generated key material: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "WARNING: private_hex is the offline release signer") {
		t.Fatalf("stderr warning = %q", stderr.String())
	}

	seed, pubBytes := decodeGeneratedKeyOutput(t, stdout.String())
	priv := ed25519.NewKeyFromSeed(seed)
	if got := priv.Public().(ed25519.PublicKey); !bytes.Equal(got, pubBytes) {
		t.Fatalf("public_hex not derived from private seed")
	}
}

func TestRunGenKeyFailsWhenStdoutWriteFails(t *testing.T) {
	err := run([]string{"-gen-key"}, failingWriter{}, ioDiscard{})
	if err == nil {
		t.Fatal("run -gen-key with failing stdout succeeded")
	}
	if !strings.Contains(err.Error(), "write generated release keypair") {
		t.Fatalf("error = %v, want write generated release keypair", err)
	}
}

func TestGenerateReleaseKeypair(t *testing.T) {
	privHex, pubHex, err := generateReleaseKeypair()
	if err != nil {
		t.Fatalf("generateReleaseKeypair: %v", err)
	}
	seed, err := hex.DecodeString(privHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("private_hex not a %d-byte seed: err=%v len=%d", ed25519.SeedSize, err, len(seed))
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("public_hex not a %d-byte key: err=%v len=%d", ed25519.PublicKeySize, err, len(pubBytes))
	}
	// public_hex MUST be the public half derived from the private seed, or the
	// operator would put a mismatched key in RELEASE_KEYRING_HEX and -sign-only
	// would reject every manifest (main.go signer_key_id match check).
	priv := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != pubHex {
		t.Fatalf("public_hex %s not derived from private seed (want %s)", pubHex, got)
	}
	// The pair signs+verifies, so the real -sign-only ceremony will work.
	msg := []byte("release manifest")
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, ed25519.Sign(priv, msg)) {
		t.Fatal("generated keypair failed sign/verify round-trip")
	}
	// Distinct keys per call (real randomness, not a fixed/zero key).
	p2, _, err := generateReleaseKeypair()
	if err != nil {
		t.Fatalf("second generateReleaseKeypair: %v", err)
	}
	if p2 == privHex {
		t.Fatal("generateReleaseKeypair returned identical keys on two calls")
	}
}

func decodeGeneratedKeyOutput(t *testing.T, output string) ([]byte, []byte) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("-gen-key output lines = %d, want 2: %q", len(lines), output)
	}
	privHex, ok := strings.CutPrefix(lines[0], "private_hex=")
	if !ok {
		t.Fatalf("first output line = %q, want private_hex=", lines[0])
	}
	pubHex, ok := strings.CutPrefix(lines[1], "public_hex=")
	if !ok {
		t.Fatalf("second output line = %q, want public_hex=", lines[1])
	}
	seed, err := hex.DecodeString(privHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("private_hex not a %d-byte seed: err=%v len=%d", ed25519.SeedSize, err, len(seed))
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("public_hex not a %d-byte key: err=%v len=%d", ed25519.PublicKeySize, err, len(pubBytes))
	}
	return seed, pubBytes
}

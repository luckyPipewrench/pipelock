// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchors_SealMissingAnchorFails(t *testing.T) {
	e := newAnchorEnv(t)
	for _, name := range defaultAnchorFiles {
		_ = os.Remove(filepath.Join(e.ws, name))
	}
	if _, _, err := e.seal(t); err == nil {
		t.Fatal("seal must fail when an anchor file is missing")
	}
}

func TestAnchors_SigningKeyNonexistent(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := runAnchors(t, "seal", "--workspace", e.ws, "--signing-key", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("seal must fail when the signing key does not exist")
	}
}

func TestAnchors_SigningKeyIsDir(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := runAnchors(t, "seal", "--workspace", e.ws, "--signing-key", t.TempDir()); err == nil {
		t.Fatal("seal must fail when the signing key is a directory")
	}
}

func TestAnchors_BaselineMalformedJSON(t *testing.T) {
	e := newAnchorEnv(t)
	if err := os.WriteFile(filepath.Join(e.ws, defaultAnchorBaselineName), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "parse baseline") {
		t.Fatalf("err = %v, want parse error", err)
	}
}

func TestAnchors_BaselineEmptyDigests(t *testing.T) {
	e := newAnchorEnv(t)
	writeBaseline(t, e.ws, anchorBaseline{
		Version:            anchorBaselineVersion,
		DigestAlgorithm:    anchorDigestAlgorithm,
		SignatureAlgorithm: anchorSignatureAlgorithm,
		Digests:            map[string]string{},
	})
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "no anchors") {
		t.Fatalf("err = %v, want no-anchors error", err)
	}
}

// TestAnchors_VerifyUnreadableAnchor covers the read-error (not not-exist)
// branch: an anchor path that became a directory cannot be read as a file.
func TestAnchors_VerifyUnreadableAnchor(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	soul := filepath.Join(e.ws, "SOUL.md")
	if err := os.Remove(soul); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(soul, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, errOut, err := e.verify(t)
	if err == nil {
		t.Fatal("verify must fail when an anchor is unreadable")
	}
	if !strings.Contains(errOut, "error:") {
		t.Errorf("stderr = %q, want an error entry", errOut)
	}
}

func TestAnchors_HomeDirError(t *testing.T) {
	prev := userHomeDir
	userHomeDir = func() (string, error) { return "", errors.New("test: no home") }
	t.Cleanup(func() { userHomeDir = prev })

	_, priv := newKeyPairFiles(t)
	// No --workspace forces resolvePaths through userHomeDir, which errors.
	if _, _, err := runAnchors(t, "seal", "--signing-key", priv); err == nil {
		t.Fatal("seal must fail when the home directory cannot be resolved")
	}
}

func TestAnchors_SealBaselineWriteError(t *testing.T) {
	e := newAnchorEnv(t)
	badBaseline := filepath.Join(e.ws, "missing-subdir", "baseline.json")
	if _, _, err := e.seal(t, "--baseline", badBaseline); err == nil {
		t.Fatal("seal must fail when the baseline path is unwritable")
	}
}

// TestAnchors_VerifyRejectsSymlinkedAnchor covers the symlink guard: replacing
// an anchor with a symlink (e.g. to a device or a huge file) is tampering and
// must fail closed, never following the link.
func TestAnchors_VerifyRejectsSymlinkedAnchor(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	soul := filepath.Join(e.ws, "SOUL.md")
	if err := os.Remove(soul); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Symlink(filepath.Join(e.ws, "IDENTITY.md"), soul); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, errOut, err := e.verify(t)
	if err == nil {
		t.Fatal("verify must fail when an anchor is a symlink")
	}
	if !strings.Contains(errOut, "symlink") {
		t.Errorf("stderr = %q, want a symlink error", errOut)
	}
}

// TestAnchors_VerifyRejectsOversizedAnchor covers the size cap: a maliciously
// large anchor must be refused before it is read into memory.
func TestAnchors_VerifyRejectsOversizedAnchor(t *testing.T) {
	prev := maxAnchorSize
	maxAnchorSize = 8 // tiny cap so the test needs no large fixture
	t.Cleanup(func() { maxAnchorSize = prev })

	e := newAnchorEnv(t) // default anchors are ~19 bytes, above the 8-byte cap
	if _, _, err := e.seal(t); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("seal err = %v, want size-cap rejection", err)
	}
}

// newKeyPairFiles writes an Ed25519 key pair to fresh temp files and returns
// (publicPath, privatePath).
func newKeyPairFiles(t *testing.T) (string, string) {
	t.Helper()
	e := newAnchorEnv(t)
	return e.pubPath, e.privPath
}

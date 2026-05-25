// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// anchorEnv is a test fixture: a workspace seeded with the default anchor files
// and an Ed25519 key pair written outside the workspace (private key for seal,
// public key for verify).
type anchorEnv struct {
	ws       string
	privPath string
	pubPath  string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
}

func newAnchorEnv(t *testing.T) anchorEnv {
	t.Helper()
	ws := t.TempDir()
	for _, name := range defaultAnchorFiles {
		if err := os.WriteFile(filepath.Join(ws, name), []byte("content of "+name+"\n"), 0o600); err != nil {
			t.Fatalf("seed anchor %s: %v", name, err)
		}
	}
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	keyDir := t.TempDir() // keys live outside the workspace, as in production
	privPath := filepath.Join(keyDir, "anchor.key")
	if err := os.WriteFile(privPath, []byte(signing.EncodePrivateKey(priv)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	pubPath := filepath.Join(keyDir, "anchor.pub")
	if err := os.WriteFile(pubPath, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return anchorEnv{ws: ws, privPath: privPath, pubPath: pubPath, priv: priv, pub: pub}
}

// reSign recomputes the manifest signature with the fixture's private key, used
// by adversarial tests that craft a tampered-but-validly-signed baseline.
func (e anchorEnv) reSign(t *testing.T, b *anchorBaseline) {
	t.Helper()
	payload, err := canonicalManifestBytes(b.Version, b.DigestAlgorithm, b.Digests)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	b.Signature = hex.EncodeToString(ed25519.Sign(e.priv, payload))
}

func (e anchorEnv) seal(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"--workspace", e.ws, "--signing-key", e.privPath}, extra...)
	return runAnchors(t, "seal", args...)
}

func (e anchorEnv) verify(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"--workspace", e.ws, "--public-key", e.pubPath}, extra...)
	return runAnchors(t, "verify", args...)
}

// chmodForTest sets path's mode through an os.FileMode variable so gosec G302
// (which flags >0o600 literals at the os.Chmod call site) does not fire on an
// intentional loose-permission negative test.
func chmodForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// runAnchors executes `hermes anchors <sub> <args...>` and returns stdout,
// stderr, and the command error (non-nil = non-zero exit).
func runAnchors(t *testing.T, sub string, args ...string) (string, string, error) {
	t.Helper()
	c := anchorsCmd()
	c.SetArgs(append([]string{sub}, args...))
	var out, errb bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errb)
	err := c.Execute()
	return out.String(), errb.String(), err
}

func TestAnchors_SealThenVerifyOK(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.ws, defaultAnchorBaselineName)); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	out, _, err := e.verify(t)
	if err != nil {
		t.Fatalf("verify after seal should pass: %v", err)
	}
	if !strings.Contains(out, "anchor integrity OK") {
		t.Errorf("verify output = %q, want OK", out)
	}
}

func TestAnchors_VerifyDetectsTamper(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.ws, "SOUL.md"), []byte("malicious identity\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_, errOut, err := e.verify(t)
	if err == nil {
		t.Fatal("verify must fail on a tampered anchor")
	}
	if !strings.Contains(errOut, "ANCHOR INTEGRITY VIOLATION") || !strings.Contains(errOut, "altered: SOUL.md") {
		t.Errorf("stderr = %q, want violation naming SOUL.md", errOut)
	}
}

func TestAnchors_VerifyDetectsMissingAnchor(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := os.Remove(filepath.Join(e.ws, "IDENTITY.md")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	_, errOut, err := e.verify(t)
	if err == nil {
		t.Fatal("verify must fail when an anchor is missing")
	}
	if !strings.Contains(errOut, "missing: IDENTITY.md") {
		t.Errorf("stderr = %q, want missing IDENTITY.md", errOut)
	}
}

func TestAnchors_VerifyWrongKeyFails(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A different public key cannot verify the operator's signature.
	otherPub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	otherPath := filepath.Join(t.TempDir(), "other.pub")
	if err := os.WriteFile(otherPath, []byte(signing.EncodePublicKey(otherPub)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err = runAnchors(t, "verify", "--workspace", e.ws, "--public-key", otherPath)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("verify err = %v, want signature failure", err)
	}
}

func TestAnchors_VerifyMissingBaselineFailsClosed(t *testing.T) {
	e := newAnchorEnv(t)
	// No seal: baseline absent. Verify must fail, not pass.
	if _, _, err := e.verify(t); err == nil {
		t.Fatal("verify must fail closed when the baseline is absent")
	}
}

func TestAnchors_SigningKeyPermissionGate(t *testing.T) {
	e := newAnchorEnv(t)
	chmodForTest(t, e.privPath, 0o644) // world-readable private key
	_, _, err := e.seal(t)
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("seal err = %v, want permission rejection on the private key", err)
	}
}

func TestAnchors_GarbageSigningKey(t *testing.T) {
	e := newAnchorEnv(t)
	if err := os.WriteFile(e.privPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := e.seal(t); err == nil {
		t.Fatal("seal must fail on an undecodable signing key")
	}
}

func TestAnchors_KeyFlagsRequired(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := runAnchors(t, "seal", "--workspace", e.ws); err == nil ||
		!strings.Contains(err.Error(), "--signing-key is required") {
		t.Fatalf("seal err = %v, want signing-key-required", err)
	}
	if _, _, err := runAnchors(t, "verify", "--workspace", e.ws); err == nil ||
		!strings.Contains(err.Error(), "--public-key is required") {
		t.Fatalf("verify err = %v, want public-key-required", err)
	}
}

func TestAnchors_CustomAnchorSet(t *testing.T) {
	e := newAnchorEnv(t)
	if err := os.WriteFile(filepath.Join(e.ws, "CHARTER.md"), []byte("charter\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, _, err := e.seal(t, "--anchor", "CHARTER.md"); err != nil {
		t.Fatalf("seal custom: %v", err)
	}
	if _, _, err := e.verify(t, "--anchor", "CHARTER.md"); err != nil {
		t.Fatalf("verify custom: %v", err)
	}
}

func TestAnchors_VerifyJSON(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, _, err := e.verify(t, "--json")
	if err != nil {
		t.Fatalf("verify --json: %v", err)
	}
	var report anchorVerifyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parse json %q: %v", out, err)
	}
	if !report.OK || report.Checked != len(defaultAnchorFiles) {
		t.Errorf("report = %+v, want OK with %d checked", report, len(defaultAnchorFiles))
	}
}

func TestAnchors_DefaultWorkspaceFromHome(t *testing.T) {
	home := t.TempDir()
	prev := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { userHomeDir = prev })

	hermesDir := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(hermesDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range defaultAnchorFiles {
		if err := os.WriteFile(filepath.Join(hermesDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	privPath := filepath.Join(t.TempDir(), "k") // outside ~/.hermes
	if err := os.WriteFile(privPath, []byte(signing.EncodePrivateKey(priv)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// No --workspace: resolves to ~/.hermes via the stubbed userHomeDir.
	if _, _, err := runAnchors(t, "seal", "--signing-key", privPath); err != nil {
		t.Fatalf("seal default workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hermesDir, defaultAnchorBaselineName)); err != nil {
		t.Fatalf("baseline not in ~/.hermes: %v", err)
	}
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// --- atomicWrite coverage tests (61.9% -> higher) ---

func TestAtomicWrite_SuccessVerifyContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic-content.txt")
	data := []byte("precise content verification")

	if err := atomicWrite(path, data, 0o600); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestAtomicWrite_EmptyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := atomicWrite(path, []byte{}, 0o600); err != nil {
		t.Fatalf("atomicWrite empty: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
}

func TestAtomicWrite_LargeData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	// 1 MiB of data.
	data := bytes.Repeat([]byte("A"), 1<<20)

	if err := atomicWrite(path, data, 0o600); err != nil {
		t.Fatalf("atomicWrite large: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(data) {
		t.Errorf("size mismatch: got %d, want %d", len(got), len(data))
	}
}

func TestAtomicWrite_MultiplePerm(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"0600", 0o600},
		{"0644", 0o644},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "perm-test.txt")

			if err := atomicWrite(path, []byte("test"), tt.perm); err != nil {
				t.Fatalf("atomicWrite: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tt.perm {
				t.Errorf("permissions = %04o, want %04o", info.Mode().Perm(), tt.perm)
			}
		})
	}
}

func TestAtomicWrite_NoTempFileLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.txt")

	if err := atomicWrite(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Only the target file should exist; no leftover .tmp files.
	for _, e := range entries {
		if e.Name() != "clean.txt" {
			t.Errorf("unexpected file left: %s", e.Name())
		}
	}
}

// --- GenerateKeyPair coverage tests (75% -> higher) ---

func TestGenerateKeyPair_UniqueKeys(t *testing.T) {
	pub1, priv1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(pub1, pub2) {
		t.Error("two generated public keys should not be identical")
	}
	if bytes.Equal(priv1, priv2) {
		t.Error("two generated private keys should not be identical")
	}
}

func TestGenerateKeyPair_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Use the generated keys to sign and verify.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("test content"), 0o600); err != nil {
		t.Fatal(err)
	}

	sig, err := SignFile(path, priv)
	if err != nil {
		t.Fatal(err)
	}

	sigPath := path + SigExtension
	if err := SaveSignature(sig, sigPath); err != nil {
		t.Fatal(err)
	}

	if err := VerifyFile(path, sigPath, pub); err != nil {
		t.Fatalf("generated keys should produce valid signatures: %v", err)
	}
}

// --- DefaultKeystorePath coverage tests (75% -> higher) ---

func TestDefaultKeystorePath_WithXDGOverride(t *testing.T) {
	// Override HOME to a known temp dir.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	path, err := DefaultKeystorePath()
	if err != nil {
		t.Fatalf("DefaultKeystorePath: %v", err)
	}
	expected := filepath.Join(dir, DefaultPipelockDir)
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}
}

// --- generateAgent coverage tests (81.8% -> higher) ---

func TestKeystore_GenerateAgent_Success(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	pub, err := ks.GenerateAgent("test-agent")
	if err != nil {
		t.Fatalf("GenerateAgent: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	// Verify files were created.
	privPath := filepath.Join(dir, agentsSubdir, "test-agent", privateKeyFile)
	pubPath := filepath.Join(dir, agentsSubdir, "test-agent", publicKeyFile)

	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key not created: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key not created: %v", err)
	}

	// Private key should have 0600 permissions.
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestKeystore_GenerateAgent_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	if _, err := ks.GenerateAgent("existing"); err != nil {
		t.Fatal(err)
	}

	// Second call should fail.
	_, err := ks.GenerateAgent("existing")
	if err == nil {
		t.Fatal("expected error when agent already exists")
	}
}

func TestKeystore_ForceGenerateAgent(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	pub1, err := ks.GenerateAgent("force-test")
	if err != nil {
		t.Fatal(err)
	}

	// Force overwrite.
	pub2, err := ks.ForceGenerateAgent("force-test")
	if err != nil {
		t.Fatalf("ForceGenerateAgent: %v", err)
	}

	// Keys should be different (new generation).
	if bytes.Equal(pub1, pub2) {
		t.Error("force-regenerated key should differ from original")
	}
}

func TestKeystore_GenerateAgent_InvalidName(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	_, err := ks.GenerateAgent("invalid name with spaces")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestKeystore_GenerateAgent_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	_, err := ks.GenerateAgent("../escape")
	if err == nil {
		t.Fatal("expected error for path traversal agent name")
	}
}

func TestKeystore_LoadKeys_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	expectedPub, err := ks.GenerateAgent("loadtest")
	if err != nil {
		t.Fatal(err)
	}

	// Load private key.
	priv, err := ks.LoadPrivateKey("loadtest")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}

	// Load public key.
	pub, err := ks.LoadPublicKey("loadtest")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !bytes.Equal(pub, expectedPub) {
		t.Error("loaded public key doesn't match generated key")
	}
}

func TestKeystore_ResolvePublicKey_OwnKey(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	expectedPub, err := ks.GenerateAgent("resolve-own")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := ks.ResolvePublicKey("resolve-own")
	if err != nil {
		t.Fatalf("ResolvePublicKey: %v", err)
	}
	if !bytes.Equal(pub, expectedPub) {
		t.Error("resolved key should match own key")
	}
}

func TestKeystore_AgentExists(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	if ks.AgentExists("nonexistent") {
		t.Error("agent should not exist before generation")
	}

	if _, err := ks.GenerateAgent("exists-check"); err != nil {
		t.Fatal(err)
	}

	if !ks.AgentExists("exists-check") {
		t.Error("agent should exist after generation")
	}
}

func TestKeystore_ListAgents(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir)

	// Initially empty.
	agents, err := ks.ListAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents initially, got %d", len(agents))
	}

	// Generate some agents.
	for _, name := range []string{"bravo", "alpha", "charlie"} {
		if _, err := ks.GenerateAgent(name); err != nil {
			t.Fatal(err)
		}
	}

	agents, err = ks.ListAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
	}
	// Should be sorted.
	if agents[0] != "alpha" || agents[1] != "bravo" || agents[2] != "charlie" {
		t.Errorf("agents not sorted: %v", agents)
	}
}

// --- DefaultKeystorePath error-branch coverage ---

// TestDefaultKeystorePath_NoHome exercises the os.UserHomeDir error branch
// by emptying HOME. Go's os.UserHomeDir on Unix returns an error when HOME
// is unset or empty, which is exactly the production failure mode this
// branch is meant to surface.
func TestDefaultKeystorePath_NoHome(t *testing.T) {
	t.Setenv("HOME", "")

	got, err := DefaultKeystorePath()
	if err == nil {
		t.Fatalf("expected error when HOME is empty, got path=%q", got)
	}
	if got != "" {
		t.Errorf("expected empty path on error, got %q", got)
	}
}

// --- LoadPublicKey + LoadPrivateKeyFile error-branch coverage ---

// TestLoadPublicKey_EmptyInput covers the early reject branch where the
// caller supplies an empty or whitespace-only input. Without this guard,
// downstream filepath.Clean and ParsePublicKey would receive a degenerate
// value and produce a less informative error.
func TestLoadPublicKey_EmptyInput(t *testing.T) {
	for _, input := range []string{"", "   ", "\t\n"} {
		if _, err := LoadPublicKey(input); err == nil {
			t.Errorf("expected error for input %q, got nil", input)
		}
	}
}

// TestLoadPrivateKeyFile_NonexistentPath covers the filepath.EvalSymlinks
// error branch. The path is operator-supplied, so the wrap-cleanly check
// is worth pinning.
func TestLoadPrivateKeyFile_NonexistentPath(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPrivateKeyFile(filepath.Join(dir, "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for nonexistent private key path")
	}
	if !strings.Contains(err.Error(), "reading private key") {
		t.Errorf("error should wrap 'reading private key', got: %v", err)
	}
}

// --- findRootKey wrong-status branch coverage ---

// TestFindRootKey_KeyIDMatchesButStatusNotRoot exercises the inner reject
// branch where the roster body's RosterSignedBy points at a key that exists
// but is marked active (or anything other than root). Findroot must reject
// even though the key_id matches, because an attacker who manages to flip
// a runtime key's status field could otherwise hijack root-only operations.
func TestFindRootKey_KeyIDMatchesButStatusNotRoot(t *testing.T) {
	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "test-key-id",
		Keys: []contract.KeyInfo{
			{
				KeyID:        "test-key-id",
				KeyPurpose:   string(PurposeRosterRoot),
				PublicKeyHex: testRosterPubHex,
				ValidFrom:    testRosterValidFrom,
				Status:       contract.KeyStatusActive, // wrong status
			},
		},
		DataClassRoot: testRosterDataClass,
	}

	_, err := findRootKey(body)
	if err == nil {
		t.Fatal("expected error when matched key has wrong status, got nil")
	}
	if !errors.Is(err, ErrRosterRootMissing) {
		t.Errorf("expected ErrRosterRootMissing, got %v", err)
	}
}

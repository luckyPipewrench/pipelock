package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeystoreGenerateAgent(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	pub, err := ks.GenerateAgent("alice")
	if err != nil {
		t.Fatalf("GenerateAgent() error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	// Check files were created.
	dir := ks.agentDir("alice")
	if _, err := os.Stat(filepath.Join(dir, privateKeyFile)); err != nil {
		t.Errorf("private key file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, publicKeyFile)); err != nil {
		t.Errorf("public key file missing: %v", err)
	}
}

func TestKeystoreGenerateAgent_AlreadyExists(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	_, err := ks.GenerateAgent("alice")
	if err == nil {
		t.Fatal("expected error for duplicate agent")
	}
}

func TestKeystoreForceGenerateAgent(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	pub1, err := ks.GenerateAgent("alice")
	if err != nil {
		t.Fatal(err)
	}

	pub2, err := ks.ForceGenerateAgent("alice")
	if err != nil {
		t.Fatalf("ForceGenerateAgent() error: %v", err)
	}

	// Keys should be different (crypto/rand).
	if bytes.Equal(pub1, pub2) {
		t.Fatal("forced regeneration produced identical key")
	}
}

func TestKeystoreLoadKeys(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	pub, err := ks.GenerateAgent("bob")
	if err != nil {
		t.Fatal(err)
	}

	loadedPub, err := ks.LoadPublicKey("bob")
	if err != nil {
		t.Fatalf("LoadPublicKey() error: %v", err)
	}
	if !bytes.Equal(pub, loadedPub) {
		t.Fatal("loaded public key does not match generated key")
	}

	priv, err := ks.LoadPrivateKey("bob")
	if err != nil {
		t.Fatalf("LoadPrivateKey() error: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestKeystoreLoadPrivateKey_NotFound(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.LoadPrivateKey("nobody")
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestKeystoreTrustKey(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Generate a key to trust.
	if _, err := ks.GenerateAgent("remote-agent"); err != nil {
		t.Fatal(err)
	}
	pubKeyPath := ks.PublicKeyPath("remote-agent")

	// Trust it under a different name.
	if err := ks.TrustKey("remote-agent", pubKeyPath); err != nil {
		t.Fatalf("TrustKey() error: %v", err)
	}

	trusted, err := ks.LoadTrustedKey("remote-agent")
	if err != nil {
		t.Fatalf("LoadTrustedKey() error: %v", err)
	}

	original, _ := ks.LoadPublicKey("remote-agent")
	if !bytes.Equal(trusted, original) {
		t.Fatal("trusted key does not match original")
	}
}

func TestKeystoreTrustKey_InvalidFile(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Write garbage to a file.
	bad := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := ks.TrustKey("bad-agent", bad)
	if err == nil {
		t.Fatal("expected error for invalid key file")
	}
}

func TestKeystoreLoadTrustedKey_NotFound(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.LoadTrustedKey("nobody")
	if err == nil {
		t.Fatal("expected error for nonexistent trusted key")
	}
}

func TestKeystoreResolvePublicKey_OwnKey(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	pub, err := ks.GenerateAgent("self")
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := ks.ResolvePublicKey("self")
	if err != nil {
		t.Fatalf("ResolvePublicKey() error: %v", err)
	}
	if !bytes.Equal(pub, resolved) {
		t.Fatal("resolved key does not match own key")
	}
}

func TestKeystoreResolvePublicKey_TrustedKey(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	if _, err := ks.GenerateAgent("remote"); err != nil {
		t.Fatal(err)
	}
	pubPath := ks.PublicKeyPath("remote")

	// Trust the key, then remove the agent directory so only trusted remains.
	if err := ks.TrustKey("remote", pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(ks.agentDir("remote")); err != nil {
		t.Fatal(err)
	}

	_, err := ks.ResolvePublicKey("remote")
	if err != nil {
		t.Fatalf("ResolvePublicKey() should find trusted key: %v", err)
	}
}

func TestKeystoreAgentExists(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	if ks.AgentExists("ghost") {
		t.Fatal("expected false for nonexistent agent")
	}

	if _, err := ks.GenerateAgent("exists"); err != nil {
		t.Fatal(err)
	}
	if !ks.AgentExists("exists") {
		t.Fatal("expected true for existing agent")
	}
}

func TestKeystoreListAgents(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Empty at first.
	agents, err := ks.ListAgents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Fatalf("expected 0 agents, got %d", len(agents))
	}

	// Generate two agents.
	if _, err := ks.GenerateAgent("bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	agents, err = ks.ListAgents()
	if err != nil {
		t.Fatal(err)
	}

	// Should be sorted.
	if len(agents) != 2 || agents[0] != "alice" || agents[1] != "bob" {
		t.Fatalf("expected [alice bob], got %v", agents)
	}
}

func TestKeystoreListTrusted(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Empty at first.
	trusted, err := ks.ListTrusted()
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 0 {
		t.Fatalf("expected 0 trusted, got %d", len(trusted))
	}

	// Generate and trust.
	if _, err := ks.GenerateAgent("peer"); err != nil {
		t.Fatal(err)
	}
	if err := ks.TrustKey("peer", ks.PublicKeyPath("peer")); err != nil {
		t.Fatal(err)
	}

	trusted, err = ks.ListTrusted()
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || trusted[0] != "peer" {
		t.Fatalf("expected [peer], got %v", trusted)
	}
}

func TestKeystoreDirectoryPermissions(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	if _, err := ks.GenerateAgent("test"); err != nil {
		t.Fatal(err)
	}

	// Agent directory should be 0700.
	info, err := os.Stat(ks.agentDir("test"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != dirPermission {
		t.Errorf("agent dir permissions = %04o, want %04o", info.Mode().Perm(), dirPermission)
	}
}

func TestValidateAgentName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"alice", false},
		{"bob-123", false},
		{"agent.v2", false},
		{"under_score", false},
		{"", true},
		{"has spaces", true},
		{"has/slash", true},
		{"special@char", true},
		// 65-char valid name fails because SanitizeAgentName truncates to 64.
		{"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgentName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAgentName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeAgentName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"alice", "alice"},
		{"has spaces", "has_spaces"},
		{"special@char!", "special_char_"},
		// 70-char input should truncate to 64.
		{"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567890", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SanitizeAgentName(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeAgentName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestKeystoreResolvePublicKey_CorruptedKey(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Generate a valid agent, then corrupt the public key file.
	if _, err := ks.GenerateAgent("corrupt"); err != nil {
		t.Fatal(err)
	}
	pubPath := ks.PublicKeyPath("corrupt")
	if err := os.WriteFile(pubPath, []byte("garbage"), 0o600); err != nil { //nolint:gosec // test path
		t.Fatal(err)
	}

	// ResolvePublicKey should return the corruption error, not silently
	// fall through to trusted keys (which also don't exist).
	_, err := ks.ResolvePublicKey("corrupt")
	if err == nil {
		t.Fatal("expected error for corrupted key")
	}
}

func TestKeystoreLoadPrivateKey_PathTraversal(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	// Attempting to load with path traversal characters should fail validation.
	_, err := ks.LoadPrivateKey("../../etc/shadow")
	if err == nil {
		t.Fatal("expected error for path traversal agent name")
	}
}

func TestKeystoreLoadPublicKey_PathTraversal(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.LoadPublicKey("../../../tmp/evil")
	if err == nil {
		t.Fatal("expected error for path traversal agent name")
	}
}

func TestKeystoreLoadTrustedKey_PathTraversal(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.LoadTrustedKey("../../exploit")
	if err == nil {
		t.Fatal("expected error for path traversal agent name")
	}
}

func TestKeystoreGenerateAgent_InvalidName(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.GenerateAgent("bad name!")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestKeystoreForceGenerateAgent_InvalidName(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.ForceGenerateAgent("bad/name")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestKeystoreTrustKey_InvalidName(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	err := ks.TrustKey("bad name!", "/dev/null")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestKeystoreTrustKey_NonexistentFile(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	err := ks.TrustKey("agent", "/nonexistent/key.pub")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestKeystoreAgentExists_InvalidName(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	if ks.AgentExists("bad name!") {
		t.Fatal("expected false for invalid agent name")
	}
}

func TestKeystoreResolvePublicKey_InvalidName(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.ResolvePublicKey("bad name!")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestKeystoreResolvePublicKey_NotFound(t *testing.T) {
	ks := NewKeystore(t.TempDir())

	_, err := ks.ResolvePublicKey("nobody")
	if err == nil {
		t.Fatal("expected error when key not found anywhere")
	}
}

func TestKeystoreListAgents_ReadError(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Create the agents directory, then make it unreadable.
	agentsDir := filepath.Join(base, agentsSubdir)
	if err := os.MkdirAll(agentsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(agentsDir, 0o000); err != nil { //nolint:gosec // test: intentionally restricting permissions
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(agentsDir, 0o700) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := ks.ListAgents()
	if err == nil {
		t.Fatal("expected error for unreadable agents directory")
	}
}

func TestKeystoreListAgents_NonDirEntries(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Generate a real agent.
	if _, err := ks.GenerateAgent("real"); err != nil {
		t.Fatal(err)
	}

	// Create a stray file in the agents directory (non-directory entry).
	agentsDir := filepath.Join(base, agentsSubdir)
	strayFile := filepath.Join(agentsDir, "stray-file.txt")
	if err := os.WriteFile(strayFile, []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}

	agents, err := ks.ListAgents()
	if err != nil {
		t.Fatal(err)
	}
	// Only the real directory should appear, not the stray file.
	if len(agents) != 1 || agents[0] != "real" {
		t.Fatalf("expected [real], got %v", agents)
	}
}

func TestKeystoreGenerateAgent_ReadOnlyBaseDir(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Make the base directory non-writable so MkdirAll fails.
	if err := os.Chmod(base, 0o500); err != nil { //nolint:gosec // test: intentionally restricting permissions
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(base, 0o700) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := ks.GenerateAgent("alice")
	if err == nil {
		t.Fatal("expected error for read-only base directory")
	}
}

func TestKeystoreListTrusted_ReadError(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Create the trusted_keys directory, then make it unreadable.
	trustedDir := filepath.Join(base, trustedSubdir)
	if err := os.MkdirAll(trustedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(trustedDir, 0o000); err != nil { //nolint:gosec // test: intentionally restricting permissions
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(trustedDir, 0o700) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := ks.ListTrusted()
	if err == nil {
		t.Fatal("expected error for unreadable trusted directory")
	}
}

func TestKeystoreListTrusted_NonPubEntries(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Generate and trust an agent.
	if _, err := ks.GenerateAgent("peer"); err != nil {
		t.Fatal(err)
	}
	if err := ks.TrustKey("peer", ks.PublicKeyPath("peer")); err != nil {
		t.Fatal(err)
	}

	// Create a stray non-.pub file in trusted_keys.
	trustedDir := filepath.Join(base, trustedSubdir)
	strayFile := filepath.Join(trustedDir, "notes.txt")
	if err := os.WriteFile(strayFile, []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Also create a subdirectory (should be skipped).
	if err := os.MkdirAll(filepath.Join(trustedDir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	trusted, err := ks.ListTrusted()
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || trusted[0] != "peer" {
		t.Fatalf("expected [peer], got %v", trusted)
	}
}

func TestKeystoreGenerateAgent_MkdirError(t *testing.T) {
	// Make the base dir unwritable so MkdirAll fails inside generateAgent.
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) }) //nolint:gosec // restore for cleanup

	ks := NewKeystore(base)
	_, err := ks.GenerateAgent("test-agent")
	if err == nil {
		t.Fatal("expected error for unwritable base directory")
	}
	if !strings.Contains(err.Error(), "creating agent directory") {
		t.Errorf("expected 'creating agent directory' error, got: %v", err)
	}
}

func TestKeystoreForceGenerateAgent_Success(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Generate once.
	pub1, err := ks.GenerateAgent("myagent")
	if err != nil {
		t.Fatal(err)
	}

	// Force regenerate — should succeed and produce different key.
	pub2, err := ks.ForceGenerateAgent("myagent")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("expected different key after force regenerate")
	}
}

func TestKeystoreTrustKey_InvalidKey(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	// Create a file with invalid key data.
	badKey := filepath.Join(base, "bad.pub")
	if err := os.WriteFile(badKey, []byte("not a valid key"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := ks.TrustKey("badagent", badKey)
	if err == nil {
		t.Fatal("expected error for invalid key data")
	}
}

func TestKeystoreTrustKey_MissingFile(t *testing.T) {
	base := t.TempDir()
	ks := NewKeystore(base)

	err := ks.TrustKey("agent", filepath.Join(base, "nonexistent.pub"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "reading public key") {
		t.Errorf("expected 'reading public key' error, got: %v", err)
	}
}

func TestKeystoreTrustKey_ReadOnlyBase(t *testing.T) {
	// TrustKey should fail when the keystore base dir is read-only
	// (MkdirAll for trusted/ subdir fails).
	base := t.TempDir()
	ks := NewKeystore(base)

	// Generate a valid key pair and save the public key.
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "test.pub")
	if err := SavePublicKey(pub, keyPath); err != nil {
		t.Fatal(err)
	}

	// Make base dir read-only so MkdirAll("trusted/") fails.
	if err := os.Chmod(base, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) }) //nolint:gosec // restore

	err = ks.TrustKey("test-agent", keyPath)
	if err == nil {
		t.Fatal("expected error for read-only base directory")
	}
}

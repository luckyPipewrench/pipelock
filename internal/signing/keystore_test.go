package signing

import (
	"bytes"
	"os"
	"path/filepath"
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

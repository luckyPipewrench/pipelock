package signing

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRedTeam_AgentNamePathTraversal tests that ValidateAgentName rejects
// agent names that exploit path traversal via ".." components. The regex
// [^a-zA-Z0-9._-] allows dots, so ".." passes sanitization unchanged.
// This means agentDir("..") resolves to filepath.Join(baseDir, "agents", "..")
// which filepath.Clean reduces to baseDir, escaping the agents subdirectory.
func TestRedTeam_AgentNamePathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		agent   string
		wantErr bool
	}{
		{"normal name", "myagent", false},
		{"dotdot traversal", "..", true},         // GAP: currently passes validation
		{"dotdotdot", "...", true},               // three dots should also be rejected
		{"hidden file prefix", ".hidden", false}, // single dot prefix is legitimate
		{"path separator slash", "../etc", true}, // slash gets replaced with underscore by sanitizer
		{"dots in middle", "my..agent", true},    // embedded ".." component is a traversal risk
		{"dot only", ".", true},                  // current directory reference
		{"trailing dots", "agent..", true},       // trailing ".." is ambiguous
		{"leading dots", "..agent", true},        // starts with ".." prefix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgentName(tt.agent)
			if tt.wantErr && err == nil {
				t.Errorf("GAP: ValidateAgentName(%q) should reject path traversal but returned nil", tt.agent)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateAgentName(%q) unexpected error: %v", tt.agent, err)
			}
		})
	}
}

// TestRedTeam_AgentDirTraversal documents that filepath.Join resolves ".." to
// the parent directory, and verifies that ValidateAgentName prevents this from
// being exploitable. Without validation, GenerateAgent("..") would write keys
// to the keystore root instead of the agents subdirectory.
func TestRedTeam_AgentDirTraversal(t *testing.T) {
	baseDir := t.TempDir()

	// Document the dangerous filepath behavior: ".." resolves to parent.
	rawPath := filepath.Join(baseDir, agentsSubdir, "..")
	resolved := filepath.Clean(rawPath)
	if resolved == baseDir {
		t.Log("CONFIRMED: filepath.Join(baseDir, \"agents\", \"..\") resolves to baseDir")
	}

	// Verify ValidateAgentName blocks ".." before it reaches filepath.Join.
	if err := ValidateAgentName(".."); err == nil {
		t.Fatal("ValidateAgentName(\"..\") should reject path traversal")
	}

	// Verify GenerateAgent rejects ".." (end-to-end protection).
	ks := NewKeystore(baseDir)
	if _, err := ks.GenerateAgent(".."); err == nil {
		t.Error("GenerateAgent(\"..\") should fail but succeeded")
	}
}

// TestRedTeam_TrustedKeyPathTraversal verifies that ".." as a trusted key name
// would escape the trusted_keys subdirectory. trustedKeyPath("..") computes
// filepath.Join(baseDir, "trusted_keys", "...pub") which is NOT traversal,
// but trustedKeyPath with carefully crafted names could still cause confusion.
func TestRedTeam_TrustedKeyPathTraversal(t *testing.T) {
	baseDir := t.TempDir()
	ks := NewKeystore(baseDir)

	// For trusted keys, the name gets ".pub" appended, so ".." becomes "...pub"
	// which is different from the agentDir case. Still, ValidateAgentName should
	// block ".." before we ever reach trustedKeyPath.
	err := ValidateAgentName("..")
	if err == nil {
		t.Error("GAP: ValidateAgentName(\"..\") should reject dotdot but returned nil")

		// Show what would happen if it proceeds to trustedKeyPath.
		path := ks.trustedKeyPath("..")
		t.Logf("trustedKeyPath(\"..\") = %s", path)
		if !strings.Contains(path, "trusted_keys") {
			t.Error("trusted key path escaped trusted_keys directory")
		}
	}
}

// TestRedTeam_GenerateAgentTraversal verifies that GenerateAgent with ".." would
// write keys to the wrong directory. This is the end-to-end impact of the bypass.
func TestRedTeam_GenerateAgentTraversal(t *testing.T) {
	baseDir := t.TempDir()
	ks := NewKeystore(baseDir)

	_, err := ks.GenerateAgent("..")
	if err == nil {
		t.Error("GAP: GenerateAgent(\"..\") should fail but succeeded, keys written to keystore root")
	}
}

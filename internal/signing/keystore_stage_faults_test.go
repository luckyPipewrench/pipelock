// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAgent_ReportsUnstageableAgentsDirectory(t *testing.T) {
	skipIfChmodCannotDeny(t)
	ks := NewKeystore(t.TempDir())
	agents := filepath.Join(ks.baseDir, agentsSubdir)
	if err := os.MkdirAll(ks.agentDir("agent"), dirPermission); err != nil {
		t.Fatalf("creating agent dir: %v", err)
	}
	// Pre-create the lock so acquiring it does not need to create a file, then
	// remove write permission. Generation gets as far as staging and cannot
	// create the staging directory.
	lockPath := filepath.Join(agents, agentLockPrefix+"agent")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("pre-creating lock: %v", err)
	}
	if err := os.Chmod(agents, 0o500); err != nil { // #nosec G302 -- directory must stay traversable while write access is removed
		t.Fatalf("restricting agents dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(agents, 0o700) }) // #nosec G302 -- restore private directory traversal for cleanup

	_, err := ks.GenerateAgent("agent")
	if err == nil {
		t.Fatal("generation succeeded without a staging directory")
	}
	if !strings.Contains(err.Error(), "creating agent staging directory") {
		t.Errorf("error = %q, want it to name the staging directory", err)
	}
	if ks.AgentExists("agent") {
		t.Error("an identity was published despite the staging failure")
	}
}

func TestRecoverAgentTransaction_ReportsFailedRestore(t *testing.T) {
	skipIfChmodCannotDeny(t)
	base := t.TempDir()
	ks := NewKeystore(base)
	agents := filepath.Join(base, agentsSubdir)

	// Backup holds the last good pair and the active directory is absent, so
	// recovery needs to rename the backup into place. A read-only agents
	// directory makes that rename impossible, and the operator has to hear that
	// their identity was not restored.
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), pub, priv)
	if err := os.Chmod(agents, 0o500); err != nil { // #nosec G302 -- directory must stay traversable while write access is removed
		t.Fatalf("restricting agents dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(agents, 0o700) }) // #nosec G302 -- restore private directory traversal for cleanup

	err := ks.recoverAgentTransaction("agent")
	if err == nil {
		t.Fatal("recovery reported success without restoring the backup")
	}
	if !strings.Contains(err.Error(), "restoring agent backup") {
		t.Errorf("error = %q, want it to name the failed restore", err)
	}
}

func TestRejectAgentKeyPathCollisions_AcceptsCleanDirectory(t *testing.T) {
	if err := rejectAgentKeyPathCollisions(t.TempDir()); err != nil {
		t.Errorf("clean directory rejected: %v", err)
	}
}

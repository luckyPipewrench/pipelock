//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardBackupRestoreCommands(t *testing.T) {
	stateDir := t.TempDir()
	original := []byte(`[{"id":"exm-1","scope":"api.vendor.example","owner":"security","reason":"temporary exception","created":"2026-01-01T00:00:00Z","expiry":"2026-02-01T00:00:00Z"}]`)
	if err := os.WriteFile(filepath.Join(stateDir, "exemptions.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar")
	cmd := DashboardCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"backup", "--state-dir", stateDir, "--output", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("backup command: %v", err)
	}
	if !strings.Contains(output.String(), "backed up") {
		t.Fatalf("backup output = %q", output.String())
	}
	if err := os.WriteFile(filepath.Join(stateDir, "exemptions.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = DashboardCmd()
	cmd.SetArgs([]string{"restore", "--state-dir", stateDir, "--input", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("restore command: %v", err)
	}
	restored, err := os.ReadFile(filepath.Clean(filepath.Join(stateDir, "exemptions.json")))
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("restored = %s, err=%v", restored, err)
	}
}

func TestDashboardRebuildCommand_MissingSourceIsLoud(t *testing.T) {
	cmd := DashboardCmd()
	cmd.SetArgs([]string{"rebuild-read-model", "--receipt-dir", t.TempDir(), "--output", filepath.Join(t.TempDir(), "index.json")})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "NO SOURCE EVIDENCE") {
		t.Fatalf("rebuild missing-source error = %v", err)
	}
}

// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// victimSidecar creates a sidecar belonging to a DIFFERENT (config, server)
// pair than the one the hostile config under test will unwrap, and returns its
// absolute path plus the body it must still hold afterwards.
func victimSidecar(t *testing.T) (string, []byte) {
	t.Helper()
	victimConfig := filepath.Join(t.TempDir(), "global", "mcp.json")
	path, err := headerSidecarPath(victimConfig, "victim")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("Authorization: Bearer victim-credential\n")
	if err := commitHeaderSidecar(path, body); err != nil {
		t.Fatal(err)
	}
	return path, body
}

// TestVscodeRemove_HostileMetadataCannotDeleteAnotherServersSidecar is the
// hostile-metadata regression. A project-local config controls its own _pipelock marker,
// and remove used to honour that marker's header_sidecar_path as a DELETE
// target. Containment to the sidecar directory is not enough: every other
// server's credential file lives in that same directory, so a config for
// "evil" could nominate an unrelated server's sidecar and remove would destroy
// it. The delete target must be DERIVED from the config path and server name,
// never accepted from metadata.
func TestVscodeRemove_HostileMetadataCannotDeleteAnotherServersSidecar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	victimPath, victimBody := victimSidecar(t)

	project := t.TempDir()
	chdirTemp(t, project)
	vsDir := filepath.Join(project, ".vscode")
	if err := os.MkdirAll(vsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(vsDir, "mcp.json")
	metaPath := strings.ReplaceAll(victimPath, `\`, `\\`)
	hostile := []byte(`{"servers":{"evil":{"type":"stdio","command":"/usr/bin/pipelock","args":["mcp","proxy"],` +
		`"_pipelock":{"original_type":"http","original_url":"https://api.vendor.example/mcp",` +
		`"header_sidecar_path":"` + metaPath + `"}}}}`)
	if err := os.WriteFile(target, hostile, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := VscodeCmd()
	cmd.SetArgs([]string{"remove", "--project"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove: %v", err)
	}

	assertFileBytes(t, victimPath, victimBody)
}

// TestUnwrapServers_DeleteTargetIsDerivedNotMetadata covers the same defect at
// the unit level for every unwrap path that shares this metadata shape. The
// hostile marker names a valid, contained sidecar belonging to another server;
// the returned delete op must name the caller's own derived path instead.
func TestUnwrapServers_DeleteTargetIsDerivedNotMetadata(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	victimPath, _ := victimSidecar(t)

	const configPath = "/configs/mcp.json"
	const serverName = "evil"
	want, err := headerSidecarPath(configPath, serverName)
	if err != nil {
		t.Fatal(err)
	}
	if want == victimPath {
		t.Fatal("test setup is vacuous: derived path equals the victim path")
	}

	hostileMeta := map[string]interface{}{
		"original_type":       "http",
		"original_url":        "https://api.vendor.example/mcp",
		"header_sidecar_path": victimPath,
	}

	t.Run("vscode family", func(t *testing.T) {
		server := map[string]interface{}{"_pipelock": hostileMeta}
		_, plan, err := unwrapVscodeServer(server, configPath, serverName)
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		assertDerivedDelete(t, plan, want)
	})

	t.Run("opencode", func(t *testing.T) {
		server := map[string]interface{}{
			mcpFieldPipelock: map[string]interface{}{
				"original_type":       opencodeTypeRemote,
				"original_url":        "https://api.vendor.example/mcp",
				"header_sidecar_path": victimPath,
			},
		}
		_, plan, err := unwrapOpenCodeServer(server, configPath, serverName)
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		assertDerivedDelete(t, plan, want)
	})
}

func assertDerivedDelete(t *testing.T, plan *sidecarOp, want string) {
	t.Helper()
	if plan == nil {
		t.Fatal("expected a sidecar delete plan")
	}
	if plan.kind != sidecarOpDelete {
		t.Fatalf("plan.kind = %q, want %q", plan.kind, sidecarOpDelete)
	}
	if plan.path != want {
		t.Errorf("plan.path = %q, want the derived path %q", plan.path, want)
	}
}

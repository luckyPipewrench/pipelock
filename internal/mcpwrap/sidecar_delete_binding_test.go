// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"path/filepath"
	"testing"
)

// TestUnwrapServer_DeleteTargetIsDerivedNotMetadata locks in that the sidecar
// delete target comes from the caller's (config path, server name) pair rather
// than from the _pipelock marker. The marker lives in an operator-editable
// config and every server's sidecar shares one directory, so honouring a
// metadata-supplied path would let one entry nominate another server's
// credential file for deletion.
func TestUnwrapServer_DeleteTargetIsDerivedNotMetadata(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	victim, err := headerSidecarPath(filepath.Join(home, "other", "config.yaml"), "victim")
	if err != nil {
		t.Fatal(err)
	}
	if err := commitHeaderSidecar(victim, []byte("Authorization: Bearer victim\n")); err != nil {
		t.Fatal(err)
	}

	const configPath = "/cfg.yaml"
	const serverName = "evil"
	want, err := headerSidecarPath(configPath, serverName)
	if err != nil {
		t.Fatal(err)
	}
	if want == victim {
		t.Fatal("test setup is vacuous: derived path equals the victim path")
	}

	server := map[string]interface{}{
		FieldPipelock: map[string]interface{}{
			"original_type":       "http",
			"original_url":        "https://api.vendor.example/mcp",
			"header_sidecar_path": victim,
		},
	}
	_, op, err := UnwrapServer(server, configPath, serverName)
	if err != nil {
		t.Fatalf("UnwrapServer: %v", err)
	}
	if op == nil || !op.IsDelete() {
		t.Fatal("expected a sidecar delete op")
	}
	if op.path != want {
		t.Errorf("delete path = %q, want the derived path %q", op.path, want)
	}
}

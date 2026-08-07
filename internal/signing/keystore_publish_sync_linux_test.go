// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signing

import (
	"path/filepath"
	"testing"
)

func TestPublishAgentDirectory_CheckpointsParentBestEffort(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "agent")
	stage := filepath.Join(root, ".stage")
	seedAgentPair(t, target, []byte("old-public"), []byte("old-private"))
	seedAgentPair(t, stage, []byte("new-public"), []byte("new-private"))

	var checkpoints []string
	if err := publishAgentDirectoryWithSync(target, stage, filepath.Join(root, ".backup"), func(path string) {
		checkpoints = append(checkpoints, path)
	}); err != nil {
		t.Fatalf("publishAgentDirectoryWithSync: %v", err)
	}
	if len(checkpoints) != 1 || checkpoints[0] != root {
		t.Errorf("directory checkpoints = %q, want one checkpoint for %q", checkpoints, root)
	}
}

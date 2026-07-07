// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderRetentionIgnoresAnchorState(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{Enabled: true, Dir: dir, RetentionDays: 1}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	marker := filepath.Join(dir, "anchor-state.json")
	if err := os.WriteFile(marker, []byte(`{"schema":"pipelock.anchorstate.v1"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if _, err := r.ExpireOldFiles(); err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("anchor-state marker was removed: %v", err)
	}
}

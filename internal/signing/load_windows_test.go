// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package signing

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsLoadPrivateKeyFileIgnoresMode is the issue #695 regression guard
// on native Windows. Go derives FileInfo.Mode() from the read-only attribute,
// never the NTFS ACL, so it reports 0666/0444 and the Unix 0o037 gate could
// never pass — the recorder signing key failed to load. With secperm skipping
// the mode check on Windows, the key must load regardless of reported mode.
func TestWindowsLoadPrivateKeyFileIgnoresMode(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	path := filepath.Join(t.TempDir(), "recorder.key")
	if err := SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	// chmod is largely a no-op on Windows (only toggles the read-only bit), but
	// document the intent: even an explicitly loosened mode must still load.
	_ = os.Chmod(path, 0o666)

	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile on Windows must succeed regardless of reported mode: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("loaded key does not match saved key")
	}
}

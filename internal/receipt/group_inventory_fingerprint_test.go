// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestFingerprintDirectoryRejectsReplacementOfOpenedDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "evidence")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "first"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, count, err := fingerprintDirectory(dir); err != nil || count != 1 {
		t.Fatalf("stable directory fingerprint: count=%d err=%v", count, err)
	}
	opened, err := recorder.OpenEvidenceDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	if err := os.Rename(dir, filepath.Join(parent, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "first"), []byte(strings.Repeat("x", 16)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fingerprintOpenedDirectory(dir, opened); err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("replaced directory mixed names and metadata: %v", err)
	}
}

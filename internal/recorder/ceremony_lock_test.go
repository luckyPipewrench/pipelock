// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
)

func TestEvidenceCeremonyLockRequiresStoppedRecorder(t *testing.T) {
	if !supportsEvidenceCeremonyLock() {
		t.Skip("platform does not provide cross-process ceremony locking")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := AcquireEvidenceCeremonyLock(dir); err == nil ||
		!strings.Contains(err.Error(), "requires a stopped recorder") {
		t.Fatalf("active-recorder lock error = %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lock, err := AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		t.Fatalf("stopped-recorder lock rejected: %v", err)
	}
	if _, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, key); err == nil || !strings.Contains(err.Error(), "locking recorder against receipt ceremonies") {
		t.Fatalf("recorder start during ceremony error = %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("release ceremony lock: %v", err)
	}
	rec, err = New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, key)
	if err != nil {
		t.Fatalf("recorder did not start after ceremony release: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close after ceremony release: %v", err)
	}
}

func TestRecorderRefreshesCeremonyLockAfterDirectoryReplacement(t *testing.T) {
	if !supportsEvidenceCeremonyLock() {
		t.Skip("platform does not provide cross-process ceremony locking")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ceremony, err := AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		t.Fatalf("lock recreated directory: %v", err)
	}
	if err := rec.ensureFile("proxy", 0); err == nil ||
		!strings.Contains(err.Error(), "refreshing recorder receipt ceremony lock") {
		t.Fatalf("ensureFile during ceremony error = %v", err)
	}
	if err := ceremony.Close(); err != nil {
		t.Fatalf("release ceremony: %v", err)
	}
	if err := rec.ensureFile("proxy", 0); err != nil {
		t.Fatalf("ensureFile after ceremony release: %v", err)
	}
	if _, err := AcquireEvidenceCeremonyLock(dir); err == nil ||
		!strings.Contains(err.Error(), "requires a stopped recorder") {
		t.Fatalf("refreshed recorder lock error = %v", err)
	}
}

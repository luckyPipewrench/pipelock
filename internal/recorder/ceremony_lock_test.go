// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
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

func TestEvidenceCeremonyLockErrorAndEmptyLifecyclePaths(t *testing.T) {
	if !supportsEvidenceCeremonyLock() {
		t.Skip("platform does not provide cross-process ceremony locking")
	}
	var nilLock *EvidenceCeremonyLock
	if err := nilLock.Close(); err != nil {
		t.Fatalf("nil lock close: %v", err)
	}
	missingDir := filepath.Join(t.TempDir(), "missing")
	if _, err := AcquireEvidenceCeremonyLock(missingDir); err == nil ||
		!strings.Contains(err.Error(), "opening receipt ceremony lock") {
		t.Fatalf("missing-dir ceremony error = %v", err)
	}
	if _, err := acquireEvidenceWriterCeremonyLock(missingDir); err == nil ||
		!strings.Contains(err.Error(), "opening receipt ceremony lock") {
		t.Fatalf("missing-dir writer error = %v", err)
	}
	originalTryLock := tryAcquireEvidenceCeremonyLock
	tryAcquireEvidenceCeremonyLock = func(*os.File) (bool, error) {
		return false, errors.New("injected lock failure")
	}
	t.Cleanup(func() { tryAcquireEvidenceCeremonyLock = originalTryLock })
	if _, err := AcquireEvidenceCeremonyLock(t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "injected lock failure") {
		t.Fatalf("injected ceremony-lock error = %v", err)
	}
	tryAcquireEvidenceCeremonyLock = originalTryLock

	dir := t.TempDir()
	rec := &Recorder{cfg: Config{Dir: dir}}
	if err := rec.releaseEvidenceWriterCeremonyLock(); err != nil {
		t.Fatalf("release absent writer lock: %v", err)
	}
	if err := rec.ensureEvidenceWriterCeremonyLock(); err != nil {
		t.Fatalf("acquire missing writer lock: %v", err)
	}
	if err := rec.releaseEvidenceWriterCeremonyLock(); err != nil {
		t.Fatalf("release acquired writer lock: %v", err)
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

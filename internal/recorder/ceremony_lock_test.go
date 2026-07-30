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
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := AcquireEvidenceCeremonyLock(notDir); err == nil ||
		!strings.Contains(err.Error(), "not an evidence directory") {
		t.Fatalf("non-directory ceremony error = %v", err)
	}
	if _, _, err := acquireEvidenceWriterCeremonyLock(notDir); err == nil ||
		!strings.Contains(err.Error(), "not an evidence directory") {
		t.Fatalf("non-directory writer error = %v", err)
	}

	missingDir := filepath.Join(t.TempDir(), "missing")
	if _, err := AcquireEvidenceCeremonyLock(missingDir); err == nil ||
		!strings.Contains(err.Error(), "opening evidence directory for receipt ceremony lock") {
		t.Fatalf("missing-dir ceremony error = %v", err)
	}
	if _, _, err := acquireEvidenceWriterCeremonyLock(missingDir); err == nil ||
		!strings.Contains(err.Error(), "opening evidence directory for receipt ceremony lock") {
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
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat evidence directory: %v", err)
	}
	if err := rec.ensureEvidenceWriterCeremonyLock(dirInfo); err != nil {
		t.Fatalf("acquire missing writer lock: %v", err)
	}
	if err := rec.releaseEvidenceWriterCeremonyLock(); err != nil {
		t.Fatalf("release acquired writer lock: %v", err)
	}
}

func TestRecorderReopensEvidenceFileAfterAtomicDirectoryReplacement(t *testing.T) {
	if !supportsEvidenceCeremonyLock() {
		t.Skip("platform does not provide cross-process ceremony locking")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "evidence")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("Mkdir evidence: %v", err)
	}
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	if err := rec.Record(Entry{SessionID: "proxy", Type: "test"}); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	oldFileInfo, err := rec.file.Stat()
	if err != nil {
		t.Fatalf("stat original evidence file: %v", err)
	}

	replacement := filepath.Join(parent, "replacement")
	if err := os.Mkdir(replacement, 0o750); err != nil {
		t.Fatalf("Mkdir replacement: %v", err)
	}
	displaced := filepath.Join(parent, "displaced")
	if err := os.Rename(dir, displaced); err != nil {
		t.Fatalf("rename original evidence directory: %v", err)
	}
	if err := os.Rename(replacement, dir); err != nil {
		t.Fatalf("install replacement evidence directory: %v", err)
	}

	if err := rec.Record(Entry{SessionID: "proxy", Type: "test"}); err != nil {
		t.Fatalf("Record after directory replacement: %v", err)
	}
	newFileInfo, err := rec.file.Stat()
	if err != nil {
		t.Fatalf("stat replacement evidence file: %v", err)
	}
	if os.SameFile(oldFileInfo, newFileInfo) {
		t.Fatal("recorder kept writing through the displaced evidence file")
	}
	visibleFileInfo, err := os.Stat(rec.file.Name())
	if err != nil {
		t.Fatalf("stat visible replacement evidence file: %v", err)
	}
	if !os.SameFile(newFileInfo, visibleFileInfo) {
		t.Fatal("recorder reopened a file that is not visible in the replacement directory")
	}
	entries, err := ReadEntries(rec.file.Name())
	if err != nil {
		t.Fatalf("read replacement evidence file: %v", err)
	}
	if len(entries) != 1 || entries[0].Sequence != 1 {
		t.Fatalf("replacement entries = %+v, want only sequence 1", entries)
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

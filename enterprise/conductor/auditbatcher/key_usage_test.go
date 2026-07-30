//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestQueueKeyMaintenanceLifecycleAcrossRecordStates(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	keyringPath := filepath.Join(root, "secrets", "keyring.json")
	backupPath := filepath.Join(root, "backups", "keyring.json")
	if _, err := InspectQueueKeys(queueDir, 0, nil); err == nil {
		t.Fatal("InspectQueueKeys(nil keyring) error = nil")
	}

	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(backupPath); err != nil {
		t.Fatal(err)
	}
	oldID := keyring.ActiveKeyID()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-dead", priv)); err != nil {
		t.Fatal(err)
	}
	deadLease, err := q.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Drop(deadLease.ID, "maintenance-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-inflight", priv)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Claim(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "batch-pending", priv)); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	legacyName := "00000000000000000004-batch-legacy-0000000000000000.json"
	legacyPath := filepath.Join(queueDir, "pending", legacyName)
	if err := writeDiskRecord(legacyPath, validDiskRecord(signedTestBatch(t, "batch-legacy-maintenance", priv))); err != nil {
		t.Fatal(err)
	}

	usage, err := InspectQueueKeys(queueDir, 0, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if usage[oldID] != 3 || usage[LegacyKeyID] != 1 {
		t.Fatalf("initial key usage = %#v, want active=3 legacy=1", usage)
	}

	rotatedOldID, newID, err := RotateQueueKeyring(queueDir, keyringPath, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedOldID != oldID || newID == oldID {
		t.Fatalf("rotation IDs old=%q new=%q, want old=%q and distinct new", rotatedOldID, newID, oldID)
	}
	for _, path := range []string{backupPath, backupPath + ".previous"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("rotation backup %s: %v", path, err)
		}
	}

	rotated, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	usage, err = InspectQueueKeys(queueDir, 0, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if usage[newID] != 4 || usage[oldID] != 0 || usage[LegacyKeyID] != 0 {
		t.Fatalf("rotated key usage = %#v, want new active=4", usage)
	}
	migratedID, err := MigrateQueueKeyring(queueDir, keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if migratedID != newID {
		t.Fatalf("MigrateQueueKeyring active = %q, want %q", migratedID, newID)
	}
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, newID); err == nil {
		t.Fatal("RevokeQueueKeyringKey(active) error = nil")
	}
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, oldID); err != nil {
		t.Fatal(err)
	}
	revoked, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(revoked.KeyIDs(), oldID) {
		t.Fatalf("revoked key %q remains before recovery", oldID)
	}

	recoveredID, err := RecoverQueueKeyring(queueDir, keyringPath, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredID != newID {
		t.Fatalf("RecoverQueueKeyring active = %q, want %q", recoveredID, newID)
	}
	recovered, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(recovered.KeyIDs(), oldID) {
		t.Fatalf("recovery did not intentionally reinstate backup key %q", oldID)
	}
	preRecover, err := LoadKeyring(keyringPath + ".pre-recover")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(preRecover.KeyIDs(), oldID) {
		t.Fatalf("pre-recover snapshot unexpectedly contains revoked key %q", oldID)
	}

	wrong, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(root, "secrets", "wrong.json")
	if err := wrong.Save(wrongPath); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverQueueKeyring(queueDir, keyringPath, wrongPath); err == nil {
		t.Fatal("RecoverQueueKeyring(wrong key) error = nil")
	}

	live, err := Open(Config{Dir: queueDir, Keyring: rotated})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	if _, err := InspectQueueKeys(queueDir, 0, rotated); !errors.Is(err, ErrQueueLocked) {
		t.Fatalf("InspectQueueKeys(live queue) error = %v, want ErrQueueLocked", err)
	}
}

func TestQueueKeyMaintenanceReportsUnreadableRecordsAndRefusesDestructiveChanges(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	keyringPath := filepath.Join(root, "keys", "keyring.json")
	backupPath := filepath.Join(root, "keys", "backup.json")
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	oldID := keyring.ActiveKeyID()
	if _, err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(backupPath); err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q.deadDir, "00000000000000000001-corrupt.json"), []byte("{bad"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	usage, err := InspectQueueKeys(queueDir, 0, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if usage[UnreadableRecordID] != 1 {
		t.Fatalf("unreadable usage = %#v, want 1", usage)
	}
	if _, _, err := RotateQueueKeyring(queueDir, keyringPath, backupPath); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("RotateQueueKeyring error = %v, want unreadable refusal", err)
	}
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, oldID); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("RevokeQueueKeyringKey error = %v, want unreadable refusal", err)
	}
	if _, err := RecoverQueueKeyring(queueDir, keyringPath, backupPath); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatalf("RecoverQueueKeyring error = %v, want unreadable refusal", err)
	}
}

func TestQueueKeyMaintenanceErrorPaths(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	keyringPath := filepath.Join(root, "keys", "keyring.json")
	backupPath := filepath.Join(root, "backup", "keyring.json")
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := EnsureKeyringParent(backupPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(backupPath); err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: queueDir, Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"rotate":  func() error { _, _, err := RotateQueueKeyring(queueDir, keyringPath, backupPath); return err },
		"migrate": func() error { _, err := MigrateQueueKeyring(queueDir, keyringPath); return err },
		"revoke":  func() error { return RevokeQueueKeyringKey(queueDir, keyringPath, "missing") },
		"recover": func() error { _, err := RecoverQueueKeyring(queueDir, keyringPath, backupPath); return err },
	} {
		t.Run("locked "+name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrQueueLocked) {
				t.Fatalf("error = %v, want ErrQueueLocked", err)
			}
		})
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(root, "missing-keyring.json")
	for name, run := range map[string]func() error{
		"rotate":  func() error { _, _, err := RotateQueueKeyring(queueDir, missing, backupPath); return err },
		"migrate": func() error { _, err := MigrateQueueKeyring(queueDir, missing); return err },
		"revoke":  func() error { return RevokeQueueKeyringKey(queueDir, missing, "missing") },
		"recover": func() error { _, err := RecoverQueueKeyring(queueDir, keyringPath, missing); return err },
	} {
		t.Run("missing keyring "+name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatal("error = nil")
			}
		})
	}

	parentFile := filepath.Join(root, "backup-parent-file")
	if err := os.WriteFile(parentFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RotateQueueKeyring(queueDir, keyringPath, filepath.Join(parentFile, "backup.json")); err == nil || !strings.Contains(err.Error(), "pre-rotation") {
		t.Fatalf("RotateQueueKeyring(pre-rotation backup) error = %v", err)
	}

	backupDir := filepath.Join(root, "backup-as-directory")
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		t.Fatal(err)
	}
	activeBeforeRotation := keyring.ActiveKeyID()
	oldID, newID, err := RotateQueueKeyring(queueDir, keyringPath, backupDir)
	if err == nil || !strings.Contains(err.Error(), "rotated keyring backup") {
		t.Fatalf("RotateQueueKeyring(directory backup) error = %v", err)
	}
	if oldID != activeBeforeRotation || newID == "" || newID == oldID {
		t.Fatalf("RotateQueueKeyring(directory backup) IDs = (%q, %q), want (%q, new non-empty ID)", oldID, newID, activeBeforeRotation)
	}
	rotated, err := LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveKeyID() != newID {
		t.Fatalf("persisted active key = %q, want returned new ID %q", rotated.ActiveKeyID(), newID)
	}

	if _, err := RecoverQueueKeyring(queueDir, backupDir, backupPath); err == nil {
		t.Fatal("RecoverQueueKeyring(directory live path) error = nil")
	}
}

func TestQueueKeyMaintenanceRefusesUninitializedQueue(t *testing.T) {
	root := t.TempDir()
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(root, "keys", "keyring.json")
	if err := EnsureKeyringParent(keyringPath); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	queueDir := filepath.Join(root, "mistyped-queue")
	if err := RevokeQueueKeyringKey(queueDir, keyringPath, "missing"); err == nil || !strings.Contains(err.Error(), "initialized queue") {
		t.Fatalf("RevokeQueueKeyringKey(uninitialized) error = %v", err)
	}
	if _, err := os.Stat(queueDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("maintenance created typo queue: %v", err)
	}
}

func TestKeyUsageLockedReportsFilesystemAndLimitErrors(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: t.TempDir(), Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = q.Close() }()
	if err := os.RemoveAll(q.deadDir); err != nil {
		t.Fatal(err)
	}
	if _, err := q.keyUsageLocked(); err == nil {
		t.Fatal("keyUsageLocked(missing dir) error = nil")
	}
	if err := os.MkdirAll(q.deadDir, dirMode); err != nil {
		t.Fatal(err)
	}
	name := "00000000000000000001-record.json"
	if err := os.WriteFile(filepath.Join(q.pendingDir, name), []byte("{}"), fileMode); err != nil {
		t.Fatal(err)
	}
	q.maxPayloadBytes = ^uint64(0)
	if _, err := q.keyUsageLocked(); err == nil || errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("keyUsageLocked(limit) error = %v, want non-corrupt configuration error", err)
	}
}

func TestLockQueueForKeyMaintenanceReportsDirectoryFailure(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(parentFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lockQueueForKeyMaintenance(filepath.Join(parentFile, "queue"), 0); err == nil {
		t.Fatal("lockQueueForKeyMaintenance(file parent) error = nil")
	}
}

func TestMigrateQueueKeyringRejectsRecordsEncryptedByAnotherKey(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	writer, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Open(Config{Dir: queueDir, Keyring: writer})
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(signedTestBatch(t, "wrong-key-record", privateKey)); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	wrong, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(root, "wrong", "keyring.json")
	if err := EnsureKeyringParent(wrongPath); err != nil {
		t.Fatal(err)
	}
	if err := wrong.Save(wrongPath); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateQueueKeyring(queueDir, wrongPath); !errors.Is(err, errQueueKeyUnavailable) {
		t.Fatalf("MigrateQueueKeyring(wrong key) error = %v, want errQueueKeyUnavailable", err)
	}
	entries, err := os.ReadDir(filepath.Join(queueDir, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("pending records = %d, want original record preserved", len(entries))
	}
}
